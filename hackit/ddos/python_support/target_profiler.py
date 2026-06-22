"""
Target Profiler — probes target before attack to gather intelligence.

Features: WAF detection, server fingerprinting, port scanning,
latency measurement, bandwidth estimation, and defense mechanism mapping.
"""

import socket
import ssl
import time
import random
import ipaddress
import concurrent.futures
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from typing import Optional


class TargetProfile:
    def __init__(self, target: str):
        self.target = target
        self.ip: Optional[str] = None
        self.port_status: dict[int, str] = {}
        self.server_header: Optional[str] = None
        self.waf_detected: list[str] = []
        self.latency_ms: float = 0
        self.bandwidth_est: float = 0
        self.defense_mechanisms: list[str] = []
        self.protocols: list[str] = []
        self.is_cloudflare: bool = False
        self.country: Optional[str] = None
        self.isp: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "target": self.target, "ip": self.ip,
            "ports": self.port_status, "server": self.server_header,
            "waf": self.waf_detected, "latency_ms": self.latency_ms,
            "defenses": self.defense_mechanisms, "protocols": self.protocols,
            "cloudflare": self.is_cloudflare,
        }


class TargetProfiler:
    WAF_SIGNATURES = {
        "cloudflare": ["__cfduid", "cf-ray", "cf-cache-status", "cloudflare"],
        "akamai": ["akamai", "x-akamai-", "x-purple-"],
        "incapsula": ["incapsula", "x-iinfo"],
        "sucuri": ["sucuri", "x-sucuri-"],
        "modsecurity": ["mod_security", "modsecurity", "no-store"],
        "f5_bigip": ["big-ip", "x-wa-info", "f5-net"],
        "imperva": ["imperva", "x-cdn"],
        "aws_waf": ["awswaf", "x-amzn-trace-id", "x-amz-cf-id"],
        "fortinet": ["fortigate", "fortiweb"],
        "barracuda": ["barracuda"],
    }

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.profile = TargetProfile(target)

    def resolve(self) -> bool:
        try:
            self.profile.ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            try:
                ipaddress.ip_address(self.target)
                self.profile.ip = self.target
                return True
            except ValueError:
                return False

    def probe_http(self, port: int = 80, ssl_proto: bool = False) -> Optional[dict]:
        scheme = "https" if ssl_proto else "http"
        url = f"{scheme}://{self.target}:{port}/"
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "text/html,*/*",
            })
            resp = urlopen(req, timeout=self.timeout)
            headers = dict(resp.headers)
            body = resp.read(4096).decode('utf-8', errors='replace').lower()
            resp.close()

            self.profile.port_status[port] = "open"
            self.profile.server_header = headers.get("Server", headers.get("server", "unknown"))
            self.profile.protocols.append(scheme)

            for waf_name, sigs in self.WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig in str(headers).lower() or sig in body:
                        self.profile.waf_detected.append(waf_name)
                        if waf_name == "cloudflare":
                            self.profile.is_cloudflare = True
                        break

            return headers
        except HTTPError as e:
            self.profile.port_status[port] = f"http_{e.code}"
            return dict(e.headers)
        except Exception:
            self.profile.port_status[port] = "closed"
            return None

    def measure_latency(self, count: int = 3) -> float:
        times = []
        for _ in range(count):
            try:
                start = time.time()
                sock = socket.create_connection(
                    (self.profile.ip or self.target, 80), timeout=self.timeout)
                sock.close()
                times.append((time.time() - start) * 1000)
            except Exception:
                pass
        if times:
            self.profile.latency_ms = sum(times) / len(times)
        return self.profile.latency_ms

    def scan_ports(self, ports: Optional[list[int]] = None) -> dict[int, str]:
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     465, 587, 993, 995, 1433, 1521, 3306, 3389,
                     5432, 6379, 8080, 8443, 9000, 27017]
        ip = self.profile.ip or self.target

        def check_port(p):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, p))
                sock.close()
                return p, "open" if result == 0 else "closed"
            except Exception:
                return p, "filtered"

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            results = ex.map(check_port, ports)
            for p, status in results:
                self.profile.port_status[p] = status

        return self.profile.port_status

    def detect_ssl(self) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((self.target, 443), timeout=self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            cert = ssock.getpeercert()
            ssock.close()
            if cert:
                self.profile.protocols.append("https")
                return True
        except Exception:
            pass
        return False

    def estimate_bandwidth(self, sample_size: int = 1024 * 100) -> float:
        try:
            sock = socket.create_connection(
                (self.profile.ip or self.target, 80), timeout=self.timeout)
            request = f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
            sock.sendall(request)
            start = time.time()
            total = 0
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                total += len(data)
                if total >= sample_size:
                    break
            elapsed = time.time() - start
            sock.close()
            if elapsed > 0:
                self.profile.bandwidth_est = (total * 8) / elapsed
                return self.profile.bandwidth_est
        except Exception:
            pass
        return 0

    def full_profile(self) -> TargetProfile:
        self.resolve()
        self.probe_http(80)
        self.probe_http(443, ssl_proto=True)
        self.measure_latency()
        self.scan_ports()
        self.detect_ssl()
        self.estimate_bandwidth()
        return self.profile

    def suggest_attack_strategy(self) -> dict:
        strategy = {
            "method": "syn",
            "workers": 50,
            "rate": 1000,
            "reason": "default",
        }
        if self.profile.is_cloudflare:
            strategy["method"] = "http"
            strategy["rate"] = 500
            strategy["reason"] = "Cloudflare detected — layer 7 recommended"
        elif "f5_bigip" in self.profile.waf_detected:
            strategy["method"] = "ack"
            strategy["reason"] = "F5 BIG-IP — ACK flood bypass"
        elif "modsecurity" in self.profile.waf_detected:
            strategy["method"] = "rst"
            strategy["reason"] = "ModSecurity — RST flood"
        if self.profile.latency_ms > 200:
            strategy["workers"] = 25
            strategy["rate"] = 500
            strategy["reason"] += ", high latency detected"
        return strategy
