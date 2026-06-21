import socket
import json
import functools
from concurrent.futures import ThreadPoolExecutor

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    urllib3 = None


@functools.lru_cache(maxsize=128)
def _resolve_host(host):
    return socket.gethostbyname(host)


class PortScanner:
    def __init__(self):
        self.common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 3306: "mysql", 5432: "postgresql",
            6379: "redis", 8080: "http-proxy", 27017: "mongodb"
        }
        self._http_pools = {}

    def _get_pool(self, host, port):
        key = (host, port)
        if key not in self._http_pools:
            if port == 443:
                self._http_pools[key] = urllib3.HTTPConnectionPool(
                    host, port=port, maxsize=10, cert_reqs='CERT_NONE',
                    assert_hostname=False
                )
            else:
                self._http_pools[key] = urllib3.HTTPConnectionPool(
                    host, port=port, maxsize=10
                )
        return self._http_pools[key]

    def scan_port(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex((host, port))
                if result == 0:
                    banner = ""
                    try:
                        if port in [80, 8080, 443] and urllib3 is not None:
                            pool = self._get_pool(host, port)
                            r = pool.request('HEAD', '/', headers={'Host': host}, timeout=2.0)
                            banner = r.data.decode('utf-8', errors='ignore').strip()
                        else:
                            if port in (21, 22):
                                pass
                            s.settimeout(2.0)
                            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        banner = "".join(c for c in banner if c.isprintable())
                    except Exception:
                        pass

                    return {
                        "port": port,
                        "status": "open",
                        "service": self.common_services.get(port, "unknown"),
                        "banner": banner[:100]
                    }
        except Exception:
            pass
        return None

    def _scan_chunk(self, host, ports_chunk):
        local_results = []
        for port in ports_chunk:
            res = self.scan_port(host, port)
            if res:
                local_results.append(res)
        return local_results

    def scan(self, host, ports=None, timeout=1, threads=100):
        socket.setdefaulttimeout(timeout)

        try:
            host = _resolve_host(host)
        except socket.gaierror:
            pass

        if ports is None:
            ports = list(range(1, 1025))
        elif isinstance(ports, str):
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(p) for p in ports.split(',')]
        else:
            ports = list(ports)

        chunk_size = max(1, len(ports) // (threads * 2))
        chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]

        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self._scan_chunk, host, chunk) for chunk in chunks]
            for future in futures:
                results.extend(future.result())

        return results

if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    ports = sys.argv[2] if len(sys.argv) > 2 else '1-1024'
    timeout = float(sys.argv[3]) / 1000.0 if len(sys.argv) > 3 else 1.0
    
    scanner = PortScanner()
    print(json.dumps(scanner.scan(host, ports=ports, timeout=timeout)))

