import socket
import json
import threading
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self):
        self.common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 3306: "mysql", 5432: "postgresql",
            6379: "redis", 8080: "http-proxy", 27017: "mongodb"
        }

    def scan_port(self, host, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((host, port))
                if result == 0:
                    banner = ""
                    try:
                        # Protocol specific probes
                        if port in [80, 8080, 443]:
                            s.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                        elif port == 21:
                            # FTP sends banner on connect, just recv
                            pass
                        elif port == 22:
                            # SSH sends banner on connect
                            pass
                        
                        s.settimeout(2.0)
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        # Clean up banner
                        banner = "".join(c for c in banner if c.isprintable())
                    except Exception:
                        pass
                    
                    return {
                        "port": port,
                        "status": "open",
                        "service": self.common_services.get(port, "unknown"),
                        "banner": banner[:100] # Limit banner length
                    }
        except Exception:
            pass
        return None

    def scan(self, host, ports=None, timeout=1, threads=100):
        if ports is None:
            ports = range(1, 1025)
        elif isinstance(ports, str):
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                ports = range(start, end + 1)
            else:
                ports = [int(p) for p in ports.split(',')]

        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.scan_port, host, port, timeout) for port in ports]
            for future in futures:
                res = future.result()
                if res:
                    results.append(res)
        
        return results

if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    ports = sys.argv[2] if len(sys.argv) > 2 else '1-1024'
    timeout = float(sys.argv[3]) / 1000.0 if len(sys.argv) > 3 else 1.0
    
    scanner = PortScanner()
    print(json.dumps(scanner.scan(host, ports=ports, timeout=timeout)))

