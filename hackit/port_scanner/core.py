import socket
import json
import errno
import time
import functools
from concurrent.futures import ThreadPoolExecutor

from .banner_engine import probe_port

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    urllib3 = None


# Ordered high-signal ports. Matches the Go engine's notion of "top100" closely
# enough that both engines scan the same surface; keep this list ordered so the
# first N entries are always the highest-value ports.
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
    8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465,
    548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000,
    32768, 1027, 1028, 1029, 1030, 8081, 2001, 8082, 6000, 9000, 6443,
    6379, 27017, 3000, 5432, 5672, 11211, 4369, 1521, 1433, 7001, 50000,
    9200, 4567, 7070, 7080, 7443, 8009, 8091, 8161, 8500, 9042, 9090,
    9100, 9300, 9418, 9999, 14265, 28017, 50030, 50050, 50060, 50070,
    50090, 60000, 60010, 60020, 60030, 2375, 2376, 2377, 4243, 8001,
    10250, 10255, 2379, 2380, 5000, 8200, 8300, 49152, 61616, 7002,
]


def expand_ports(spec, default_count=100):
    """Expand a port spec into a concrete, ordered list of port numbers.

    Accepts ``topN``/``top``, ``default``, ``all``/``full``, comma lists and
    ``lo-hi`` ranges. Unparseable tokens are dropped rather than raising, so a
    typo degrades to a smaller scan instead of killing the whole run.
    """
    if spec is None:
        return list(TOP_PORTS[:default_count])
    if isinstance(spec, (list, tuple, set)):
        out = []
        for item in spec:
            try:
                p = int(item)
            except (TypeError, ValueError):
                continue
            if 0 < p <= 65535:
                out.append(p)
        return sorted(set(out))

    text = str(spec).strip().lower()
    if not text or text == 'default':
        return list(TOP_PORTS[:default_count])
    if text in ('all', 'full'):
        return list(range(1, 65536))
    if text.startswith('top'):
        tail = text[3:]
        try:
            n = int(tail) if tail else default_count
        except ValueError:
            n = default_count
        if n <= len(TOP_PORTS):
            return list(TOP_PORTS[:n])
        # Beyond the curated list, extend deterministically so the count is real.
        extra = [p for p in range(1, 65536) if p not in set(TOP_PORTS)]
        return list(TOP_PORTS) + extra[: max(0, n - len(TOP_PORTS))]

    out = []
    for token in text.replace(' ', '').split(','):
        if not token:
            continue
        if '-' in token:
            lo, _, hi = token.partition('-')
            if not (lo.isdigit() and hi.isdigit()):
                continue
            a, b = int(lo), int(hi)
            if a > b:
                a, b = b, a
            out.extend(range(max(1, a), min(65535, b) + 1))
        elif token.isdigit():
            p = int(token)
            if 0 < p <= 65535:
                out.append(p)
    return sorted(set(out))


@functools.lru_cache(maxsize=128)
def _resolve_host(host):
    return socket.gethostbyname(host)


def classify_connect_error(errno_value):
    """Map a socket errno to a scan state.

    ``connect_ex`` returns 0 for a completed handshake and a POSIX errno
    otherwise. Treating every non-zero value as "closed" is what makes naive
    scanners lie about firewalled hosts: ECONNREFUSED is a real RST, but
    ETIMEDOUT and EHOSTUNREACH mean the probe never reached a listener.
    """
    if errno_value == 0:
        return "open", "handshake-complete"
    if errno_value in (errno.ECONNREFUSED,):
        return "closed", "connection-refused"
    if errno_value in (errno.ETIMEDOUT, getattr(errno, "EAGAIN", 11)):
        return "filtered", "connect-timeout"
    if errno_value in (getattr(errno, "EHOSTUNREACH", 113), getattr(errno, "ENETUNREACH", 101)):
        return "unreachable", "no-route"
    if errno_value in (errno.EACCES, errno.EPERM):
        return "filtered", "blocked-by-policy"
    if errno_value == errno.ECONNRESET:
        return "closed", "connection-reset"
    if errno_value == getattr(errno, "EHOSTDOWN", 112):
        return "unreachable", "host-down"
    return "error", "errno-%d" % errno_value


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

    def _connect_state(self, host, port, timeout, attempts=2):
        """Probe a TCP port, retrying only the ambiguous outcomes.

        A refused connection is final: retrying it cannot change the answer and
        would only double the scan time. A timeout or a host-unreachable may be
        a transient drop, so it gets one more chance before being reported.
        """
        last_state, last_reason, last_errno = "error", "no-attempt", -1
        connect_ms = 0
        for attempt in range(max(1, attempts)):
            started = time.time()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((host, port))
            except OSError as exc:
                result = getattr(exc, "errno", None) or errno.EIO
            connect_ms = int((time.time() - started) * 1000)
            state, reason = classify_connect_error(result)
            last_state, last_reason, last_errno = state, reason, result
            if state in ("open", "closed"):
                break
            if attempt + 1 < attempts and timeout > 0.25:
                continue
            break
        return last_state, last_reason, last_errno, connect_ms

    def scan_port(self, host, port, banner_timeout=2.0):
        started = time.time()
        state, reason, err_no, connect_ms = self._connect_state(
            host, port, banner_timeout)

        if state != "open":
            return {
                "port": port,
                "status": state,
                "service": self.common_services.get(port, "unknown"),
                "banner": "",
                "banner_status": "empty",
                "banner_protocol": "",
                "banner_confidence": 0.0,
                "confidence": 0.9 if state == "closed" else 0.5,
                "reason": reason,
                "errno": err_no,
                "elapsed_ms": int((time.time() - started) * 1000),
                "connect_ms": connect_ms,
            }

        probe = probe_port(host, port, timeout=banner_timeout)
        banner = probe.get("banner", "")
        protocol = probe.get("protocol", "")
        product = probe.get("product", "")
        version = probe.get("version", "")

        service = product or self.common_services.get(port, "unknown")
        if not product and protocol:
            service = protocol
        if not protocol or protocol == "unknown":
            # Nothing was decoded, so any version is a guess pulled from raw
            # text. Keep the evidence, drop the fabricated version.
            version = ""
            service = "unknown" if not product else service

        if banner:
            banner_status = "truncated" if banner.endswith("…") else "full"
        else:
            banner_status = "empty"

        confidence = probe.get("confidence", 0.0)
        if confidence <= 0.0:
            confidence = 0.60 if service != "unknown" else 0.45

        return {
            "port": port,
            "status": "open",
            "service": service,
            "version": version,
            "banner": banner,
            "banner_status": banner_status,
            "banner_protocol": protocol,
            "banner_confidence": round(confidence, 2),
            "banner_evidence": probe.get("evidence", ""),
            "banner_mismatch": bool(probe.get("mismatch")),
            "confidence": round(confidence, 2),
            "reason": (protocol + "-observed") if protocol else "port-default-match",
            "elapsed_ms": int((time.time() - started) * 1000),
            "connect_ms": connect_ms,
        }

    def _scan_chunk(self, host, ports_chunk, on_result=None, include_closed=False):
        local_results = []
        for port in ports_chunk:
            res = self.scan_port(host, port)
            if res:
                if on_result is not None:
                    try:
                        on_result(res)
                    except Exception:
                        pass
                if res.get("status") == "open" or (include_closed and res.get("status") in ("closed", "error")):
                    local_results.append(res)
        return local_results

    def scan(self, host, ports=None, timeout=1, threads=100, on_result=None, include_closed=False):
        socket.setdefaulttimeout(timeout)

        try:
            host = _resolve_host(host)
        except socket.gaierror:
            pass

        ports = expand_ports(ports, default_count=1024) if ports is None else expand_ports(ports)
        if not ports:
            return []

        chunk_size = max(1, len(ports) // (threads * 2))
        chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]

        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self._scan_chunk, host, chunk, on_result, include_closed) for chunk in chunks]
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

