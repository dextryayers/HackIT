"""Protocol-accurate banner capture for the Python engine.

The old ``scan_port`` read one socket buffer and guessed the service from the
port number alone. This module mirrors the Go/Rust probe engines: an ordered
plan per port, an accumulating reader, and protocol decoders that report what
was actually observed on the wire.
"""

from __future__ import annotations

import re
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

BANNER_MAX = 16384
GREET_WAIT = 0.45
PROBE_WAIT = 0.90
IDLE_GAP = 0.12
MAX_STAGES = 6

_HTTP_STATUS = re.compile(r"^HTTP/\d\.\d\s+\d{3}", re.I)
_HTTP_SERVER = re.compile(r"^server:\s*(.+)$", re.I)
_HTTP_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_VERSION_RE = re.compile(r"\d+\.\d+")


# ─────────────────────────────────────────────────────────────────
# Probe plan
# ─────────────────────────────────────────────────────────────────

GREETING_PORTS = {
    21, 990, 22, 2222, 2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230,
    25, 465, 587, 2525, 110, 995, 143, 993, 119,
    3306, 3307, 3308, 3309, 3310, 3311, 3312,
    5432, 5433, 5434, 5435, 5436, 5437, 5438, 5439, 5440,
    6379, 6380, 6381, 6382, 6383, 6384, 6385,
    27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025,
    5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910,
    1521, 1522, 1523, 1524, 1525, 1526, 1527,
    3389, 3390, 3391, 3392, 23, 873, 445, 111, 5672, 5671, 9042, 9160,
    6660, 6667, 6697, 194,
}

NOT_HTTP_PORTS = {
    21, 22, 23, 25, 110, 143, 465, 587, 636, 990, 993, 995,
    1883, 2222, 3306, 3389, 5222, 5432, 5671, 5672, 5900,
    6379, 8883, 9042, 11211, 25565, 27017,
}

NOT_TLS_PORTS = {
    21, 22, 23, 25, 110, 143, 1883, 3306, 5222, 5672, 6379, 6667, 11211, 25565, 27017,
}

HTTP_PORTS = {
    80, 81, 82, 83, 84, 85, 86, 88, 89, 90, 443, 4433, 4443,
    3000, 3001, 3002, 3003, 3004, 4000, 5000, 554, 631,
    7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007,
    7080, 7081, 7443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8010, 8011, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8123, 8200, 8201, 8222, 8300, 8301, 8302, 8400,
    8443, 8444, 8445, 8446, 8447, 8448, 8449, 8450,
    8500, 8501, 8502, 8503, 8504, 8554, 8600,
    8880, 8881, 8882, 8883, 8884, 8885, 8886, 8887, 8888, 8889, 8890, 8891, 8892,
    9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,
    9090, 9091, 9200, 9201, 9202, 9203, 9204, 9205, 9206, 9207, 9208, 9209, 9210,
    9443, 9444, 9445, 9446, 9447, 9448, 9449, 9450,
    10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010,
    15672, 18080, 18081, 18082, 18083, 18084, 18085, 18086, 18087, 18088, 18089, 18090,
    28080, 28081, 28082, 28083, 28084, 28085, 28086, 28087, 28088, 28089, 28090,
    3100, 3101, 3102, 4646, 50001, 50002, 50003, 50004, 50005,
    5800, 5801, 5802, 5803, 5804, 5805, 5984, 61616, 61620, 6443, 6444,
    9093, 9094, 9095, 9096, 9097, 10250, 10251, 10252, 10253, 10254, 10255, 10256,
    2375, 2377, 4243,
}

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "curl/8.7.1",
]


def _http_payload(host: str, port: int, path: str = "/") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: {USER_AGENTS[port % len(USER_AGENTS)]}\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def _postgres_startup() -> bytes:
    params = b"user\x00hackit\x00database\x00postgres\x00\x00"
    body = struct.pack(">II", 8 + len(params), 196608) + params
    return body


def _mongo_ismaster() -> bytes:
    doc = (
        b"\x13\x00\x00\x00"
        b"\x10ismaster\x00"
        b"\x01\x00\x00\x00"
        b"\x00"
    )
    msg = struct.pack("<IIII", 0, 1, 0, 2004) + b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00" + struct.pack("<II", 0, 0xFFFFFFFF) + doc
    return struct.pack("<I", len(msg)) + msg[4:]


def _mssql_prelogin() -> bytes:
    return bytes([
        0x12, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x1A, 0x00, 0x06, 0x01, 0x00, 0x20,
        0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
        0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
        0x01, 0xFF, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])


def _cassandra_startup(version: int = 4) -> bytes:
    body = b"\x00\x01\x00\x0bCQL_VERSION\x00\x05" + b"3.0.0"
    return bytes([version, 0, 0, 0, 1, 0, 0, 0, len(body)]) + body


def _rdp_negotiate() -> bytes:
    return bytes([
        0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
        0x00, 0x00, 0x00,
    ])


def _smb_negotiate() -> bytes:
    body = bytearray()
    body += b"\x00\x00\x00\x00\xfeSMB"
    body += struct.pack("<H", 0x40)
    body += struct.pack("<H", 4)
    body += struct.pack("<H", 1)
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)
    body += b"\x00" * 16
    body += b"\x00" * 4
    body += bytes([0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03])
    struct.pack_into(">I", body, 0, len(body) - 4)
    return bytes(body)


def _kafka_api_versions() -> bytes:
    body = struct.pack(">hhi", 18, 0, 1) + struct.pack(">h", 6) + b"hackit"
    return struct.pack(">I", len(body)) + body


def _minecraft_handshake(host: str, port: int) -> bytes:
    payload = b"\x00\x04" + host.encode() + struct.pack(">H", port) + b"\x01"
    return bytes([len(payload)]) + payload + b"\x01\x00"


def build_plan(port: int, host: str) -> List[Tuple[str, Optional[bytes], float]]:
    """Return ordered (name, payload, settle) stages. ``payload=None`` = read first."""
    plan: List[Tuple[str, Optional[bytes], float]] = []

    if port in GREETING_PORTS:
        plan.append(("greeting", None, GREET_WAIT))

    def add(name: str, payload: Optional[bytes], settle: float = PROBE_WAIT) -> None:
        plan.append((name, payload, settle))

    if port in (25, 465, 587, 2525):
        add("smtp", b"EHLO hackit.local\r\n")
    elif port == 110:
        add("pop3", b"CAPA\r\n")
    elif port == 143:
        add("imap", b"a1 CAPABILITY\r\n")
    elif port == 119:
        add("nntp", b"MODE READER\r\n")
    elif port == 21:
        add("ftp", b"FEAT\r\n")
        add("ftp-tls", b"AUTH TLS\r\n")
    elif 5432 <= port <= 5440:
        add("postgres-ssl", bytes([0, 0, 0, 8, 4, 210, 22, 47]))
        add("postgres-startup", _postgres_startup())
    elif 6379 <= port <= 6385:
        add("redis", b"INFO server\r\n")
    elif port == 16379:
        add("redis-cluster", b"CLUSTER INFO\r\n")
    elif 27017 <= port <= 27025:
        add("mongodb", _mongo_ismaster())
    elif port == 1433:
        add("mssql", _mssql_prelogin())
    elif 1521 <= port <= 1527:
        add("oracle-tns", b"\x00\x57\x00\x00\x01\x00\x00\x00\x01\x3a\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x3d\x00\x00\x00\x00\x00\x00")
    elif port in (9042, 9043, 9044):
        add("cassandra", _cassandra_startup())
    elif port == 9160:
        add("cassandra-thrift", b"\x80\x01\x00\x01\x00\x00\x00\x01")
    elif 5900 <= port <= 5910:
        add("vnc", b"RFB 003.008\n")
    elif 3389 <= port <= 3392:
        add("rdp", _rdp_negotiate())
    elif port in (389, 3268):
        add("ldap", b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
    elif port in (5672, 5671):
        add("amqp", b"AMQP\x00\x00\x09\x01")
    elif port in (1883, 8883):
        add("mqtt", b"\x10\x0e\x00\x04MQTT\x04\x00\x00\x00\x00\x00\x00")
    elif 9092 <= port <= 9097:
        add("kafka", _kafka_api_versions())
    elif port in (4222, 6222):
        add("nats", b'CONNECT {"verbose":false}\r\nPING\r\n')
    elif 11211 <= port <= 11215:
        add("memcached", b"stats\r\n")
    elif port == 2181:
        add("zookeeper", b"srvr")
        add("zookeeper-ruok", b"ruok")
    elif port in (2375, 2376, 4243):
        add("docker", _http_payload(host, port, "/version"))
    elif port in (6443, 6444, 8001):
        add("kubernetes", _http_payload(host, port, "/version"))
    elif 9200 <= port <= 9210:
        add("elasticsearch", _http_payload(host, port))
    elif port == 445:
        add("smb", _smb_negotiate())
    elif port == 873:
        add("rsync", b"@RSYNCD: 31.0\n")
    elif port == 25565:
        add("minecraft", _minecraft_handshake(host, port))
    elif port in (554, 8554):
        add("rtsp", b"OPTIONS rtsp://localhost RTSP/1.0\r\nCSeq: 1\r\n\r\n")
    elif port == 5060:
        add("sip", b"OPTIONS sip:probe@localhost SIP/2.0\r\nVia: SIP/2.0/TCP localhost\r\nFrom: <sip:probe@localhost>;tag=1\r\nTo: <sip:probe@localhost>\r\nCall-ID: 1@localhost\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")

    if port in HTTP_PORTS:
        add("http", _http_payload(host, port))
    elif port not in NOT_HTTP_PORTS:
        add("http", _http_payload(host, port))

    if port not in NOT_TLS_PORTS:
        add("tls", None)

    add("crlf", b"\r\n", 0.4)
    return plan[:MAX_STAGES]


# ─────────────────────────────────────────────────────────────────
# Reading
# ─────────────────────────────────────────────────────────────────

def _read_until_quiet(sock: socket.socket, first: float, limit: int = BANNER_MAX) -> bytes:
    out = bytearray()
    try:
        sock.settimeout(first)
        chunk = sock.recv(4096)
    except (socket.timeout, OSError):
        return bytes(out)
    if not chunk:
        return bytes(out)
    out.extend(chunk)
    while len(out) < limit:
        try:
            sock.settimeout(IDLE_GAP)
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        out.extend(chunk[: limit - len(out)])
    return bytes(out)


def _run_stage(host: str, port: int, name: str, payload: Optional[bytes], settle: float, timeout: float) -> Dict:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except OSError:
        return {}
    try:
        if payload is not None and payload:
            try:
                sock.sendall(payload)
            except OSError:
                return {}
        raw = _read_until_quiet(sock, settle)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if not raw:
        return {}
    result = decode(port, raw)
    result["evidence"] = name
    return result


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────

def probe_port(host: str, port: int, timeout: float = 1.5) -> Dict:
    """Probe one port and return a decoded banner record.

    Keys: banner, protocol, product, version, confidence, evidence, mismatch.
    """
    deadline = max(0.6, min(5.0, timeout))
    best: Dict = {}
    for name, payload, settle in build_plan(port, host):
        res = _run_stage(host, port, name, payload, settle, deadline)
        if not res:
            continue
        if not best or res.get("confidence", 0) > best.get("confidence", 0) or (
            res.get("confidence", 0) == best.get("confidence", 0)
            and len(res.get("banner", "")) > len(best.get("banner", ""))
        ):
            best = res
        if best.get("confidence", 0) >= 0.80:
            break
    if not best:
        return {"banner": "", "protocol": "", "product": "", "version": "",
                "confidence": 0.0, "evidence": "no-response", "mismatch": False}
    finalize(best, port)
    return best


def finalize(info: Dict, port: int) -> None:
    banner = " ".join(str(info.get("banner", "")).split())
    info["banner"] = banner[:260]
    protocol = info.get("protocol", "")
    if protocol and not _port_is_expected(protocol, port):
        # Real service on an unconventional port: flag it, keep the evidence.
        info["mismatch"] = True
        if info.get("confidence", 0.0) > 0.55:
            info["confidence"] = info["confidence"] - 0.05
    info.setdefault("mismatch", False)


EXPECTED_PORTS = {
    "ftp": {21, 2100, 2121, 8021},
    "ssh": {22, 222, 2022, *range(2222, 2231)},
    "smtp": {25, 465, 587, 2525},
    "pop3": {110, 995},
    "imap": {143, 993},
    "mysql": {*range(3306, 3313), 33060},
    "redis": {*range(6379, 6386), 16379, 26379},
    "mongodb": set(range(27017, 27026)),
    "memcached": set(range(11211, 11216)),
    "vnc": set(range(5900, 5911)),
    "rsync": {873},
}


def _port_is_expected(proto: str, port: int) -> bool:
    ports = EXPECTED_PORTS.get(proto)
    return not ports or port in ports


# ─────────────────────────────────────────────────────────────────
# Decoders
# ─────────────────────────────────────────────────────────────────

def decode(port: int, raw: bytes) -> Dict:
    info: Dict = {"banner": "", "protocol": "", "product": "", "version": "",
                  "confidence": 0.0, "evidence": "", "mismatch": False}

    if _is_tls(raw):
        info.update(protocol="tls", product="TLS", confidence=0.9,
                    banner=_tls_label(raw))
        return info

    version = _decode_mysql(raw)
    if version:
        info.update(protocol="mysql", product="MySQL",
                    version=version.split()[0],
                    banner=f"MySQL {version}", confidence=0.98)
        return info

    text = _sanitize(raw)
    if text.startswith("SSH-"):
        line = _first_line(text)
        product, ver = _parse_ssh(line)
        info.update(protocol="ssh", product=product, version=ver, banner=line, confidence=0.99)
        return info

    if text.startswith("RFB "):
        line = _first_line(text)
        info.update(protocol="vnc", product="VNC", version=line[4:].strip(),
                    banner=line, confidence=0.97)
        return info

    if _is_redis(raw):
        ver = _redis_version(text)
        info.update(protocol="redis", product="Redis", version=ver,
                    banner=f"Redis {ver}" if ver else _first_line(text), confidence=0.95)
        return info

    if _is_mongo(raw):
        ver = _bson_version(raw)
        info.update(protocol="mongodb", product="MongoDB", version=ver,
                    banner=f"MongoDB {ver}" if ver else "MongoDB", confidence=0.93)
        return info

    if b"SMB" in raw[:16]:
        dialect = _smb_dialect(raw)
        info.update(protocol="smb", product="SMB", version=dialect,
                    banner=f"SMB {dialect}", confidence=0.95)
        return info

    if len(raw) >= 11 and raw[0] == 0x03 and raw[1] == 0x00:
        info.update(protocol="rdp", product="RDP", banner="RDP (X.224 negotiation)",
                    confidence=0.88)
        return info

    if raw.startswith(b"AMQP"):
        info.update(protocol="amqp", product="RabbitMQ",
                    banner="AMQP connection.start", confidence=0.95)
        return info

    if len(raw) >= 4 and raw[0] == 0x20 and raw[1] == 0x02:
        info.update(protocol="mqtt", product="MQTT", banner="MQTT CONNACK", confidence=0.9)
        return info

    if _HTTP_STATUS.match(text):
        return _decode_http(text, tls=False)

    classified = _classify_text(port, text)
    if classified:
        proto, product, conf = classified
        info.update(protocol=proto, product=product, confidence=conf,
                    version=_text_version(text, proto), banner=_summarize(text))
        return info

    if text:
        info.update(protocol="unknown", banner=_truncate(text, 220), confidence=0.3)
    return info


def _decode_http(text: str, tls: bool) -> Dict:
    info: Dict = {"banner": "", "protocol": "https" if tls else "http",
                  "product": "HTTP", "version": "", "confidence": 0.99 if tls else 0.90,
                  "evidence": "", "mismatch": False}
    parts: List[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        t = line.strip()
        if not t:
            continue
        if _HTTP_STATUS.match(t):
            parts.append(t)
            continue
        m = _HTTP_SERVER.match(t)
        if m:
            server = m.group(1).strip()
            parts.append(f"Server: {server}")
            product, version = _split_product_version(server)
            if product:
                info["product"] = product
                info["version"] = version
            info["confidence"] = 0.97
            continue
        low = t.lower()
        if low.startswith(("x-powered-by:", "via:", "content-type:", "x-generator:")):
            parts.append(t)
        if len(parts) >= 5:
            break
    m = _HTTP_TITLE.search(text)
    if m:
        title = " ".join(m.group(1).split())
        if title and len(title) < 120:
            parts.append(f"Title: {title}")
    info["banner"] = " | ".join(parts) if parts else _truncate(text, 160)
    return info


def _split_product_version(header: str) -> Tuple[str, str]:
    header = header.strip()
    if not header:
        return "", ""
    if "/" in header:
        product, _, rest = header.partition("/")
        first = rest.strip().split()[0] if rest.strip() else ""
        return product.strip(), first.rstrip(";") if _VERSION_RE.search(first) else ""
    fields = header.split()
    product = fields[0]
    for f in fields[1:]:
        if _VERSION_RE.search(f):
            return product, f.rstrip(";")
    return product, ""


def _classify_text(port: int, text: str) -> Optional[Tuple[str, str, float]]:
    low = text.lower()
    rules = [
        ("ftp", "FTP", (" 220 ", "vsftpd", "proftpd", "pure-ftpd", "filezilla"), 0.92),
        ("smtp", "SMTP", ("esmtp", "postfix", "exim", "sendmail", "smtp"), 0.90),
        ("pop3", "POP3", ("+ok", "pop3", "dovecot"), 0.88),
        ("imap", "IMAP", ("* ok", "imap", "dovecot", "cyrus"), 0.88),
        ("telnet", "Telnet", ("login:", "password:"), 0.70),
        ("memcached", "Memcached", ("curr_items", "version "), 0.85),
        ("rsync", "rsync", ("@rsyncd",), 0.97),
        ("zookeeper", "ZooKeeper", ("imok", "mode:"), 0.85),
        ("elasticsearch", "Elasticsearch", ("you know, for search", "lucene_version"), 0.95),
        ("prometheus", "Prometheus", ("# help", "# type"), 0.85),
        ("sip", "SIP", ("sip/2.0",), 0.92),
        ("rtsp", "RTSP", ("rtsp/1.0",), 0.95),
        ("xmpp", "XMPP", ("stream:stream", "jabber"), 0.90),
        ("irc", "IRC", ("ircd", "notice auth"), 0.85),
        ("nntp", "NNTP", ("200 ", "nntp", "inn "), 0.80),
    ]
    for proto, product, needles, conf in rules:
        if any(n in low for n in needles):
            return proto, product, conf
    return None


def _text_version(text: str, proto: str) -> str:
    patterns = {
        "ftp": r"(?i)(?:vsftpd|proftpd|pure-ftpd|filezilla)[^\d]*([\d.]+)",
        "smtp": r"(?i)(?:postfix|exim|sendmail|opensmtpd)[^\d]*([\d.]+)",
        "memcached": r"(?i)VERSION\s+([\d.]+)",
        "rsync": r"(?i)@rsyncd:\s*([\d.]+)",
    }
    pat = patterns.get(proto)
    if not pat:
        return ""
    m = re.search(pat, text)
    return m.group(1) if m else ""


def _is_tls(raw: bytes) -> bool:
    return len(raw) >= 5 and raw[0] == 0x16 and raw[1] == 0x03 and raw[2] <= 0x04


def _tls_label(raw: bytes) -> str:
    return {
        0x01: "TLS 1.0 handshake",
        0x02: "TLS 1.1 handshake",
        0x03: "TLS 1.2 handshake",
        0x04: "TLS 1.3 handshake",
    }.get(raw[2] if len(raw) > 2 else -1, "TLS handshake")


def _decode_mysql(raw: bytes) -> Optional[str]:
    if len(raw) < 6 or raw[3] != 0x00 or raw[4] != 0x0A:
        return None
    rest = raw[5:]
    end = rest.find(b"\x00")
    if end <= 0 or end > 64:
        return None
    try:
        version = rest[:end].decode("ascii", errors="ignore")
    except Exception:
        return None
    if not version or not version[0].isdigit() or "." not in version:
        return None
    return version


def _is_redis(raw: bytes) -> bool:
    return raw[:1] in (b"+", b"-", b":", b"$", b"*") and b"\r\n" in raw


def _redis_version(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("redis_version:"):
            return line.split(":", 1)[1].strip()
    return ""


def _is_mongo(raw: bytes) -> bool:
    if len(raw) < 16:
        return False
    length = struct.unpack("<I", raw[:4])[0]
    if length > len(raw):
        return False
    opcode = struct.unpack("<I", raw[12:16])[0]
    return opcode in (1, 2004, 2013)


def _bson_version(raw: bytes) -> str:
    idx = raw.find(b"version\x00")
    if idx < 0:
        return ""
    start = idx + 8
    if start + 4 > len(raw):
        return ""
    n = struct.unpack("<I", raw[start:start + 4])[0]
    if n <= 1 or n > 32 or start + 4 + n > len(raw):
        return ""
    try:
        return raw[start + 4:start + 4 + n - 1].decode("ascii")
    except UnicodeDecodeError:
        return ""


def _smb_dialect(raw: bytes) -> str:
    if len(raw) < 10:
        return ""
    dialect = struct.unpack("<H", raw[8:10])[0]
    return {
        0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0",
        0x0302: "3.0.2", 0x0311: "3.1.1",
    }.get(dialect, "2.x")


def _parse_ssh(line: str) -> Tuple[str, str]:
    parts = line.split("-", 2)
    if len(parts) < 3:
        return "SSH", ""
    fields = re.split(r"[_ ]", parts[2])
    product = fields[0] if fields else "SSH"
    version = fields[1] if len(fields) > 1 else ""
    return product, version


def _sanitize(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore")
    return "".join(ch for ch in text if ch in "\r\n\t" or " " <= ch <= "~").strip()


def _first_line(text: str) -> str:
    return text.splitlines()[0].strip() if text.splitlines() else ""


def _summarize(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()][:2]
    return _truncate(" | ".join(lines), 220)


def _truncate(text: str, n: int) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= n else flat[:n] + "…"
