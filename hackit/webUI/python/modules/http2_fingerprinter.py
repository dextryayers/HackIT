import httpx
import asyncio
import socket
import struct
import re
from models import IntelligenceFinding

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

SETTINGS_IDS = {
    0x1: "SETTINGS_HEADER_TABLE_SIZE",
    0x2: "SETTINGS_ENABLE_PUSH",
    0x3: "SETTINGS_MAX_CONCURRENT_STREAMS",
    0x4: "SETTINGS_INITIAL_WINDOW_SIZE",
    0x5: "SETTINGS_MAX_FRAME_SIZE",
    0x6: "SETTINGS_MAX_HEADER_LIST_SIZE",
    0x8: "SETTINGS_ENABLE_CONNECT_PROTOCOL",
}

SERVER_PROFILES = {
    "nginx": {
        "header_table_size": 4096,
        "max_concurrent_streams": 128,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "apache": {
        "header_table_size": 4096,
        "max_concurrent_streams": 100,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "caddy": {
        "header_table_size": 4096,
        "max_concurrent_streams": 256,
        "initial_window_size": 1048576,
        "max_frame_size": 1048576,
        "enable_push": 0,
    },
    "iis": {
        "header_table_size": 4096,
        "max_concurrent_streams": 100,
        "initial_window_size": 65535,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "cloudflare": {
        "header_table_size": 4096,
        "max_concurrent_streams": 256,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "fastly": {
        "header_table_size": 4096,
        "max_concurrent_streams": 100,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "akamai": {
        "header_table_size": 4096,
        "max_concurrent_streams": 128,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "h2o": {
        "header_table_size": 4096,
        "max_concurrent_streams": 100,
        "initial_window_size": 65536,
        "max_frame_size": 65536,
        "enable_push": 0,
    },
}

HTTP2_SETTINGS_FRAME_TYPE = 0x4
HTTP2_SETTINGS_ACK = 0x01

def parse_settings_frame(data):
    settings = {}
    offset = 0
    while offset + 5 <= len(data):
        identifier = struct.unpack("!H", data[offset:offset+2])[0]
        value = struct.unpack("!I", data[offset+2:offset+6])[0]
        settings[identifier] = value
        offset += 6
    return settings

def match_profile(settings):
    for profile_name, profile_vals in SERVER_PROFILES.items():
        matches = 0
        total = 0
        for sid, sname in SETTINGS_IDS.items():
            expected_val = profile_vals.get(sname.lower().replace("settings_", ""))
            if expected_val is not None and sid in settings:
                total += 1
                if settings[sid] == expected_val:
                    matches += 1
        if total > 0 and matches / total >= 0.6:
            return profile_name, matches, total
    return None, 0, 0

async def try_http2_direct(host):
    try:
        loop = asyncio.get_event_loop()
        sock = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=3.0)),
            timeout=3.0
        )
        sock.settimeout(3.0)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.do_handshake()
        alpn = ssock.selected_alpn_protocol()
        ssock.close()
        sock.close()
        return alpn
    except Exception:
        return None

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    host = target.strip().lower()
    if host.startswith("http"):
        from urllib.parse import urlparse
        host = urlparse(host).netloc

    base_url = f"https://{host}"

    try:
        http2_supported = False
        alpn_protocol = await try_http2_direct(host)
        if alpn_protocol:
            http2_supported = alpn_protocol == "h2"
            findings.append(IntelligenceFinding(
                entity=f"ALPN: {alpn_protocol}",
                type="HTTP ALPN Protocol",
                source="HTTP2Fingerprinter",
                confidence="High",
                color="emerald" if http2_supported else "orange",
                threat_level="Informational",
                raw_data=f"Negotiated protocol via ALPN: {alpn_protocol}",
                tags=["alpn", "http2", "tls"]
            ))

        try:
            async with await client.build_client() as c:
                resp = await client.get(base_url, timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                             "Accept": "*/*"})
                http_version = getattr(resp, "http_version", "")
                if http_version:
                    is_h2 = "h2" in str(http_version) or "2" in str(http_version)
                    findings.append(IntelligenceFinding(
                        entity=f"HTTP version: {http_version}",
                        type="HTTP Protocol Version",
                        source="HTTP2Fingerprinter",
                        confidence="High",
                        color="emerald" if is_h2 or http2_supported else "slate",
                        threat_level="Informational",
                        raw_data=f"HTTP version negotiated: {http_version}",
                        tags=["http-version"]
                    ))

                headers = dict(resp.headers)
                alt_svc = headers.get("alt-svc", "")
                if alt_svc:
                    has_h3 = "h3" in alt_svc.lower()
                    findings.append(IntelligenceFinding(
                        entity=f"Alt-Svc: {alt_svc[:200]}",
                        type="HTTP Alternative Services",
                        source="HTTP2Fingerprinter",
                        confidence="High",
                        color="cyan" if has_h3 else "slate",
                        threat_level="Informational",
                        raw_data=alt_svc[:500],
                        tags=["alt-svc", "http3" if has_h3 else "http-alternative"]
                    ))
                    if has_h3:
                        findings.append(IntelligenceFinding(
                            entity="HTTP/3 (QUIC) advertised via Alt-Svc",
                            type="HTTP/3 Support",
                            source="HTTP2Fingerprinter",
                            confidence="High",
                            color="cyan",
                            threat_level="Informational",
                            raw_data=f"Alt-Svc header indicates HTTP/3 support: {alt_svc[:300]}",
                            tags=["http3", "quic"]
                        ))

        except Exception:
            pass

        try:
            async with await client.build_client() as c:
                dns_resp = await client.get(
                    f"https://dns.google/resolve?name={host}&type=HTTPS",
                    timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if dns_resp.status_code == 200:
                    dns_data = dns_resp.json()
                    answers = dns_data.get("Answer", [])
                    for ans in answers:
                        rdata = ans.get("data", "")
                        if "alpn=" in rdata.lower() or "h2" in rdata.lower() or "h3" in rdata.lower():
                            findings.append(IntelligenceFinding(
                                entity=f"HTTPS/SVCB DNS record: {rdata[:200]}",
                                type="DNS HTTPS/SVCB Record",
                                source="HTTP2Fingerprinter",
                                confidence="Medium",
                                color="cyan",
                                threat_level="Informational",
                                raw_data=rdata[:500],
                                tags=["dns", "svcb", "https-record"]
                            ))
        except Exception:
            pass

        if http2_supported:
            try:
                loop = asyncio.get_event_loop()
                sock = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=3.0)),
                    timeout=3.0
                )
                sock.settimeout(3.0)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2"])
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                ssock.do_handshake()

                ssock.sendall(HTTP2_PREFACE)
                settings_frame_header = ssock.recv(9)
                if len(settings_frame_header) >= 9:
                    length = struct.unpack("!I", b"\x00" + settings_frame_header[:3])[0]
                    frame_type = settings_frame_header[3]
                    flags = settings_frame_header[4]
                    stream_id = struct.unpack("!I", settings_frame_header[5:9])[0] & 0x7FFFFFFF

                    if frame_type == HTTP2_SETTINGS_FRAME_TYPE:
                        payload = ssock.recv(length)
                        settings = parse_settings_frame(payload[:length])

                        for sid, sname in SETTINGS_IDS.items():
                            if sid in settings:
                                findings.append(IntelligenceFinding(
                                    entity=f"{sname} = {settings[sid]}",
                                    type="HTTP/2 Setting",
                                    source="HTTP2Fingerprinter",
                                    confidence="High",
                                    color="slate",
                                    threat_level="Informational",
                                    raw_data=f"Setting ID {hex(sid)} ({sname}): {settings[sid]}",
                                    tags=["http2", "settings"]
                                ))

                        profile_name, match_count, total_count = match_profile(settings)
                        if profile_name:
                            findings.append(IntelligenceFinding(
                                entity=f"Server profile: {profile_name} ({match_count}/{total_count} settings match)",
                                type="HTTP/2 Server Fingerprint",
                                source="HTTP2Fingerprinter",
                                confidence="High",
                                color="purple",
                                threat_level="Informational",
                                raw_data=f"Matched profile: {profile_name} | Matched settings: {match_count}/{total_count}",
                                tags=["http2", "fingerprint", profile_name]
                            ))

                ssock.close()
                sock.close()
            except Exception:
                pass

        findings.append(IntelligenceFinding(
            entity=f"HTTP/2: {'Supported' if http2_supported else 'Not supported'}, HTTP/3: {'Advertised' if alt_svc and 'h3' in alt_svc.lower() else 'Not detected'}",
            type="HTTP/2 & HTTP/3 Summary",
            source="HTTP2Fingerprinter",
            confidence="High",
            color="cyan" if http2_supported else "slate",
            threat_level="Informational",
            raw_data=f"HTTP/2: {http2_supported} | ALPN: {alpn_protocol} | Alt-Svc: {alt_svc[:100] if alt_svc else 'none'}",
            tags=["http2", "http3", "summary"]
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"HTTP2 Fingerprint error: {str(e)[:100]}",
            type="HTTP2 Fingerprint Error",
            source="HTTP2Fingerprinter",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
