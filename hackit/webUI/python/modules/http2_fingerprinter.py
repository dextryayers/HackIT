import httpx
import asyncio
import socket
import struct
import re
import ssl
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

PRIORITY_FRAME_TYPE = 0x2
HEADERS_FRAME_TYPE = 0x1
SETTINGS_FRAME_TYPE = 0x4
PUSH_PROMISE_FRAME_TYPE = 0x5
GOAWAY_FRAME_TYPE = 0x7
WINDOW_UPDATE_FRAME_TYPE = 0x8
CONTINUATION_FRAME_TYPE = 0x9

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
    "traefik": {
        "header_table_size": 4096,
        "max_concurrent_streams": 250,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "envoy": {
        "header_table_size": 4096,
        "max_concurrent_streams": 100,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "litespeed": {
        "header_table_size": 4096,
        "max_concurrent_streams": 100,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "openresty": {
        "header_table_size": 4096,
        "max_concurrent_streams": 128,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "varnish": {
        "header_table_size": 4096,
        "max_concurrent_streams": 100,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
    "lighttpd": {
        "header_table_size": 4096,
        "max_concurrent_streams": 128,
        "initial_window_size": 65536,
        "max_frame_size": 16384,
        "enable_push": 0,
    },
}

HTTP2_SETTINGS_FRAME_TYPE = 0x4
HTTP2_SETTINGS_ACK = 0x01

HTTP3_ALT_SVC_PATTERN = re.compile(r'h3[=-]\d{2,}|h3\b')
QUIC_VERSIONS = ["v1", "v2", "draft-29", "draft-28", "draft-27"]

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

def parse_priority_frame(data):
    try:
        exclusive = bool(data[0] & 0x80)
        stream_dep = struct.unpack("!I", b"\x00" + data[:3])[0] & 0x7FFFFFFF
        weight = data[4] if len(data) > 4 else 0
        return {"exclusive": exclusive, "stream_dependency": stream_dep, "weight": weight + 1}
    except Exception:
        return None

def detect_h3_from_dns(dns_response):
    if not dns_response:
        return False
    return bool(re.search(r'alpn=.*h3', dns_response, re.IGNORECASE))

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

async def try_http2_direct_tls13_only(host):
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
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.do_handshake()
        alpn = ssock.selected_alpn_protocol()
        ssock.close()
        sock.close()
        return alpn
    except Exception:
        return None

async def get_http_response_details(client, base_url):
    info = {}
    try:
        resp = await client.get(base_url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                     "Accept": "*/*", "Accept-Encoding": "gzip, deflate, br"})
        info["http_version"] = getattr(resp, "http_version", "")
        info["headers"] = dict(resp.headers)
        info["status_code"] = resp.status_code
        return info
    except Exception:
        return info

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    host = target.strip().lower()
    if host.startswith("http"):
        from urllib.parse import urlparse
        host = urlparse(host).netloc

    base_url = f"https://{host}"

    try:
        http2_supported = False
        http3_advertised = False
        alt_svc_header = ""
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
            if http2_supported:
                findings.append(IntelligenceFinding(
                    entity="HTTP/2 support confirmed via ALPN h2 negotiation",
                    type="HTTP/2 Support",
                    source="HTTP2Fingerprinter",
                    confidence="High",
                    color="cyan",
                    threat_level="Informational",
                    raw_data="ALPN negotiated h2 successfully",
                    tags=["http2", "alpn"]
                ))
        else:
            findings.append(IntelligenceFinding(
                entity="ALPN negotiation failed or not available",
                type="HTTP ALPN Protocol",
                source="HTTP2Fingerprinter",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["alpn", "tls"]
            ))

        http_details = await get_http_response_details(client, base_url)
        http_version = http_details.get("http_version", "")
        headers = http_details.get("headers", {})

        if http_version:
            is_h2 = "h2" in str(http_version) or "2" in str(http_version)
            is_h3 = "h3" in str(http_version) or "3" in str(http_version)
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
            if is_h3:
                findings.append(IntelligenceFinding(
                    entity="HTTP/3 (QUIC) currently in use",
                    type="HTTP/3 Active",
                    source="HTTP2Fingerprinter",
                    confidence="High",
                    color="cyan",
                    threat_level="Informational",
                    raw_data=f"Active HTTP version: {http_version}",
                    tags=["http3", "quic", "active"]
                ))

        alt_svc = headers.get("alt-svc", "")
        alt_svc_header = alt_svc
        if alt_svc:
            has_h3 = bool(HTTP3_ALT_SVC_PATTERN.search(alt_svc))
            http3_advertised = has_h3
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
                quic_versions = re.findall(r'h3[=-](\d+)', alt_svc)
                if quic_versions:
                    findings.append(IntelligenceFinding(
                        entity=f"QUIC versions advertised: {', '.join(quic_versions)}",
                        type="HTTP/3 QUIC Versions",
                        source="HTTP2Fingerprinter",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["http3", "quic-version"]
                    ))
        else:
            findings.append(IntelligenceFinding(
                entity="No Alt-Svc header present",
                type="HTTP Alternative Services",
                source="HTTP2Fingerprinter",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["alt-svc"]
            ))

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
                        if "alpn=" in rdata.lower() or "h2" in rdata.lower() or "h3" in rdata.lower() or "quic" in rdata.lower():
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
                            if "h3" in rdata.lower():
                                findings.append(IntelligenceFinding(
                                    entity="HTTP/3 via SVCB/HTTPS DNS record",
                                    type="HTTP/3 SVCB DNS",
                                    source="HTTP2Fingerprinter",
                                    confidence="Medium",
                                    color="cyan",
                                    threat_level="Informational",
                                    tags=["http3", "dns", "svcb"]
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
                sock.settimeout(5.0)
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
                        else:
                            findings.append(IntelligenceFinding(
                                entity=f"Unknown server profile: {match_count}/{total_count} matched generic",
                                type="HTTP/2 Server Fingerprint",
                                source="HTTP2Fingerprinter",
                                confidence="Medium",
                                color="slate",
                                threat_level="Informational",
                                tags=["http2", "fingerprint", "unknown"]
                            ))

                        enable_push = settings.get(0x2, -1)
                        if enable_push == 1:
                            findings.append(IntelligenceFinding(
                                entity="Server Push is ENABLED",
                                type="HTTP/2 Server Push",
                                source="HTTP2Fingerprinter",
                                confidence="High",
                                color="orange",
                                threat_level="Informational",
                                raw_data="SETTINGS_ENABLE_PUSH = 1",
                                tags=["http2", "server-push"]
                            ))
                        elif enable_push == 0:
                            findings.append(IntelligenceFinding(
                                entity="Server Push is DISABLED",
                                type="HTTP/2 Server Push",
                                source="HTTP2Fingerprinter",
                                confidence="High",
                                color="slate",
                                threat_level="Informational",
                                tags=["http2", "server-push"]
                            ))

                        initial_window = settings.get(0x4, -1)
                        max_frame = settings.get(0x5, -1)
                        max_concurrent = settings.get(0x3, -1)
                        if max_frame:
                            window_info = f"Initial window: {initial_window} bytes, Max frame: {max_frame} bytes, Max concurrent streams: {max_concurrent}"
                            findings.append(IntelligenceFinding(
                                entity=f"Flow control: {window_info}",
                                type="HTTP/2 Flow Control",
                                source="HTTP2Fingerprinter",
                                confidence="High",
                                color="slate",
                                threat_level="Informational",
                                raw_data=f"Settings window: {initial_window}, Max frame: {max_frame}, Max streams: {max_concurrent}",
                                tags=["http2", "flow-control"]
                            ))

                ssock.sendall(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                try:
                    goaway_frame = ssock.recv(17)
                    if len(goaway_frame) >= 17:
                        last_stream = struct.unpack("!I", goaway_frame[9:13])[0] & 0x7FFFFFFF
                        error_code = struct.unpack("!I", goaway_frame[13:17])[0]
                        error_names = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR",
                                       3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED",
                                       6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL",
                                       9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR",
                                       11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY",
                                       13: "HTTP_1_1_REQUIRED"}
                        error_name = error_names.get(error_code, f"UNKNOWN({error_code})")
                        findings.append(IntelligenceFinding(
                            entity=f"GOAWAY last_stream_id={last_stream}, error={error_name}",
                            type="HTTP/2 GOAWAY Frame",
                            source="HTTP2Fingerprinter",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"GOAWAY: last_stream={last_stream}, error_code={error_code} ({error_name})",
                            tags=["http2", "goaway"]
                        ))
                except Exception:
                    pass

                ssock.close()
                sock.close()
            except Exception:
                pass

        tls13_h2 = await try_http2_direct_tls13_only(host)
        if tls13_h2:
            findings.append(IntelligenceFinding(
                entity=f"HTTP/2 over TLS 1.3: {tls13_h2}",
                type="HTTP/2 TLS 1.3 Support",
                source="HTTP2Fingerprinter",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                tags=["http2", "tls13"]
            ))

        server = headers.get("server", "").lower()
        via = headers.get("via", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()
        platform = {}
        if "cloudflare" in server or "cloudflare" in via:
            platform["Cloudflare"] = "CDN"
        if "cloudfront" in server or "cloudfront" in via:
            platform["CloudFront"] = "CDN"
        if "akamai" in server:
            platform["Akamai"] = "CDN"
        if "fastly" in server:
            platform["Fastly"] = "CDN"
        if "nginx" in server:
            platform["Nginx"] = "Web Server"
        if "apache" in server:
            platform["Apache"] = "Web Server"
        if "iis" in server or "microsoft-iis" in server:
            platform["IIS"] = "Web Server"
        if "caddy" in server:
            platform["Caddy"] = "Web Server"
        if "openresty" in server:
            platform["OpenResty"] = "Web Server"
        if "traefik" in server:
            platform["Traefik"] = "Reverse Proxy"
        if "envoy" in server:
            platform["Envoy"] = "Reverse Proxy"
        if "litespeed" in server:
            platform["LiteSpeed"] = "Web Server"
        for plat, ptype in platform.items():
            findings.append(IntelligenceFinding(
                entity=f"{plat} ({ptype})",
                type="HTTP/2 Platform Detection",
                source="HTTP2Fingerprinter",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["platform", plat.lower()]
            ))

        findings.append(IntelligenceFinding(
            entity=f"HTTP/2: {'Supported' if http2_supported else 'Not supported'}, HTTP/3: {'Advertised' if http3_advertised else 'Not detected'}",
            type="HTTP/2 & HTTP/3 Summary",
            source="HTTP2Fingerprinter",
            confidence="High",
            color="cyan" if http2_supported else "slate",
            threat_level="Informational",
            raw_data=f"HTTP/2: {http2_supported} | ALPN: {alpn_protocol} | Alt-Svc: {alt_svc_header[:100] if alt_svc_header else 'none'}",
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
