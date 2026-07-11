import httpx
import asyncio
import socket
import struct
import re
import ssl
from module_common import safe_fetch, make_finding
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
        resp = await safe_fetch(client, base_url, timeout=10.0,
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
            findings.append(make_finding(
                entity=f"ALPN: {alpn_protocol}",
                ftype="HTTP ALPN Protocol",
                source="HTTP2Fingerprinter",
                confidence="High",
                color="emerald" if http2_supported else "orange",
                threat_level="Informational",
                raw_data=f"Negotiated protocol via ALPN: {alpn_protocol}",
                tags=["alpn", "http2", "tls"]
            ))
            if http2_supported:
                findings.append(make_finding(
                    entity="HTTP/2 support confirmed via ALPN h2 negotiation",
                    ftype="HTTP/2 Support",
                    source="HTTP2Fingerprinter",
                    confidence="High",
                    color="cyan",
                    threat_level="Informational",
                    raw_data="ALPN negotiated h2 successfully",
                    tags=["http2", "alpn"]
                ))
        else:
            findings.append(make_finding(
                entity="ALPN negotiation failed or not available",
                ftype="HTTP ALPN Protocol",
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
            findings.append(make_finding(
                entity=f"HTTP version: {http_version}",
                ftype="HTTP Protocol Version",
                source="HTTP2Fingerprinter",
                confidence="High",
                color="emerald" if is_h2 or http2_supported else "slate",
                threat_level="Informational",
                raw_data=f"HTTP version negotiated: {http_version}",
                tags=["http-version"]
            ))
            if is_h3:
                findings.append(make_finding(
                    entity="HTTP/3 (QUIC) currently in use",
                    ftype="HTTP/3 Active",
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
            findings.append(make_finding(
                entity=f"Alt-Svc: {alt_svc[:200]}",
                ftype="HTTP Alternative Services",
                source="HTTP2Fingerprinter",
                confidence="High",
                color="cyan" if has_h3 else "slate",
                threat_level="Informational",
                raw_data=alt_svc[:500],
                tags=["alt-svc", "http3" if has_h3 else "http-alternative"]
            ))
            if has_h3:
                findings.append(make_finding(
                    entity="HTTP/3 (QUIC) advertised via Alt-Svc",
                    ftype="HTTP/3 Support",
                    source="HTTP2Fingerprinter",
                    confidence="High",
                    color="cyan",
                    threat_level="Informational",
                    raw_data=f"Alt-Svc header indicates HTTP/3 support: {alt_svc[:300]}",
                    tags=["http3", "quic"]
                ))
                quic_versions = re.findall(r'h3[=-](\d+)', alt_svc)
                if quic_versions:
                    findings.append(make_finding(
                        entity=f"QUIC versions advertised: {', '.join(quic_versions)}",
                        ftype="HTTP/3 QUIC Versions",
                        source="HTTP2Fingerprinter",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["http3", "quic-version"]
                    ))
        else:
            findings.append(make_finding(
                entity="No Alt-Svc header present",
                ftype="HTTP Alternative Services",
                source="HTTP2Fingerprinter",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["alt-svc"]
            ))

        try:
            async with await client.build_client() as c:
                dns_resp = await safe_fetch(client, 
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
                            findings.append(make_finding(
                                entity=f"HTTPS/SVCB DNS record: {rdata[:200]}",
                                ftype="DNS HTTPS/SVCB Record",
                                source="HTTP2Fingerprinter",
                                confidence="Medium",
                                color="cyan",
                                threat_level="Informational",
                                raw_data=rdata[:500],
                                tags=["dns", "svcb", "https-record"]
                            ))
                            if "h3" in rdata.lower():
                                findings.append(make_finding(
                                    entity="HTTP/3 via SVCB/HTTPS DNS record",
                                    ftype="HTTP/3 SVCB DNS",
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
                                findings.append(make_finding(
                                    entity=f"{sname} = {settings[sid]}",
                                    ftype="HTTP/2 Setting",
                                    source="HTTP2Fingerprinter",
                                    confidence="High",
                                    color="slate",
                                    threat_level="Informational",
                                    raw_data=f"Setting ID {hex(sid)} ({sname}): {settings[sid]}",
                                    tags=["http2", "settings"]
                                ))

                        profile_name, match_count, total_count = match_profile(settings)
                        if profile_name:
                            findings.append(make_finding(
                                entity=f"Server profile: {profile_name} ({match_count}/{total_count} settings match)",
                                ftype="HTTP/2 Server Fingerprint",
                                source="HTTP2Fingerprinter",
                                confidence="High",
                                color="purple",
                                threat_level="Informational",
                                raw_data=f"Matched profile: {profile_name} | Matched settings: {match_count}/{total_count}",
                                tags=["http2", "fingerprint", profile_name]
                            ))
                        else:
                            findings.append(make_finding(
                                entity=f"Unknown server profile: {match_count}/{total_count} matched generic",
                                ftype="HTTP/2 Server Fingerprint",
                                source="HTTP2Fingerprinter",
                                confidence="Medium",
                                color="slate",
                                threat_level="Informational",
                                tags=["http2", "fingerprint", "unknown"]
                            ))

                        enable_push = settings.get(0x2, -1)
                        if enable_push == 1:
                            findings.append(make_finding(
                                entity="Server Push is ENABLED",
                                ftype="HTTP/2 Server Push",
                                source="HTTP2Fingerprinter",
                                confidence="High",
                                color="orange",
                                threat_level="Informational",
                                raw_data="SETTINGS_ENABLE_PUSH = 1",
                                tags=["http2", "server-push"]
                            ))
                        elif enable_push == 0:
                            findings.append(make_finding(
                                entity="Server Push is DISABLED",
                                ftype="HTTP/2 Server Push",
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
                            findings.append(make_finding(
                                entity=f"Flow control: {window_info}",
                                ftype="HTTP/2 Flow Control",
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
                        findings.append(make_finding(
                            entity=f"GOAWAY last_stream_id={last_stream}, error={error_name}",
                            ftype="HTTP/2 GOAWAY Frame",
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

        if http2_supported and settings:
            hpack = analyze_hpack_efficiency(settings)
            if hpack:
                findings.append(make_finding(
                    entity=f"HPACK: table_size={hpack.get('table_size', '?')}, efficiency={hpack.get('efficiency', '?')} ({hpack.get('profile', '?')})",
                    ftype="HTTP/2 HPACK Analysis",
                    source="HTTP2Fingerprinter",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["http2", "hpack", "compression"]
                ))

            tls_fp = detect_tls_fingerprint(alpn_protocol, headers.get("server", ""), settings)
            if tls_fp.get("likely_server"):
                findings.append(make_finding(
                    entity=f"Likely server: {tls_fp['likely_server']} (TLS fingerprint match)",
                    ftype="HTTP/2 TLS Fingerprint",
                    source="HTTP2Fingerprinter",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    tags=["http2", "fingerprint", "tls"]
                ))

        push_indicators = detect_push_promise_via_headers(headers)
        for ind in push_indicators:
            findings.append(make_finding(
                entity=f"Server push indicator: {ind}",
                ftype="HTTP/2 Push Indicator",
                source="HTTP2Fingerprinter",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                tags=["http2", "server-push"]
            ))

        h3_details = check_h3_alt_svc_advanced(alt_svc_header)
        if h3_details:
            for k, v in h3_details.items():
                findings.append(make_finding(
                    entity=f"HTTP/3 detail - {k}: {v}",
                    ftype="HTTP/3 Detail",
                    source="HTTP2Fingerprinter",
                    confidence="Medium",
                    color="cyan",
                    threat_level="Informational",
                    tags=["http3", "quic", k]
                ))

        tls13_h2 = await try_http2_direct_tls13_only(host)
        if tls13_h2:
            findings.append(make_finding(
                entity=f"HTTP/2 over TLS 1.3: {tls13_h2}",
                ftype="HTTP/2 TLS 1.3 Support",
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
            findings.append(make_finding(
                entity=f"{plat} ({ptype})",
                ftype="HTTP/2 Platform Detection",
                source="HTTP2Fingerprinter",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["platform", plat.lower()]
            ))

        findings.append(make_finding(
            entity=f"HTTP/2: {'Supported' if http2_supported else 'Not supported'}, HTTP/3: {'Advertised' if http3_advertised else 'Not detected'}",
            ftype="HTTP/2 & HTTP/3 Summary",
            source="HTTP2Fingerprinter",
            confidence="High",
            color="cyan" if http2_supported else "slate",
            threat_level="Informational",
            raw_data=f"HTTP/2: {http2_supported} | ALPN: {alpn_protocol} | Alt-Svc: {alt_svc_header[:100] if alt_svc_header else 'none'}",
            tags=["http2", "http3", "summary"]
        ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"HTTP2 Fingerprint error: {str(e)[:100]}",
            ftype="HTTP2 Fingerprint Error",
            source="HTTP2Fingerprinter",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings

# === EXTENDED UPGRADE: HPACK analysis, priority frames, WINDOW_UPDATE, more profiles ===

MORE_SERVER_PROFILES = {
    "h2o": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 65536, "enable_push": 0},
    "nghttpx": {"header_table_size": 4096, "max_concurrent_streams": 200, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "gunicorn": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "hypercorn": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "uwsgi": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "node http2": {"header_table_size": 4096, "max_concurrent_streams": 128, "initial_window_size": 65535, "max_frame_size": 16384, "enable_push": 0},
    "netty": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 65536, "enable_push": 0},
    "tomcat": {"header_table_size": 4096, "max_concurrent_streams": 200, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "jetty": {"header_table_size": 4096, "max_concurrent_streams": 128, "initial_window_size": 65536, "max_frame_size": 65536, "enable_push": 0},
    "caddy": {"header_table_size": 4096, "max_concurrent_streams": 256, "initial_window_size": 1048576, "max_frame_size": 1048576, "enable_push": 0},
    "traefik": {"header_table_size": 4096, "max_concurrent_streams": 250, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "envoy": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "litespeed": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "openresty": {"header_table_size": 4096, "max_concurrent_streams": 128, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "varnish": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "lighttpd": {"header_table_size": 4096, "max_concurrent_streams": 128, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "apigee": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "aws elb": {"header_table_size": 4096, "max_concurrent_streams": 200, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "gcp lb": {"header_table_size": 4096, "max_concurrent_streams": 250, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
    "azure app gateway": {"header_table_size": 4096, "max_concurrent_streams": 100, "initial_window_size": 65536, "max_frame_size": 16384, "enable_push": 0},
}

HPACK_HEADER_TABLE_SIZES = {
    4096: "nginx/apache typical",
    8192: "larger table (some proxies)",
    16384: "cloudflare/fastly typical",
    65536: "large table (caddy/h2o)",
}

PRIORITY_SETTINGS_ANALYSIS = {
    256: "Default weight 256 (RFC 7540 default)",
    16: "Lowest weight possible",
    256: "Highest weight possible",
}

GRACEFUL_SHUTDOWN_CODES = {
    0: "NO_ERROR (graceful)",
    1: "PROTOCOL_ERROR",
    2: "INTERNAL_ERROR",
    3: "FLOW_CONTROL_ERROR",
    4: "SETTINGS_TIMEOUT",
    5: "STREAM_CLOSED",
    6: "FRAME_SIZE_ERROR",
    7: "REFUSED_STREAM",
    8: "CANCEL",
    9: "COMPRESSION_ERROR",
    10: "CONNECT_ERROR",
    11: "ENHANCE_YOUR_CALM",
    12: "INADEQUATE_SECURITY",
    13: "HTTP_1_1_REQUIRED",
}

HPACK_DYNAMIC_TABLE_ESTIMATE = re.compile(r'(?:[A-Z][a-z]+:\s*[^\r\n]+){2,}', re.MULTILINE)

def analyze_hpack_efficiency(settings):
    analysis = {}
    try:
        table_size = settings.get(0x1, 4096)
        if table_size <= 4096:
            analysis["table_size"] = table_size
            analysis["efficiency"] = "Low (small table - more bytes per request)"
        elif table_size <= 16384:
            analysis["efficiency"] = "Medium (standard table)"
        else:
            analysis["efficiency"] = "High (large table - better compression)"
        analysis["profile"] = HPACK_HEADER_TABLE_SIZES.get(table_size, "Custom size")
    except Exception:
        pass
    return analysis

def parse_priority_frame_detailed(data):
    result = {}
    try:
        if len(data) >= 5:
            exclusive = bool(data[0] & 0x80)
            stream_dep = struct.unpack("!I", b"\x00" + data[:3])[0] & 0x7FFFFFFF
            weight = data[4] if len(data) > 4 else 0
            result["exclusive"] = exclusive
            result["stream_dependency"] = stream_dep
            result["weight"] = weight + 1
            if weight == 0:
                result["meaning"] = "Lowest priority"
            elif weight < 128:
                result["meaning"] = "Below average priority"
            elif weight == 127:
                result["meaning"] = "Default priority"
            elif weight < 255:
                result["meaning"] = "Above average priority"
            else:
                result["meaning"] = "Highest priority"
    except Exception:
        pass
    return result

def analyze_window_update(payload):
    analysis = {}
    try:
        if len(payload) >= 4:
            increment = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
            analysis["window_size_increment"] = increment
            if increment == 0:
                analysis["note"] = "Zero increment (protocol error?)"
            elif increment < 65536:
                analysis["note"] = "Small window update"
            elif increment < 1048576:
                analysis["note"] = "Medium window update"
            else:
                analysis["note"] = "Large window update (high throughput)"
    except Exception:
        pass
    return analysis

def detect_push_promise_via_headers(headers):
    indicators = []
    try:
        link_header = headers.get("link", "")
        if link_header and "rel=preload" in link_header.lower():
            indicators.append("Link preload headers (push-like)")
        server_push = headers.get("x-http2-push", "")
        if server_push:
            indicators.append(f"X-HTTP2-Push header: {server_push}")
    except Exception:
        pass
    return indicators

def check_h3_alt_svc_advanced(alt_svc):
    details = {}
    try:
        if not alt_svc:
            return details
        for part in alt_svc.split(","):
            part = part.strip()
            m = re.match(r'h3[=-](\d+)', part)
            if m:
                ver = m.group(1)
                details["h3_version"] = ver
                if "ma=" in part:
                    m2 = re.search(r'ma=(\d+)', part)
                    if m2:
                        details["max_age"] = m2.group(1)
                if "persist=" in part:
                    m3 = re.search(r'persist=(\d)', part)
                    if m3:
                        details["persist"] = m3.group(1)
    except Exception:
        pass
    return details

def detect_tls_fingerprint(alpn, cipher, settings):
    fingerprint = {}
    try:
        fingerprint["alpn"] = alpn
        if alpn and alpn == "h2":
            fingerprint["h2_negotiated"] = True
        fingerprint["cipher"] = cipher
        if settings:
            window = settings.get(0x4)
            max_frame = settings.get(0x5)
            streams = settings.get(0x3)
            if window and max_frame:
                if window == 1048576 and max_frame == 1048576:
                    fingerprint["likely_server"] = "Caddy/h2o"
                elif window == 65536 and max_frame == 16384:
                    fingerprint["likely_server"] = "nginx/apache typical"
                elif window == 2147483647:
                    fingerprint["likely_server"] = "Custom (very large window)"
    except Exception:
        pass
    return fingerprint
