#!/usr/bin/env python3
"""
HackIT Defense Console — target telemetry, flood detection, hardening.

Tiga hal yang dikerjakan modul ini, semuanya di sisi server:

  1. sample   — sampler resource ringan (CPU, TCP states, backlog, conntrack,
                fd, netdev, syncookies) yang bisa jalan lokal atau lewat SSH.
  2. detect   — analisis deret sampel, kenali pola SYN flood, connection
                exhaustion, slowloris, UDP flood, fd/conntrack pressure,
                lalu keluarkan temuan + rule mitigasi.
  3. harden   — generator konfigurasi nftables, sysctl, dan nginx yang siap
                dipasang, plus verifikasi nilai sysctl yang sedang aktif.

Contoh:
    python -m hackit.ddos.defense sample --interval 1
    python -m hackit.ddos.defense monitor --remote root@10.0.0.5 --seconds 60
    python -m hackit.ddos.defense detect --file samples.jsonl
    python -m hackit.ddos.defense harden --profile all --out hardening/
    python -m hackit.ddos.defense verify
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# ── ANSI ──────────────────────────────────────────────────────────────────
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{RESET}"


def _rule(width: int = 74, ch: str = "─") -> str:
    return _c(ch * width, DIM)


# ── 1. SAMPLER ────────────────────────────────────────────────────────────

TCP_STATES = {
    "01": "estab", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1",
    "05": "fin_wait2", "06": "time_wait", "07": "close", "08": "close_wait",
    "09": "last_ack", "0A": "listen", "0B": "closing",
}


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def _parse_paired(path: str) -> dict:
    """Parse /proc/net/{snmp,netstat} into {'TcpExt.SyncookiesSent': n, ...}."""
    lines = _read(path).splitlines()
    out: dict[str, int] = {}
    for i in range(0, len(lines) - 1, 2):
        head = lines[i].split()
        vals = lines[i + 1].split()
        if not head or not vals:
            continue
        prefix = head[0].rstrip(":")
        for name, val in zip(head[1:], vals[1:]):
            try:
                out[f"{prefix}.{name}"] = int(val)
            except ValueError:
                continue
    return out


def _cpu_times() -> tuple[int, int]:
    line = _read("/proc/stat").splitlines()[0].split()
    nums = [int(x) for x in line[1:9]]
    total = sum(nums)
    idle = nums[3] + nums[4]  # idle + iowait
    return total, idle


def _meminfo() -> tuple[int, int]:
    total = avail = 0
    for line in _read("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            total = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            avail = int(line.split()[1])
    return total, avail


def _tcp_states() -> dict:
    counts = {v: 0 for v in TCP_STATES.values()}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in _read(path).splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            name = TCP_STATES.get(parts[3])
            if name:
                counts[name] += 1
    return counts


def _netdev() -> dict:
    rx_b = tx_b = rx_p = tx_p = 0
    for line in _read("/proc/net/dev").splitlines()[2:]:
        if ":" not in line:
            continue
        iface, data = line.split(":", 1)
        if iface.strip() == "lo":
            continue
        cols = data.split()
        if len(cols) < 10:
            continue
        rx_b += int(cols[0]); rx_p += int(cols[1])
        tx_b += int(cols[8]); tx_p += int(cols[9])
    return {"rx_bytes": rx_b, "rx_pkts": rx_p, "tx_bytes": tx_b, "tx_pkts": tx_p}


def _int_file(path: str, default: int = -1) -> int:
    txt = _read(path).strip()
    try:
        return int(txt)
    except ValueError:
        return default


def sample_once(prev: Optional[dict] = None) -> dict:
    """One telemetry sample. `prev` supplies the CPU delta baseline."""
    now = time.time()
    total, idle = _cpu_times()
    cpu_pct = 0.0
    if prev and prev.get("_cpu_total") is not None:
        d_total = total - prev["_cpu_total"]
        d_idle = idle - prev["_cpu_idle"]
        if d_total > 0:
            cpu_pct = max(0.0, min(100.0, 100.0 * (1.0 - d_idle / d_total)))
    mem_total, mem_avail = _meminfo()
    file_nr = _read("/proc/sys/fs/file-nr").split()
    snmp = _parse_paired("/proc/net/snmp")
    netstat = _parse_paired("/proc/net/netstat")
    load = _read("/proc/loadavg").split()

    s = {
        "ts": now,
        "cpu_pct": round(cpu_pct, 2),
        "load1": float(load[0]) if load else 0.0,
        "load5": float(load[1]) if len(load) > 1 else 0.0,
        "mem_total_kb": mem_total,
        "mem_avail_kb": mem_avail,
        "mem_used_pct": round(100.0 * (1 - mem_avail / mem_total), 2) if mem_total else 0.0,
        "tcp": _tcp_states(),
        "conntrack": {
            "count": _int_file("/proc/sys/net/netfilter/nf_conntrack_count"),
            "max": _int_file("/proc/sys/net/netfilter/nf_conntrack_max"),
        },
        "fd": {
            "used": int(file_nr[0]) if file_nr else -1,
            "max": int(file_nr[2]) if len(file_nr) > 2 else -1,
        },
        "net": _netdev(),
        "tcp_ext": {
            "syncookies_sent": netstat.get("TcpExt.SyncookiesSent", 0),
            "syncookies_recv": netstat.get("TcpExt.SyncookiesRecv", 0),
            "listen_overflows": netstat.get("TcpExt.ListenOverflows", 0),
            "listen_drops": netstat.get("TcpExt.ListenDrops", 0),
            "tcp_timeouts": netstat.get("TcpExt.TCPTimeouts", 0),
            "abort_on_memory": netstat.get("TcpExt.TCPAbortOnMemory", 0),
            "abort_on_overflow": netstat.get("TcpExt.TCPAbortOnOverflow", 0),
            "retrans": netstat.get("TcpExt.TCPRetransSegs", 0),
        },
        "udp_in": snmp.get("Udp.InDatagrams", 0),
        "_cpu_total": total,
        "_cpu_idle": idle,
    }
    return s


def _public(s: dict) -> dict:
    return {k: v for k, v in s.items() if not k.startswith("_")}


def sample_loop(interval: float, count: int = 0) -> None:
    """Emit one JSON line per interval until interrupted."""
    prev = None
    emitted = 0
    while True:
        cur = sample_once(prev)
        prev = cur
        print(json.dumps(_public(cur)), flush=True)
        emitted += 1
        if count and emitted >= count:
            return
        time.sleep(interval)


# ── remote sampler ────────────────────────────────────────────────────────

SAMPLE_SRC = r'''
import json, time
from pathlib import Path

def read(p):
    try: return Path(p).read_text()
    except OSError: return ""

STATE = {"01":"estab","02":"syn_sent","03":"syn_recv","04":"fin_wait1","05":"fin_wait2",
         "06":"time_wait","07":"close","08":"close_wait","09":"last_ack","0A":"listen","0B":"closing"}

def paired(p):
    ls = read(p).splitlines(); out = {}
    for i in range(0, len(ls)-1, 2):
        h = ls[i].split(); v = ls[i+1].split()
        if not h or not v: continue
        pre = h[0].rstrip(":")
        for n, x in zip(h[1:], v[1:]):
            try: out[pre+"."+n] = int(x)
            except ValueError: pass
    return out

def cpu():
    n = [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:9]]
    return sum(n), n[3]+n[4]

def tcp():
    c = {v:0 for v in STATE.values()}
    for p in ("/proc/net/tcp","/proc/net/tcp6"):
        for ln in read(p).splitlines()[1:]:
            f = ln.split()
            if len(f) > 3 and f[3] in STATE: c[STATE[f[3]]] += 1
    return c

def net():
    rb=tb=rp=tp=0
    for ln in read("/proc/net/dev").splitlines()[2:]:
        if ":" not in ln: continue
        i,d = ln.split(":",1)
        if i.strip()=="lo": continue
        c=d.split()
        if len(c)<10: continue
        rb+=int(c[0]); rp+=int(c[1]); tb+=int(c[8]); tp+=int(c[9])
    return {"rx_bytes":rb,"rx_pkts":rp,"tx_bytes":tb,"tx_pkts":tp}

def one(prev):
    t, idle = cpu(); pct = 0.0
    if prev and prev[0] is not None:
        dt = t-prev[0]; di = idle-prev[1]
        if dt > 0: pct = max(0.0, min(100.0, 100.0*(1-di/dt)))
    mem = {}
    for ln in read("/proc/meminfo").splitlines():
        if ln.startswith(("MemTotal:","MemAvailable:")):
            k,v = ln.split(":")[0], int(ln.split()[1]); mem[k]=v
    nr = read("/proc/sys/fs/file-nr").split()
    ns = paired("/proc/net/netstat"); sn = paired("/proc/net/snmp")
    ld = read("/proc/loadavg").split()
    def iv(p, d=-1):
        try: return int(read(p).strip())
        except ValueError: return d
    mt = mem.get("MemTotal",0); ma = mem.get("MemAvailable",0)
    return {"ts": time.time(), "cpu_pct": round(pct,2),
            "load1": float(ld[0]) if ld else 0.0, "load5": float(ld[1]) if len(ld)>1 else 0.0,
            "mem_total_kb": mt, "mem_avail_kb": ma,
            "mem_used_pct": round(100.0*(1-ma/mt),2) if mt else 0.0,
            "tcp": tcp(),
            "conntrack": {"count": iv("/proc/sys/net/netfilter/nf_conntrack_count"),
                          "max": iv("/proc/sys/net/netfilter/nf_conntrack_max")},
            "fd": {"used": int(nr[0]) if nr else -1, "max": int(nr[2]) if len(nr)>2 else -1},
            "net": net(),
            "tcp_ext": {"syncookies_sent": ns.get("TcpExt.SyncookiesSent",0),
                        "syncookies_recv": ns.get("TcpExt.SyncookiesRecv",0),
                        "listen_overflows": ns.get("TcpExt.ListenOverflows",0),
                        "listen_drops": ns.get("TcpExt.ListenDrops",0),
                        "tcp_timeouts": ns.get("TcpExt.TCPTimeouts",0),
                        "abort_on_memory": ns.get("TcpExt.TCPAbortOnMemory",0),
                        "abort_on_overflow": ns.get("TcpExt.TCPAbortOnOverflow",0),
                        "retrans": ns.get("TcpExt.TCPRetransSegs",0)},
            "udp_in": sn.get("Udp.InDatagrams",0)}, (t, idle)

prev = (None, None)
while True:
    s, cpu_now = one(prev); prev = cpu_now
    print(json.dumps(s), flush=True)
    time.sleep(INTERVAL)
'''


class RemoteSampler:
    """Runs the sampler on another host through ssh, source piped over stdin."""

    def __init__(self, remote: str, interval: float = 1.0, ssh_port: int = 22):
        self.remote = remote
        self.interval = interval
        self.ssh_port = ssh_port
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        if not shutil.which("ssh"):
            raise RuntimeError("ssh client not found")
        src = SAMPLE_SRC.replace("INTERVAL", str(self.interval))
        cmd = ["ssh", "-p", str(self.ssh_port), "-o", "BatchMode=yes",
               "-o", "ConnectTimeout=8", self.remote, "python3", "-"]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        assert self.proc.stdin
        self.proc.stdin.write(src)
        self.proc.stdin.close()

    def readline(self) -> Optional[str]:
        if not self.proc or not self.proc.stdout:
            return None
        return self.proc.stdout.readline()

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


def stream_samples(remote: Optional[str], interval: float, seconds: int,
                   ssh_port: int = 22, on_sample=None) -> list[dict]:
    """Collect samples locally or remotely and return them."""
    samples: list[dict] = []
    deadline = time.time() + seconds

    if on_sample:
        on_sample  # reserved for live UI hooks

    if remote:
        rs = RemoteSampler(remote, interval, ssh_port)
        rs.start()
        try:
            while time.time() < deadline:
                line = rs.readline()
                if not line:
                    break
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    s = json.loads(line)
                except json.JSONDecodeError:
                    continue
                samples.append(s)
        finally:
            rs.stop()
        return samples

    prev = None
    while time.time() < deadline:
        cur = sample_once(prev)
        prev = cur
        samples.append(_public(cur))
        time.sleep(interval)
    return samples


# ── 2. DETECTOR ───────────────────────────────────────────────────────────


@dataclass
class Finding:
    severity: str          # critical | high | medium | low
    title: str
    evidence: str
    action: str
    tag: str = ""

    def as_dict(self) -> dict:
        return {
            "severity": self.severity, "title": self.title,
            "evidence": self.evidence, "action": self.action, "tag": self.tag,
        }


@dataclass
class Thresholds:
    syn_recv: int = 128
    syn_cookie_delta: int = 1
    listen_overflow_delta: int = 1
    conntrack_pct: float = 80.0
    fd_pct: float = 85.0
    cpu_pct: float = 85.0
    udp_pps: float = 5000.0
    net_pps: float = 300000.0
    time_wait: int = 30000
    close_wait: int = 5000
    timeout_delta: int = 50


def _delta(a: dict, b: dict) -> float:
    try:
        return float(b) - float(a)
    except (TypeError, ValueError):
        return 0.0


def detect(samples: list[dict], th: Optional[Thresholds] = None) -> list[Finding]:
    th = th or Thresholds()
    findings: list[Finding] = []
    if len(samples) < 2:
        return [Finding("low", "Data tidak cukup", f"{len(samples)} sampel", "Jalankan monitor ≥ 10 detik.")]

    syn_flood_seen = False

    first, last = samples[0], samples[-1]
    span = max(0.001, last.get("ts", 0) - first.get("ts", 0))

    # ── SYN flood / backlog pressure
    cookie_d = _delta(first.get("tcp_ext", {}).get("syncookies_sent", 0),
                      last.get("tcp_ext", {}).get("syncookies_sent", 0))
    overflow_d = _delta(first.get("tcp_ext", {}).get("listen_overflows", 0),
                        last.get("tcp_ext", {}).get("listen_overflows", 0))
    drop_d = _delta(first.get("tcp_ext", {}).get("listen_drops", 0),
                    last.get("tcp_ext", {}).get("listen_drops", 0))
    syn_peak = max((s.get("tcp", {}).get("syn_recv", 0) for s in samples), default=0)
    halfopen = max((s.get("tcp", {}).get("syn_sent", 0) for s in samples), default=0)
    if cookie_d >= th.syn_cookie_delta:
        syn_flood_seen = True
        findings.append(Finding(
            "critical", "SYN flood terdeteksi (syncookies aktif)",
            f"SyncookiesSent +{int(cookie_d)} dalam {span:.0f}s, SYN_RECV puncak {syn_peak}",
            "Aktifkan SYN cookies + batasi new connection per IP di nftables (rule di harden).",
            "syn-flood"))
    if overflow_d >= th.listen_overflow_delta or drop_d >= th.listen_overflow_delta:
        findings.append(Finding(
            "critical", "Accept backlog overflow",
            f"ListenOverflows +{int(overflow_d)}, ListenDrops +{int(drop_d)}",
            "Naikkan somaxconn/backlog dan pasang rate limit SYN per source.",
            "backlog"))
    if syn_peak >= th.syn_recv and cookie_d < th.syn_cookie_delta:
        findings.append(Finding(
            "high", "Half-open connection menumpuk",
            f"SYN_RECV puncak {syn_peak} (ambang {th.syn_recv})",
            "Periksa apakah syncookies menyala; kalau tidak, backlog sedang diisi.",
            "syn-backlog"))

    # ── connection / conntrack / fd exhaustion
    ct = last.get("conntrack", {})
    ct_pct = 100.0 * ct.get("count", 0) / ct["max"] if ct.get("max", 0) > 0 else 0
    if ct_pct >= th.conntrack_pct:
        findings.append(Finding(
            "high", "Conntrack hampir penuh",
            f"{ct.get('count')} / {ct.get('max')} ({ct_pct:.1f}%)",
            "Naikkan nf_conntrack_max, atau drop early di raw table sebelum conntrack.",
            "conntrack"))
    fd = last.get("fd", {})
    fd_pct = 0.0
    if 0 < fd.get("max", 0) < 1_000_000_000:
        fd_pct = 100.0 * fd.get("used", 0) / fd["max"]
    if fd_pct >= th.fd_pct:
        findings.append(Finding(
            "high", "File descriptor hampir habis",
            f"{fd.get('used')} / {fd.get('max')} ({fd_pct:.1f}%)",
            "Naikkan LimitNOFILE untuk service dan fs.file-max.",
            "fd"))
    tw = max((s.get("tcp", {}).get("time_wait", 0) for s in samples), default=0)
    if tw >= th.time_wait:
        findings.append(Finding(
            "medium", "TIME_WAIT menumpuk",
            f"TIME_WAIT puncak {tw}",
            "Aktifkan tcp_tw_reuse dan turunkan tcp_fin_timeout.",
            "timewait"))
    cw = max((s.get("tcp", {}).get("close_wait", 0) for s in samples), default=0)
    if cw >= th.close_wait:
        findings.append(Finding(
            "medium", "CLOSE_WAIT tinggi (app tidak menutup socket)",
            f"CLOSE_WAIT puncak {cw}",
            "Periksa bug keep-alive di aplikasi; CLOSE_WAIT bukan masalah jaringan.",
            "closewait"))

    # ── slowloris / slow read
    timeout_d = _delta(first.get("tcp_ext", {}).get("tcp_timeouts", 0),
                       last.get("tcp_ext", {}).get("tcp_timeouts", 0))
    estab_peak = max((s.get("tcp", {}).get("estab", 0) for s in samples), default=0)
    if timeout_d >= th.timeout_delta and estab_peak > 200 and not syn_flood_seen:
        findings.append(Finding(
            "high", "Pola slow connection (slowloris / slow read)",
            f"TCP timeouts +{int(timeout_d)}, ESTAB puncak {estab_peak}",
            "Turunkan client_header_timeout/client_body_timeout dan batasi koneksi per IP.",
            "slowloris"))

    # ── CPU / memory
    cpu_avg = sum(s.get("cpu_pct", 0) for s in samples) / len(samples)
    cpu_peak = max(s.get("cpu_pct", 0) for s in samples)
    if cpu_peak >= th.cpu_pct:
        findings.append(Finding(
            "high" if cpu_avg >= th.cpu_pct else "medium",
            "CPU jenuh",
            f"rata-rata {cpu_avg:.1f}%, puncak {cpu_peak:.1f}%",
            "Cari proses pembebani (top -H), lalu pindahkan parsing berat keluar dari jalur request.",
            "cpu"))
    mem_peak = max(s.get("mem_used_pct", 0) for s in samples)
    if mem_peak >= 90:
        findings.append(Finding(
            "high", "Memori hampir habis",
            f"pemakaian puncak {mem_peak:.1f}%",
            "Batasi body size di nginx dan pasang limit memori per worker.",
            "memory"))

    # ── UDP / volumetric
    udp_pps = _delta(first.get("udp_in", 0), last.get("udp_in", 0)) / span
    if udp_pps >= th.udp_pps:
        findings.append(Finding(
            "high", "Lonjakan datagram UDP",
            f"{udp_pps:,.0f} pkt/s",
            "Rate limit UDP per source dan matikan service UDP yang tidak dipakai.",
            "udp-flood"))
    rx_pps = _delta(first.get("net", {}).get("rx_pkts", 0), last.get("net", {}).get("rx_pkts", 0)) / span
    if rx_pps >= th.net_pps:
        findings.append(Finding(
            "medium", "Throughput paket masuk sangat tinggi",
            f"{rx_pps:,.0f} pkt/s diterima",
            "Ini level volumetric; mitigasi harus di upstream/ISP, bukan di host.",
            "volumetric"))

    if not findings:
        findings.append(Finding(
            "low", "Tidak ada pola serangan yang cocok",
            f"{len(samples)} sampel, CPU puncak {cpu_peak:.1f}%, ESTAB puncak {estab_peak}",
            "Baseline bersih. Simpan sebagai pembanding saat ada insiden.",
            "clean"))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f.severity, 9))
    return findings


# ── 3. HARDENING GENERATOR ────────────────────────────────────────────────

DEF_SYSCTL = """\
# HackIT hardening — kernel network baseline
# Pasang: /etc/sysctl.d/99-hackit-hardening.conf lalu `sysctl --system`

# SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_abort_on_overflow = 0

# Connection lifecycle
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_local_port_range = 10240 65000

# Conntrack & fd
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20
net.netfilter.nf_conntrack_tcp_timeout_established = 600
fs.file-max = 2097152
fs.nr_open = 2097152

# Buffer (jangan dinaikkan sembarangan; ini untuk 1G-10G link)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
"""

DEF_NFT = """\
#!/usr/sbin/nft -f
# HackIT hardening — nftables ingress policy
# Verifikasi: nft -c -f <file>   |   Pasang: nft -f <file>
# CATATAN: sesuaikan {ssh_port} dan {http_ports} sebelum dipasang.

flush ruleset

table inet filter {{
    set syn_flood {{ type ipv4_addr; flags dynamic,timeout; timeout 60s; }}
    set udp_flood {{ type ipv4_addr; flags dynamic,timeout; timeout 60s; }}

    chain input {{
        type filter hook input priority filter; policy drop;

        ct state invalid drop
        iifname "lo" accept
        ct state established,related accept

        # ICMP: cukup untuk PMTU, sisanya dibuang
        ip protocol icmp icmp type {{ echo-request, destination-unreachable, time-exceeded }} \\
            limit rate 10/second burst 20 packets accept
        ip protocol icmp drop

        # SSH: brute-force throttle
        tcp dport {ssh_port} ct state new \\
            limit rate 5/second burst 10 packets accept
        tcp dport {ssh_port} ct state new \\
            limit rate over 5/second add @syn_flood {{ ip saddr }} drop
        tcp dport {ssh_port} ct state new drop

        # HTTP/HTTPS: new connection per source, lalu global cap
        tcp dport {{ {http_ports} }} ct state new \\
            limit rate over 50/second burst 100 packets add @syn_flood {{ ip saddr }} drop
        tcp dport {{ {http_ports} }} ct state new \\
            limit rate 400/second burst 800 packets accept
        tcp dport {{ {http_ports} }} ct state new drop
        tcp dport {{ {http_ports} }} accept

        # DNS (kalau resolver lokal dipakai)
        udp dport 53 limit rate 100/second burst 200 packets accept
        udp dport 53 limit rate over 100/second add @udp_flood {{ ip saddr }} drop

        # Sisanya: rate limit UDP generik supaya tidak jadi amplifier
        meta l4proto udp limit rate 2000/second burst 4000 packets accept
        meta l4proto udp limit rate over 2000/second add @udp_flood {{ ip saddr }} drop

        # Jangan pernah membalas ke set yang sudah ditandai
        ip saddr @syn_flood drop
        ip saddr @udp_flood drop

        counter drop
    }}

    chain forward {{ type filter hook forward priority filter; policy drop; }}
    chain output {{ type filter hook output priority filter; policy accept; }}
}}
"""

DEF_NGINX = """\
# HackIT hardening — nginx rate limiting & timeout
# Taruh di http{} untuk zona, di server{} untuk limit dan timeout.

# ── http {} ──
limit_req_zone  $binary_remote_addr zone=req_per_ip:20m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_per_ip:20m;
limit_req_zone  $server_name        zone=req_global:10m rate=2000r/s;

# ── server {} ──
client_header_timeout   10s;
client_body_timeout     10s;
send_timeout            10s;
keepalive_timeout       15s;
reset_timedout_connection on;

client_max_body_size    8m;
large_client_header_buffers 4 8k;

limit_req        zone=req_per_ip burst=20 nodelay;
limit_req        zone=req_global burst=500 nodelay;
limit_conn       conn_per_ip 20;
limit_req_status 429;
limit_conn_status 429;

# Slowloris: jangan biarkan header setengah jadi menahan worker
client_header_buffer_size 1k;

# Kalau di belakang proxy/CDN, ambil IP asli dan pakai itu untuk limit
# set_real_ip_from 10.0.0.0/8;
# real_ip_header   X-Forwarded-For;
# real_ip_recursive on;
"""


def generate_hardening(profile: str = "all", ssh_port: int = 22,
                       http_ports: str = "80, 443") -> dict[str, str]:
    """Return {name: content} for the requested profile."""
    ports = ", ".join(p.strip() for p in http_ports.split(",") if p.strip())
    out: dict[str, str] = {}
    if profile in ("all", "sysctl"):
        out["99-hackit-hardening.conf"] = DEF_SYSCTL
    if profile in ("all", "nftables"):
        out["hackit-hardening.nft"] = DEF_NFT.format(ssh_port=ssh_port, http_ports=ports)
    if profile in ("all", "nginx"):
        out["hackit-nginx-limits.conf"] = DEF_NGINX
    return out


def write_hardening(files: dict[str, str], out_dir: str) -> list[Path]:
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in files.items():
        p = dest / name
        p.write_text(content)
        written.append(p)
    return written


# ── sysctl verification ───────────────────────────────────────────────────

RECOMMENDED = {
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.tcp_max_syn_backlog": "8192",
    "net.core.somaxconn": "8192",
    "net.ipv4.tcp_fin_timeout": "15",
    "net.ipv4.tcp_tw_reuse": "1",
    "net.ipv4.tcp_rfc1337": "1",
    "net.ipv4.tcp_abort_on_overflow": "0",
    "net.core.netdev_max_backlog": "16384",
    "net.netfilter.nf_conntrack_max": "262144",
    "fs.file-max": "2097152",
}


def _sysctl_get(key: str) -> Optional[str]:
    path = "/proc/sys/" + key.replace(".", "/")
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def verify_sysctl() -> list[tuple[str, str, str, bool]]:
    rows = []
    for key, want in RECOMMENDED.items():
        cur = _sysctl_get(key)
        if cur is None:
            rows.append((key, "n/a", want, False))
            continue
        ok = cur == want
        if not ok:
            try:
                ok = int(cur) >= int(want) and key not in (
                    "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_abort_on_overflow")
            except ValueError:
                ok = False
        rows.append((key, cur, want, ok))
    return rows


# ── RENDER ────────────────────────────────────────────────────────────────

SEV_COLOR = {"critical": RED, "high": RED, "medium": YELLOW, "low": CYAN}


def render_sample(s: dict, prev: Optional[dict] = None) -> str:
    tcp = s.get("tcp", {})
    parts = [
        f"{_c('CPU', DIM)} {s.get('cpu_pct', 0):5.1f}%",
        f"{_c('MEM', DIM)} {s.get('mem_used_pct', 0):5.1f}%",
        f"{_c('ESTAB', DIM)} {tcp.get('estab', 0):6d}",
        f"{_c('SYN_RECV', DIM)} {tcp.get('syn_recv', 0):5d}",
        f"{_c('TW', DIM)} {tcp.get('time_wait', 0):6d}",
        f"{_c('CT', DIM)} {s.get('conntrack', {}).get('count', 0):6d}",
        f"{_c('FD', DIM)} {s.get('fd', {}).get('used', 0):6d}",
        f"{_c('LOAD', DIM)} {s.get('load1', 0):4.2f}",
    ]
    line = "  ".join(parts)
    if prev:
        rx = _delta(prev.get("net", {}).get("rx_pkts", 0), s.get("net", {}).get("rx_pkts", 0))
        dt = max(0.001, s.get("ts", 0) - prev.get("ts", 0))
        line += f"  {_c('RX', DIM)} {rx / dt:,.0f} pps"
    return line


def render_findings(findings: Iterable[Finding]) -> None:
    print()
    print(_c("  TEMUAN", BOLD))
    print("  " + _rule(72))
    for f in findings:
        color = SEV_COLOR.get(f.severity, WHITE)
        print(f"  {_c('●', color)} {_c(f.severity.upper(), color)}  {BOLD}{f.title}{RESET}")
        print(f"      {DIM}{f.evidence}{RESET}")
        print(f"      {CYAN}→ {f.action}{RESET}")
    print("  " + _rule(72))


# ── CLI ───────────────────────────────────────────────────────────────────


def _cmd_sample(args: argparse.Namespace) -> int:
    try:
        sample_loop(args.interval, args.count)
    except KeyboardInterrupt:
        return 0
    return 0


def _cmd_monitor(args: argparse.Namespace) -> int:
    print(_c(f"  collecting {args.seconds}s from {args.remote or 'local'}"
             f" every {args.interval}s", DIM))
    prev = None
    samples: list[dict] = []

    def handle(s: dict) -> None:
        nonlocal prev
        samples.append(s)
        print(render_sample(s, prev))
        prev = s

    def handle_local(raw: dict) -> None:
        nonlocal prev
        samples.append(_public(raw))
        print(render_sample(_public(raw), prev and _public(prev)))
        prev = raw

    if args.remote:
        rs = RemoteSampler(args.remote, args.interval, args.ssh_port)
        try:
            rs.start()
        except Exception as exc:  # noqa: BLE001 - surface ssh failure plainly
            print(f"  {RED}ssh gagal: {exc}{RESET}")
            return 2
        deadline = time.time() + args.seconds
        try:
            while time.time() < deadline:
                line = rs.readline()
                if not line:
                    break
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    handle(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            rs.stop()
    else:
        end = time.time() + args.seconds
        prev = sample_once(None)  # prime the CPU delta baseline
        try:
            while time.time() < end:
                cur = sample_once(prev)
                handle_local(cur)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass

    if samples:
        findings = detect(samples, Thresholds())
        render_findings(findings)
        if args.save:
            Path(args.save).write_text("\n".join(json.dumps(s) for s in samples))
            print(f"  {DIM}samples → {args.save}{RESET}")
        if args.json:
            print(json.dumps({"samples": len(samples),
                              "findings": [f.as_dict() for f in findings]}, indent=2))
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"  {RED}file not found: {path}{RESET}")
        return 2
    samples = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            samples.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    findings = detect(samples, Thresholds())
    render_findings(findings)
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    return 0


def _cmd_harden(args: argparse.Namespace) -> int:
    files = generate_hardening(args.profile, args.ssh_port, args.http_ports)
    if args.out:
        written = write_hardening(files, args.out)
        for p in written:
            print(f"  {GREEN}wrote{RESET} {p}")
        print(f"  {DIM}verifikasi nft: nft -c -f {args.out}/hackit-hardening.nft{RESET}")
        print(f"  {DIM}pasang sysctl: sudo cp {args.out}/99-hackit-hardening.conf "
              f"/etc/sysctl.d/ && sudo sysctl --system{RESET}")
    else:
        for name, content in files.items():
            print(_c(f"# ── {name} " + "─" * max(0, 60 - len(name)), DIM))
            print(content)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    rows = verify_sysctl()
    print()
    print(f"  {BOLD}{'KEY':<42} {'NOW':>10} {'TARGET':>10}  STATE{RESET}")
    print("  " + _rule(74))
    bad = 0
    for key, cur, want, ok in rows:
        state = _c("OK", GREEN) if ok else _c("TUNE", RED)
        if not ok:
            bad += 1
        print(f"  {key:<42} {cur:>10} {want:>10}  {state}")
    print("  " + _rule(74))
    print(f"  {bad} nilai perlu disesuaikan" if bad else f"  {_c('semua nilai sudah sesuai', GREEN)}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hackit.ddos.defense",
        description="Server-side telemetry, flood detection, and hardening.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("sample", help="emit JSON samples (local)")
    sp.add_argument("--interval", type=float, default=1.0)
    sp.add_argument("--count", type=int, default=0, help="0 = unlimited")
    sp.set_defaults(func=_cmd_sample)

    mp = sub.add_parser("monitor", help="live monitor + auto-detect")
    mp.add_argument("--remote", default="", help="user@host (ssh)")
    mp.add_argument("--ssh-port", type=int, default=22)
    mp.add_argument("--interval", type=float, default=1.0)
    mp.add_argument("--seconds", type=int, default=30)
    mp.add_argument("--save", default="")
    mp.add_argument("--json", action="store_true")
    mp.set_defaults(func=_cmd_monitor)

    dp = sub.add_parser("detect", help="analyse a saved sample file")
    dp.add_argument("--file", required=True)
    dp.add_argument("--json", action="store_true")
    dp.set_defaults(func=_cmd_detect)

    hp = sub.add_parser("harden", help="generate hardening configs")
    hp.add_argument("--profile", default="all",
                    choices=["all", "sysctl", "nftables", "nginx"])
    hp.add_argument("--ssh-port", type=int, default=22)
    hp.add_argument("--http-ports", default="80, 443")
    hp.add_argument("--out", default="")
    hp.set_defaults(func=_cmd_harden)

    vp = sub.add_parser("verify", help="compare sysctl against recommendations")
    vp.set_defaults(func=_cmd_verify)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # Output piped into head/less: close quietly instead of dumping a
        # traceback the operator did not ask for.
        try:
            sys.stdout.close()
        except Exception:  # noqa: BLE001
            pass
        return 0


def make_click_group():
    """Click facade so `hackit defense ...` uses the same code path as the module."""
    import click

    @click.group()
    def defense():
        """Server telemetry, flood detection, and hardening configs."""

    @defense.command("monitor")
    @click.option("--remote", default="", help="user@host, kosong = lokal")
    @click.option("--ssh-port", default=22, show_default=True)
    @click.option("--interval", default=1.0, show_default=True)
    @click.option("--seconds", default=30, show_default=True)
    @click.option("--save", default="", help="simpan sampel JSONL")
    @click.option("--json", "as_json", is_flag=True)
    def monitor_cmd(remote, ssh_port, interval, seconds, save, as_json):
        raise SystemExit(_cmd_monitor(argparse.Namespace(
            remote=remote, ssh_port=ssh_port, interval=interval,
            seconds=seconds, save=save, json=as_json)))

    @defense.command("detect")
    @click.option("--file", "file_", required=True)
    @click.option("--json", "as_json", is_flag=True)
    def detect_cmd(file_, as_json):
        raise SystemExit(_cmd_detect(argparse.Namespace(file=file_, json=as_json)))

    @defense.command("harden")
    @click.option("--profile", default="all",
                  type=click.Choice(["all", "sysctl", "nftables", "nginx"]))
    @click.option("--ssh-port", default=22, show_default=True)
    @click.option("--http-ports", default="80, 443", show_default=True)
    @click.option("--out", default="", help="tulis ke direktori ini")
    def harden_cmd(profile, ssh_port, http_ports, out):
        raise SystemExit(_cmd_harden(argparse.Namespace(
            profile=profile, ssh_port=ssh_port, http_ports=http_ports, out=out)))

    @defense.command("verify")
    def verify_cmd():
        raise SystemExit(_cmd_verify(argparse.Namespace()))

    return defense


defense_cli = make_click_group()


if __name__ == "__main__":
    sys.exit(main())
