import os
import sys
import json
import subprocess
import shlex
from datetime import datetime
from typing import List, Optional

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
RUST_BIN = os.path.join(ENGINE_DIR, "rust_engine", "target", "release", "keystrike")

PROTOCOLS_RUST = [
    "ftp", "ssh", "telnet", "smtp", "pop3", "imap", "http", "https",
    "mysql", "postgresql", "postgres", "redis", "ldap",
    "mssql", "mqtt", "vnc", "smb", "snmp",
]

PROTOCOLS_HYDRA = [
    "ftp", "ssh", "telnet", "smtp", "pop3", "imap", "http", "https",
    "mysql", "postgresql", "postgres", "redis", "ldap",
    "mssql", "mqtt", "vnc", "smb", "snmp",
    "rdp", "ldaps", "smtps", "imaps", "pop3s",
    "oracle", "cisco",
]

PROTOCOL_PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "http": 80, "https": 443,
    "pop3": 110, "imap": 143, "ldap": 389, "ldaps": 636, "mysql": 3306,
    "rdp": 3389, "postgresql": 5432, "postgres": 5432, "redis": 6379,
    "smb": 445, "snmp": 161, "vnc": 5900, "mssql": 1433, "oracle": 1521,
    "mqtt": 1883, "mqtts": 8883, "smtps": 465, "imaps": 993, "pop3s": 995,
}

PROTOCOL_NAMES = {
    "ftp": "FTP", "ssh": "SSH", "telnet": "Telnet", "smtp": "SMTP",
    "http": "HTTP", "https": "HTTPS", "pop3": "POP3", "imap": "IMAP",
    "ldap": "LDAP", "ldaps": "LDAPS", "mysql": "MySQL", "rdp": "RDP",
    "postgresql": "PostgreSQL", "postgres": "PostgreSQL", "redis": "Redis",
    "smb": "SMB", "snmp": "SNMP", "vnc": "VNC", "mssql": "MSSQL",
    "oracle": "Oracle", "mqtt": "MQTT", "mqtts": "MQTTS",
    "smtps": "SMTPS", "imaps": "IMAPS", "pop3s": "POP3S",
}


def list_protocols():
    return PROTOCOLS_HYDRA


def get_protocol_name(proto):
    return PROTOCOL_NAMES.get(proto, proto.upper())


def get_default_port(proto):
    return PROTOCOL_PORTS.get(proto, 0)


def run_rust_engine(target, port, protocol, users, passwords, threads=32, timeout=10,
                    proxy=None, expand_words=False):
    if not os.path.exists(RUST_BIN):
        return {"status": "error", "message": "Rust engine not built. Run: cd rust_engine && cargo build --release"}

    import tempfile

    userlist_file = None
    passlist_file = None

    try:
        if len(users) > 1:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(users))
                userlist_file = f.name
        if len(passwords) > 1:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(passwords))
                passlist_file = f.name

        cmd = [
            RUST_BIN, "-t", target, "-P", protocol,
            "--json", "-T", str(threads), "--timeout", str(timeout),
        ]
        if port:
            cmd.extend(["-p", str(port)])
        if len(users) == 1:
            cmd.extend(["-u", users[0]])
        elif userlist_file:
            cmd.extend(["-U", userlist_file])
        if len(passwords) == 1:
            cmd.extend(["-w", passwords[0]])
        elif passlist_file:
            cmd.extend(["-W", passlist_file])
        if proxy:
            cmd.extend(["--proxy", proxy])
        if expand_words:
            cmd.append("--expand-words")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        results = []
        for line in proc.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(data)
            except json.JSONDecodeError:
                continue

        return _parse_rust_results(results, protocol, target, port)

    finally:
        if userlist_file and os.path.exists(userlist_file):
            os.unlink(userlist_file)
        if passlist_file and os.path.exists(passlist_file):
            os.unlink(passlist_file)


def _parse_rust_results(results, protocol, target, port):
    found = []
    final = None
    prog = {"attempted": 0, "total": 0, "found": 0, "speed": 0, "elapsed": 0}

    for r in results:
        s = r.get("status")
        if s == "progress":
            prog.update(r)
        elif s == "found":
            found.append({
                "username": r.get("username", ""),
                "password": r.get("password", ""),
                "protocol": protocol,
                "target": target,
                "port": port or get_default_port(protocol),
            })
        elif s == "complete":
            final = r
        elif s == "error":
            return {"status": "error", "message": r.get("message", "")}

    return {
        "status": "complete",
        "protocol": protocol,
        "target": target,
        "port": port or get_default_port(protocol),
        "total_attempts": final.get("total_attempts", prog["total"]) if final else prog["total"],
        "elapsed": final.get("elapsed", prog["elapsed"]) if final else prog["elapsed"],
        "speed": final.get("speed", f"{prog['speed']:.0f}/s") if final else f"{prog['speed']:.0f}/s",
        "found": found,
        "found_count": len(found),
    }


def run_hydra(target, port, protocol, users, passwords, threads=16, timeout=10):
    hydra = "/usr/bin/hydra"
    if not os.path.exists(hydra):
        return {"status": "error", "message": "hydra not found"}

    import tempfile

    userlist_file = None
    passlist_file = None

    try:
        if len(users) > 1:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(users))
                userlist_file = f.name
        if len(passwords) > 1:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(passwords))
                passlist_file = f.name

        use_list = userlist_file is not None
        pw_list = passlist_file is not None

        cmd = [hydra, "-t", str(threads), "-f"]
        if not use_list:
            cmd.extend(["-l", users[0]])
        else:
            cmd.extend(["-L", userlist_file])
        if not pw_list:
            cmd.extend(["-p", passwords[0]])
        else:
            cmd.extend(["-P", passlist_file])

        if port:
            cmd.extend(["-s", str(port)])

        cmd.extend([f"{protocol}://{target}"])

        env = os.environ.copy()
        env["HYDRA_PROXY_CONNECT_TIMEOUT"] = str(timeout)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Hydra timed out"}

        output = proc.stdout + proc.stderr
        found = []
        for line in output.split('\n'):
            if "login:" in line.lower() and "password:" in line.lower():
                parts = line.strip().split()
                user_val = ""
                pass_val = ""
                for i, p in enumerate(parts):
                    if p.lower() == "login:" and i + 1 < len(parts):
                        user_val = parts[i + 1].rstrip(',')
                    if p.lower() == "password:" and i + 1 < len(parts):
                        pass_val = parts[i + 1].rstrip(',')
                if user_val and pass_val:
                    found.append({
                        "username": user_val,
                        "password": pass_val,
                        "protocol": protocol,
                        "target": target,
                        "port": port or get_default_port(protocol),
                    })

        total_attempts = 0
        import re
        for line in output.split('\n'):
            m = re.search(r'(\d+)\s+attempt', line)
            if m:
                total_attempts = int(m.group(1))

        return {
            "status": "complete",
            "protocol": protocol,
            "target": target,
            "port": port or get_default_port(protocol),
            "total_attempts": total_attempts,
            "elapsed": 0,
            "speed": "",
            "found": found,
            "found_count": len(found),
            "hydra_output": output,
        }

    finally:
        if userlist_file and os.path.exists(userlist_file):
            os.unlink(userlist_file)
        if passlist_file and os.path.exists(passlist_file):
            os.unlink(passlist_file)


def run_bruteforce(target, port, protocol, users, passwords, threads=32, timeout=10,
                   prefer_rust=True, proxy=None, expand_words=False):
    if prefer_rust and protocol in PROTOCOLS_RUST and os.path.exists(RUST_BIN):
        return run_rust_engine(target, port, protocol, users, passwords,
                               threads, timeout, proxy=proxy, expand_words=expand_words)
    if protocol in PROTOCOLS_HYDRA:
        return run_hydra(target, port, protocol, users, passwords, threads, timeout)
    return {"status": "error", "message": f"Protocol {protocol} not supported"}
