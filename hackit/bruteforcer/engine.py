"""Python front end for the KeyStrike brute-force engine.

Everything real goes through the Rust binary: it speaks the actual wire
protocol for every supported service, so a credential reported here was
accepted by the target, not guessed at.

The bridge streams: the engine emits NDJSON as it works, this module parses it
line by line and hands each event to a callback, so the caller can render live
progress and print credentials the instant they land. Nothing is buffered until
the process exits.

Nothing in this module fabricates a result. If the binary is missing, the run
fails loudly. If a protocol is unsupported, the run fails loudly. There is no
"pretend" path.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
from typing import Callable, Dict, Iterable, List, Optional, Tuple

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
RUST_DIR = os.path.join(ENGINE_DIR, "rust_engine")
RUST_BIN = os.path.join(RUST_DIR, "target", "release", "keystrike")
WORDLIST_DIR = os.path.join(ENGINE_DIR, "wordlists")

# ─────────────────────────── protocol table ───────────────────────────
# Every entry is a protocol the Rust engine actually implements. The port is
# the service default; `tls` marks the implicit-TLS variants.
PROTOCOLS: List[Tuple[str, int]] = [
    ("ssh", 22),
    ("ftp", 21),
    ("telnet", 23),
    ("smtp", 25),
    ("smtps", 465),
    ("pop3", 110),
    ("pop3s", 995),
    ("imap", 143),
    ("imaps", 993),
    ("http", 80),
    ("https", 443),
    ("ldap", 389),
    ("ldaps", 636),
    ("mysql", 3306),
    ("postgresql", 5432),
    ("redis", 6379),
    ("mssql", 1433),
    ("mqtt", 1883),
    ("mqtts", 8883),
    ("vnc", 5900),
    ("smb", 445),
    ("snmp", 161),
    ("rdp", 3389),
]

PROTOCOL_PORTS: Dict[str, int] = dict(PROTOCOLS)
PROTOCOL_PORTS["postgres"] = 5432

PROTOCOL_NAMES: Dict[str, str] = {
    "ssh": "SSH", "ftp": "FTP", "telnet": "Telnet", "smtp": "SMTP",
    "smtps": "SMTPS", "pop3": "POP3", "pop3s": "POP3S", "imap": "IMAP",
    "imaps": "IMAPS", "http": "HTTP", "https": "HTTPS", "ldap": "LDAP",
    "ldaps": "LDAPS", "mysql": "MySQL", "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL", "redis": "Redis", "mssql": "MSSQL",
    "mqtt": "MQTT", "mqtts": "MQTTS", "vnc": "VNC", "smb": "SMB",
    "snmp": "SNMP", "rdp": "RDP",
}

# Protocols whose credential check needs no username (a VNC password is the
# whole secret; an SNMP community string is the whole secret).
USERLESS = {"vnc", "snmp"}

# Protocols that carry HTTP request knobs.
HTTP_FAMILY = {"http", "https"}


def list_protocols() -> List[str]:
    return [name for name, _ in PROTOCOLS]


def get_protocol_name(proto: str) -> str:
    return PROTOCOL_NAMES.get(proto, proto.upper())


def get_default_port(proto: str) -> int:
    return PROTOCOL_PORTS.get(proto, 0)


def is_supported(proto: str) -> bool:
    return proto in PROTOCOL_PORTS


def engine_available() -> bool:
    return os.path.isfile(RUST_BIN) and os.access(RUST_BIN, os.X_OK)


def build_engine() -> Tuple[bool, str]:
    """Compile the Rust engine. Returns (ok, output)."""
    cargo = shutil.which("cargo")
    if not cargo:
        return False, "cargo not found on PATH — install a Rust toolchain to build the engine"
    proc = subprocess.run(
        [cargo, "build", "--release"],
        cwd=RUST_DIR,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


# ─────────────────────────── wordlists ───────────────────────────
def list_wordlists() -> Dict[str, str]:
    """Built-in wordlist name → absolute path."""
    out: Dict[str, str] = {}
    if not os.path.isdir(WORDLIST_DIR):
        return out
    for entry in sorted(os.listdir(WORDLIST_DIR)):
        if entry.endswith(".txt"):
            out[entry[:-4]] = os.path.join(WORDLIST_DIR, entry)
    return out


def load_wordlist(spec: str) -> List[str]:
    """Resolve a built-in wordlist name or a filesystem path into lines.

    Blank lines and `#` comments are dropped, duplicates are collapsed in
    first-seen order, and the original casing is preserved — a password list
    that silently lowercases its entries would test the wrong passwords.
    """
    path = spec
    if not os.path.isfile(path):
        builtin = list_wordlists().get(spec)
        if builtin is None:
            raise FileNotFoundError(f"no wordlist named {spec!r} and no file at that path")
        path = builtin

    seen = set()
    out: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            if not line or line.lstrip().startswith("#"):
                continue
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
    return out


def default_users() -> List[str]:
    try:
        return load_wordlist("users")
    except FileNotFoundError:
        return []


def default_passwords() -> List[str]:
    try:
        return load_wordlist("passwords")
    except FileNotFoundError:
        return []


def _probe_smb_negotiate() -> bytes:
    """Minimal SMB2 NEGOTIATE, enough to get a NEGOTIATE response back."""
    dialects = b"".join(d.to_bytes(2, "little") for d in (0x0311, 0x0302, 0x0210, 0x0202))
    body = (
        (36).to_bytes(2, "little")
        + (4).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + b"\x00\x00"
        + b"\x00" * 4
        + b"\x11" * 16
        + b"\x00" * 8
        + b"\x00\x00"
        + b"\x00\x00"
        + dialects
    )
    header = (
        b"\xfeSMB"
        + (64).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + b"\x00" * 4
        + (0).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 16
    )
    packet = header + body
    return len(packet).to_bytes(4, "big") + packet


def _probe_rdp_negotiate() -> bytes:
    """TPKT + X.224 Connection Request asking for TLS or NLA."""
    x224 = b"\x06\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
    total = len(x224) + 4
    return b"\x03\x00" + total.to_bytes(2, "big") + x224


def _probe_mqtt_connect() -> bytes:
    """MQTT 3.1.1 CONNECT with an empty client id — every broker answers."""
    variable = b"\x00\x04MQTT\x04\x02\x00\x3c"  # proto, level 4, clean session, keepalive 60
    payload = b"\x00\x00"  # zero-length client id
    body = variable + payload
    return b"\x10" + bytes([len(body)]) + body


def _probe_postgres_ssl() -> bytes:
    """PostgreSQL SSLRequest — the backend answers 'S' or 'N'."""
    return b"\x00\x00\x00\x08\x04\xd2\x16\x2f"


# ─────────────────────────── service detection ───────────────────────────
# Banner signatures, applied to whatever the service says on connect. These are
# the real greetings the daemons send, so detection is a read, not a guess.
_BANNER_RULES: List[Tuple[str, "re.Pattern[str]"]] = [
    ("ssh", re.compile(rb"^SSH-\d")),
    ("ftp", re.compile(rb"^220[\s\S]*?(ftp|vsftpd|proftpd|filezilla|pure-ftpd)", re.I)),
    ("smtp", re.compile(rb"^220[\s\S]*?(smtp|esmtp|postfix|exim|sendmail|exchange)", re.I)),
    ("pop3", re.compile(rb"^\+OK")),
    ("imap", re.compile(rb"^\* OK")),
    ("vnc", re.compile(rb"^RFB \d{3}\.\d{3}")),
    ("telnet", re.compile(rb"^\xff[\xfb-\xfe]")),
    ("mysql", re.compile(rb"^[\x00-\xff]{3}\x00\x0a")),
    ("mqtt", re.compile(rb"^[\x20\x10]")),
    ("http", re.compile(rb"^HTTP/\d\.\d")),
]


def _read_banner(sock: socket.socket, limit: int = 512) -> bytes:
    """Read whatever the peer sends, stopping after a short idle gap.

    A single `recv` can return half a greeting, so keep reading until the peer
    goes quiet. The idle window is short: a service that has nothing to say
    should not cost the caller the whole probe timeout.
    """
    chunks = bytearray()
    try:
        sock.settimeout(0.35)
        while len(chunks) < limit:
            piece = sock.recv(min(limit - len(chunks), 4096))
            if not piece:
                break
            chunks.extend(piece)
    except (socket.timeout, OSError):
        pass
    return bytes(chunks)


def detect_service(target: str, port: int, timeout: float = 3.0) -> Dict[str, object]:
    """Identify the service on `target:port` from what it actually says.

    Passive banners cover SSH/FTP/SMTP/POP3/IMAP/VNC/MySQL. Services that stay
    silent until asked get a protocol-correct probe: an HTTP request, a Redis
    `PING`, or an LDAP bind-less search. Anything still unidentified is reported
    as unknown rather than guessed from the port number.
    """
    result: Dict[str, object] = {
        "target": target,
        "port": port,
        "protocol": None,
        "banner": "",
        "detail": "",
    }

    try:
        sock = socket.create_connection((target, port), timeout=timeout)
    except OSError as exc:
        result["detail"] = f"connect failed: {exc}"
        return result

    try:
        sock.settimeout(timeout)
        banner = _read_banner(sock)

        for proto, rule in _BANNER_RULES:
            if rule.search(banner):
                result["protocol"] = proto
                result["banner"] = banner[:200].decode("utf-8", "replace").rstrip("\r\n")
                return result

        # Silent services — ask each one the question it answers. Each probe
        # gets its own connection: an HTTP request sent to Redis makes Redis
        # drop the socket, so sharing one would poison the next probe.
        silent_probes = [
            (
                "http",
                b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n",
                lambda r: bool(re.match(rb"^HTTP/\d\.\d", r)),
            ),
            # RESP array form: every Redis accepts it, and the inline form is
            # disabled on some hardened builds.
            (
                "redis",
                b"*1\r\n$4\r\nPING\r\n",
                lambda r: bool(re.match(rb"^[+-](PONG|NOAUTH|ERR|WRONGPASS)", r)),
            ),
            (
                "postgresql",
                _probe_postgres_ssl(),
                lambda r: r[:1] in (b"S", b"N"),
            ),
            (
                "smb",
                _probe_smb_negotiate(),
                lambda r: r[4:8] == b"\xfeSMB",
            ),
            (
                "rdp",
                _probe_rdp_negotiate(),
                lambda r: len(r) >= 6 and r[0] == 0x03 and r[5] == 0xD0,
            ),
            (
                "mqtt",
                _probe_mqtt_connect(),
                lambda r: len(r) >= 4 and r[0] == 0x20 and r[1] == 0x02,
            ),
        ]

        for proto, probe, matches in silent_probes:
            try:
                with socket.create_connection((target, port), timeout=timeout) as probe_sock:
                    probe_sock.settimeout(timeout)
                    probe_sock.sendall(probe)
                    reply = _read_banner(probe_sock, 256)
            except OSError:
                continue
            if matches(reply):
                result["protocol"] = proto
                result["banner"] = reply[:200].decode("utf-8", "replace").rstrip("\r\n")
                return result

        if banner:
            result["banner"] = banner[:200].decode("utf-8", "replace").rstrip("\r\n")
        result["detail"] = "no protocol signature in the service greeting"
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_port(target: str, port: int, timeout: float = 3.0) -> bool:
    """True when a TCP connection completes. Used for the reachability gate."""
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


# ─────────────────────────── engine invocation ───────────────────────────
class EngineError(RuntimeError):
    """The engine could not run, or reported a fatal error."""


def _write_temp_lines(lines: Iterable[str], suffix: str = ".txt") -> Optional[str]:
    lines = list(lines)
    if not lines:
        return None
    handle = tempfile.NamedTemporaryFile(
        mode="w", delete=False, suffix=suffix, encoding="utf-8"
    )
    try:
        handle.write("\n".join(lines))
        handle.write("\n")
    finally:
        handle.close()
    return handle.name


def build_command(
    target: str,
    port: int,
    protocol: str,
    *,
    user: Optional[str] = None,
    userlist: Optional[str] = None,
    password: Optional[str] = None,
    passlist: Optional[str] = None,
    combo_file: Optional[str] = None,
    extra: str = "",
    threads: int = 16,
    timeout: int = 10,
    stop_on_first: bool = False,
    retries: int = 1,
    rate: float = 0.0,
    wait: float = 0.0,
    resume: Optional[str] = None,
    max_blocking: Optional[int] = None,
    expand_words: bool = False,
    check: bool = False,
    verbose: bool = False,
    http: Optional[Dict[str, object]] = None,
) -> List[str]:
    """Assemble the engine argv. Kept separate so it is testable without a run."""
    cmd = [RUST_BIN, "-t", target, "-P", protocol, "--json", "-T", str(threads),
           "--timeout", str(timeout), "--retries", str(retries)]

    if port:
        cmd.extend(["-p", str(port)])
    if stop_on_first:
        cmd.append("-f")
    if expand_words:
        cmd.append("--expand-words")
    if check:
        cmd.append("--check")
    if verbose:
        cmd.append("-v")
    if rate:
        cmd.extend(["--rate", str(rate)])
    if wait:
        cmd.extend(["--wait", str(wait)])
    if resume:
        cmd.extend(["--resume", resume])
    if max_blocking:
        cmd.extend(["--max-blocking", str(max_blocking)])
    if extra:
        cmd.extend(["-e", extra])

    if combo_file:
        cmd.extend(["-C", combo_file])
    else:
        if userlist:
            cmd.extend(["-U", userlist])
        elif user:
            cmd.extend(["-u", user])
        if passlist:
            cmd.extend(["-W", passlist])
        elif password is not None:
            cmd.extend(["-w", password])

    if http:
        if http.get("path"):
            cmd.extend(["--http-path", str(http["path"])])
        if http.get("method"):
            cmd.extend(["--http-method", str(http["method"]).upper()])
        if http.get("body"):
            cmd.extend(["--http-body", str(http["body"])])
        if http.get("fail"):
            cmd.extend(["--http-fail", str(http["fail"])])
        if http.get("success"):
            cmd.extend(["--http-success", str(http["success"])])
        for header in http.get("headers") or []:
            cmd.extend(["--http-header", str(header)])
        if http.get("tls"):
            cmd.append("--http-tls")
        if http.get("force_basic"):
            cmd.append("--http-force-basic")

    return cmd


def _drain(stream, sink: List[str], on_log: Optional[Callable[[str], None]] = None) -> None:
    try:
        for line in stream:
            text = line.rstrip("\n")
            sink.append(text)
            if on_log is not None and text.strip():
                on_log(text)
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except (ValueError, OSError):
            pass


def run_engine(
    cmd: List[str],
    *,
    on_event: Optional[Callable[[Dict[str, object]], None]] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> Dict[str, object]:
    """Run the engine, streaming its NDJSON, and return the terminal summary.

    `on_event` receives every parsed JSON object as it arrives — progress
    ticks, credential hits, the final summary. `on_log` receives the engine's
    stderr chatter (verbose per-attempt lines, transport warnings).
    """
    if not engine_available():
        raise EngineError(
            f"engine binary not found at {RUST_BIN} — build it with: "
            f"cd {RUST_DIR} && cargo build --release"
        )

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace",
    )

    stderr_lines: List[str] = []
    stderr_thread = threading.Thread(
        target=_drain, args=(proc.stderr, stderr_lines, on_log), daemon=True
    )
    stderr_thread.start()

    found: List[Dict[str, object]] = []
    summary: Optional[Dict[str, object]] = None
    last_progress: Dict[str, object] = {}
    fatal: Optional[str] = None

    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Not NDJSON: the engine only does this for a clap usage error,
                # which it writes to stderr, so ignore the stray line.
                continue

            status = event.get("status")
            if status == "progress":
                last_progress = event
            elif status == "found":
                found.append(event)
            elif status == "complete":
                summary = event
            elif status == "error":
                fatal = str(event.get("message", "engine error"))

            if on_event is not None:
                on_event(event)
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise
    finally:
        try:
            proc.stdout.close()  # type: ignore[union-attr]
        except (ValueError, OSError):
            pass
        returncode = proc.wait()
        stderr_thread.join(timeout=2)

    if fatal:
        raise EngineError(fatal)
    if summary is None:
        detail = "\n".join(stderr_lines[-5:]) or f"exit code {returncode}"
        raise EngineError(f"engine exited without a summary: {detail}")

    results = summary.get("results") or found
    return {
        "status": "complete",
        "protocol": summary.get("protocol", cmd[cmd.index("-P") + 1]),
        "target": summary.get("target", cmd[cmd.index("-t") + 1]),
        "port": summary.get("port", 0),
        "total_attempts": summary.get("total_attempts", last_progress.get("attempted", 0)),
        "total_combos": summary.get("total_combos", last_progress.get("total", 0)),
        "elapsed": summary.get("elapsed", last_progress.get("elapsed", 0.0)),
        "speed": summary.get("speed", ""),
        "speed_raw": summary.get("speed_raw", last_progress.get("speed", 0.0)),
        "transport_errors": summary.get("transport_errors", 0),
        "stopped_early": summary.get("stopped_early", False),
        "stopped_at": summary.get("stopped_at", 0),
        "found": [
            {
                "username": entry.get("username", ""),
                "password": entry.get("password", ""),
                "protocol": entry.get("protocol", summary.get("protocol", "")),
                "target": entry.get("target", summary.get("target", "")),
                "port": entry.get("port", summary.get("port", 0)),
            }
            for entry in results
        ],
        "found_count": len(results),
        "log": stderr_lines,
    }


def run_bruteforce(
    target: str,
    port: int,
    protocol: str,
    users: Optional[List[str]] = None,
    passwords: Optional[List[str]] = None,
    threads: int = 16,
    timeout: int = 10,
    *,
    userlist: Optional[str] = None,
    passlist: Optional[str] = None,
    combo_file: Optional[str] = None,
    extra: str = "",
    stop_on_first: bool = False,
    retries: int = 1,
    rate: float = 0.0,
    wait: float = 0.0,
    resume: Optional[str] = None,
    max_blocking: Optional[int] = None,
    expand_words: bool = False,
    check: bool = False,
    verbose: bool = False,
    http: Optional[Dict[str, object]] = None,
    on_event: Optional[Callable[[Dict[str, object]], None]] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> Dict[str, object]:
    """Brute-force one service and return the engine's terminal summary.

    `users`/`passwords` are in-memory lists; `userlist`/`passlist` are paths to
    existing files and are passed straight through, which matters for lists of
    a million entries. `combo_file` replaces both with `user:pass` lines.

    `on_event` is called for every engine event as it arrives, so a caller can
    print progress and credentials live instead of waiting for the end.
    """
    protocol = protocol.lower().strip()
    if protocol == "postgres":
        protocol = "postgresql"
    if not is_supported(protocol):
        raise EngineError(
            f"protocol {protocol!r} is not implemented by the engine "
            f"(supported: {', '.join(list_protocols())})"
        )

    effective_port = port or get_default_port(protocol)

    temp_paths: List[str] = []
    try:
        user_arg = None
        userlist_path = userlist
        if not combo_file:
            if userlist_path is None:
                users = list(users or [])
                if len(users) == 1:
                    user_arg = users[0]
                elif users:
                    userlist_path = _write_temp_lines(users, ".users")
                    if userlist_path:
                        temp_paths.append(userlist_path)

            password_arg = None
            passlist_path = passlist
            if passlist_path is None:
                passwords = list(passwords or [])
                if len(passwords) == 1:
                    password_arg = passwords[0]
                elif passwords:
                    passlist_path = _write_temp_lines(passwords, ".pass")
                    if passlist_path:
                        temp_paths.append(passlist_path)
        else:
            user_arg = None
            userlist_path = None
            password_arg = None
            passlist_path = None

        if not combo_file and user_arg is None and userlist_path is None and protocol not in USERLESS:
            raise EngineError(
                "no usernames supplied — pass a user, a userlist, or a combo file"
            )
        if not combo_file and password_arg is None and passlist_path is None:
            raise EngineError(
                "no passwords supplied — pass a password, a passlist, or a combo file"
            )

        cmd = build_command(
            target,
            effective_port,
            protocol,
            user=user_arg,
            userlist=userlist_path,
            password=password_arg,
            passlist=passlist_path,
            combo_file=combo_file,
            extra=extra,
            threads=threads,
            timeout=timeout,
            stop_on_first=stop_on_first,
            retries=retries,
            rate=rate,
            wait=wait,
            resume=resume,
            max_blocking=max_blocking,
            expand_words=expand_words,
            check=check,
            verbose=verbose,
            http=http,
        )
        return run_engine(cmd, on_event=on_event, on_log=on_log)
    finally:
        for path in temp_paths:
            try:
                os.unlink(path)
            except OSError:
                pass


def run_multi(
    target: str,
    protocol: str,
    port: int = 0,
    **kwargs,
) -> Dict[str, object]:
    """Alias kept for callers that used the old single-protocol helper."""
    return run_bruteforce(target, port, protocol, **kwargs)
