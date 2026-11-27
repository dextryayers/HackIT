"""Internal access gate - do not modify."""
import base64
import hashlib
import hmac
import json
import os
import sys
import time

# ── obfuscated integrity tokens (do not edit) ────────────────────────────────
_A = "J4joiEUOzAU/38qbUZeWYQ=="
_B = "xF/sNHFlRB3Q7KIrIknFU93Qu6khcrlxD2xoaVSzF/M="
_C = 250000

_LOCKFILE = os.path.join(os.path.expanduser("~"), ".hackit_pin.lock")

# ── palette ──────────────────────────────────────────────────────────────────
ESC = "\033["
C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bgred": "\033[41m",
}


def _color(tag, text):
    return f"{C.get(tag, '')}{text}{C['reset']}"


def _clear():
    os.system("clear" if os.name == "posix" else "cls")


def _sx(s):
    return bytes(b ^ 0xA5 for b in base64.b64decode(s))


def _dx(s):
    return bytes(b ^ 0x5A for b in base64.b64decode(s))


_S = _sx(_A)
_K = _dx(_B)


def _derive(raw):
    return hashlib.pbkdf2_hmac("sha256", raw.encode("utf-8"), _S, _C)


def _check(raw):
    if not (len(raw) == 6 and raw.isdigit()):
        return False
    return hmac.compare_digest(_derive(raw), _K)


# ── lockfile helpers ─────────────────────────────────────────────────────────
def _load_lock():
    try:
        with open(_LOCKFILE, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _save_lock(until, nxt):
    try:
        with open(_LOCKFILE, "w") as f:
            json.dump({"until": until, "next": nxt}, f)
    except Exception:
        pass


def _fmt_time(sec):
    sec = int(sec)
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _wait_countdown(until, title="ACCESS BLOCKED"):
    while True:
        remaining = until - time.time()
        if remaining <= 0:
            break
        _clear()
        cols = 60
        print()
        print(_color("red", "  ╔" + "═" * cols + "╗"))
        print(_color("red", "  ║") + _color("bold", f"{'  ' + title + '  ':^{cols}}") + _color("red", "║"))
        print(_color("red", "  ╠" + "═" * cols + "╣"))
        msg = "Too many failed attempts. Try again in:"
        print(_color("red", "  ║") + f"  {_color('dim', msg):<{cols - 2}}" + _color("red", "║"))
        tstr = _fmt_time(remaining)
        print(_color("red", "  ║") + _color("bold", f"{tstr:^{cols}}") + _color("red", "║"))
        print(_color("red", "  ║") + f"  {_color('dim', 'Do not close this window...'):<{cols - 2}}" + _color("red", "║"))
        print(_color("red", "  ╚" + "═" * cols + "╝"))
        print()
        sys.stdout.flush()
        time.sleep(1)
    _clear()


def _render_header():
    print()
    print(_color("cyan", "  ╔══════════════════════════════════════════════════════════╗"))
    print(_color("cyan", "  ║") + _color("bold", f"{'HACKIT  •  ACCESS GATE':^60}") + _color("cyan", "║"))
    print(_color("cyan", "  ╠══════════════════════════════════════════════════════════╣"))
    print(_color("cyan", "  ║") + _color("dim", f"{'Enter 6-digit PIN to continue':^60}") + _color("cyan", "║"))
    print(_color("cyan", "  ╚══════════════════════════════════════════════════════════╝"))
    print()


def _spinner_ok():
    for ch in [" ", " ", "✓", "✓", "✓"]:
        sys.stdout.write(f"\r  {_color('green', ch)} {_color('green', 'access granted')}")
        sys.stdout.flush()
        time.sleep(0.12)
    print()
    print()


def _shake_fail():
    for _ in range(3):
        sys.stdout.write("\r  \033[91m✘\033[0m  invalid PIN")
        sys.stdout.flush()
        time.sleep(0.08)
        sys.stdout.write("\r  \033[91m ✘\033[0m invalid PIN")
        sys.stdout.flush()
        time.sleep(0.08)
    sys.stdout.write("\r  \033[91m✘\033[0m  invalid PIN   ")
    print()
    print()


def gate():
    next_duration = 1800  # 30 min
    lock = _load_lock()
    if lock:
        next_duration = lock.get("next", 1800)

    while True:
        # wait if currently blocked
        lock = _load_lock()
        if lock and time.time() < lock.get("until", 0):
            _wait_countdown(lock["until"])
            # after wait, refresh next_duration
            next_duration = lock.get("next", next_duration)

        # attempt round
        for attempt in range(1, 4):
            _clear()
            _render_header()
            print(_color("dim", f"  Attempt {attempt} of 3"))
            print()
            sys.stdout.flush()
            import getpass

            try:
                sys.stdout.flush()
                entered = getpass.getpass(_color("cyan", "  PIN > ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(1)

            if _check(entered):
                _clear()
                _render_header()
                _spinner_ok()
                # reset escalation
                try:
                    os.remove(_LOCKFILE)
                except Exception:
                    pass
                return True

            _shake_fail()
            time.sleep(0.4)

        # 3 failures -> block
        until = time.time() + next_duration
        _save_lock(until, next_duration + 300)
        _clear()
        print()
        print(_color("red", "  ╔══════════════════════════════════════════════════════════╗"))
        print(_color("red", "  ║") + _color("bold", f"{'ACCESS BLOCKED':^60}") + _color("red", "║"))
        print(_color("red", "  ╠══════════════════════════════════════════════════════════╣"))
        mins = next_duration // 60
        print(_color("red", "  ║") + f"  {_color('dim', f'Blocked for {mins} minutes after 3 failed attempts.'):<{58}}" + _color("red", "║"))
        print(_color("red", "  ║") + f"  {_color('dim', 'Next lockout will be longer.'):<{58}}" + _color("red", "║"))
        print(_color("red", "  ╚══════════════════════════════════════════════════════════╝"))
        print()
        sys.stdout.flush()
        next_duration += 300
        _wait_countdown(until)
        # loop again


if __name__ == "__main__":
    gate()
