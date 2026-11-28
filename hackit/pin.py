"""Internal access gate - do not modify."""
import base64
import hashlib
import hmac
import json
import os
import shutil
import sys
import threading
import time

# ── obfuscated integrity tokens (do not edit) ────────────────────────────────
_A = "J4joiEUOzAU/38qbUZeWYQ=="
_B = "xF/sNHFlRB3Q7KIrIknFU93Qu6khcrlxD2xoaVSzF/M="
_C = 250000

_LOCKFILE = os.path.join(os.path.expanduser("~"), ".hackit_pin.lock")

# ── palette ──────────────────────────────────────────────────────────────────
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
}
RGB = ["\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[94m", "\033[95m"]


def _color(tag, text):
    return f"{C.get(tag, '')}{text}{C['reset']}"


def _rgb(i, text):
    return f"{RGB[i % len(RGB)]}{text}{C['reset']}"


def _clear():
    os.system("clear" if os.name == "posix" else "cls")


def _term():
    return shutil.get_terminal_size()


def _box_width():
    cols = _term().columns
    return min(62, max(40, cols - 6))


def _left_pad():
    cols = _term().columns
    bw = _box_width()
    return max(0, (cols - (bw + 2)) // 2)


def _pad(s):
    return " " * _left_pad() + s


def _box_top(color_fn, i=0):
    bw = _box_width()
    lp = _left_pad()
    line = " " * lp + color_fn(i, "╔" + "═" * bw + "╗")
    print(line)


def _box_bot(color_fn, i=0):
    bw = _box_width()
    lp = _left_pad()
    line = " " * lp + color_fn(i, "╚" + "═" * bw + "╝")
    print(line)


def _box_line(text, color_fn, i=0, fill=" "):
    bw = _box_width()
    lp = _left_pad()
    vis = len(text)
    # strip ansi for length calc
    import re

    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    vis = len(clean)
    pad = max(0, bw - vis - 2)
    line = " " * lp + color_fn(i, "║") + " " + text + " " * (pad + 1) + color_fn(i, "║")
    print(line)


def _box_sep(color_fn, i=0):
    bw = _box_width()
    lp = _left_pad()
    print(" " * lp + color_fn(i, "╠" + "═" * bw + "╣"))


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


def _rgb_border_pulse(frames=12, delay=0.06, title=None):
    for i in range(frames):
        _clear()
        cf = lambda idx, t: _rgb((i + idx) % len(RGB), t)
        _box_top(cf, i)
        if title:
            _box_line(_color("bold", f"{title:^{_box_width() - 2}}"), cf, i)
            _box_sep(cf, i)
        _box_bot(cf, i)
        print()
        sys.stdout.flush()
        time.sleep(delay)


def _wait_countdown(until, title="ACCESS BLOCKED"):
    while True:
        remaining = until - time.time()
        if remaining <= 0:
            break
        _clear()
        i = int(time.time() * 4) % len(RGB)
        cf = lambda idx, t: _rgb((i + idx) % len(RGB), t)
        _box_top(cf, i)
        _box_line(_color("bold", f"{title:^{_box_width() - 2}}"), cf, i)
        _box_sep(cf, i)
        msg = "Too many failed attempts. Try again in:"
        _box_line(_color("dim", f"{msg:^{_box_width() - 2}}"), cf, i)
        tstr = _fmt_time(remaining)
        _box_line(_color("bold", f"{tstr:^{_box_width() - 2}}"), cf, i)
        _box_line(_color("dim", f"{'Do not close this window...':^{_box_width() - 2}}"), cf, i)
        _box_bot(cf, i)
        print()
        sys.stdout.flush()
        time.sleep(1)
    _clear()


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


def _spinner_ok():
    for ch in [" ", " ", "✓", "✓", "✓"]:
        sys.stdout.write(f"\r  {_color('green', ch)} {_color('green', 'access granted')}")
        sys.stdout.flush()
        time.sleep(0.12)
    print()
    print()


def gate():
    next_duration = 1800
    lock = _load_lock()
    if lock:
        next_duration = lock.get("next", 1800)

    while True:
        lock = _load_lock()
        if lock and time.time() < lock.get("until", 0):
            _wait_countdown(lock["until"])
            next_duration = lock.get("next", next_duration)

        for attempt in range(1, 4):
            _clear()
            _rgb_border_pulse(8, 0.05, "HACKIT  •  ACCESS GATE")
            _clear()
            i = 0
            cf = lambda idx, t: _rgb(idx % len(RGB), t)
            _box_top(cf, i)
            _box_line(_color("bold", f"{'HACKIT  •  ACCESS GATE':^{_box_width() - 2}}"), cf, i)
            _box_sep(cf, i)
            _box_line(_color("dim", f"{'Enter 6-digit PIN to continue':^{_box_width() - 2}}"), cf, i)
            _box_line("", cf, i)
            _box_line(_color("dim", f"{'Attempt ' + str(attempt) + ' of 3':^{_box_width() - 2}}"), cf, i)
            _box_bot(cf, i)
            print()
            sys.stdout.flush()

            import getpass

            # animated RGB border while waiting for input
            stop_evt = threading.Event()
            H = 8
            bw = _box_width()
            lp = _left_pad()

            def _anim():
                frame = 0
                while not stop_evt.is_set():
                    sys.stdout.write("\033[s")
                    sys.stdout.write(f"\033[{H}A")
                    sys.stdout.write("\r" + " " * lp + _rgb(frame % len(RGB), "╔" + "═" * bw + "╗"))
                    sys.stdout.write(f"\033[{H - 1}B")
                    sys.stdout.write("\r" + " " * lp + _rgb((frame + 3) % len(RGB), "╚" + "═" * bw + "╝"))
                    sys.stdout.write("\033[u")
                    sys.stdout.flush()
                    frame += 1
                    time.sleep(0.12)

            t = threading.Thread(target=_anim, daemon=True)
            t.start()

            try:
                sys.stdout.flush()
                entered = getpass.getpass(_color("cyan", "  PIN > ")).strip()
            except (EOFError, KeyboardInterrupt):
                stop_evt.set()
                t.join(timeout=0.5)
                print()
                sys.exit(1)
            stop_evt.set()
            t.join(timeout=0.5)

            if _check(entered):
                _clear()
                i = 0
                cf = lambda idx, t: _rgb(idx % len(RGB), t)
                _box_top(cf, i)
                _box_line(_color("bold", f"{'HACKIT  •  ACCESS GATE':^{_box_width() - 2}}"), cf, i)
                _box_sep(cf, i)
                _box_line(_color("green", f"{'access granted':^{_box_width() - 2}}"), cf, i)
                _box_bot(cf, i)
                print()
                _spinner_ok()
                try:
                    os.remove(_LOCKFILE)
                except Exception:
                    pass
                time.sleep(0.3)
                _clear()
                return True

            _shake_fail()
            time.sleep(0.4)

        until = time.time() + next_duration
        _save_lock(until, next_duration + 300)
        _clear()
        i = 0
        cf = lambda idx, t: _rgb(idx % len(RGB), t)
        _box_top(cf, i)
        _box_line(_color("bold", f"{'ACCESS BLOCKED':^{_box_width() - 2}}"), cf, i)
        _box_sep(cf, i)
        mins = next_duration // 60
        _box_line(_color("dim", f"{'Blocked for ' + str(mins) + ' minutes after 3 failed attempts.':^{_box_width() - 2}}"), cf, i)
        _box_line(_color("dim", f"{'Next lockout will be longer.':^{_box_width() - 2}}"), cf, i)
        _box_bot(cf, i)
        print()
        sys.stdout.flush()
        next_duration += 300
        _wait_countdown(until)


if __name__ == "__main__":
    gate()
