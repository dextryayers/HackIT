"""
HackIT SQLi — V2.1 CYBER
Premium · Animated · Glass-morphism · Real-time streaming
"""

import os, sys, json, re, time, threading, subprocess, math, random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from pathlib import Path
from datetime import datetime

SQ_DIR = Path(__file__).parent
GO_BINARY = SQ_DIR / "go" / "bin" / "worker"
GO_DIR = SQ_DIR / "go"
TS = lambda: datetime.now().strftime("%H:%M:%S")

# ── Premium Cyberpunk Palette ──
BG_DEPTH    = "#050810"
BG_DARK     = "#0a1020"
BG_MID      = "#0f1a2a"
BG_CARD     = "#111d30"
BG_CARD2    = "#162238"
BG_INSET    = "#0c1520"
GREEN       = "#00ff88"
GREEN_DIM   = "#006644"
RED         = "#ff2244"
RED_DIM     = "#661122"
YELLOW      = "#ffbb33"
YELLOW_DIM  = "#664400"
CYAN        = "#00ddff"
CYAN_DIM    = "#005566"
BLUE        = "#3388ff"
BLUE_DIM    = "#003366"
ORANGE      = "#ff6633"
PURPLE      = "#aa44ff"
WHITE       = "#d0d8e0"
DIM         = "#405060"
DIM2        = "#203040"
BORDER      = "#1a2a3a"
GLOW_GREEN  = "#00ff8844"
GLOW_CYAN   = "#00ddff33"
GLOW_RED    = "#ff224433"

FONT = "Monospace" if sys.platform == "linux" else "Consolas"


def _shift(col, amt):
    r = max(0, min(255, int(col[1:3], 16) + amt))
    g = max(0, min(255, int(col[3:5], 16) + amt))
    b = max(0, min(255, int(col[5:7], 16) + amt))
    return f"#{r:02x}{g:02x}{b:02x}"


def _alpha(col, a):
    """Apply alpha to hex color by blending with black"""
    r = int(col[1:3], 16) * a + 0 * (1 - a)
    g = int(col[3:5], 16) * a + 0 * (1 - a)
    b = int(col[5:7], 16) * a + 0 * (1 - a)
    return f"#{int(r):02x}{int(g):02x}{int(b):02x}"


def _rgba(col, alpha):
    """Convert hex to rgba string"""
    r, g, b = int(col[1:3], 16), int(col[3:5], 16), int(col[5:7], 16)
    return f"#{r:02x}{g:02x}{b:02x}"


# ═══════════════════════════════════════════════════════════
#  ANIMATION: MATRIX RAIN
# ═══════════════════════════════════════════════════════════

class MatrixRain(tk.Canvas):
    def __init__(self, parent, **kw):
        super().__init__(parent, bd=0, highlightthickness=0, **kw)
        self._chars = "0123456789ABCDEF"
        self._drops = []
        self._running = False
        self._timer = None

    def start(self):
        w = self.winfo_width() or 1440
        self._drops = [{"x": random.randint(0, w), "y": random.randint(-200, 0),
                        "speed": random.uniform(0.5, 2.0), "len": random.randint(5, 20)}
                       for _ in range(60)]
        self._running = True
        self._tick()

    def stop(self):
        self._running = False
        if self._timer:
            self.after_cancel(self._timer)
            self._timer = None
        self.delete("all")

    def _tick(self):
        if not self._running:
            return
        try:
            self.delete("all")
            w = self.winfo_width()
            h = self.winfo_height()
        except (tk.TclError, Exception):
            self._running = False
            return
        if w < 10: w = 1440
        if h < 10: h = 860
        for d in self._drops:
            d["y"] += d["speed"]
            if d["y"] > h + 20:
                d["y"] = -random.randint(10, 100)
                d["x"] = random.randint(0, w)
                d["speed"] = random.uniform(0.5, 2.0)
                d["len"] = random.randint(5, 20)
            for i in range(d["len"]):
                if d["y"] - i < 0 or d["y"] - i > h:
                    continue
                ch = random.choice(self._chars)
                alpha = 1.0 - (i / d["len"]) ** 0.5
                color = f"#00{int(0xaa * alpha):02x}{int(0x44 * alpha):02x}"
                self.create_text(d["x"], d["y"] - i * 14, text=ch, fill=color,
                                 font=(FONT, 8))
        self._timer = self.after(60, self._tick)


# ═══════════════════════════════════════════════════════════
#  ANIMATION: PULSING GLOW
# ═══════════════════════════════════════════════════════════

class GlowRing(tk.Canvas):
    def __init__(self, parent, size=40, color=CYAN, **kw):
        super().__init__(parent, bd=0, highlightthickness=0,
                         width=size, height=size, **kw)
        self._size = size
        self._color = color
        self._phase = 0
        self._running = False
        self._timer = None

    def start(self):
        self._running = True
        self._tick()

    def stop(self):
        self._running = False
        if self._timer:
            self.after_cancel(self._timer)
            self._timer = None
        self.delete("all")

    def pulse(self, color=None):
        if color:
            self._color = color
        self._running = True
        self._tick()

    def _tick(self):
        if not self._running:
            return
        try:
            self.delete("all")
        except tk.TclError:
            self._running = False
            return
        s = self._size // 2
        self._phase = (self._phase + 0.05) % (2 * math.pi)
        # Outer glow
        for i in range(8):
            frac = i / 8
            r = 3 + frac * 8 + math.sin(self._phase * 2 + frac * 4) * 2
            alpha = 0.3 - frac * 0.3
            col = _alpha(self._color, max(0, alpha))
            self.create_oval(s - r, s - r, s + r, s + r,
                             outline=col, width=1)
        # Inner dot
        pulse = 0.7 + math.sin(self._phase * 3) * 0.3
        col = _alpha(self._color, pulse)
        self.create_oval(s - 3, s - 3, s + 3, s + 3,
                         fill=col, outline=col)
        self._timer = self.after(50, self._tick)


# ═══════════════════════════════════════════════════════════
#  ANIMATED SPINNER
# ═══════════════════════════════════════════════════════════

class NeonSpinner(tk.Canvas):
    CHARS = ["◜", "◝", "◞", "◟"]
    COLORS = [GREEN, CYAN, YELLOW, ORANGE]

    def __init__(self, parent, size=22, **kw):
        super().__init__(parent, bd=0, highlightthickness=0,
                         width=size, height=size, **kw)
        self._size = size
        self._idx = 0
        self._running = False
        self._timer = None

    def start(self):
        self._running = True
        self._tick()

    def stop(self):
        self._running = False
        if self._timer:
            self.after_cancel(self._timer)
            self._timer = None
        self.delete("all")

    def _tick(self):
        if not self._running:
            return
        try:
            self.delete("all")
        except tk.TclError:
            self._running = False
            return
        s = self._size
        c = self.COLORS[self._idx % len(self.COLORS)]
        ch = self.CHARS[self._idx % len(self.CHARS)]
        # Glow
        for i in range(3, 0, -1):
            self.create_text(s//2, s//2, text=ch, fill=_alpha(c, 0.15/i),
                             font=(FONT, s//2 + i*2, "bold"))
        self.create_text(s//2, s//2, text=ch, fill=c,
                         font=(FONT, s//2, "bold"))
        self._idx += 1
        self._timer = self.after(100, self._tick)


# ═══════════════════════════════════════════════════════════
#  SCAN PROGRESS BAR
# ═══════════════════════════════════════════════════════════

class ScanBar(tk.Canvas):
    def __init__(self, parent, height=4, **kw):
        super().__init__(parent, bd=0, highlightthickness=0,
                         height=height, **kw)
        self._height = height
        self._progress = 0.0
        self._running = False
        self._timer = None

    def start(self):
        self._progress = 0.0
        self._running = True
        self._tick()

    def stop(self):
        self._running = False
        if self._timer:
            self.after_cancel(self._timer)
            self._timer = None
        self.delete("all")

    def _tick(self):
        if not self._running:
            return
        try:
            self.delete("all")
        except tk.TclError:
            self._running = False
            return
        w = self.winfo_width()
        if w < 10: return
        h = self._height
        self._progress = min(1.0, self._progress + random.uniform(0.003, 0.02))
        # Indeterminate shimmer
        phase = time.time() * 2
        for x in range(0, int(w), 2):
            dist = abs(x / w - self._progress)
            alpha = max(0, 1 - dist * 4)
            # Wave pattern
            wave = math.sin((x / w) * 20 + phase) * 0.3 + 0.7
            a = alpha * wave
            if a > 0.05:
                r = 0
                g = max(0, int(0xdd * a * (0.5 + 0.5 * math.sin(phase + x/50))))
                b = max(0, int(0xff * a * (0.3 + 0.7 * math.sin(phase * 0.7 + x/30))))
                self.create_line(x, 0, x, h, fill=f"#{r:02x}{g:02x}{b:02x}")
        self._timer = self.after(50, self._tick)


# ═══════════════════════════════════════════════════════════
#  STREAMING GO ENGINE (unchanged logic)
# ═══════════════════════════════════════════════════════════

class GoEngine:
    FLAG_MAP = {
        'database':     '--db', 'columns': '--column', 'dump_table': '--dump-table',
        'list_dbs':     '--list-dbs', 'list_tables': '--list-tables',
        'list_columns': '--list-columns', 'dump_all': '--dump-all',
        'risk_level':   '--risk-level', 'follow_redirect': '--follow-redirect',
        'randomize_case': '--randomize-case', 'bypass_waf': '--bypass-waf',
        'os_detect':    '--os-detect', 'waf_detect': '--waf-detect',
        'smart_diff':   '--smart-diff', 'tech_detect': '--tech-detect',
        'banner_grab':  '--banner-grab', 'priv_esc': '--priv-esc',
        'os_access':    '--os-access', 'exfil_dns': '--exfil-dns',
        'exfil_http':   '--exfil-http', 'no_color': '--no-color',
        'output_format':'--output-format', 'crawl_depth': '--crawl-depth',
        'crawl_threads':'--crawl-threads', 'crawl_extract': '--crawl-extract',
        'crawl_sensitive':'--crawl-sensitive', 'crawl_procs': '--crawl-procs',
        'crawl_views':  '--crawl-views', 'crawl_indexes': '--crawl-indexes',
        'crawl_system': '--crawl-system', 'crawl_output': '--crawl-output',
        'crawl_report': '--crawl-report', 'count_rows': '--count-rows',
        'extract_technique':'--extract-technique', 'extract_charset':'--extract-charset',
        'extract_workers':'--extract-workers', 'extract_batch':'--extract-batch',
        'network_scan': '--network-scan', 'scan_target': '--scan-target',
        'scan_ports':   '--scan-ports', 'auth_bypass': '--auth-bypass',
        'auth_user':    '--auth-user', 'auth_pass': '--auth-pass',
        'file_read':    '--file-read', 'file_write': '--file-write',
        'file_exec':    '--file-exec', 'oob_channel': '--oob-channel',
        'oob_domain':   '--oob-domain',
    }
    BOOL_FLAGS = frozenset({
        'follow_redirect', 'randomize_case', 'bypass_waf', 'fingerprint',
        'banner_grab', 'os_detect', 'waf_detect', 'smart_diff', 'baseline',
        'tech_detect', 'list_dbs', 'list_tables', 'list_columns', 'schema',
        'count_rows', 'dump_all', 'priv_esc', 'os_access', 'exfil_dns',
        'exfil_http', 'no_color', 'crawl_extract', 'crawl_sensitive',
        'crawl_procs', 'crawl_views', 'crawl_indexes', 'crawl_system',
        'network_scan', 'auth_bypass', 'stealth',
    })
    STRING_FLAGS = frozenset({
        'data', 'cookie', 'header', 'agent', 'referer', 'method',
        'proxy', 'mode', 'tamper', 'encode', 'database', 'table',
        'column', 'search', 'dump_table', 'crawl_mode', 'crawl_output',
        'crawl_report', 'extract_technique', 'extract_charset',
        'scan_target', 'scan_ports', 'auth_user', 'auth_pass',
        'file_read', 'file_write', 'file_exec', 'oob_channel', 'oob_domain',
        'output_format',
    })
    INT_FLAGS = frozenset({
        'timeout', 'risk_level', 'depth', 'threads', 'delay',
        'verbose', 'retry', 'crawl_depth', 'crawl_threads',
        'extract_workers', 'extract_batch',
    })

    def __init__(self):
        self.binary = GO_BINARY
        self._proc = None

    @property
    def available(self):
        return self.binary.exists()

    def ensure_compiled(self):
        if self.binary.exists():
            return True
        try:
            subprocess.run(["go", "build", "-o", str(self.binary), "."],
                           cwd=str(GO_DIR), capture_output=True, timeout=120)
            return self.binary.exists()
        except Exception:
            return False

    def _build_args(self, url, verbose_lvl=2, **kwargs):
        args = [str(self.binary), "-u", url]
        if verbose_lvl:
            args.extend(["--verbose", str(verbose_lvl)])
        for k, v in kwargs.items():
            if v is None or v is False:
                continue
            flag = self.FLAG_MAP.get(k, f"--{k.replace('_', '-')}")
            if k in self.BOOL_FLAGS:
                if v: args.append(flag)
            elif k in self.INT_FLAGS:
                args.extend([flag, str(int(v))])
            elif k in self.STRING_FLAGS:
                val = str(v)
                if val: args.extend([flag, val])
            elif isinstance(v, bool):
                if v: args.append(flag)
            elif isinstance(v, int):
                args.extend([flag, str(v)])
            elif isinstance(v, str):
                if v: args.extend([flag, v])
            elif isinstance(v, (tuple, list)):
                for item in v:
                    s = str(item)
                    if s: args.extend([flag, s])
        return args

    def run(self, url, timeout=300, **kwargs):
        args = self._build_args(url, verbose_lvl=0, **kwargs)
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0 and not r.stdout.strip():
                err = r.stderr.strip()[:300] if r.stderr.strip() else f"exit code {r.returncode}"
                return [{"error": err}]
            return self._parse_stdout(r.stdout)
        except subprocess.TimeoutExpired:
            return [{"error": "Go engine timed out"}]
        except Exception as e:
            return [{"error": str(e)}]

    def run_stream(self, url, on_verbose=None, stop_event=None, **kwargs):
        args = self._build_args(url, verbose_lvl=2, **kwargs)
        try:
            self._proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
            proc = self._proc

            def read_stderr():
                try:
                    for line in iter(proc.stderr.readline, ''):
                        if not line: break
                        line = line.rstrip('\n\r')
                        if on_verbose: on_verbose(line)
                except ValueError: pass

            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            stdout_data = []
            while True:
                if stop_event and stop_event.is_set():
                    proc.kill(); break
                line = proc.stdout.readline()
                if not line: break
                stdout_data.append(line.rstrip('\n\r'))

            proc.wait(timeout=10)
            stderr_thread.join(timeout=5)
            return self._parse_stdout(''.join(stdout_data))
        except Exception:
            return None
        finally:
            self._proc = None

    def kill(self):
        if self._proc and self._proc.poll() is None:
            try: self._proc.kill()
            except Exception: pass
            self._proc = None

    def _parse_stdout(self, raw):
        if not raw or not raw.strip(): return None
        raw = raw.strip()
        try: return json.loads(raw)
        except json.JSONDecodeError: pass
        for line in reversed(raw.split('\n')):
            line = line.strip()
            if not line: continue
            try: return json.loads(line)
            except json.JSONDecodeError: continue
        try: return [json.loads(raw)]
        except (json.JSONDecodeError, TypeError): pass
        return None


# ═══════════════════════════════════════════════════════════
#  CUSTOM WIDGETS
# ═══════════════════════════════════════════════════════════

class HoverButton(tk.Canvas):
    def __init__(self, parent, text, command, width=100, height=34,
                 bg_color="#00aa55", hover_color=None, text_color=WHITE,
                 font_size=9, corner=6, **kw):
        super().__init__(parent, bd=0, highlightthickness=0,
                         width=width, height=height, **kw)
        self._text = text
        self._cmd = command
        self._w = width; self._h = height
        self._bg = bg_color; self._hover = hover_color or _shift(bg_color, 20)
        self._fg = text_color; self._fs = font_size; self._cr = corner
        self._disabled = False
        self._norm_bg = bg_color
        self._dis_bg = "#15202a"
        self._dis_fg = "#304050"
        self._hovering = False
        self._pulse = 0

        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", lambda e: self._enter())
        self.bind("<Leave>", lambda e: self._leave())
        self._draw(self._bg)

    def _draw(self, bg):
        self.delete("all")
        cr = self._cr
        w, h = self._w, self._h
        self.create_rounded_rect(1, 1, w-1, h-1, cr, fill=bg, outline="")
        # Subtle top highlight
        self.create_rounded_rect(1, 1, w-1, h//2+2, cr, fill=_alpha("#ffffff", 0.06), outline="")
        if self._disabled:
            c = self._dis_fg
        else:
            c = self._fg
        self.create_text(w//2, h//2, text=self._text, fill=c,
                         font=(FONT, self._fs, "bold"))

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kw):
        pts = [x1+r, y1, x2-r, y1, x2, y1+r, x2, y2-r,
               x2-r, y2, x1+r, y2, x1, y2-r, x1, y1+r]
        return self.create_polygon(pts, smooth=True, **kw)

    def _enter(self):
        if not self._disabled:
            self._draw(self._hover)

    def _leave(self):
        if not self._disabled:
            self._draw(self._norm_bg)

    def _on_click(self, e):
        if not self._disabled and self._cmd:
            # Click flash
            self._draw(_shift(self._norm_bg, -15))
            self.after(80, lambda: self._draw(self._norm_bg))
            self._cmd()

    def set_disabled(self, disabled):
        self._disabled = disabled
        if disabled:
            self._draw(self._dis_bg)
        else:
            self._draw(self._norm_bg)

    def set_text(self, text):
        self._text = text
        self._draw(self._norm_bg if not self._disabled else self._dis_bg)


class GlassFrame(tk.Frame):
    def __init__(self, parent, bg=BG_CARD, border=BORDER, **kw):
        super().__init__(parent, bg=bg, highlightbackground=border,
                         highlightthickness=1, **kw)

    def pack(self, **kw):
        super().pack(**kw)
        return self


class ScrollFrame(tk.Frame):
    def __init__(self, parent, bg=BG_CARD2, **kw):
        super().__init__(parent, bg=bg, **kw)
        self.canvas = tk.Canvas(self, bg=bg, bd=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical",
                                        command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.inner.bind("<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

    def clear(self):
        for w in self.inner.winfo_children():
            w.destroy()


# ═══════════════════════════════════════════════════════════
#  MAIN GUI — V2.1 CYBER
# ═══════════════════════════════════════════════════════════

class SQLiGUI:
    def __init__(self):
        try:
            self._init_gui()
        except Exception as e:
            print(f"[GUI INIT FATAL] {e}", file=sys.stderr)
            try: self.root.destroy()
            except: pass
            self._init_ok = False
        else:
            self._init_ok = True

    def _init_gui(self):
        self.root = tk.Tk()
        self.root.title("HackIT SQLi v2.1 — CYBER INJECTION CONSOLE")
        self.root.configure(bg=BG_DEPTH)
        # Responsive size: fit screen, default 1200x750
        try:
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            w = min(1400, max(900, sw - 80))
            h = min(820, max(600, sh - 80))
        except Exception:
            w, h = 1200, 750
        self.root.geometry(f"{w}x{h}")
        self.root.minsize(max(800, w//2), max(500, h//2))

        # ── State (must be set before signal handlers) ──
        self._window_open = True
        self._scanning = False

        # ── State ──
        self.scan_thread = None
        self.results = []; self.findings = []; self.enums = []
        self.databases = []; self.tables = []; self.columns = []
        self.selected_db = None; self.selected_table = None
        self.scan_url = ""
        self._scan_bar = None
        self._spinner = None
        self._glow = None
        self._header_glow = None
        self._scanning = False
        self._col_vars = {}
        self.tab_states = [True] + [False] * 6
        self._scan_start_time = 0
        self._payload_count = 0
        self._vuln_count = 0
        self._verbose_buffer = []
        self._last_verbose_update = 0

        try:
            self._setup_styles()
        except Exception as e:
            print(f"[GUI STEP styles] {e}", file=sys.stderr)
        try:
            self._build_ui()
        except Exception as e:
            print(f"[GUI STEP build_ui] {e}", file=sys.stderr)
        try:
            self._bind_keys()
        except Exception as e:
            print(f"[GUI STEP bind_keys] {e}", file=sys.stderr)

    def _safe_close(self):
        if not self._window_open:
            return
        self._window_open = False
        self._stop_scan()
        # Graceful tkinter destroy, then force exit
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            try: self.root.destroy()
            except Exception: pass
        # Force exit in case threads block
        os._exit(0)

    def _setup_styles(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TNotebook", background=BG_DEPTH, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG_MID, foreground=DIM,
                    padding=[22, 8], font=(FONT, 9), borderwidth=0)
        s.map("TNotebook.Tab", background=[("selected", BG_CARD)],
              foreground=[("selected", CYAN)])
        s.configure("Treeview", background=BG_INSET, foreground=WHITE,
                    fieldbackground=BG_INSET, font=(FONT, 9),
                    borderwidth=0, rowheight=30)
        s.configure("Treeview.Heading", background=BG_MID, foreground=CYAN,
                    font=(FONT, 9, "bold"), borderwidth=0)
        s.map("Treeview.Heading", background=[("active", BG_CARD)])
        s.map("Treeview", background=[("selected", "#0a2a3a")])
        try:
            s.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
        except tk.TclError:
            pass
        try:
            s.configure("Vertical.TScrollbar", background=BG_MID, troughcolor=BG_DEPTH,
                        bordercolor=BG_DEPTH, arrowcolor=CYAN)
        except tk.TclError:
            pass

    # ═══════════════ UI BUILD ═══════════════

    def _build_ui(self):
        for step in ['header', 'sub_bar', 'url_bar', 'notebook', 'status_bar']:
            try:
                getattr(self, f'_build_{step}')(self.root)
            except Exception as e:
                print(f"[GUI BUILD {step}] {e}", file=sys.stderr)

    # ── HEADER ──

    def _build_header(self, parent):
        hdr = tk.Frame(parent, bg=BG_MID, height=64)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Glow border (Canvas for animated pulse)
        self._header_glow = tk.Canvas(hdr, bg=BG_MID, height=2,
                                       bd=0, highlightthickness=0)
        self._header_glow.pack(fill="x", side="bottom")

        # Left side: brand
        lt = tk.Frame(hdr, bg=BG_MID)
        lt.pack(side="left", padx=(16, 4), pady=10)

        # Neon logo mark
        logo_c = tk.Canvas(lt, width=36, height=36, bg=BG_MID, bd=0,
                            highlightthickness=0)
        logo_c.pack(side="left")
        logo_c.create_oval(6, 6, 30, 30, outline=CYAN, width=2, fill=BG_DEPTH)
        logo_c.create_text(18, 18, text="H", fill=CYAN, font=(FONT, 16, "bold"))

        tk.Label(lt, text="HACKIT", font=(FONT, 20, "bold"),
                 fg=WHITE, bg=BG_MID).pack(side="left", padx=(8, 0))
        tk.Label(lt, text="SQLi", font=(FONT, 20, "bold"),
                 fg=CYAN, bg=BG_MID).pack(side="left")
        ver = tk.Frame(lt, bg=BG_DEPTH, bd=0,
                        highlightbackground=CYAN, highlightthickness=1)
        ver.pack(side="left", padx=(6, 0))
        tk.Label(ver, text=" v2.1 ", font=(FONT, 7, "bold"),
                 fg=CYAN, bg=BG_DEPTH).pack()

        # Center: tagline
        tk.Label(lt, text="/// CYBER INJECTION CONSOLE",
                 font=(FONT, 8), fg=DIM, bg=BG_MID
                 ).pack(side="left", padx=(12, 0), pady=(14, 0))

        # Right side: status
        rt = tk.Frame(hdr, bg=BG_MID)
        rt.pack(side="right", padx=16, pady=8)

        # Animated glow ring
        self._glow = GlowRing(rt, size=36, color=GREEN, bg=BG_MID)
        self._glow.pack(side="left", padx=(0, 8))

        self.status_label = tk.Label(rt, text="●  READY",
                                     font=(FONT, 11, "bold"), fg=GREEN, bg=BG_MID)
        self.status_label.pack(side="left")

        # Badge
        badge = tk.Frame(rt, bg="#051210", bd=0,
                          highlightbackground=GREEN, highlightthickness=1)
        badge.pack(side="left", padx=(14, 0))
        tk.Label(badge, text=" ⚡ 2270p · 20e · LIVE ",
                 font=(FONT, 7), fg=GREEN, bg="#051210").pack(padx=8, pady=3)

        tk.Frame(parent, height=1, bg=BORDER).pack(fill="x")

    # ── SUB BAR (stats) ──

    def _build_sub_bar(self, parent):
        bar = tk.Frame(parent, bg=BG_DEPTH, height=28)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self._stat_elapsed = tk.Label(bar, text="⏱  00:00", font=(FONT, 8),
                                       fg=DIM, bg=BG_DEPTH)
        self._stat_elapsed.pack(side="left", padx=(14, 8))

        self._stat_payloads = tk.Label(bar, text="■  0 payloads", font=(FONT, 8),
                                        fg=DIM, bg=BG_DEPTH)
        self._stat_payloads.pack(side="left", padx=8)

        self._stat_vulns = tk.Label(bar, text="⚠  0 vulns", font=(FONT, 8),
                                     fg=DIM, bg=BG_DEPTH)
        self._stat_vulns.pack(side="left", padx=8)

        # Spinner
        self._spinner = NeonSpinner(bar, size=16, bg=BG_DEPTH)
        self._spinner.pack(side="left", padx=(4, 0))

        # Scan bar
        self._scan_bar = ScanBar(bar, height=4, bg=BG_DEPTH)
        self._scan_bar.pack(side="left", fill="x", expand=True, padx=12)

        self._stat_status = tk.Label(bar, text="", font=(FONT, 8),
                                      fg=CYAN, bg=BG_DEPTH)
        self._stat_status.pack(side="right", padx=14)

        tk.Frame(parent, height=1, bg=BORDER).pack(fill="x")

    # ── URL BAR ──

    def _build_url_bar(self, parent):
        bar = tk.Frame(parent, bg=BG_MID, height=52,
                        highlightbackground=BORDER, highlightthickness=1)
        bar.pack(fill="x", padx=10, pady=(6, 2))
        bar.pack_propagate(False)

        tk.Label(bar, text="*", font=(FONT, 14), fg=CYAN, bg=BG_MID
                 ).pack(side="left", padx=(14, 2))
        tk.Label(bar, text="TARGET", font=(FONT, 7, "bold"), fg=CYAN, bg=BG_MID
                 ).pack(side="left", padx=(0, 8))

        self.url_entry = tk.Entry(bar, font=(FONT, 12), fg=WHITE,
                                   bg=BG_INSET, bd=0, insertbackground=CYAN,
                                   relief="flat",
                                   highlightbackground="#1a3040", highlightthickness=0)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=4, ipady=6, ipadx=8)
        self.url_entry.insert(0, "https://example.com/index.php?id=1")

        btn_frame = tk.Frame(bar, bg=BG_MID)
        btn_frame.pack(side="left", padx=4)

        self.run_btn = tk.Button(btn_frame, text="SCAN", font=(FONT, 8, "bold"),
                                 bg="#008844", fg=WHITE, bd=0, padx=14, pady=6,
                                 cursor="hand2", activebackground="#00aa55",
                                 command=self._run_scan)
        self.run_btn.pack(side="left", padx=2)

        self.stop_btn = tk.Button(btn_frame, text="STOP", font=(FONT, 8, "bold"),
                                  bg="#882222", fg=WHITE, bd=0, padx=14, pady=6,
                                  cursor="hand2", activebackground="#aa3333",
                                  command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=2)

    # ── NOTEBOOK ──

    def _build_notebook(self, parent):
        nf = tk.Frame(parent, bg=BG_DEPTH)
        nf.pack(fill="both", expand=True, padx=10, pady=(4, 0))
        self.nb = ttk.Notebook(nf)
        self.nb.pack(fill="both", expand=True)
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

        self._scan_tab()
        self._databases_tab()
        self._tables_tab()
        self._columns_tab()
        self._dump_tab()
        self._sensitive_tab()
        self._schema_tab()
        self._update_tab_states()

    def _tab_frame(self, title_icon, title_text):
        f = tk.Frame(self.nb, bg=BG_DEPTH)
        return f

    def _make_text_widget(self, parent, **kw):
        t = scrolledtext.ScrolledText(
            parent, bg=BG_INSET, fg=WHITE, font=(FONT, 9),
            insertbackground=CYAN, bd=0, padx=16, pady=12,
            state="normal", wrap="word",
            highlightbackground=BORDER, highlightthickness=0, **kw)
        for tag, col in [("green", GREEN), ("red", RED), ("yellow", YELLOW),
                          ("cyan", CYAN), ("dim", DIM), ("orange", ORANGE),
                          ("purple", PURPLE), ("blue", BLUE), ("verbose", GREEN_DIM)]:
            t.tag_configure(tag, foreground=col)
        t.tag_configure("bold", font=(FONT, 10, "bold"))
        return t

    def _make_tree(self, parent, columns, widths, anchors=None):
        tr = ttk.Treeview(parent, columns=columns, show="headings",
                           selectmode="browse")
        for i, c in enumerate(columns):
            tr.heading(c, text=c)
            w = widths[i] if i < len(widths) else 100
            a = anchors[i] if anchors and i < len(anchors) else "w"
            tr.column(c, width=w, anchor=a)
        sc = ttk.Scrollbar(parent, orient="vertical", command=tr.yview)
        tr.configure(yscrollcommand=sc.set)
        tr.pack(side="left", fill="both", expand=True)
        sc.pack(side="right", fill="y")
        return tr

    def _tree_bar(self, parent, label, *buttons):
        c = tk.Frame(parent, bg=BG_CARD, height=38,
                      highlightbackground=BORDER, highlightthickness=1)
        c.pack(fill="x")
        c.pack_propagate(False)
        bg = BG_CARD
        for item in label:
            if isinstance(item, tuple):
                tk.Label(c, text=item[0], font=item[1], fg=item[2], bg=bg
                         ).pack(side="left", padx=item[3] if len(item) > 3 else (0, 0))
            else:
                tk.Label(c, text=item, font=(FONT, 8), fg=DIM, bg=bg
                         ).pack(side="left", padx=6)
        for txt, fg, cmd in buttons:
            btn = tk.Button(c, text=txt, font=(FONT, 8), bg="#0a1a28", fg=fg,
                            bd=0, padx=10, pady=2, cursor="hand2",
                            activebackground="#122a3a",
                            command=cmd)
            btn.pack(side="left", padx=3)
        status = tk.Label(c, text="", font=(FONT, 8), fg=YELLOW, bg=bg)
        status.pack(side="right", padx=12)
        return c, status

    # ── SCAN TAB ──

    def _scan_tab(self):
        f = self._tab_frame("🔍", "LIVE SCAN")
        self.nb.add(f, text=" 🔍  LIVE SCAN   ")
        self.scan_output = self._make_text_widget(f)
        self.scan_output.pack(fill="both", expand=True)
        self._print_banner()

    def _print_banner(self):
        lines = [
            ("╔══════════════════════════════════════════════════╗\n", "dim"),
            ("║           H A C K I T   S Q L i   v 2 . 1       ║\n", "cyan"),
            ("║      2270 Payloads  ·  20 Engines  ·  LIVE      ║\n", "green"),
            ("║       CYBER INJECTION CONSOLE — Premium Edition  ║\n", "purple"),
            ("╚══════════════════════════════════════════════════╝\n\n", "dim"),
            (f"  ⚡ [{TS()}] Engine initialized — verbose streaming ACTIVE\n", "green"),
            (f"  ⌨  [{TS()}] Ctrl+R Scan · Ctrl+S/Esc Stop · Ctrl+Q Quit · Terminal Ctrl+C Exit\n\n", "dim"),
        ]
        for line, tag in lines:
            self.scan_output.insert("end", line, tag)

    # ── DATABASES TAB ──

    def _databases_tab(self):
        f = self._tab_frame("🗄️", "DATABASES")
        self.nb.add(f, text=" 🗄️  DATABASES   ")
        h, self.db_progress = self._tree_bar(f,
            [("DATABASES", (FONT, 9, "bold"), CYAN, 12)],
            ("🔄 Refresh", WHITE, lambda: self._load_dbs()),
            ("📋 List All", CYAN, self._list_all_dbs),
            ("🔎 Explore All", GREEN, self._explore_all_dbs))
        self.db_count_label = tk.Label(h, text="", font=(FONT, 8), fg=DIM, bg=BG_CARD)
        self.db_count_label.pack(side="left", padx=6)
        b = tk.Frame(f, bg=BG_DEPTH)
        b.pack(fill="both", expand=True)
        self.db_tree = self._make_tree(b,
            ("#", "Database", "Tables", "Status"),
            [40, 300, 80, 150],
            ["center", "w", "center", "center"])
        self.db_tree.bind("<Double-Button-1>", self._on_db_select)
        self.db_info = tk.Label(f, text="  🔒 — Scan a target first",
                                font=(FONT, 8), fg="#304050", bg=BG_DEPTH, anchor="w")
        self.db_info.pack(fill="x", padx=14, pady=4)

    # ── TABLES TAB ──

    def _tables_tab(self):
        f = self._tab_frame("📋", "TABLES")
        self.nb.add(f, text=" 📋  TABLES   ")
        h, self.tbl_loading = self._tree_bar(f,
            [("DB:", (FONT, 8, "bold"), DIM, (10, 2))],
            ("🔄 Refresh", WHITE, self._load_tables),
            ("📋 List All", CYAN, self._list_all_tables),
            ("🔍 Find Interesting", GREEN, self._find_interesting_tables))
        self.tbl_db_label = tk.Label(h, text="—", font=(FONT, 11, "bold"),
                                      fg=CYAN, bg=BG_CARD)
        self.tbl_db_label.pack(side="left")
        b = tk.Frame(f, bg=BG_DEPTH)
        b.pack(fill="both", expand=True)
        self.tbl_tree = self._make_tree(b,
            ("#", "Table", "Columns", "Interesting"),
            [40, 300, 80, 120],
            ["center", "w", "center", "center"])
        self.tbl_tree.bind("<Double-Button-1>", self._on_tbl_select)
        self.tbl_info = tk.Label(f, text="  🔒 — Select a database first",
                                 font=(FONT, 8), fg="#304050", bg=BG_DEPTH, anchor="w")
        self.tbl_info.pack(fill="x", padx=14, pady=4)

    # ── COLUMNS TAB ──

    def _columns_tab(self):
        f = self._tab_frame("📊", "COLUMNS")
        self.nb.add(f, text=" 📊  COLUMNS   ")
        h, self.col_loading = self._tree_bar(f,
            [("Table:", (FONT, 8, "bold"), DIM, (10, 2)),
             ("DB:", (FONT, 8, "bold"), DIM, (10, 0))],
            ("🔄 Refresh", WHITE, self._load_columns),
            ("🔍 Find Sensitive", ORANGE, self._find_sensitive_cols),
            ("▶ Dump Now", GREEN, lambda: (self.nb.select(4), self._load_dump())))
        self.col_tbl_val = tk.Label(h, text="—", font=(FONT, 11, "bold"),
                                     fg=CYAN, bg=BG_CARD)
        self.col_tbl_val.pack(side="left", padx=(0, 2))
        tk.Label(h, text="|  DB:", font=(FONT, 8, "bold"), fg=DIM, bg=BG_CARD
                 ).pack(side="left", padx=(4, 2))
        self.col_db_val = tk.Label(h, text="—", font=(FONT, 9), fg=DIM, bg=BG_CARD)
        self.col_db_val.pack(side="left")
        b = tk.Frame(f, bg=BG_DEPTH)
        b.pack(fill="both", expand=True)
        cols = ("#", "Column", "Type", "Nullable", "PK", "Default", "Sensitive")
        self.col_tree = self._make_tree(b, cols,
            [40, 170, 130, 70, 45, 130, 80],
            ["center", "w", "w", "center", "center", "w", "center"])
        self.col_tree.bind("<Double-Button-1>", self._on_col_select)
        self.col_info = tk.Label(f, text="  🔒 — Select a table first",
                                 font=(FONT, 8), fg="#304050", bg=BG_DEPTH, anchor="w")
        self.col_info.pack(fill="x", padx=14, pady=4)

    # ── DUMP TAB ──

    def _dump_tab(self):
        f = self._tab_frame("💾", "DUMP")
        self.nb.add(f, text=" 💾  DUMP   ")
        h, _ = self._tree_bar(f,
            [("Table:", (FONT, 8, "bold"), DIM, (10, 2)),
             ("DB:", (FONT, 8, "bold"), DIM, (10, 0))])
        self.dump_tbl_label = tk.Label(h, text="—", font=(FONT, 11, "bold"),
                                        fg=CYAN, bg=BG_CARD)
        self.dump_tbl_label.pack(side="left", padx=(0, 2))
        tk.Label(h, text="|  DB:", font=(FONT, 8, "bold"), fg=DIM, bg=BG_CARD
                 ).pack(side="left", padx=(4, 2))
        self.dump_db_label = tk.Label(h, text="—", font=(FONT, 9), fg=DIM, bg=BG_CARD)
        self.dump_db_label.pack(side="left")

        paned = tk.PanedWindow(f, bg=BG_DEPTH, sashwidth=2,
                                sashrelief="flat", orient="vertical")
        paned.pack(fill="both", expand=True)

        # Column selector
        col_sel = tk.Frame(paned, bg=BG_CARD2,
                            highlightbackground=BORDER, highlightthickness=1)
        paned.add(col_sel, height=110)
        sel_hdr = tk.Frame(col_sel, bg=BG_CARD2)
        sel_hdr.pack(fill="x", padx=8, pady=(4, 0))
        tk.Label(sel_hdr, text="COLUMNS TO DUMP", font=(FONT, 8, "bold"),
                 fg=CYAN, bg=BG_CARD2).pack(side="left")
        self._toggle_all_var = tk.BooleanVar(value=True)
        tk.Checkbutton(sel_hdr, text="Select All", variable=self._toggle_all_var,
                       font=(FONT, 8), fg=DIM, bg=BG_CARD2, selectcolor=BG_DEPTH,
                       command=self._toggle_all_cols).pack(side="left", padx=10)
        self.dump_loading = tk.Label(sel_hdr, text="", font=(FONT, 8), fg=YELLOW, bg=BG_CARD2)
        self.dump_loading.pack(side="right", padx=8)

        self._col_scroll = ScrollFrame(col_sel, bg=BG_CARD2)
        self._col_scroll.pack(fill="both", expand=True, padx=8, pady=4)

        # Dump output
        dump_frame = tk.Frame(paned, bg=BG_DEPTH)
        paned.add(dump_frame)
        tb_frame = tk.Frame(dump_frame, bg=BG_CARD, height=34)
        tb_frame.pack(fill="x")
        tb_frame.pack_propagate(False)

        for txt, bg, fg, cmd in [
            ("  🚀 DUMP  ", "#008844", WHITE, self._load_dump),
            ("📋 Copy", "#0a1a28", WHITE, self._copy_dump),
            ("🧹 Clear", "#0a1a28", DIM, lambda: self.dump_output.delete(1.0, "end")),
            ("💾 JSON", "#0a1a28", CYAN, self._save_dump),
            ("📄 CSV", "#0a1a28", YELLOW, self._save_dump_csv),
        ]:
            b = tk.Button(tb_frame, text=txt, font=(FONT, 8, "bold") if "DUMP" in txt else (FONT, 8),
                          bg=bg, fg=fg, bd=0, padx=12, pady=2, cursor="hand2",
                          activebackground=_shift(bg, 15), command=cmd)
            b.pack(side="left", padx=4, pady=2)

        self.dump_output = scrolledtext.ScrolledText(
            dump_frame, bg=BG_INSET, fg=WHITE, font=(FONT, 9),
            insertbackground=CYAN, bd=0, padx=12, pady=8,
            state="normal", wrap="none",
            highlightbackground=BORDER, highlightthickness=0)
        self.dump_output.pack(fill="both", expand=True)
        for t, c in [("green", GREEN), ("red", RED), ("dim", DIM), ("cyan", CYAN),
                      ("yellow", YELLOW), ("orange", ORANGE)]:
            self.dump_output.tag_configure(t, foreground=c)
        self.dump_output.tag_configure("bold", font=(FONT, 10, "bold"))
        self.dump_info = tk.Label(f, text="  🔒 — Select a table first",
                                  font=(FONT, 8), fg="#304050", bg=BG_DEPTH, anchor="w")
        self.dump_info.pack(fill="x", padx=14, pady=2)

    # ── SENSITIVE TAB ──

    def _sensitive_tab(self):
        f = self._tab_frame("🔑", "SENSITIVE")
        self.nb.add(f, text=" 🔑  SENSITIVE   ")
        h, self.sens_loading = self._tree_bar(f,
            [("SENSITIVE DATA SCANNER", (FONT, 9, "bold"), CYAN, 12)])
        b = tk.Frame(f, bg=BG_DEPTH)
        b.pack(fill="both", expand=True)
        cols = ("Risk", "DB", "Table", "Column", "Category", "Sample", "Confidence")
        self.sens_tree = self._make_tree(b, cols,
            [80, 130, 130, 130, 110, 220, 85])
        self.sens_info = tk.Label(f, text="  🔒 — Scan a target first",
                                  font=(FONT, 8), fg="#304050", bg=BG_DEPTH, anchor="w")
        self.sens_info.pack(fill="x", padx=14, pady=4)

    # ── SCHEMA TAB ──

    def _schema_tab(self):
        f = self._tab_frame("📐", "SCHEMA")
        self.nb.add(f, text=" 📐  SCHEMA   ")
        h, self.sch_loading = self._tree_bar(f,
            [("DATABASE SCHEMA EXPLORER", (FONT, 9, "bold"), CYAN, 12)])
        self.schema_output = self._make_text_widget(f)
        self.schema_output.pack(fill="both", expand=True)

    # ── STATUS BAR ──

    def _build_status_bar(self, parent):
        bar = tk.Frame(parent, bg=BG_DEPTH, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.info_label = tk.Label(bar, text="●  READY", font=(FONT, 8),
                                    fg=DIM, bg=BG_DEPTH, anchor="w")
        self.info_label.pack(side="left", padx=14)
        self.count_label = tk.Label(bar, text="", font=(FONT, 8),
                                     fg=DIM, bg=BG_DEPTH, anchor="e")
        self.count_label.pack(side="right", padx=14)

        # Hint
        hint = tk.Frame(parent, bg=BG_DEPTH, height=16)
        hint.pack(fill="x", side="bottom")
        hint.pack_propagate(False)
        tk.Label(hint,
            text="Enter  Run  |  Ctrl+R  Scan  |  Ctrl+S / Esc  Stop  |  Ctrl+Q  Quit  |  Terminal Ctrl+C  Exit",
            font=(FONT, 7), fg="#203040", bg=BG_DEPTH).pack(pady=2)

    def _bind_keys(self):
        self.root.bind("<Control-r>", lambda e: self._run_scan())
        self.root.bind("<Control-s>", lambda e: self._stop_scan())
        self.root.bind("<Control-q>", lambda e: self._safe_close())
        self.root.bind("<Return>", lambda e: self._run_scan())
        self.root.bind("<Escape>", lambda e: self._stop_scan())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)


    # ═══════════════ TAB STATE ═══════════════

    def _set_tab_state(self, idx, enabled):
        self.tab_states[idx] = enabled
        try: self.nb.tab(idx, state="normal" if enabled else "disabled")
        except tk.TclError: pass

    def _update_tab_states(self):
        for i, en in enumerate(self.tab_states):
            try: self.nb.tab(i, state="normal" if en else "disabled")
            except tk.TclError: pass

    def _on_tab_change(self, e=None):
        try: sel = self.nb.index(self.nb.select())
        except tk.TclError: return
        if 0 < sel < len(self.tab_states) and not self.tab_states[sel]:
            self.nb.select(0)

    # ═══════════════ LOGGING ═══════════════

    def _log(self, text, color="dim"):
        tag = color if color in {"green","red","yellow","cyan","dim",
                                  "orange","purple","blue","verbose"} else "dim"
        self.scan_output.insert("end", f"  [{TS()}] {text}\n", tag)
        self.scan_output.see("end")

    def _log_verbose(self, line):
        color = "verbose"
        if "VULN" in line or "vuln" in line.lower():
            color = "orange"
        elif "payload" in line.lower():
            color = "cyan"
        elif "ERROR" in line or "FAIL" in line:
            color = "red"
        elif "SUCCESS" in line or "found" in line.lower():
            color = "green"
        self.scan_output.insert("end", f"  {line}\n", color)
        self.scan_output.see("end")

    def _clear_tree(self, tree):
        for item in tree.get_children():
            tree.delete(item)

    def _set_busy(self, busy):
        self._scanning = busy
        if busy:
            self._glow.pulse(YELLOW)
            self.status_label.config(text="●  SCANNING", fg=YELLOW)
            try: self.run_btn.config(state="disabled")
            except: pass
            try: self.stop_btn.config(state="normal")
            except: pass
            self._scan_bar.start()
            self._stat_status.config(text="scanning in progress...")
            self._header_glow.config(bg=BG_MID)
            self._pulse_header(True)
        else:
            self._glow.pulse(GREEN)
            self.status_label.config(text="●  IDLE", fg=GREEN)
            try: self.run_btn.config(state="normal")
            except: pass
            try: self.stop_btn.config(state="disabled")
            except: pass
            self._scan_bar.stop()
            self._stat_status.config(text="")
            self._pulse_header(False)

    def _pulse_header(self, active):
        self._header_glow.delete("all")
        try:
            w = self._header_glow.winfo_width()
        except tk.TclError:
            return
        if w < 10:
            w = 1440
        if active:
            phase = time.time() * 2
            for x in range(0, w, 2):
                frac = x / w
                wave = math.sin(frac * 20 + phase) * 0.3 + 0.7
                r = 0
                g = max(0, int(0xdd * wave * (0.6 + 0.4 * math.sin(phase + frac * 10))))
                b = max(0, int(0xff * wave * (0.4 + 0.6 * math.sin(phase * 0.7 + frac * 8))))
                self._header_glow.create_line(x, 0, x, 2, fill=f"#{r:02x}{g:02x}{b:02x}")
            self.root.after(50, lambda: self._pulse_header(True) if (self._scanning and self._window_open) else None)
        else:
            self._header_glow.create_line(0, 0, w, 2, fill=BG_MID)

    def _toggle_all_cols(self):
        val = self._toggle_all_var.get()
        for var in self._col_vars.values():
            var.set(val)

    def _copy_dump(self):
        text = self.dump_output.get(1.0, "end-1c")
        if text.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._log("📋 Dump copied to clipboard", "green")

    def _save_dump(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if path:
            text = self.dump_output.get(1.0, "end-1c")
            with open(path, 'w') as f: f.write(text)
            self._log(f"💾 Dump saved: {path}", "green")

    def _save_dump_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if path:
            text = self.dump_output.get(1.0, "end-1c")
            lines = [l.strip() for l in text.strip().split('\n') if l.startswith("  ")]
            with open(path, 'w') as f: f.write('\n'.join(lines))
            self._log(f"💾 CSV saved: {path}", "green")

    # ═══════════════ SCAN FLOW ═══════════════

    def _clear_all(self):
        self.scan_output.delete(1.0, "end")
        self.dump_output.delete(1.0, "end")
        self.schema_output.delete(1.0, "end")
        self._clear_tree(self.db_tree)
        self._clear_tree(self.tbl_tree)
        self._clear_tree(self.col_tree)
        self._clear_tree(self.sens_tree)
        self.results = []; self.findings = []; self.enums = []
        self.databases = []; self.tables = []; self.columns = []
        self.selected_db = None; self.selected_table = None
        self._col_vars = {}
        self._payload_count = 0; self._vuln_count = 0
        self._col_scroll.clear()
        for i in range(1, 7): self._set_tab_state(i, False)
        self._print_banner()
        self.count_label.config(text="")
        self.db_count_label.config(text="")
        self._stat_elapsed.config(text="⏱  00:00")
        self._stat_payloads.config(text="■  0 payloads")
        self._stat_vulns.config(text="⚠  0 vulns")
        self._stat_status.config(text="")

    def _run_scan(self):
        if self._scanning or (self.scan_thread and self.scan_thread.is_alive()):
            return
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Required", "Enter a target URL")
            return
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_entry.delete(0, "end")
            self.url_entry.insert(0, url)

        self.scan_url = url
        self._clear_all()
        self._log(f"▶  SCAN  {url}", "cyan")
        self._log("   Risk: 5 | Threads: 30 | WAF Bypass: ON | Verbose: ON", "dim")
        self._scan_start_time = time.time()
        self._set_busy(True)
        self.info_label.config(text=f"●  Scanning {url}...")
        self._update_live_stats()

        opts = {
            'risk_level': 5, 'bypass_waf': True, 'threads': 30,
            'timeout': 30, 'depth': 5, 'verbose': 2,
            'follow_redirect': True, 'fingerprint': True,
            'banner_grab': True, 'os_detect': True, 'waf_detect': True,
            'tech_detect': True, 'smart_diff': True,
            'list_dbs': True, 'dump_all': False,
        }
        self.scan_thread = ScanThread(
            url=url, opts=opts,
            on_line=lambda line: self.root.after(0, self._log_verbose, line),
            on_result=self._on_result,
            on_error=self._on_scan_error,
            on_payload=lambda: self.root.after(0, self._inc_payload),
            on_vuln=lambda: self.root.after(0, self._inc_vuln),
        )
        self.scan_thread.start()

    def _inc_payload(self): self._payload_count += 1
    def _inc_vuln(self): self._vuln_count += 1

    def _update_live_stats(self):
        if not self._scanning or not self._window_open: return
        try:
            elapsed = int(time.time() - self._scan_start_time)
            m, s = divmod(elapsed, 60)
            self._stat_elapsed.config(text=f"⏱  {m:02d}:{s:02d}")
            self._stat_payloads.config(text=f"■  {self._payload_count} payloads")
            self._stat_vulns.config(text=f"⚠  {self._vuln_count} vulns")
            self._stat_status.config(text=f"scanning {self.scan_url[:50]}...")
        except tk.TclError:
            return
        self.root.after(500, self._update_live_stats)

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.stop()
            self.scan_thread.kill_engine()
            self._log("■  STOPPED by user", "yellow")
            self._set_busy(False)
            self.info_label.config(text="●  Scan stopped")

    def _on_result(self, results):
        self.results = results
        self.findings = [r for r in results if r.get('parameter') != 'enumeration']
        self.enums = [r for r in results if r.get('parameter') == 'enumeration']
        self._vuln_count = len(self.findings)

        if not results:
            self._log("⚠  Scan finished — no data returned.", "yellow")
            self._log("   Possible causes: target unreachable, not vulnerable, or blocked.", "dim")
            self._log("   Check the verbose output above for connection errors.", "dim")
        else:
            self._log(f"✅  DONE  {len(results)} total | {len(self.findings)} vulns | "
                       f"{len(self.enums)} enums", "green")

        if self.findings:
            self._log("", "dim")
            self._log("──  VULNERABILITIES  ──", "bold")
            for f in self.findings:
                dbms = f.get('dbms', '?')
                ptype = f.get('type', '?')
                param = f.get('parameter', '?')
                conf = f.get('confidence', 0)
                icon = {"Error-based": "⚡", "Boolean-based": "🔍",
                        "Time-based": "⏱", "Union-based": "🔗",
                        "Stacked query": "📚"}.get(ptype, "•")
                self._log(f"  {icon} [{ptype}] {param} (DB: {dbms}, conf: {conf:.0%})",
                          "orange" if conf > 0.8 else "yellow")
                if f.get('payload'):
                    self._log(f"     Payload: {f['payload'][:120]}", "dim")

        for e in self.enums:
            if e.get('type') == 'list-dbs':
                dbs = [d.strip() for d in e.get('payload', '').split(',') if d.strip()]
                self.databases = dbs
                break

        if self.databases:
            self._log("", "dim")
            self._log(f"🗄️  DATABASES ({len(self.databases)})", "bold")
            for db in self.databases:
                self._log(f"   {db}", "green")
            self._populate_dbs()
            self._set_tab_state(1, True)
            self._set_tab_state(5, True)
            self._set_tab_state(6, True)
            self.db_info.config(
                text=f"  {len(self.databases)} databases — double-click to explore")
        else:
            self._log("No databases enumerated", "yellow")
            self.db_info.config(text="  No databases found")

        self._set_busy(False)
        self.count_label.config(
            text=f"{len(self.findings)} vulns | {len(self.databases)} DBs")
        self.info_label.config(
            text=f"●  Done — {len(self.findings)} vulns, {len(self.databases)} databases")
        self._show_schema()

    def _on_scan_error(self, msg):
        self._log(f"  ERROR: {msg}", "red")
        self._set_busy(False)
        self._glow.pulse(RED)
        self.status_label.config(text="●  ERROR", fg=RED)
        self.info_label.config(text=f"●  Error: {msg}")
        self._stat_status.config(text="")

    # ═══════════════ DATABASES ═══════════════

    def _populate_dbs(self):
        self._clear_tree(self.db_tree)
        for i, db in enumerate(self.databases):
            tag = "e" if i % 2 == 0 else "o"
            self.db_tree.insert("", "end", values=(i + 1, db, "?"), tags=(tag,))
        self.db_tree.tag_configure("e", background="#080e18")
        self.db_tree.tag_configure("o", background="#0c1420")
        self.db_count_label.config(text=f"{len(self.databases)} databases")

    def _on_db_select(self, e):
        sel = self.db_tree.selection()
        if not sel: return
        vals = self.db_tree.item(sel[0], "values")
        if len(vals) >= 2:
            self.selected_db = vals[1]
            self.tbl_db_label.config(text=self.selected_db)
            self._set_tab_state(2, True)
            self.nb.select(2)
            self.tbl_info.config(
                text=f"  Loading tables from {self.selected_db}...")
            self._load_tables()

    # ═══════════════ TABLES ═══════════════

    def _load_tables(self):
        if not self.selected_db or not self.scan_url: return
        self._clear_tree(self.tbl_tree)
        self.tbl_loading.config(text="loading...")

        def task():
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled(): return
                results = engine.run(
                    self.scan_url, list_tables=True, timeout=120,
                    database=self.selected_db)
                tbls = []; err_msg = None
                if results:
                    for r in results:
                        if r.get('type') == 'list-tables':
                            tbls.extend(t.strip() for t in
                                        r.get('payload','').split(',') if t.strip())
                        elif 'error' in r: err_msg = r['error']
                self.tables = tbls
                self.root.after(0, self._populate_tables)
                self.root.after(0, lambda: self.tbl_loading.config(text=""))
                if err_msg and not tbls:
                    self.root.after(0, lambda: self.tbl_info.config(
                        text=f"  Error fetching tables: {err_msg}"))
            except Exception as ex:
                self.root.after(0, lambda: self.tbl_info.config(text=f"  Error: {ex}"))
                self.root.after(0, lambda: self.tbl_loading.config(text=""))
        threading.Thread(target=task, daemon=True).start()

    def _populate_tables(self):
        self._clear_tree(self.tbl_tree)
        interesting_keywords = ['user','admin','account','credential','login',
                                'passwd','secret','token','member','customer',
                                'employee','person','staff','auth','profile',
                                'session','password','email','config']
        for i, tbl in enumerate(self.tables):
            is_int = any(k in tbl.lower() for k in interesting_keywords)
            tag = "interesting" if is_int else ("e" if i % 2 == 0 else "o")
            interesting_text = "🔴 YES" if is_int else ""
            self.tbl_tree.insert("", "end", values=(i+1, tbl, "?", interesting_text),
                                  tags=(tag,))
        self.tbl_tree.tag_configure("e", background="#080e18")
        self.tbl_tree.tag_configure("o", background="#0c1420")
        self.tbl_tree.tag_configure("interesting", background="#2a1018")
        self.tbl_loading.config(text="")
        self.tbl_info.config(
            text=f"  {len(self.tables)} tables — double-click to view columns")

    def _on_tbl_select(self, e):
        sel = self.tbl_tree.selection()
        if not sel: return
        vals = self.tbl_tree.item(sel[0], "values")
        if len(vals) >= 2:
            self.selected_table = vals[1]
            self.col_tbl_val.config(text=self.selected_table)
            self.col_db_val.config(text=self.selected_db or "")
            self.dump_tbl_label.config(text=self.selected_table)
            self.dump_db_label.config(text=self.selected_db or "")
            self._set_tab_state(3, True)
            self._set_tab_state(4, True)
            self.nb.select(3)
            self.col_info.config(
                text=f"  Loading columns from {self.selected_db}.{self.selected_table}...")
            self._load_columns()

    # ═══════════════ COLUMNS ═══════════════

    def _load_columns(self):
        if not self.selected_db or not self.selected_table or not self.scan_url: return
        self._clear_tree(self.col_tree)
        self.col_loading.config(text="loading...")

        def task():
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled(): return
                results = engine.run(
                    self.scan_url, list_columns=True, timeout=120,
                    database=self.selected_db, table=self.selected_table)
                cols = []; err_msg = None
                if results:
                    for r in results:
                        if r.get('type') == 'list-columns':
                            cols.extend(c.strip() for c in
                                        r.get('payload','').split(',') if c.strip())
                        elif 'error' in r: err_msg = r['error']
                self.columns = cols
                self.root.after(0, self._populate_columns)
                self.root.after(0, lambda: self.col_loading.config(text=""))
                if err_msg and not cols:
                    self.root.after(0, lambda: self.col_info.config(
                        text=f"  Error fetching columns: {err_msg}"))
            except Exception as ex:
                self.root.after(0, lambda: self.col_info.config(text=f"  Error: {ex}"))
                self.root.after(0, lambda: self.col_loading.config(text=""))
        threading.Thread(target=task, daemon=True).start()

    def _populate_columns(self):
        self._clear_tree(self.col_tree)
        for i, col in enumerate(self.columns):
            tag = "e" if i % 2 == 0 else "o"
            self.col_tree.insert("", "end",
                values=(i+1, col, "—", "—", "—", "—", ""), tags=(tag,))
        self.col_tree.tag_configure("e", background="#080e18")
        self.col_tree.tag_configure("o", background="#0c1420")
        self.col_loading.config(text="")
        self.col_info.config(
            text=f"  {len(self.columns)} columns — double-click to dump")
        self._build_col_checkboxes()

    def _build_col_checkboxes(self):
        self._col_scroll.clear()
        self._col_vars = {}
        self._toggle_all_var.set(True)
        row = tk.Frame(self._col_scroll.inner, bg=BG_CARD2)
        row.pack(fill="x", anchor="w", pady=2)
        for col in self.columns:
            var = tk.BooleanVar(value=True)
            self._col_vars[col] = var
            cb = tk.Checkbutton(row, text=col, variable=var,
                font=(FONT, 8), fg=CYAN, bg=BG_CARD2,
                selectcolor=BG_DEPTH, activebackground=BG_CARD2,
                activeforeground=CYAN, anchor="w")
            cb.pack(side="left", padx=(0, 4))

    def _on_col_select(self, e):
        self.nb.select(4)
        self._load_dump()

    # ═══════════════ DUMP ═══════════════

    def _load_dump(self):
        if not self.selected_db or not self.selected_table or not self.scan_url: return
        selected_cols = [c for c, v in self._col_vars.items() if v.get()]
        col_str = ",".join(selected_cols) if selected_cols else "*"
        self.dump_loading.config(text="dumping...")
        self.dump_output.delete(1.0, "end")
        self.dump_output.insert("end",
            f"┌─ DUMP REQUEST ─────────────────────────────┐\n", "cyan")
        self.dump_output.insert("end", f"  Columns : {col_str}\n", "green")
        self.dump_output.insert("end",
            f"  Table   : {self.selected_db}.{self.selected_table}\n", "green")
        self.dump_output.insert("end",
            f"└────────────────────────────────────────────┘\n\n", "cyan")
        self.dump_output.insert("end", f"[{TS()}] Dumping data...\n", "dim")
        self.dump_info.config(text=f"  Dumping {col_str}...")

        def task():
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled():
                    self.root.after(0, lambda: self._dump_error("Go binary not available"))
                    return
                results = engine.run(
                    self.scan_url, timeout=120,
                    dump_table=self.selected_table,
                    database=self.selected_db,
                    column=",".join(selected_cols) if selected_cols else "*")
                self.root.after(0, lambda: self._show_dump(results, col_str))
            except Exception as ex:
                self.root.after(0, lambda: self._dump_error(str(ex)))
        threading.Thread(target=task, daemon=True).start()

    def _dump_error(self, msg):
        self.dump_loading.config(text="")
        self.dump_output.insert("end", f"\n[{TS()}] ERROR: {msg}\n", "red")
        self.dump_info.config(text=f"  Error: {msg}")

    def _show_dump(self, results, col_str):
        self.dump_loading.config(text="")
        self.dump_output.delete(1.0, "end")
        if not results:
            self.dump_output.insert("end", f"[{TS()}] No data returned\n", "red")
            self.dump_info.config(text="  No data returned"); return
        if isinstance(results, list) and results and isinstance(results[0], dict) \
           and 'error' in results[0]:
            self.dump_output.insert("end", f"[{TS()}] ENGINE ERROR: {results[0]['error']}\n", "red")
            self.dump_info.config(text=f"  Error: {results[0]['error']}"); return
        entries = [r for r in results if r.get('type') == 'dump-table']
        if not entries: entries = results[:100]
        self.dump_output.insert("end",
            f"┌─ DUMP: {self.selected_db}.{self.selected_table} ─────┐\n", "cyan")
        self.dump_output.insert("end", f"  Columns : {col_str}\n", "green")
        self.dump_output.insert("end", f"  Rows    : {len(entries)}\n", "green")
        self.dump_output.insert("end",
            f"└──────────────────────────────────────────────────┘\n\n", "cyan")
        for entry in entries:
            payload = entry.get('payload', '')
            details = entry.get('details', '')
            if payload:
                try:
                    data = json.loads(payload)
                    if isinstance(data, list):
                        for row in data:
                            if isinstance(row, dict):
                                line = " | ".join(
                                    f"{k}:{v}" for k, v in row.items())[:300]
                                self.dump_output.insert("end", f"  {line}\n", "green")
                            else:
                                self.dump_output.insert("end", f"  {row}\n", "green")
                    else:
                        self.dump_output.insert("end", f"  {payload}\n", "green")
                except json.JSONDecodeError:
                    self.dump_output.insert("end", f"  {payload[:200]}\n", "green")
            if details:
                self.dump_output.insert("end", f"    {details}\n", "dim")
        self.dump_output.insert("end",
            f"\n[{TS()}] DUMP COMPLETE — {len(entries)} rows\n", "green")
        self.dump_info.config(
            text=f"  {len(entries)} rows from {self.selected_db}.{self.selected_table}")

    # ═══════════════ SCHEMA ═══════════════

    def _show_schema(self):
        self.schema_output.delete(1.0, "end")
        self.schema_output.insert("end",
            "╔══════════════════════════════════════╗\n", "dim")
        self.schema_output.insert("end",
            "║     DATABASE SCHEMA OVERVIEW        ║\n", "cyan")
        self.schema_output.insert("end",
            "╚══════════════════════════════════════╝\n\n", "dim")
        if not self.databases:
            self.schema_output.insert("end", "  No databases found\n", "yellow"); return
        for db in self.databases:
            self.schema_output.insert("end", f"  📁 {db}\n", "green")
        self.schema_output.insert("end",
            f"\n  [{TS()}] Schema loaded — {len(self.databases)} databases\n", "dim")

    # ═══════════════ EXPLORE ═══════════════

    def _load_dbs(self):
        if not self.scan_url: return
        self.db_progress.config(text="loading...")
        def task():
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled(): return
                results = engine.run(self.scan_url, list_dbs=True, timeout=120)
                dbs = []; err_msg = None
                if results:
                    for r in results:
                        if r.get('type') == 'list-dbs':
                            dbs.extend(d.strip() for d in
                                       r.get('payload','').split(',') if d.strip())
                        elif 'error' in r: err_msg = r['error']
                self.databases = dbs
                self.root.after(0, self._populate_dbs)
                self.root.after(0, lambda: self.db_progress.config(text=""))
                if err_msg and not dbs:
                    self.root.after(0, lambda: self.db_info.config(text=f"  Error: {err_msg}"))
            except Exception:
                self.root.after(0, lambda: self.db_progress.config(text="error"))
        threading.Thread(target=task, daemon=True).start()

    def _list_all_dbs(self):
        if not self.databases:
            self._log("No databases to list", "yellow"); return
        self._log(f"📋 ALL DATABASES ({len(self.databases)})", "bold")
        for db in self.databases:
            self._log(f"   📁 {db}", "green")

    def _explore_all_dbs(self):
        if not self.scan_url or not self.databases:
            self._log("No databases to explore — scan first", "yellow"); return
        self._log(f"🔎 Exploring ALL {len(self.databases)} databases...", "cyan")
        self._set_busy(True)

        def explore_one(db):
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled(): return []
                results = engine.run(self.scan_url, list_tables=True, database=db)
                tbls = []
                if results:
                    for r in results:
                        if r.get('type') == 'list-tables':
                            tbls.extend(t.strip() for t in
                                        r.get('payload','').split(',') if t.strip())
                return tbls
            except Exception: return []

        def task():
            for db in self.databases.copy():
                if self._scanning:
                    self.root.after(0, lambda d=db: self._log(f"   📁 {d} — exploring...", "dim"))
                tbls = explore_one(db)
                if self._scanning:
                    interesting = [t for t in tbls if any(x in t.lower()
                        for x in ['user','admin','account','credential','login',
                                   'passwd','secret','token','member','customer',
                                   'employee','person','staff','auth','profile',
                                   'session','password','email','config'])]
                    self.root.after(0, lambda d=db, t=len(tbls), i=len(interesting):
                        self._log(f"   📁 {d} — {t} tables ({i} interesting)", "green"))
            self.root.after(0, lambda: self._log("✅ Database exploration complete", "green"))
            self.root.after(0, self._set_busy, False)
        threading.Thread(target=task, daemon=True).start()

    def _list_all_tables(self):
        if not self.tables:
            self._log("No tables to list", "yellow"); return
        self._log(f"📋 TABLES IN {self.selected_db} ({len(self.tables)})", "bold")
        interesting_keywords = ['user','admin','account','credential','login',
                                'passwd','secret','token','member','customer',
                                'employee','person','staff','auth','profile',
                                'session','password','email','config']
        for tbl in self.tables:
            is_int = any(k in tbl.lower() for k in interesting_keywords)
            icon = "🔴" if is_int else "  "
            self._log(f"   {icon} {tbl}", "orange" if is_int else "dim")

    def _find_interesting_tables(self):
        if not self.tables: return
        interesting_keywords = ['user','admin','account','credential','login',
                                'passwd','secret','token','member','customer',
                                'employee','person','staff','auth','profile',
                                'session','password','email','config']
        found = [t for t in self.tables if any(k in t.lower() for k in interesting_keywords)]
        if found:
            self._log(f"🔍 Found {len(found)} interesting tables:", "green")
            for t in found: self._log(f"   🔴 {t}", "orange")
            for item in self.tbl_tree.get_children():
                vals = self.tbl_tree.item(item, "values")
                if len(vals) >= 2 and any(k in vals[1].lower() for k in interesting_keywords):
                    self.tbl_tree.item(item, tags=("interesting",))
            self.tbl_tree.tag_configure("interesting", background="#2a1018")
        else:
            self._log("No interesting tables found", "yellow")

    def _find_sensitive_cols(self):
        if not self.columns: return
        sensitive_keywords = ['pass','pwd','secret','token','key','credit',
                              'card','ssn','social','security','pin','auth',
                              'hash','salt','password','email','phone','address']
        found = [c for c in self.columns if any(k in c.lower() for k in sensitive_keywords)]
        if found:
            self._log(f"🔍 Sensitive columns in {self.selected_table}:", "orange")
            for c in found: self._log(f"   ⚠ {c}", "red")
            for item in self.col_tree.get_children():
                vals = self.col_tree.item(item, "values")
                if len(vals) >= 2 and any(k in vals[1].lower() for k in sensitive_keywords):
                    self.col_tree.item(item, tags=("sensitive",))
            self.col_tree.tag_configure("sensitive", background="#2a1018")
        else:
            self._log(f"No sensitive columns found in {self.selected_table}", "dim")

    # ═══════════════ CLOSE ═══════════════

    def _on_close(self):
        if not self._window_open:
            return
        self._window_open = False
        self._scanning = False
        # Kill any running scan
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread.kill_engine()
        # Kill any animation timers
        for w in (self._scan_bar, self._spinner, self._glow):
            if w is not None:
                try: w.stop()
                except Exception: pass
        if self._header_glow is not None:
            try: self._header_glow.delete("all")
            except Exception: pass
        # Destroy tk and force exit
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            try: self.root.destroy()
            except Exception: pass
        os._exit(0)

    def run(self):
        if not self._init_ok:
            return
        try:
            self.root.mainloop()
        except (tk.TclError, Exception) as e:
            print(f"[GUI FATAL] {e}", file=sys.stderr)
            if self._window_open:
                self._safe_close()


# ═══════════════════════════════════════════════════════════
#  SCAN THREAD (unchanged)
# ═══════════════════════════════════════════════════════════

class ScanThread(threading.Thread):
    def __init__(self, url, opts, on_line=None, on_result=None,
                 on_error=None, on_payload=None, on_vuln=None):
        super().__init__(daemon=True)
        self.url = url; self.opts = opts
        self.on_line = on_line; self.on_result = on_result
        self.on_error = on_error; self.on_payload = on_payload
        self.on_vuln = on_vuln
        self._stop = threading.Event()
        self._engine = None

    def stop(self): self._stop.set()
    def stopped(self): return self._stop.is_set()
    def kill_engine(self):
        if self._engine:
            self._engine.kill()

    def run(self):
        try:
            self._engine = GoEngine()
            engine = self._engine
            if not engine.available:
                self.on_error("Go binary not found"); return
            if not engine.ensure_compiled():
                self.on_error("Go compilation failed"); return

            def line_handler(line):
                if self.stopped(): engine.kill(); return
                if self.on_line: self.on_line(line)
                if "payload" in line.lower() or "testing" in line.lower():
                    if self.on_payload: self.on_payload()
                if "vuln" in line.lower() or "found" in line.lower() or "SUCCESS" in line:
                    if self.on_vuln: self.on_vuln()

            results = engine.run_stream(
                self.url, on_verbose=line_handler,
                stop_event=self._stop, **self.opts)
            if self.stopped(): return
            if isinstance(results, list):
                if results and isinstance(results[0], dict):
                    if results[0].get('parameter') == 'error' or 'error' in results[0]:
                        self.on_error(results[0].get('payload', results[0].get('error', 'Unknown error')))
                    else:
                        self.on_result(results)
                else:
                    self.on_result(results)
            elif results is None:
                self.on_error("Engine returned no results")
            else:
                self.on_result([results] if isinstance(results, dict) else [])
        except Exception as e:
            self.on_error(str(e))


def launch_gui():
    SQLiGUI().run()

if __name__ == "__main__":
    launch_gui()
