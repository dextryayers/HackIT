"""
HackIT SQLi — GUI v7.0 ULTIMATE
Real-time streaming · Animated scanner · Live verbose output · Zero bugs
"""

import os, sys, json, re, time, threading, subprocess, signal, queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from pathlib import Path
from datetime import datetime

SQ_DIR = Path(__file__).parent
GO_BINARY = SQ_DIR / "go" / "bin" / "worker"
GO_DIR = SQ_DIR / "go"
TS = lambda: datetime.now().strftime("%H:%M:%S")

DARK = "#0a0e14"
MID = "#111820"
CARD = "#151d28"
CARD2 = "#18222e"
CARD3 = "#1c2838"
WHITE = "#e6eef5"
GREEN = "#4ae08a"
RED = "#f05050"
YELLOW = "#f0c040"
CYAN = "#40c0f0"
BLUE = "#5090f0"
DIM = "#607080"
ORANGE = "#f09040"
PURPLE = "#b080f0"
BORDER = "#1e2a36"
LBORDER = "#2a3848"
VERBOSE = "#2a4a3a"

FONT = "Monospace" if sys.platform == "linux" else "Consolas"


def _shift(col, amt):
    r = max(0, min(255, int(col[1:3], 16) + amt))
    g = max(0, min(255, int(col[3:5], 16) + amt))
    b = max(0, min(255, int(col[5:7], 16) + amt))
    return f"#{r:02x}{g:02x}{b:02x}"


def _ts_color(text, color):
    return f"[{TS()}] {text}"


# ── ANIMATED SPINNER ──

class Spinner(tk.Canvas):
    CHARS = ["◜", "◝", "◞", "◟"]
    COLORS = [GREEN, CYAN, YELLOW, ORANGE]

    def __init__(self, parent, size=20, **kw):
        super().__init__(parent, bd=0, highlightthickness=0, width=size, height=size, **kw)
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
        self.delete("all")
        s = self._size
        c = self.COLORS[self._idx % len(self.COLORS)]
        ch = self.CHARS[self._idx % len(self.CHARS)]
        self.create_text(s//2, s//2, text=ch, fill=c,
                         font=(FONT, s//2, "bold"))
        self._idx += 1
        self._timer = self.after(120, self._tick)


# ── STREAMING GO ENGINE ──

class GoEngine:
    def __init__(self):
        self.binary = GO_BINARY

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
            flag = k.replace('_', '-')
            if isinstance(v, bool) and v:
                args.append(f"--{flag}")
            elif isinstance(v, int):
                args.extend([f"--{flag}", str(v)])
            elif isinstance(v, str) and v:
                args.extend([f"--{flag}", v])
            elif isinstance(v, list):
                for item in v:
                    args.extend([f"--{flag}", str(item)])
        return args

    def run(self, url, **kwargs):
        args = self._build_args(url, verbose_lvl=0, **kwargs)
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=300)
            return self._parse_stdout(r.stdout)
        except Exception:
            return None

    def run_stream(self, url, on_verbose=None, **kwargs):
        """Run with streaming. on_verbose(line) called for each log line.
           Returns parsed JSON results from stdout."""
        args = self._build_args(url, verbose_lvl=2, **kwargs)
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True, bufsize=1)

            # Read stderr (verbose log) in a thread
            json_result = [None]

            def read_stderr():
                for line in iter(proc.stderr.readline, ''):
                    if not line:
                        break
                    line = line.rstrip('\n\r')
                    if on_verbose:
                        on_verbose(line)

            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            # Read stdout (JSON result)
            stdout_data = []
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                stdout_data.append(line.rstrip('\n\r'))

            proc.wait()
            stderr_thread.join(timeout=5)

            full = ''.join(stdout_data)
            return self._parse_stdout(full)

        except Exception:
            return None

    def _parse_stdout(self, raw):
        """Parse JSON result from stdout"""
        if not raw or not raw.strip():
            return None
        raw = raw.strip()
        # Try direct parse first
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        # Try each line in reverse
        for line in reversed(raw.split('\n')):
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return None


# ── MODERN BUTTON ──

class ModernButton(tk.Frame):
    def __init__(self, parent, text, command, bg_color="#18a048",
                 fg_color="white", font_size=9, width=100, height=36, **kw):
        super().__init__(parent, width=width, height=height, **kw)
        self.pack_propagate(False)
        self._btn = tk.Button(
            self, text=text, font=(FONT, font_size, "bold"),
            fg=fg_color, bg=bg_color, bd=0, relief="flat",
            activebackground=_shift(bg_color, 20),
            activeforeground=fg_color,
            cursor="hand2", command=command
        )
        self._btn.pack(fill="both", expand=True)
        self._norm_bg = bg_color
        self._disabled_bg = "#1a2028"
        self._disabled_fg = "#404a54"

    def set_disabled(self, disabled):
        if disabled:
            self._btn.config(bg=self._disabled_bg, fg=self._disabled_fg,
                             cursor="", state="disabled")
        else:
            self._btn.config(bg=self._norm_bg, fg="white",
                             cursor="hand2", state="normal")


# ── SCROLLABLE FRAME ──

class ScrollFrame(tk.Frame):
    def __init__(self, parent, bg=CARD2, **kw):
        super().__init__(parent, bg=bg, **kw)
        self.canvas = tk.Canvas(self, bg=bg, bd=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
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


# ── MAIN GUI ──

class SQLiGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HackIT SQLi v7.0 — Ultimate Injection Console")
        self.root.geometry("1440x860")
        self.root.configure(bg=DARK)
        self.root.minsize(1100, 700)

        if sys.platform != 'win32':
            signal.signal(signal.SIGINT, lambda s, f: self._safe_close())
            signal.signal(signal.SIGTSTP, lambda s, f: self._safe_close())

        self.scan_thread = None
        self.results = []
        self.findings = []
        self.enums = []
        self.databases = []
        self.tables = []
        self.columns = []
        self.selected_db = None
        self.selected_table = None
        self.scan_url = ""
        self._window_open = True
        self._scanning = False
        self._col_vars = {}
        self.tab_states = [True] + [False] * 6
        self._scan_start_time = 0
        self._payload_count = 0
        self._vuln_count = 0

        self._setup_styles()
        self._build_ui()

        self.root.bind("<Control-r>", lambda e: self._run_scan())
        self.root.bind("<Control-s>", lambda e: self._stop_scan())
        self.root.bind("<Control-q>", lambda e: self._safe_close())
        self.root.bind("<Return>", lambda e: self._run_scan())
        self.root.bind("<Escape>", lambda e: self._stop_scan())
        self.root.bind_all("<Control-c>", lambda e: self._safe_close())
        self.root.bind_all("<Control-z>", lambda e: self._safe_close())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<Destroy>",
                       lambda e: self._on_close() if e.widget == self.root else None)

    def _safe_close(self):
        if self._window_open:
            self._window_open = False
            self._on_close()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TNotebook", background=DARK, borderwidth=0)
        s.configure("TNotebook.Tab", background=MID, foreground="#404a54",
                    padding=[20, 7], font=(FONT, 9), borderwidth=0)
        s.map("TNotebook.Tab", background=[("selected", CARD)],
              foreground=[("selected", WHITE)])
        s.configure("Treeview", background="#0d1420", foreground=WHITE,
                    fieldbackground="#0d1420", font=(FONT, 9),
                    borderwidth=0, rowheight=28)
        s.configure("Treeview.Heading", background=MID, foreground=CYAN,
                    font=(FONT, 9, "bold"), borderwidth=0)
        s.map("Treeview.Heading", background=[("active", CARD)])
        s.map("Treeview", background=[("selected", "#1a2a3a")])
        s.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])

    # ═══════════════ UI BUILD ═══════════════

    def _build_ui(self):
        self._build_header()
        self._build_live_stats()
        self._build_url_bar()
        self._build_notebook()
        self._build_status_bar()
        self._build_hint()

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=MID, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Frame(hdr, bg=GREEN, height=2).pack(fill="x")

        # Left: logo + title
        lt = tk.Frame(hdr, bg=MID)
        lt.pack(side="left", padx=(18, 4), pady=8)
        tk.Label(lt, text="⚡", font=(FONT, 24), fg=RED, bg=MID).pack(side="left")
        tk.Label(lt, text="HACKIT  SQLi  v7.0",
                 font=(FONT, 18, "bold"), fg=RED, bg=MID).pack(side="left", padx=(6, 4))
        tk.Label(lt, text="ULTIMATE CONSOLE",
                 font=(FONT, 8, "bold"), fg=DIM, bg=MID).pack(side="left", padx=(4, 0),
                                                                pady=(12, 0))

        # Right: status area
        rt = tk.Frame(hdr, bg=MID)
        rt.pack(side="right", padx=16, pady=6)

        # Spinner
        self._spinner = Spinner(rt, size=22, bg=MID)
        self._spinner.pack(side="left", padx=(0, 8))

        # Status LED
        self._status_led = tk.Canvas(rt, width=14, height=14, bg=MID, bd=0,
                                      highlightthickness=0)
        self._status_led.pack(side="left", padx=(0, 6))
        self._draw_led("idle")

        self.status_label = tk.Label(rt, text="● IDLE",
                                     font=(FONT, 11, "bold"), fg=GREEN, bg=MID)
        self.status_label.pack(side="left")

        # Engine badge
        badge = tk.Frame(rt, bg="#0a1a14", bd=1, relief="solid",
                         highlightbackground=GREEN, highlightthickness=0)
        badge.pack(side="left", padx=(14, 0))
        tk.Label(badge, text=" 2270p · 20e · LIVE ",
                 font=(FONT, 8), fg=GREEN, bg="#0a1a14").pack(padx=6, pady=2)

        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x")

    def _draw_led(self, state):
        self._status_led.delete("all")
        c = {"idle": GREEN, "scanning": YELLOW, "done": CYAN, "error": RED}.get(state, GREEN)
        x = y = 7
        r = 5
        self._status_led.create_oval(x - r, y - r, x + r, y + r, fill=c, outline=c)
        self._status_led.create_oval(x - r - 2, y - r - 2, x + r + 2, y + r + 2,
                                      fill="", outline=c, width=1, stipple="gray25")

    def _build_live_stats(self):
        bar = tk.Frame(self.root, bg="#080c12", height=24)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self._stat_elapsed = tk.Label(bar, text="⏱ 00:00", font=(FONT, 8),
                                       fg=DIM, bg="#080c12")
        self._stat_elapsed.pack(side="left", padx=(12, 8))

        self._stat_payloads = tk.Label(bar, text="■ 0 payloads", font=(FONT, 8),
                                        fg=DIM, bg="#080c12")
        self._stat_payloads.pack(side="left", padx=8)

        self._stat_vulns = tk.Label(bar, text="⚠ 0 vulns", font=(FONT, 8),
                                     fg=DIM, bg="#080c12")
        self._stat_vulns.pack(side="left", padx=8)

        self._stat_status = tk.Label(bar, text="", font=(FONT, 8),
                                      fg=CYAN, bg="#080c12")
        self._stat_status.pack(side="right", padx=12)

        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x")

    def _update_live_stats(self):
        if not self._scanning:
            return
        elapsed = int(time.time() - self._scan_start_time)
        m, s = divmod(elapsed, 60)
        self._stat_elapsed.config(text=f"⏱ {m:02d}:{s:02d}")
        self._stat_payloads.config(text=f"■ {self._payload_count} payloads")
        self._stat_vulns.config(text=f"⚠ {self._vuln_count} vulns")
        self._stat_status.config(text=f"scanning {self.scan_url[:60]}...")
        self.root.after(500, self._update_live_stats)

    def _build_url_bar(self):
        bar = tk.Frame(self.root, bg=CARD,
                       highlightbackground=BORDER, highlightthickness=1, height=48)
        bar.pack(fill="x", padx=8, pady=(4, 2))
        bar.pack_propagate(False)

        tk.Label(bar, text="🎯", font=(FONT, 12), fg=CYAN, bg=CARD
                 ).pack(side="left", padx=(10, 2))
        tk.Label(bar, text="TARGET", font=(FONT, 8, "bold"), fg=CYAN, bg=CARD
                 ).pack(side="left", padx=(0, 6))

        self.url_entry = tk.Entry(bar, font=(FONT, 12), fg=WHITE,
                                   bg="#0d1420", bd=0, insertbackground=GREEN,
                                   relief="flat",
                                   highlightbackground=LBORDER, highlightthickness=1)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=4, ipady=7, ipadx=8)
        self.url_entry.insert(0, "https://example.com/index.php?id=1")

        f1 = tk.Frame(bar, bg=CARD, width=120, height=38)
        f1.pack(side="left", padx=(4, 2))
        f1.pack_propagate(False)
        self.run_btn = ModernButton(f1, "▶ SCAN", self._run_scan, "#18a048",
                                     width=120, height=38)
        self.run_btn.pack(fill="both", expand=True)

        f2 = tk.Frame(bar, bg=CARD, width=120, height=38)
        f2.pack(side="left", padx=(2, 8))
        f2.pack_propagate(False)
        self.stop_btn = ModernButton(f2, "■ STOP", self._stop_scan, "#882020",
                                      width=120, height=38)
        self.stop_btn.set_disabled(True)
        self.stop_btn.pack(fill="both", expand=True)

    def _build_notebook(self):
        nf = tk.Frame(self.root, bg=DARK)
        nf.pack(fill="both", expand=True, padx=8, pady=(2, 0))
        self.nb = ttk.Notebook(nf)
        self.nb.pack(fill="both", expand=True)
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

        self._build_scan_tab()
        self._build_databases_tab()
        self._build_tables_tab()
        self._build_columns_tab()
        self._build_dump_tab()
        self._build_sensitive_tab()
        self._build_schema_tab()
        self._update_tab_states()

    def _build_scan_tab(self):
        f = tk.Frame(self.nb, bg=DARK)
        self.nb.add(f, text=" 🔍 LIVE SCAN   ")
        self.scan_output = scrolledtext.ScrolledText(
            f, bg="#0a111a", fg=WHITE, font=(FONT, 9),
            insertbackground=GREEN, bd=0, padx=16, pady=12,
            state="normal", wrap="word",
            highlightbackground=BORDER, highlightthickness=0)
        self.scan_output.pack(fill="both", expand=True)

        for t, c in [("green", GREEN), ("red", RED), ("yellow", YELLOW),
                      ("cyan", CYAN), ("dim", DIM), ("orange", ORANGE),
                      ("purple", PURPLE), ("blue", BLUE), ("verbose", VERBOSE)]:
            self.scan_output.tag_configure(t, foreground=c)
        self.scan_output.tag_configure("bold", font=(FONT, 10, "bold"))
        self._print_banner()

    def _print_banner(self):
        for line, tag in [
            ("╔══════════════════════════════════════════════╗\n", "dim"),
            ("║        HACKIT SQLi ENGINE v7.0              ║\n", "green"),
            ("║    2270 Payloads  ·  20 Engines  ·  LIVE    ║\n", "cyan"),
            ("║    ULTIMATE CONSOLE — Real-time Streaming   ║\n", "purple"),
            ("╚══════════════════════════════════════════════╝\n\n", "dim"),
            (f"  [{TS()}] Engine ready — verbose streaming ON\n", "dim"),
            (f"  [{TS()}] Ctrl+R Scan | Ctrl+S/Esc Stop | Ctrl+Q Quit\n\n", "dim"),
        ]:
            self.scan_output.insert("end", line, tag)

    def _build_databases_tab(self):
        f = tk.Frame(self.nb, bg=DARK)
        self.nb.add(f, text=" 🗄️  DATABASES   ")
        h = tk.Frame(f, bg=CARD, height=36,
                      highlightbackground=LBORDER, highlightthickness=1)
        h.pack(fill="x")
        h.pack_propagate(False)
        tk.Label(h, text="DATABASES", font=(FONT, 9, "bold"), fg=CYAN, bg=CARD
                 ).pack(side="left", padx=12)
        self.db_count_label = tk.Label(h, text="", font=(FONT, 8), fg=DIM, bg=CARD)
        self.db_count_label.pack(side="left", padx=6)
        # Controls
        tk.Button(h, text="🔄 Refresh", font=(FONT, 8), bg="#1a2a3a", fg=WHITE,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=lambda: self._load_dbs()).pack(side="left", padx=6)
        tk.Button(h, text="📋 List All", font=(FONT, 8), bg="#1a2a3a", fg=CYAN,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=self._list_all_dbs).pack(side="left", padx=2)
        tk.Button(h, text="🔎 Explore All", font=(FONT, 8), bg="#1a2a3a", fg=GREEN,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=self._explore_all_dbs).pack(side="left", padx=2)
        self.db_progress = tk.Label(h, text="", font=(FONT, 8), fg=YELLOW, bg=CARD)
        self.db_progress.pack(side="right", padx=12)
        b = tk.Frame(f, bg=DARK)
        b.pack(fill="both", expand=True)
        self.db_tree = ttk.Treeview(b, columns=("#", "Database", "Tables", "Status"),
                                     show="headings", selectmode="browse")
        for c in ("#", "Database", "Tables", "Status"):
            self.db_tree.heading(c, text=c)
        self.db_tree.column("#", width=40, anchor="center")
        self.db_tree.column("Database", width=300)
        self.db_tree.column("Tables", width=80, anchor="center")
        self.db_tree.column("Status", width=150)
        sc = ttk.Scrollbar(b, orient="vertical", command=self.db_tree.yview)
        self.db_tree.configure(yscrollcommand=sc.set)
        self.db_tree.pack(side="left", fill="both", expand=True)
        sc.pack(side="right", fill="y")
        self.db_tree.bind("<Double-Button-1>", self._on_db_select)
        self.db_info = tk.Label(f, text="  🔒 — Scan a target first",
                                font=(FONT, 8), fg="#404a54", bg=DARK, anchor="w")
        self.db_info.pack(fill="x", padx=14, pady=4)

    def _build_tables_tab(self):
        f = tk.Frame(self.nb, bg=DARK)
        self.nb.add(f, text=" 📋 TABLES   ")
        c = tk.Frame(f, bg=CARD, height=36,
                      highlightbackground=LBORDER, highlightthickness=1)
        c.pack(fill="x")
        c.pack_propagate(False)
        tk.Label(c, text="DB:", font=(FONT, 8, "bold"), fg=DIM, bg=CARD
                 ).pack(side="left", padx=(10, 2))
        self.tbl_db_label = tk.Label(c, text="—", font=(FONT, 11, "bold"),
                                      fg=CYAN, bg=CARD)
        self.tbl_db_label.pack(side="left")
        self.tbl_loading = tk.Label(c, text="", font=(FONT, 8), fg=YELLOW, bg=CARD)
        self.tbl_loading.pack(side="left", padx=8)
        tk.Button(c, text="🔄 Refresh", font=(FONT, 8), bg="#1a2a3a", fg=WHITE,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=self._load_tables).pack(side="left", padx=2)
        tk.Button(c, text="📋 List All", font=(FONT, 8), bg="#1a2a3a", fg=CYAN,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=self._list_all_tables).pack(side="left", padx=2)
        tk.Button(c, text="🔍 Find Interesting", font=(FONT, 8), bg="#1a2a3a", fg=GREEN,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=self._find_interesting_tables).pack(side="left", padx=2)
        b = tk.Frame(f, bg=DARK)
        b.pack(fill="both", expand=True)
        self.tbl_tree = ttk.Treeview(b, columns=("#", "Table", "Columns", "Interesting"),
                                      show="headings", selectmode="browse")
        for c in ("#", "Table", "Columns", "Interesting"):
            self.tbl_tree.heading(c, text=c)
        self.tbl_tree.column("#", width=40, anchor="center")
        self.tbl_tree.column("Table", width=300)
        self.tbl_tree.column("Columns", width=80, anchor="center")
        self.tbl_tree.column("Interesting", width=120)
        sc = ttk.Scrollbar(b, orient="vertical", command=self.tbl_tree.yview)
        self.tbl_tree.configure(yscrollcommand=sc.set)
        self.tbl_tree.pack(side="left", fill="both", expand=True)
        sc.pack(side="right", fill="y")
        self.tbl_tree.bind("<Double-Button-1>", self._on_tbl_select)
        self.tbl_info = tk.Label(f, text="  🔒 — Select a database first",
                                 font=(FONT, 8), fg="#404a54", bg=DARK, anchor="w")
        self.tbl_info.pack(fill="x", padx=14, pady=4)

    def _build_columns_tab(self):
        f = tk.Frame(self.nb, bg=DARK)
        self.nb.add(f, text=" 📊 COLUMNS   ")
        c = tk.Frame(f, bg=CARD, height=36,
                      highlightbackground=LBORDER, highlightthickness=1)
        c.pack(fill="x")
        c.pack_propagate(False)
        self.col_tbl_label = tk.Label(c, text="Table:", font=(FONT, 8, "bold"),
                                       fg=DIM, bg=CARD)
        self.col_tbl_label.pack(side="left", padx=(10, 2))
        self.col_tbl_val = tk.Label(c, text="—", font=(FONT, 11, "bold"),
                                     fg=CYAN, bg=CARD)
        self.col_tbl_val.pack(side="left", padx=(0, 12))
        tk.Label(c, text="DB:", font=(FONT, 8, "bold"), fg=DIM, bg=CARD
                 ).pack(side="left", padx=(0, 2))
        self.col_db_val = tk.Label(c, text="—", font=(FONT, 9), fg=DIM, bg=CARD)
        self.col_db_val.pack(side="left")
        self.col_loading = tk.Label(c, text="", font=(FONT, 8), fg=YELLOW, bg=CARD)
        self.col_loading.pack(side="left", padx=8)
        tk.Button(c, text="🔄 Refresh", font=(FONT, 8), bg="#1a2a3a", fg=WHITE,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=self._load_columns).pack(side="left", padx=2)
        tk.Button(c, text="🔍 Find Sensitive", font=(FONT, 8), bg="#1a2a3a", fg=ORANGE,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=self._find_sensitive_cols).pack(side="left", padx=2)
        tk.Button(c, text="▶ Dump Now", font=(FONT, 8), bg="#1a3a1a", fg=GREEN,
                  bd=0, padx=8, pady=1, cursor="hand2",
                  command=lambda: (self.nb.select(4), self._load_dump())).pack(side="left", padx=2)
        b = tk.Frame(f, bg=DARK)
        b.pack(fill="both", expand=True)
        cols = ("#", "Column", "Type", "Nullable", "PK", "Default", "Sensitive")
        self.col_tree = ttk.Treeview(b, columns=cols, show="headings", selectmode="browse")
        widths = [40, 170, 130, 70, 45, 130, 80]
        anchors = ["center", "w", "w", "center", "center", "w", "center"]
        for i, col in enumerate(cols):
            self.col_tree.heading(col, text=col)
            self.col_tree.column(col, width=widths[i], anchor=anchors[i])
        sc = ttk.Scrollbar(b, orient="vertical", command=self.col_tree.yview)
        self.col_tree.configure(yscrollcommand=sc.set)
        self.col_tree.pack(side="left", fill="both", expand=True)
        sc.pack(side="right", fill="y")
        self.col_tree.bind("<Double-Button-1>", self._on_col_select)
        self.col_info = tk.Label(f, text="  🔒 — Select a table first",
                                 font=(FONT, 8), fg="#404a54", bg=DARK, anchor="w")
        self.col_info.pack(fill="x", padx=14, pady=4)

    def _build_dump_tab(self):
        f = tk.Frame(self.nb, bg=DARK)
        self.nb.add(f, text=" 💾 DUMP   ")
        c = tk.Frame(f, bg=CARD, height=34,
                      highlightbackground=LBORDER, highlightthickness=1)
        c.pack(fill="x")
        c.pack_propagate(False)
        tk.Label(c, text="Table:", font=(FONT, 8, "bold"), fg=DIM, bg=CARD
                 ).pack(side="left", padx=(10, 2))
        self.dump_tbl_label = tk.Label(c, text="—", font=(FONT, 11, "bold"),
                                        fg=CYAN, bg=CARD)
        self.dump_tbl_label.pack(side="left", padx=(0, 12))
        tk.Label(c, text="DB:", font=(FONT, 8, "bold"), fg=DIM, bg=CARD
                 ).pack(side="left", padx=(0, 2))
        self.dump_db_label = tk.Label(c, text="—", font=(FONT, 9), fg=DIM, bg=CARD)
        self.dump_db_label.pack(side="left")

        paned = tk.PanedWindow(f, bg=DARK, sashwidth=2, sashrelief="flat",
                                orient="vertical")
        paned.pack(fill="both", expand=True)

        col_sel = tk.Frame(paned, bg=CARD2,
                           highlightbackground=LBORDER, highlightthickness=1)
        paned.add(col_sel, height=100)
        sel_hdr = tk.Frame(col_sel, bg=CARD2)
        sel_hdr.pack(fill="x", padx=8, pady=(4, 0))
        tk.Label(sel_hdr, text="COLUMNS TO DUMP", font=(FONT, 8, "bold"),
                 fg=CYAN, bg=CARD2).pack(side="left")
        self._toggle_all_var = tk.BooleanVar(value=True)
        tk.Checkbutton(sel_hdr, text="Select All", variable=self._toggle_all_var,
                       font=(FONT, 8), fg=DIM, bg=CARD2, selectcolor=DARK,
                       command=self._toggle_all_cols).pack(side="left", padx=10)
        self.dump_loading = tk.Label(sel_hdr, text="", font=(FONT, 8), fg=YELLOW, bg=CARD2)
        self.dump_loading.pack(side="right", padx=8)

        self._col_scroll = ScrollFrame(col_sel, bg=CARD2)
        self._col_scroll.pack(fill="both", expand=True, padx=8, pady=4)

        dump_frame = tk.Frame(paned, bg=DARK)
        paned.add(dump_frame)
        tb_frame = tk.Frame(dump_frame, bg=CARD, height=32)
        tb_frame.pack(fill="x")
        tb_frame.pack_propagate(False)
        self.dump_btn = tk.Button(tb_frame, text="  🚀 DUMP  ",
                                   font=(FONT, 9, "bold"),
                                   bg="#18a048", fg="white", bd=0, padx=14, pady=2,
                                   cursor="hand2", command=self._load_dump,
                                   activebackground=_shift("#18a048", 20),
                                   activeforeground="white")
        self.dump_btn.pack(side="left", padx=6, pady=2)

        for txt, bg, fg, cmd in [
            ("📋 Copy", "#1a2a3a", WHITE, self._copy_dump),
            ("🧹 Clear", "#1a2a3a", DIM, lambda: self.dump_output.delete(1.0, "end")),
            ("💾 JSON", "#1a2a3a", CYAN, self._save_dump),
            ("📄 CSV", "#1a2a3a", YELLOW, self._save_dump_csv),
        ]:
            tk.Button(tb_frame, text=txt, font=(FONT, 8), bg=bg, fg=fg, bd=0,
                      padx=8, pady=2, cursor="hand2",
                      activebackground=_shift(bg, 15),
                      command=cmd).pack(side="left", padx=3, pady=2)

        self.dump_output = scrolledtext.ScrolledText(
            dump_frame, bg="#0a1018", fg=WHITE, font=(FONT, 9),
            insertbackground=GREEN, bd=0, padx=12, pady=8,
            state="normal", wrap="none",
            highlightbackground=BORDER, highlightthickness=0)
        self.dump_output.pack(fill="both", expand=True)
        for t, c in [("green", GREEN), ("red", RED), ("dim", DIM), ("cyan", CYAN),
                      ("yellow", YELLOW), ("orange", ORANGE)]:
            self.dump_output.tag_configure(t, foreground=c)
        self.dump_output.tag_configure("bold", font=(FONT, 10, "bold"))
        self.dump_info = tk.Label(f, text="  🔒 — Select a table first",
                                  font=(FONT, 8), fg="#404a54", bg=DARK, anchor="w")
        self.dump_info.pack(fill="x", padx=14, pady=2)

    def _build_sensitive_tab(self):
        f = tk.Frame(self.nb, bg=DARK)
        self.nb.add(f, text=" 🔑 SENSITIVE   ")
        h = tk.Frame(f, bg=CARD, height=34,
                      highlightbackground=LBORDER, highlightthickness=1)
        h.pack(fill="x")
        h.pack_propagate(False)
        tk.Label(h, text="SENSITIVE DATA SCANNER", font=(FONT, 9, "bold"),
                 fg=CYAN, bg=CARD).pack(side="left", padx=12)
        self.sens_loading = tk.Label(h, text="", font=(FONT, 8), fg=YELLOW, bg=CARD)
        self.sens_loading.pack(side="left", padx=10)
        b = tk.Frame(f, bg=DARK)
        b.pack(fill="both", expand=True)
        cols = ("Risk", "DB", "Table", "Column", "Category", "Sample", "Confidence")
        self.sens_tree = ttk.Treeview(b, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            self.sens_tree.heading(c, text=c)
        for c, w in [("Risk", 80), ("DB", 130), ("Table", 130), ("Column", 130),
                      ("Category", 110), ("Sample", 220), ("Confidence", 85)]:
            self.sens_tree.column(c, width=w)
        sc = ttk.Scrollbar(b, orient="vertical", command=self.sens_tree.yview)
        self.sens_tree.configure(yscrollcommand=sc.set)
        self.sens_tree.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        sc.pack(side="right", fill="y", pady=4)
        self.sens_info = tk.Label(f, text="  🔒 — Scan a target first",
                                  font=(FONT, 8), fg="#404a54", bg=DARK, anchor="w")
        self.sens_info.pack(fill="x", padx=14, pady=4)

    def _build_schema_tab(self):
        f = tk.Frame(self.nb, bg=DARK)
        self.nb.add(f, text=" 📐 SCHEMA   ")
        h = tk.Frame(f, bg=CARD, height=34,
                      highlightbackground=LBORDER, highlightthickness=1)
        h.pack(fill="x")
        h.pack_propagate(False)
        tk.Label(h, text="DATABASE SCHEMA EXPLORER", font=(FONT, 9, "bold"),
                 fg=CYAN, bg=CARD).pack(side="left", padx=12)
        self.sch_loading = tk.Label(h, text="", font=(FONT, 8), fg=YELLOW, bg=CARD)
        self.sch_loading.pack(side="left", padx=10)
        self.schema_output = scrolledtext.ScrolledText(
            f, bg="#0a111a", fg=WHITE, font=(FONT, 9),
            insertbackground=GREEN, bd=0, padx=16, pady=12,
            state="normal", wrap="word",
            highlightbackground=BORDER, highlightthickness=0)
        self.schema_output.pack(fill="both", expand=True)
        for t, c in [("green", GREEN), ("cyan", CYAN), ("dim", DIM),
                      ("yellow", YELLOW), ("orange", ORANGE), ("purple", PURPLE)]:
            self.schema_output.tag_configure(t, foreground=c)
        self.schema_output.tag_configure("bold", font=(FONT, 10, "bold"))

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg="#060a0e", height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.info_label = tk.Label(bar, text="● READY", font=(FONT, 8),
                                    fg=DIM, bg="#060a0e", anchor="w")
        self.info_label.pack(side="left", padx=12)
        self.count_label = tk.Label(bar, text="", font=(FONT, 8),
                                     fg=DIM, bg="#060a0e", anchor="e")
        self.count_label.pack(side="right", padx=12)
        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x", side="bottom", before=bar)

    def _build_hint(self):
        hint = tk.Frame(self.root, bg="#060a0e", height=18)
        hint.pack(fill="x", side="bottom")
        hint.pack_propagate(False)
        tk.Label(hint,
                 text="Enter  Run  |  Ctrl+R  Scan  |  Ctrl+S / Esc  Stop  |  Ctrl+Q  Quit  |  Dbl-click drill-down",
                 font=(FONT, 7), fg="#303a44", bg="#060a0e").pack(pady=2)

    # ═══════════════ TAB STATE ═══════════════

    def _set_tab_state(self, idx, enabled):
        self.tab_states[idx] = enabled
        try:
            self.nb.tab(idx, state="normal" if enabled else "disabled")
        except tk.TclError:
            pass

    def _update_tab_states(self):
        for i, en in enumerate(self.tab_states):
            try:
                self.nb.tab(i, state="normal" if en else "disabled")
            except tk.TclError:
                pass

    def _on_tab_change(self, e=None):
        try:
            sel = self.nb.index(self.nb.select())
        except tk.TclError:
            return
        if 0 < sel < len(self.tab_states) and not self.tab_states[sel]:
            self.nb.select(0)

    # ═══════════════ LOGGING ═══════════════

    def _log(self, text, color="dim"):
        tag = color if color in {"green", "red", "yellow", "cyan", "dim",
                                  "orange", "purple", "blue", "verbose"} else "dim"
        self.scan_output.insert("end", f"  [{TS()}] {text}\n", tag)
        self.scan_output.see("end")

    def _log_verbose(self, line):
        """Log raw verbose output from Go engine"""
        # Color-code by content
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
            self._draw_led("scanning")
            self.status_label.config(text="● SCANNING", fg=YELLOW)
            self.run_btn.set_disabled(True)
            self.stop_btn.set_disabled(False)
            self._spinner.start()
            self.info_label.config(text="● SCANNING — streaming verbose output...")
        else:
            self._draw_led("idle")
            self.status_label.config(text="● IDLE", fg=GREEN)
            self.run_btn.set_disabled(False)
            self.stop_btn.set_disabled(True)
            self._spinner.stop()
            self.info_label.config(text="● READY")

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
            with open(path, 'w') as f:
                f.write(text)
            self._log(f"💾 Dump saved: {path}", "green")

    def _save_dump_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV", "*.csv")])
        if path:
            text = self.dump_output.get(1.0, "end-1c")
            lines = [l.strip() for l in text.strip().split('\n') if l.startswith("  ")]
            with open(path, 'w') as f:
                f.write('\n'.join(lines))
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
        self.results = []
        self.findings = []
        self.enums = []
        self.databases = []
        self.tables = []
        self.columns = []
        self.selected_db = None
        self.selected_table = None
        self._col_vars = {}
        self._payload_count = 0
        self._vuln_count = 0
        self._col_scroll.clear()
        for i in range(1, 7):
            self._set_tab_state(i, False)
        self._print_banner()
        self.count_label.config(text="")
        self.db_count_label.config(text="")
        self._stat_elapsed.config(text="⏱ 00:00")
        self._stat_payloads.config(text="■ 0 payloads")
        self._stat_vulns.config(text="⚠ 0 vulns")
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
        self._log(f"▶ SCAN  {url}", "cyan")
        self._log("   Risk: 5 | Threads: 30 | WAF Bypass: ON | Verbose: ON", "dim")
        self._scan_start_time = time.time()
        self._set_busy(True)
        self.info_label.config(text=f"● Scanning {url}...")
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

    def _inc_payload(self):
        self._payload_count += 1

    def _inc_vuln(self):
        self._vuln_count += 1

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.stop()
            self._log("■ STOPPED by user", "yellow")
            self._set_busy(False)
            self.info_label.config(text="● Scan stopped")

    def _on_result(self, results):
        self.results = results
        self.findings = [r for r in results if r.get('parameter') != 'enumeration']
        self.enums = [r for r in results if r.get('parameter') == 'enumeration']
        self._vuln_count = len(self.findings)

        self._draw_led("done")
        self._log(f"✅ DONE  {len(results)} total | {len(self.findings)} vulns | "
                   f"{len(self.enums)} enums", "green")

        if self.findings:
            self._log("", "dim")
            self._log("── VULNERABILITIES ──", "bold")
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
            self._log(f"🗄️ DATABASES ({len(self.databases)})", "bold")
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
            text=f"● Done — {len(self.findings)} vulns, {len(self.databases)} databases")
        self._show_schema()

    def _on_scan_error(self, msg):
        self._log(f"ERROR: {msg}", "red")
        self._set_busy(False)
        self._draw_led("error")
        self.status_label.config(text="● ERROR", fg=RED)
        self.info_label.config(text=f"● Error: {msg}")

    # ═══════════════ DATABASES ═══════════════

    def _populate_dbs(self):
        self._clear_tree(self.db_tree)
        for i, db in enumerate(self.databases):
            tag = "e" if i % 2 == 0 else "o"
            self.db_tree.insert("", "end", values=(i + 1, db, "?"), tags=(tag,))
        self.db_tree.tag_configure("e", background="#0d1420")
        self.db_tree.tag_configure("o", background="#111820")
        self.db_count_label.config(text=f"{len(self.databases)} databases")

    def _on_db_select(self, e):
        sel = self.db_tree.selection()
        if not sel:
            return
        vals = self.db_tree.item(sel[0], "values")
        if len(vals) >= 2:
            self.selected_db = vals[1]
            self.tbl_db_label.config(text=self.selected_db)
            self._set_tab_state(2, True)
            self.nb.select(2)
            self.tbl_info.config(text=f"  Loading tables from {self.selected_db}...")
            self._load_tables()

    # ═══════════════ TABLES ═══════════════

    def _load_tables(self):
        if not self.selected_db or not self.scan_url:
            return
        self._clear_tree(self.tbl_tree)
        self.tbl_loading.config(text="loading...")

        def task():
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled():
                    return
                results = engine.run(self.scan_url, list_tables=True,
                                      database=self.selected_db)
                tbls = []
                if results:
                    for r in results:
                        if r.get('type') == 'list-tables':
                            tbls.extend(t.strip() for t in
                                        r.get('payload', '').split(',') if t.strip())
                self.tables = tbls
                self.root.after(0, self._populate_tables)
            except Exception as ex:
                self.root.after(0, lambda: self.tbl_info.config(text=f"  Error: {ex}"))

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
            self.tbl_tree.insert("", "end",
                                  values=(i + 1, tbl, "?", interesting_text),
                                  tags=(tag,))
        self.tbl_tree.tag_configure("e", background="#0d1420")
        self.tbl_tree.tag_configure("o", background="#111820")
        self.tbl_tree.tag_configure("interesting", background="#2a1a1a")
        self.tbl_loading.config(text="")
        self.tbl_info.config(text=f"  {len(self.tables)} tables — double-click to view columns")

    def _on_tbl_select(self, e):
        sel = self.tbl_tree.selection()
        if not sel:
            return
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
        if not self.selected_db or not self.selected_table or not self.scan_url:
            return
        self._clear_tree(self.col_tree)
        self.col_loading.config(text="loading...")

        def task():
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled():
                    return
                results = engine.run(self.scan_url, list_columns=True,
                                      database=self.selected_db,
                                      table=self.selected_table)
                cols = []
                if results:
                    for r in results:
                        if r.get('type') == 'list-columns':
                            cols.extend(c.strip() for c in
                                        r.get('payload', '').split(',') if c.strip())
                self.columns = cols
                self.root.after(0, self._populate_columns)
            except Exception as ex:
                self.root.after(0, lambda: self.col_info.config(text=f"  Error: {ex}"))

        threading.Thread(target=task, daemon=True).start()

    def _populate_columns(self):
        self._clear_tree(self.col_tree)
        for i, col in enumerate(self.columns):
            tag = "e" if i % 2 == 0 else "o"
            self.col_tree.insert("", "end",
                                  values=(i + 1, col, "—", "—", "—", "—", ""),
                                  tags=(tag,))
        self.col_tree.tag_configure("e", background="#0d1420")
        self.col_tree.tag_configure("o", background="#111820")
        self.col_loading.config(text="")
        self.col_info.config(text=f"  {len(self.columns)} columns — double-click to dump")
        self._build_col_checkboxes()

    def _build_col_checkboxes(self):
        self._col_scroll.clear()
        self._col_vars = {}
        self._toggle_all_var.set(True)
        row = tk.Frame(self._col_scroll.inner, bg=CARD2)
        row.pack(fill="x", anchor="w", pady=2)
        for col in self.columns:
            var = tk.BooleanVar(value=True)
            self._col_vars[col] = var
            cb = tk.Checkbutton(row, text=col, variable=var,
                                font=(FONT, 8), fg=CYAN, bg=CARD2,
                                selectcolor=DARK, activebackground=CARD2,
                                activeforeground=CYAN, anchor="w")
            cb.pack(side="left", padx=(0, 4))

    def _on_col_select(self, e):
        self.nb.select(4)
        self._load_dump()

    # ═══════════════ DUMP ═══════════════

    def _load_dump(self):
        if not self.selected_db or not self.selected_table or not self.scan_url:
            return
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
                results = engine.run(self.scan_url, dump_table=True,
                                      database=self.selected_db,
                                      table=self.selected_table,
                                      columns=selected_cols if selected_cols else ["*"])
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
            self.dump_info.config(text="  No data returned")
            return
        entries = [r for r in results if r.get('type') == 'dump-table']
        if not entries:
            entries = results[:100]
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
            self.schema_output.insert("end", "  No databases found\n", "yellow")
            return
        for db in self.databases:
            self.schema_output.insert("end", f"  📁 {db}\n", "green")
        self.schema_output.insert("end",
            f"\n  [{TS()}] Schema loaded — {len(self.databases)} databases\n", "dim")

    # ═══════════════ EXPLORE ACTIONS ═══════════════

    def _load_dbs(self):
        """Re-load databases from current scan"""
        if not self.scan_url:
            return
        self.db_progress.config(text="loading...")
        def task():
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled():
                    return
                results = engine.run(self.scan_url, list_dbs=True)
                dbs = []
                if results:
                    for r in results:
                        if r.get('type') == 'list-dbs':
                            dbs.extend(d.strip() for d in
                                       r.get('payload','').split(',') if d.strip())
                self.databases = dbs
                self.root.after(0, self._populate_dbs)
                self.root.after(0, lambda: self.db_progress.config(text=""))
            except Exception:
                self.root.after(0, lambda: self.db_progress.config(text="error"))
        threading.Thread(target=task, daemon=True).start()

    def _list_all_dbs(self):
        """Log all databases to scan output"""
        if not self.databases:
            self._log("No databases to list", "yellow")
            return
        self._log(f"📋 ALL DATABASES ({len(self.databases)})", "bold")
        for db in self.databases:
            self._log(f"   📁 {db}", "green")

    def _explore_all_dbs(self):
        """Enumerate tables for EVERY database in parallel"""
        if not self.scan_url or not self.databases:
            self._log("No databases to explore — scan first", "yellow")
            return
        self._log(f"🔎 Exploring ALL {len(self.databases)} databases...", "cyan")
        self._set_busy(True)

        def explore_one(db):
            try:
                engine = GoEngine()
                if not engine.available or not engine.ensure_compiled():
                    return []
                results = engine.run(self.scan_url, list_tables=True, database=db)
                tbls = []
                if results:
                    for r in results:
                        if r.get('type') == 'list-tables':
                            tbls.extend(t.strip() for t in
                                       r.get('payload','').split(',') if t.strip())
                return tbls
            except Exception:
                return []

        def task():
            all_dbs = self.databases.copy()
            for db in all_dbs:
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
        """Log all tables to scan output"""
        if not self.tables:
            self._log("No tables to list", "yellow")
            return
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
        """Find and highlight interesting tables"""
        if not self.tables:
            return
        interesting_keywords = ['user','admin','account','credential','login',
                                'passwd','secret','token','member','customer',
                                'employee','person','staff','auth','profile',
                                'session','password','email','config']
        found = [t for t in self.tables if any(k in t.lower() for k in interesting_keywords)]
        if found:
            self._log(f"🔍 Found {len(found)} interesting tables:", "green")
            for t in found:
                self._log(f"   🔴 {t}", "orange")
            # Highlight in tree
            for item in self.tbl_tree.get_children():
                vals = self.tbl_tree.item(item, "values")
                if len(vals) >= 2 and any(k in vals[1].lower() for k in interesting_keywords):
                    self.tbl_tree.item(item, tags=("interesting",))
            self.tbl_tree.tag_configure("interesting", background="#2a1a1a")
        else:
            self._log("No interesting tables found", "yellow")

    def _find_sensitive_cols(self):
        """Find sensitive columns in current table"""
        if not self.columns:
            return
        sensitive_keywords = ['pass', 'pwd', 'secret', 'token', 'key', 'credit',
                              'card', 'ssn', 'social', 'security', 'pin', 'auth',
                              'hash', 'salt', 'password', 'email', 'phone', 'address']
        found = [c for c in self.columns if any(k in c.lower() for k in sensitive_keywords)]
        if found:
            self._log(f"🔍 Sensitive columns in {self.selected_table}:", "orange")
            for c in found:
                self._log(f"   ⚠ {c}", "red")
            # Highlight in tree
            for item in self.col_tree.get_children():
                vals = self.col_tree.item(item, "values")
                if len(vals) >= 2 and any(k in vals[1].lower() for k in sensitive_keywords):
                    self.col_tree.item(item, tags=("sensitive",))
            self.col_tree.tag_configure("sensitive", background="#2a1a1a")
        else:
            self._log(f"No sensitive columns found in {self.selected_table}", "dim")

    # ═══════════════ CLOSE ═══════════════

    def _on_close(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.stop()
        try:
            self.root.destroy()
        except Exception:
            pass
        os._exit(0)

    def run(self):
        self.root.mainloop()


# ── SCAN THREAD WITH STREAMING ──

class ScanThread(threading.Thread):
    def __init__(self, url, opts, on_line=None, on_result=None,
                 on_error=None, on_payload=None, on_vuln=None):
        super().__init__(daemon=True)
        self.url = url
        self.opts = opts
        self.on_line = on_line
        self.on_result = on_result
        self.on_error = on_error
        self.on_payload = on_payload
        self.on_vuln = on_vuln
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

    def run(self):
        try:
            engine = GoEngine()
            if not engine.available:
                self.on_error("Go binary not found")
                return
            if not engine.ensure_compiled():
                self.on_error("Go compilation failed")
                return

            def line_handler(line):
                if self.stopped():
                    return
                if self.on_line:
                    self.on_line(line)
                if "payload" in line.lower() or "testing" in line.lower():
                    if self.on_payload:
                        self.on_payload()
                if "vuln" in line.lower() or "found" in line.lower() or "SUCCESS" in line:
                    if self.on_vuln:
                        self.on_vuln()

            results = engine.run_stream(self.url, on_verbose=line_handler, **self.opts)
            if self.stopped():
                return
            # Any list response (including []) is a valid scan result
            if isinstance(results, list):
                if results and isinstance(results[0], dict) and 'error' in results[0]:
                    self.on_error(results[0]['error'])
                else:
                    self.on_result(results)
            elif results is None:
                self.on_error("Engine returned no results")
            else:
                # Single dict or other result
                self.on_result([results] if isinstance(results, dict) else [])
        except Exception as e:
            self.on_error(str(e))


def launch_gui():
    SQLiGUI().run()


if __name__ == "__main__":
    launch_gui()
