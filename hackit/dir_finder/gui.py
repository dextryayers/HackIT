"""
Dir Finder GUI v3.0 — Professional tkinter interface with full Go engine integration.
Deep reconnaissance with Smart Analyzer, live stats, and modern dark theme.
"""
import json, os, re, subprocess, sys, threading, queue, time, webbrowser
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

ENGINE_DIR = Path(__file__).parent
GO_BINARY = ENGINE_DIR / "go" / "dir_finder"
DB_DIR = ENGINE_DIR / "db"
ANALYZER_SCRIPT = ENGINE_DIR / "analyzer.py"

ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# ── Modern Dark Palette ──────────────────────────────────────────────
class Palette:
    BG        = "#0d1117"
    MID       = "#161b22"
    CARD      = "#1c2333"
    CARD2     = "#21262d"
    WHITE     = "#e6edf3"
    GREEN     = "#3fb950"
    RED       = "#f85149"
    YELLOW    = "#d29922"
    CYAN      = "#58a6ff"
    BLUE      = "#1f6feb"
    DIM       = "#8b949e"
    ORANGE    = "#d47602"
    PINK      = "#f778ba"
    PURPLE    = "#a371f7"
    BORDER    = "#30363d"
    HEADER_BG = "#0d1117"
    INPUT_BG  = "#0d1117"
    SUCCESS   = "#2ea043"
    DANGER    = "#da3633"
    FONT      = ("Consolas", 10)
    UI_FONT   = ("Segoe UI", 10)
    BOLD      = ("Segoe UI", 10, "bold")
    TITLE     = ("Segoe UI", 16, "bold")
    MONO_SM   = ("Consolas", 9)
    MONO_LG   = ("Consolas", 11)

STATUS_TAGS = {
    (200, 299): ("s2xx", Palette.GREEN, "2xx"),
    (300, 399): ("s3xx", Palette.CYAN,  "3xx"),
    (400, 499): ("s4xx", Palette.YELLOW, "4xx"),
    (500, 599): ("s5xx", Palette.RED,    "5xx"),
}

def strip_ansi(text):
    return ANSI_RE.sub("", text)

def status_tag(code):
    for (lo, hi), (tag, color, _) in STATUS_TAGS.items():
        if lo <= code <= hi:
            return tag, color
    return "default", Palette.WHITE


class SmartAnalyzerDialog:
    """Modal dialog to run Smart Analyzer and import results"""
    def __init__(self, parent, target_url):
        self.parent = parent
        self.target_url = target_url
        self.result = None
        self._build()

    def _build(self):
        self.win = tk.Toplevel(self.parent)
        self.win.title("Smart Analysis")
        self.win.geometry("700x520")
        self.win.configure(bg=Palette.BG)
        self.win.transient(self.parent)
        self.win.grab_set()

        hdr = tk.Frame(self.win, bg=Palette.CARD2, height=50)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="\U0001f50d  Smart Analysis Engine", fg=Palette.CYAN,
                 bg=Palette.CARD2, font=Palette.TITLE).place(x=16, rely=0.5, anchor=tk.W)

        sep = tk.Frame(self.win, bg=Palette.BORDER, height=1)
        sep.pack(fill=tk.X)

        f = tk.Frame(self.win, bg=Palette.BG, padx=12, pady=8)
        f.pack(fill=tk.BOTH, expand=True)

        tk.Label(f, text="Target:", fg=Palette.DIM, bg=Palette.BG,
                 font=Palette.UI_FONT).pack(anchor=tk.W)
        self.url_lbl = tk.Label(f, text=self.target_url, fg=Palette.CYAN, bg=Palette.BG,
                                font=Palette.MONO_LG, wraplength=600, anchor=tk.W)
        self.url_lbl.pack(fill=tk.X, pady=(0, 8))

        tk.Label(f, text="Analysis Output:", fg=Palette.DIM, bg=Palette.BG,
                 font=Palette.UI_FONT).pack(anchor=tk.W)

        tf = tk.Frame(f, bg=Palette.MID)
        tf.pack(fill=tk.BOTH, expand=True)

        self.log = tk.Text(tf, wrap=tk.WORD, state=tk.DISABLED, bg=Palette.MID,
                          fg=Palette.WHITE, font=Palette.MONO_SM, padx=6, pady=4,
                          relief=tk.FLAT, bd=1)
        sb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        bf = tk.Frame(self.win, bg=Palette.BG, padx=12, pady=8)
        bf.pack(fill=tk.X)

        self.run_btn = tk.Button(bf, text="\u25b6  Start Analysis", font=Palette.BOLD,
                                 bg=Palette.SUCCESS, fg=Palette.WHITE, relief=tk.FLAT,
                                 padx=16, pady=6, cursor="hand2",
                                 activebackground=Palette.GREEN, activeforeground=Palette.WHITE,
                                 command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.import_btn = tk.Button(bf, text="\u2b07  Import Endpoints", font=Palette.BOLD,
                                    bg=Palette.BLUE, fg=Palette.WHITE, relief=tk.FLAT,
                                    padx=16, pady=6, cursor="hand2", state=tk.DISABLED,
                                    activebackground=Palette.CYAN, activeforeground=Palette.WHITE,
                                    command=self._import)
        self.import_btn.pack(side=tk.LEFT)

        self.status = tk.Label(bf, text="Ready to analyze", fg=Palette.DIM, bg=Palette.BG)
        self.status.pack(side=tk.RIGHT)

    def _log(self, msg):
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _run(self):
        self.run_btn.config(state=tk.DISABLED, text="\u23f3  Running...")
        self.status.config(text="Analyzing...")
        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Starting smart analysis...\n")
        threading.Thread(target=self._run_worker, daemon=True).start()

    def _run_worker(self):
        try:
            from hackit.dir_finder.analyzer import SmartAnalyzer
            analyzer = SmartAnalyzer(self.target_url)
            self.result = analyzer.run_smart_analysis()
            analyzer.save_analysis(str(ENGINE_DIR / "smart_analysis.json"))

            self.win.after(0, self._on_complete)
        except Exception as e:
            self.win.after(0, lambda: self._on_error(str(e)))

    def _on_complete(self):
        r = self.result
        self._log("[+] Analysis complete!")
        self._log(f"[+] WAF: {r['waf']}")
        self._log(f"[+] CMS: {r['cms']}")
        self._log(f"[+] Tech: {', '.join(r['tech'][:8])}")
        self._log(f"[+] Endpoints discovered: {len(r['endpoints'])}")
        self._log(f"[+] Wordlist categories: {', '.join(r['recommended_wordlists'][:5])}")
        if r.get('js_files'):
            self._log(f"[+] JS files found: {len(r['js_files'])}")
        self.run_btn.config(text="\u2713  Done", state=tk.NORMAL)
        self.import_btn.config(state=tk.NORMAL)
        self.status.config(text=f"Done — {len(r['endpoints'])} endpoints", fg=Palette.GREEN)

    def _on_error(self, err):
        self._log(f"[!] Error: {err}")
        self.run_btn.config(text="\u25b6  Retry", state=tk.NORMAL)
        self.status.config(text="Failed", fg=Palette.RED)

    def _import(self):
        if self.result:
            self.parent.event_generate("<<ImportEndpoints>>")
        self.win.destroy()

    def wait(self):
        self.parent.wait_window(self.win)
        return self.result


class DirFinderGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Dir Finder v3.0 — HackIT")
        self.root.geometry("1360x840")
        self.root.minsize(1024, 680)
        self.root.configure(bg=Palette.BG)
        self._setup_style()

        # State
        self.process = None
        self.running = False
        self.results = []
        self._all_items = []
        self.log_queue = queue.Queue()
        self.start_time = None
        self._scan_progress = 0
        self._elapsed_id = None
        self._smart_endpoints = []
        self.paused = False

        # String vars for all controls
        self.url_var = tk.StringVar()
        self.wl_var = tk.StringVar()
        self.custom_var = tk.StringVar()
        self.threads_var = tk.StringVar(value="50")
        self.timeout_var = tk.StringVar(value="10")
        self.delay_var = tk.StringVar(value="0")
        self.ext_var = tk.StringVar(value="php,asp,html,txt")
        self.method_var = tk.StringVar(value="GET")
        self.exclude_var = tk.StringVar(value="404")
        self.include_var = tk.StringVar()
        self.recursive_depth_var = tk.StringVar(value="3")
        self.max_rate_var = tk.StringVar(value="0")
        self.retries_var = tk.StringVar(value="2")
        self.user_agent_var = tk.StringVar()
        self.cookie_var = tk.StringVar()
        self.auth_var = tk.StringVar()
        self.auth_type_var = tk.StringVar(value="basic")
        self.proxy_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.min_size_var = tk.StringVar()
        self.max_size_var = tk.StringVar()
        self.exclude_sizes_var = tk.StringVar()
        self.exclude_text_var = tk.StringVar()
        self.exclude_regex_var = tk.StringVar()
        self.match_status_var = tk.StringVar()
        self.filter_status_var = tk.StringVar()
        self.wordlist_cat_var = tk.StringVar()
        self.prefix_var = tk.StringVar()
        self.suffix_var = tk.StringVar()
        self.subdirs_var = tk.StringVar()
        self.wl_count_var = tk.StringVar(value="Paths: 0")
        self.stat_wl_var = tk.StringVar(value="Wordlist: 0")

        # Bool vars
        self.follow_var = tk.BooleanVar(value=False)
        self.recursive_var = tk.BooleanVar(value=False)
        self.deep_recursive_var = tk.BooleanVar(value=False)
        self.force_recursive_var = tk.BooleanVar(value=False)
        self.random_agent_var = tk.BooleanVar(value=False)
        self.detect_waf_var = tk.BooleanVar(value=False)
        self.detect_tech_var = tk.BooleanVar(value=False)
        self.detect_backup_var = tk.BooleanVar(value=False)
        self.smart_filter_var = tk.BooleanVar(value=True)
        self.extract_js_var = tk.BooleanVar(value=False)
        self.http2_var = tk.BooleanVar(value=False)
        self.crawl_var = tk.BooleanVar(value=False)
        self.full_url_var = tk.BooleanVar(value=False)
        self.quiet_var = tk.BooleanVar(value=False)
        self.verbose_var = tk.BooleanVar(value=False)
        self.tor_var = tk.BooleanVar(value=False)
        self.follow_redirects_var = tk.BooleanVar(value=False)
        self.force_ext_var = tk.BooleanVar(value=False)
        self.uppercase_var = tk.BooleanVar(value=False)
        self.lowercase_var = tk.BooleanVar(value=False)
        self.capital_var = tk.BooleanVar(value=False)
        self.api_mode_var = tk.BooleanVar(value=False)
        self.save_session_var = tk.BooleanVar(value=False)
        self.auto_calibration_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._update_wordlist_info()
        self.root.after(100, self._poll_queue)

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        bg = Palette.BG
        style.configure(".", background=bg, foreground=Palette.WHITE,
                        fieldbackground=Palette.INPUT_BG, selectbackground=Palette.BLUE,
                        font=Palette.UI_FONT)
        style.configure("TLabel", background=bg, foreground=Palette.WHITE)
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=Palette.CARD, foreground=Palette.CYAN,
                        bordercolor=Palette.BORDER, lightcolor=Palette.BORDER, darkcolor=Palette.BORDER)
        style.configure("TLabelframe.Label", background=Palette.CARD, foreground=Palette.CYAN,
                        font=("Segoe UI", 9, "bold"))
        style.configure("TButton", background=Palette.CARD2, foreground=Palette.WHITE,
                        bordercolor=Palette.BORDER, focuscolor="none",
                        lightcolor=Palette.BORDER, darkcolor=Palette.BORDER, font=Palette.BOLD)
        style.map("TButton", background=[("active", Palette.MID)])
        style.configure("Start.TButton", background=Palette.SUCCESS, foreground=Palette.WHITE,
                        bordercolor=Palette.GREEN)
        style.map("Start.TButton", background=[("active", Palette.GREEN), ("disabled", "#1a3b2c")])
        style.configure("Stop.TButton", background=Palette.DANGER, foreground=Palette.WHITE,
                        bordercolor=Palette.RED)
        style.map("Stop.TButton", background=[("active", Palette.RED), ("disabled", "#3a1010")])
        style.configure("Accent.TButton", background=Palette.BLUE, foreground=Palette.WHITE,
                        bordercolor=Palette.CYAN)
        style.map("Accent.TButton", background=[("active", Palette.CYAN)])
        style.configure("Treeview", background=Palette.MID, foreground=Palette.WHITE,
                        fieldbackground=Palette.MID, bordercolor=Palette.BORDER)
        style.map("Treeview", background=[("selected", Palette.BLUE)])
        style.configure("Treeview.Heading", background=Palette.CARD, foreground=Palette.CYAN,
                        bordercolor=Palette.BORDER, font=("Segoe UI", 9, "bold"))
        style.configure("Horizontal.TProgressbar", background=Palette.CYAN,
                        troughcolor=Palette.MID, bordercolor=Palette.BORDER)
        style.configure("TEntry", fieldbackground=Palette.INPUT_BG, foreground=Palette.WHITE,
                        bordercolor=Palette.BORDER)
        style.configure("TSpinbox", fieldbackground=Palette.INPUT_BG, foreground=Palette.WHITE)
        style.configure("TCombobox", fieldbackground=Palette.INPUT_BG, foreground=Palette.WHITE,
                        selectbackground=Palette.BLUE, arrowcolor=Palette.WHITE)
        style.configure("Vertical.TScrollbar", background=Palette.CARD, bordercolor=Palette.BORDER,
                        troughcolor=Palette.MID, arrowcolor=Palette.WHITE)
        style.map("TCheckbutton", background=[("active", bg)], foreground=[("active", Palette.WHITE)])

    def _build_ui(self):
        self._build_menu()
        self._build_header()
        self._build_panels()
        self._build_status_bar()

    # ── Menu ────────────────────────────────────────────────────────
    def _build_menu(self):
        mb = tk.Menu(self.root, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        fm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        fm.add_command(label="Open Wordlist...", command=self._browse, accelerator="Ctrl+O")
        fm.add_separator()
        fm.add_command(label="Save Results", command=self._save, accelerator="Ctrl+S")
        fm.add_command(label="Export JSON", command=lambda: self._export("json"))
        fm.add_command(label="Export CSV", command=lambda: self._export("csv"))
        fm.add_separator()
        fm.add_command(label="Clear All", command=self._clear, accelerator="Ctrl+Shift+C")
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close, accelerator="Alt+F4")
        mb.add_cascade(label="File", menu=fm)

        tm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        tm.add_command(label="Smart Analysis...", command=self._run_smart_analysis, accelerator="F6")
        tm.add_command(label="Browse DB Wordlists...", command=self._browse_db, accelerator="Ctrl+D")
        tm.add_separator()
        tm.add_command(label="Open DB Folder", command=lambda: webbrowser.open(str(DB_DIR)))
        tm.add_command(label="Open Go Engine Folder", command=lambda: webbrowser.open(str(ENGINE_DIR / "go")))
        mb.add_cascade(label="Tools", menu=tm)

        vm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        vm.add_command(label="Show All Results", command=lambda: self.search_var.set(""))
        vm.add_command(label="Show Only 2xx", command=lambda: self.search_var.set("200"))
        vm.add_command(label="Show Only 3xx", command=lambda: self.search_var.set("30"))
        vm.add_command(label="Show Only 4xx", command=lambda: self.search_var.set("40"))
        vm.add_command(label="Show Only 5xx", command=lambda: self.search_var.set("50"))
        mb.add_cascade(label="View", menu=vm)

        hm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        hm.add_command(label="About", command=self._about)
        hm.add_command(label="Help", command=self._show_help)
        mb.add_cascade(label="Help", menu=hm)
        self.root.config(menu=mb)

    # ── Header ───────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=Palette.HEADER_BG, height=52)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        title = tk.Label(hdr, text="\U0001f4c1  DIR FINDER", fg=Palette.CYAN, bg=Palette.HEADER_BG,
                         font=("Segoe UI", 18, "bold"))
        title.place(x=16, rely=0.5, anchor=tk.W)

        sub = tk.Label(hdr, text="Directory & File Scanner — Go Engine", fg=Palette.DIM,
                       bg=Palette.HEADER_BG, font=("Segoe UI", 10))
        sub.place(x=200, rely=0.5, anchor=tk.W)

        self.stat_elapsed = tk.StringVar(value="Time: 00:00:00")
        tk.Label(hdr, textvariable=self.stat_elapsed, fg=Palette.DIM, bg=Palette.HEADER_BG,
                 font=("Segoe UI", 9)).place(relx=1.0, x=-14, rely=0.3, anchor=tk.E)

        self.stat_rate = tk.StringVar(value="Rate: 0/s")
        tk.Label(hdr, textvariable=self.stat_rate, fg=Palette.DIM, bg=Palette.HEADER_BG,
                 font=("Segoe UI", 9)).place(relx=1.0, x=-14, rely=0.7, anchor=tk.E)

        sep = tk.Frame(self.root, bg=Palette.BORDER, height=1)
        sep.pack(fill=tk.X)

    # ── Panels ───────────────────────────────────────────────────────
    def _build_panels(self):
        pw = tk.PanedWindow(self.root, bg=Palette.BG, sashrelief=tk.FLAT,
                            sashwidth=4, sashpad=0, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(pw, bg=Palette.BG)
        right = tk.Frame(pw, bg=Palette.BG)
        pw.add(left, width=480, minsize=380)
        pw.add(right, width=860, minsize=580)

        self._build_control_panel(left)
        self._build_content_panel(right)

    def _build_control_panel(self, parent):
        cb = ttk.Frame(parent, padding=4)
        cb.pack(fill=tk.BOTH, expand=True)

        # Scrollable control panel
        canvas = tk.Canvas(cb, bg=Palette.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(cb, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel, add="+")

        sf = scroll_frame

        # ── Target ─────────────────────────────────────────────────
        grp = ttk.LabelFrame(sf, text="\U0001f310  Target", padding=6)
        grp.pack(fill=tk.X, pady=1)

        r = ttk.Frame(grp)
        r.pack(fill=tk.X)
        ttk.Label(r, text="URL:", width=5).pack(side=tk.LEFT)
        e = ttk.Entry(r, textvariable=self.url_var)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        tk.Button(r, text="\u2398", font=("Segoe UI", 10), bg=Palette.CARD, fg=Palette.WHITE,
                  relief=tk.FLAT, width=2, cursor="hand2",
                  command=lambda: self.url_var.set(self.root.clipboard_get())).pack(side=tk.LEFT)

        # ── Wordlist ───────────────────────────────────────────────
        grp = ttk.LabelFrame(sf, text="\U0001f4c4  Wordlist", padding=6)
        grp.pack(fill=tk.X, pady=1)

        r = ttk.Frame(grp)
        r.pack(fill=tk.X)
        ttk.Label(r, text="File:", width=5).pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=self.wl_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        ttk.Button(r, text="Browse", command=self._browse).pack(side=tk.LEFT)

        r = ttk.Frame(grp)
        r.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r, text="Cat:", width=5).pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=self.wordlist_cat_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        ttk.Button(r, text="DB", width=3, command=self._browse_db).pack(side=tk.LEFT)
        ttk.Label(r, text="(e.g. common,php/wordpress)", foreground=Palette.DIM,
                  font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(4, 0))

        # ── Options ────────────────────────────────────────────────
        grp = ttk.LabelFrame(sf, text="\u2699  Scan Options", padding=6)
        grp.pack(fill=tk.X, pady=1)

        rf = ttk.Frame(grp)
        rf.pack(fill=tk.X)
        items = [
            ("Threads", self.threads_var, "50", 1, 999),
            ("Timeout", self.timeout_var, "10", 1, 300),
            ("Delay ms", self.delay_var, "0", 0, 60000),
            ("Retries", self.retries_var, "2", 0, 20),
        ]
        for label, var, default, lo, hi in items:
            f = ttk.Frame(rf)
            f.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
            ttk.Label(f, text=label, font=("Segoe UI", 8)).pack()
            ttk.Spinbox(f, from_=lo, to=hi, textvariable=var, width=5,
                        font=("Consolas", 9)).pack()

        r2 = ttk.Frame(grp)
        r2.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r2, text="Ext:").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.ext_var, width=14).pack(side=tk.LEFT, padx=(0, 4))

        ttk.Label(r2, text="Method:").pack(side=tk.LEFT)
        ttk.Combobox(r2, textvariable=self.method_var,
                     values=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"],
                     width=7, state="readonly").pack(side=tk.LEFT, padx=(0, 4))

        ttk.Label(r2, text="Rate/s:").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.max_rate_var, width=5).pack(side=tk.LEFT)

        r3 = ttk.Frame(grp)
        r3.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r3, text="Prefixes:").pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self.prefix_var, width=10).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(r3, text="Suffixes:").pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self.suffix_var, width=10).pack(side=tk.LEFT)

        r5 = ttk.Frame(grp)
        r5.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r5, text="Subdirs:").pack(side=tk.LEFT)
        ttk.Entry(r5, textvariable=self.subdirs_var, width=20).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(r5, text="Depth:").pack(side=tk.LEFT)
        ttk.Spinbox(r5, from_=1, to=10, textvariable=self.recursive_depth_var, width=3).pack(side=tk.LEFT)

        # Checkboxes
        cf = ttk.Frame(grp)
        cf.pack(fill=tk.X, pady=(2, 0))
        for var, text in [
            (self.recursive_var, "Recursive"),
            (self.deep_recursive_var, "Deep"),
            (self.force_recursive_var, "Force"),
            (self.follow_redirects_var, "Follow"),
            (self.random_agent_var, "Rand-UA"),
            (self.force_ext_var, "Force-Ext"),
            (self.http2_var, "HTTP/2"),
            (self.crawl_var, "Crawl"),
        ]:
            ttk.Checkbutton(cf, text=text, variable=var).pack(side=tk.LEFT, padx=1)

        # ── Filters ────────────────────────────────────────────────
        grp = ttk.LabelFrame(sf, text="\U0001f50d  Filters", padding=6)
        grp.pack(fill=tk.X, pady=1)

        r = ttk.Frame(grp)
        r.pack(fill=tk.X)
        ttk.Label(r, text="Exclude St:").pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=self.exclude_var, width=8).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(r, text="Include:").pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=self.include_var, width=8).pack(side=tk.LEFT)
        ttk.Label(r, text="Min:").pack(side=tk.LEFT, padx=(4, 0))
        ttk.Entry(r, textvariable=self.min_size_var, width=5).pack(side=tk.LEFT)
        ttk.Label(r, text="Max:").pack(side=tk.LEFT, padx=(4, 0))
        ttk.Entry(r, textvariable=self.max_size_var, width=5).pack(side=tk.LEFT)

        r2 = ttk.Frame(grp)
        r2.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r2, text="Exclude Sizes:").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.exclude_sizes_var, width=10).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(r2, text="Text:").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.exclude_text_var, width=10).pack(side=tk.LEFT)
        ttk.Label(r2, text="Regex:").pack(side=tk.LEFT, padx=(4, 0))
        ttk.Entry(r2, textvariable=self.exclude_regex_var, width=10).pack(side=tk.LEFT)

        r3 = ttk.Frame(grp)
        r3.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r3, text="Match St:").pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self.match_status_var, width=8).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(r3, text="Filter St:").pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self.filter_status_var, width=8).pack(side=tk.LEFT)

        # ── Detection ──────────────────────────────────────────────
        grp = ttk.LabelFrame(sf, text="\U0001f4a1  Detection", padding=6)
        grp.pack(fill=tk.X, pady=1)

        cf = ttk.Frame(grp)
        cf.pack(fill=tk.X)
        for var, text in [
            (self.detect_waf_var, "WAF Detect"),
            (self.detect_tech_var, "Tech Detect"),
            (self.detect_backup_var, "Backup Scan"),
            (self.extract_js_var, "JS Extract"),
            (self.smart_filter_var, "Smart Filter"),
            (self.auto_calibration_var, "Auto-Calibrate"),
            (self.api_mode_var, "API Mode"),
        ]:
            ttk.Checkbutton(cf, text=text, variable=var).pack(side=tk.LEFT, padx=1)

        # ── Connection ─────────────────────────────────────────────
        grp = ttk.LabelFrame(sf, text="\U0001f4e1  Connection & Auth", padding=6)
        grp.pack(fill=tk.X, pady=1)

        r = ttk.Frame(grp)
        r.pack(fill=tk.X)
        ttk.Label(r, text="Proxy:").pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=self.proxy_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Checkbutton(r, text="Tor", variable=self.tor_var).pack(side=tk.LEFT)

        r2 = ttk.Frame(grp)
        r2.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r2, text="User-Agent:").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.user_agent_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        r3 = ttk.Frame(grp)
        r3.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r3, text="Cookie:").pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self.cookie_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        r3b = ttk.Frame(grp)
        r3b.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r3b, text="Auth:").pack(side=tk.LEFT)
        ttk.Entry(r3b, textvariable=self.auth_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Combobox(r3b, textvariable=self.auth_type_var,
                     values=["basic", "digest", "bearer", "ntlm", "jwt"],
                     width=7, state="readonly").pack(side=tk.LEFT)

        # ── Output ─────────────────────────────────────────────────
        grp = ttk.LabelFrame(sf, text="\U0001f4be  Output", padding=6)
        grp.pack(fill=tk.X, pady=1)

        r = ttk.Frame(grp)
        r.pack(fill=tk.X)
        ttk.Checkbutton(r, text="Full URL", variable=self.full_url_var).pack(side=tk.LEFT, padx=1)
        ttk.Checkbutton(r, text="Quiet", variable=self.quiet_var).pack(side=tk.LEFT, padx=1)
        ttk.Checkbutton(r, text="Verbose", variable=self.verbose_var).pack(side=tk.LEFT, padx=1)
        ttk.Checkbutton(r, text="Save Session", variable=self.save_session_var).pack(side=tk.LEFT, padx=1)
        ttk.Checkbutton(r, text="Uppercase", variable=self.uppercase_var).pack(side=tk.LEFT, padx=1)
        ttk.Checkbutton(r, text="Lowercase", variable=self.lowercase_var).pack(side=tk.LEFT, padx=1)
        ttk.Checkbutton(r, text="Capital", variable=self.capital_var).pack(side=tk.LEFT, padx=1)

        r2 = ttk.Frame(grp)
        r2.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(r2, text="Output:").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.output_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))

        self.wl_count_lbl = ttk.Label(grp, textvariable=self.wl_count_var, foreground=Palette.DIM)
        self.wl_count_lbl.pack(anchor=tk.E)

        # ── Action Buttons ─────────────────────────────────────────
        ab = ttk.Frame(sf)
        ab.pack(fill=tk.X, pady=6)

        self.start_btn = tk.Button(ab, text="\u25b6  START SCAN", font=("Segoe UI", 11, "bold"),
                                   bg=Palette.SUCCESS, fg=Palette.WHITE, relief=tk.FLAT,
                                   padx=20, pady=8, cursor="hand2",
                                   activebackground=Palette.GREEN, activeforeground=Palette.WHITE,
                                   command=self._start)
        self.start_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))

        self.stop_btn = tk.Button(ab, text="\u25a0  STOP", font=("Segoe UI", 11, "bold"),
                                  bg=Palette.DANGER, fg=Palette.WHITE, relief=tk.FLAT,
                                  padx=20, pady=8, cursor="hand2", state=tk.DISABLED,
                                  activebackground=Palette.RED, activeforeground=Palette.WHITE,
                                  command=self._stop)
        self.stop_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

        sm_btn = tk.Button(ab, text="\U0001f50d  SMART", font=("Segoe UI", 9, "bold"),
                           bg=Palette.PURPLE, fg=Palette.WHITE, relief=tk.FLAT,
                           padx=12, pady=8, cursor="hand2",
                           activebackground="#8256d0", activeforeground=Palette.WHITE,
                           command=self._run_smart_analysis)
        sm_btn.pack(side=tk.RIGHT, padx=(3, 0))

        # ── Stats ──────────────────────────────────────────────────
        st = ttk.LabelFrame(sf, text="\U0001f4ca  Statistics", padding=6)
        st.pack(fill=tk.X, pady=1)

        sf2 = ttk.Frame(st)
        sf2.pack(fill=tk.X)

        self.stat_labels = {}
        for label, key, color in [
            ("Total", "total", Palette.WHITE),
            ("2xx", "s2xx", Palette.GREEN),
            ("3xx", "s3xx", Palette.CYAN),
            ("4xx", "s4xx", Palette.YELLOW),
            ("5xx", "s5xx", Palette.RED),
        ]:
            f = tk.Frame(sf2, bg=Palette.CARD, highlightbackground=Palette.BORDER, highlightthickness=1)
            f.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
            tk.Label(f, text=label, fg=Palette.DIM, bg=Palette.CARD, font=("Segoe UI", 8)).pack(pady=(2, 0))
            v = tk.StringVar(value="0")
            tk.Label(f, textvariable=v, fg=color, bg=Palette.CARD, font=("Segoe UI", 14, "bold")).pack(pady=(1, 2))
            self.stat_labels[key] = v

        sf3 = ttk.Frame(st)
        sf3.pack(fill=tk.X, pady=(3, 0))
        ttk.Label(sf3, textvariable=self.stat_wl_var, foreground=Palette.DIM).pack(side=tk.RIGHT)

    # ── Content Panel (Results + Log) ──────────────────────────────
    def _build_content_panel(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        # Results tab
        rf = ttk.Frame(nb)
        nb.add(rf, text="\U0001f4cb  Results")

        # Search bar
        sr = ttk.Frame(rf)
        sr.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(sr, text="\U0001f50d  Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        se = ttk.Entry(sr, textvariable=self.search_var)
        se.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(sr, text="Clear", width=5, command=lambda: self.search_var.set("")).pack(side=tk.LEFT)
        self.count_var = tk.StringVar(value="Found: 0")
        ttk.Label(sr, textvariable=self.count_var, foreground=Palette.CYAN,
                  font=Palette.BOLD).pack(side=tk.RIGHT, padx=(6, 0))

        # Legend
        leg = ttk.Frame(rf)
        leg.pack(fill=tk.X, pady=(0, 4))
        for color, text in [(Palette.GREEN, "2xx Success"), (Palette.CYAN, "3xx Redirect"),
                             (Palette.YELLOW, "4xx Client Error"), (Palette.RED, "5xx Server Error")]:
            f = tk.Frame(leg, bg=Palette.CARD, highlightbackground=color, highlightthickness=1, padx=6, pady=1)
            f.pack(side=tk.LEFT, padx=(0, 6))
            tk.Label(f, text=text, fg=color, bg=Palette.CARD, font=("Segoe UI", 8, "bold")).pack()

        # Tree
        tf = ttk.Frame(rf)
        tf.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(tf, columns=("status", "path", "size", "redirect", "type", "title"),
                                 show="headings", selectmode="extended")
        cols = [
            ("status", "Status", 55, tk.CENTER),
            ("path", "Path", 380, tk.W),
            ("size", "Size", 75, tk.CENTER),
            ("redirect", "Redirect", 200, tk.W),
            ("type", "Content-Type", 150, tk.W),
            ("title", "Title", 200, tk.W),
        ]
        for col, h, w, a in cols:
            self.tree.heading(col, text=h)
            self.tree.column(col, width=w, anchor=a, minwidth=40)

        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        for (lo, hi), (tag, color, _) in STATUS_TAGS.items():
            self.tree.tag_configure(tag, foreground=color)
        self.tree.tag_configure("hidden", foreground=Palette.DIM)
        self.tree.tag_configure("even", background="#131b26")
        self.tree.tag_configure("odd", background=Palette.MID)
        self.tree.bind("<Double-1>", self._on_tree_double)
        self.tree.bind("<Button-3>", self._on_tree_right)
        self.search_var.trace_add("write", lambda *_: self._filter_results())

        # Log tab
        lf = ttk.Frame(nb)
        nb.add(lf, text="\U0001f4dd  Log")
        self.log_text = tk.Text(lf, wrap=tk.WORD, state=tk.DISABLED, bg=Palette.MID,
                                fg=Palette.WHITE, font=Palette.MONO_SM, padx=6, pady=4,
                                relief=tk.FLAT, bd=1)
        lsb = ttk.Scrollbar(lf, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=lsb.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Smart Analysis tab
        saf = ttk.Frame(nb)
        nb.add(saf, text="\U0001f50d  Smart Analysis")
        self.sa_text = tk.Text(saf, wrap=tk.WORD, state=tk.DISABLED, bg=Palette.MID,
                               fg=Palette.WHITE, font=Palette.MONO_SM, padx=6, pady=4,
                               relief=tk.FLAT, bd=1)
        sasb = ttk.Scrollbar(saf, orient=tk.VERTICAL, command=self.sa_text.yview)
        self.sa_text.configure(yscrollcommand=sasb.set)
        self.sa_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sasb.pack(side=tk.RIGHT, fill=tk.Y)

        self.root.bind("<<ImportEndpoints>>", self._on_smart_import)

    # ── Status Bar ──────────────────────────────────────────────────
    def _build_status_bar(self):
        sb = tk.Frame(self.root, bg=Palette.CARD, height=28)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)

        self.progress = ttk.Progressbar(sb, mode="determinate")
        self.progress.pack(fill=tk.X)

        bf = tk.Frame(sb, bg=Palette.CARD)
        bf.pack(fill=tk.X, padx=8, pady=2)
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(bf, textvariable=self.status_var, fg=Palette.DIM, bg=Palette.CARD,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)

        self.progress_label = tk.StringVar(value="")
        tk.Label(bf, textvariable=self.progress_label, fg=Palette.CYAN, bg=Palette.CARD,
                 font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=(0, 8))

    # ── Shortcuts ───────────────────────────────────────────────────
    def _bind_shortcuts(self):
        self.root.bind("<Control-o>", lambda e: self._browse())
        self.root.bind("<Control-d>", lambda e: self._browse_db())
        self.root.bind("<Control-s>", lambda e: self._save())
        self.root.bind("<Control-Shift-C>", lambda e: self._clear())
        self.root.bind("<Escape>", lambda e: self._stop() if self.running else None)
        self.root.bind("<F5>", lambda e: self._start() if not self.running else None)
        self.root.bind("<F6>", lambda e: self._run_smart_analysis())

    # ── Wordlist Helpers ────────────────────────────────────────────
    def _update_wordlist_info(self, *_):
        n = self._path_count()
        self.wl_count_var.set(f"Paths: {n}")
        self.stat_wl_var.set(f"Wordlist: {n}")

    def _path_count(self):
        n = 0
        wl = self.wl_var.get().strip()
        if wl and os.path.isfile(wl):
            try:
                with open(wl) as f:
                    n += sum(1 for line in f if line.strip() and not line.startswith("#"))
            except Exception:
                pass
        cust = self.custom_var.get().strip() if hasattr(self, 'custom_var') else ""
        if cust:
            n += len([p for p in cust.split("\n") if p.strip()])
        return n

    def _prepare_wordlist(self):
        paths = []
        wl = self.wl_var.get().strip()
        if wl and os.path.isfile(wl):
            try:
                with open(wl) as f:
                    for line in f:
                        p = line.strip()
                        if p and not p.startswith("#"):
                            paths.append(p)
            except Exception as e:
                messagebox.showerror("Error", f"Wordlist error: {e}")
                return None
        # Custom paths via Smart Analysis
        if self._smart_endpoints:
            paths.extend(self._smart_endpoints)
        if not paths:
            return None
        return ",".join(paths), len(paths)

    def _browse(self):
        path = filedialog.askopenfilename(title="Select Wordlist",
                                          filetypes=[("Text", "*.txt"), ("Wordlist", "*.lst"),
                                                     ("All", "*.*")])
        if path:
            self.wl_var.set(path)
            self._update_wordlist_info()

    def _browse_db(self):
        if not DB_DIR.exists():
            messagebox.showinfo("DB", "Wordlist db/ not found.")
            return
        w = tk.Toplevel(self.root)
        w.title("DB Wordlists")
        w.geometry("620x480")
        w.configure(bg=Palette.BG)
        w.transient(self.root)

        tk.Label(w, text="\U0001f4c1  Built-in Wordlist Database", fg=Palette.CYAN,
                 bg=Palette.BG, font=("Segoe UI", 13, "bold")).pack(pady=(12, 2))
        tk.Label(w, text="Select a wordlist file to use", fg=Palette.DIM,
                 bg=Palette.BG, font=("Segoe UI", 9)).pack(pady=(0, 8))

        f = ttk.Frame(w)
        f.pack(fill=tk.BOTH, expand=True, padx=12)

        cols = ("file", "count")
        tv = ttk.Treeview(f, columns=cols, show="headings", selectmode="browse")
        tv.heading("file", text="File Path")
        tv.heading("count", text="Entries")
        tv.column("file", width=420)
        tv.column("count", width=80, anchor=tk.CENTER)
        sc = ttk.Scrollbar(f, orient=tk.VERTICAL, command=tv.yview)
        tv.configure(yscrollcommand=sc.set)
        tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sc.pack(side=tk.RIGHT, fill=tk.Y)

        files = sorted(DB_DIR.rglob("*.txt"))
        for fpath in files:
            rel = fpath.relative_to(ENGINE_DIR)
            cnt = 0
            if fpath.stat().st_size:
                try:
                    cnt = sum(1 for l in fpath.read_text().splitlines()
                              if l.strip() and not l.startswith("#"))
                except Exception:
                    pass
            tv.insert("", tk.END, values=(str(rel), cnt))

        bf = ttk.Frame(w)
        bf.pack(fill=tk.X, padx=12, pady=8)

        def select():
            sel = tv.selection()
            if not sel:
                return
            vals = tv.item(sel[0], "values")
            if vals and vals[0]:
                full = ENGINE_DIR / vals[0]
                if full.exists():
                    self.wl_var.set(str(full))
                    w.destroy()

        ttk.Button(bf, text="Select", command=select).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(bf, text="Cancel", command=w.destroy).pack(side=tk.RIGHT)

    # ── Smart Analysis ─────────────────────────────────────────────
    def _run_smart_analysis(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Enter a target URL first")
            return
        dialog = SmartAnalyzerDialog(self.root, url)
        result = dialog.wait()
        if result and result.get("endpoints"):
            self._smart_endpoints = result["endpoints"]
            self._log_sa(f"[+] Smart Analysis complete:")
            self._log_sa(f"    WAF: {result.get('waf', 'N/A')}")
            self._log_sa(f"    CMS: {result.get('cms', 'N/A')}")
            self._log_sa(f"    Tech: {', '.join(result.get('tech', [])[:6])}")
            self._log_sa(f"    Endpoints: {len(result['endpoints'])}")
            self._log_sa(f"    Categories: {', '.join(result.get('recommended_wordlists', [])[:5])}")
            self._log_sa(f"    Use --wordlist-categories or browse DB for tech-specific wordlists")
            # Update wordlist count
            self._update_wordlist_info()
            messagebox.showinfo("Smart Analysis", f"Found {len(result['endpoints'])} endpoints.\n"
                                                   "Start scan to include them in the wordlist.")
        elif result:
            self._log_sa("[!] Smart Analysis completed but found no endpoints.")
        else:
            self._log_sa("[!] Smart Analysis cancelled or failed.")

    def _log_sa(self, msg):
        self.sa_text.configure(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.sa_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.sa_text.see(tk.END)
        self.sa_text.configure(state=tk.DISABLED)

    def _on_smart_import(self, event):
        self._log_sa("[+] Endpoints from Smart Analysis imported.")

    # ── Scan Lifecycle ──────────────────────────────────────────────
    def _start(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Target URL is required")
            return

        res = self._prepare_wordlist()
        if not res:
            messagebox.showerror("Error", "No wordlist. Select a file or run Smart Analysis.")
            return
        paths_str, total = res

        if not GO_BINARY.exists():
            messagebox.showerror("Error", f"Go binary not found:\n{GO_BINARY}\n\nBuild: cd go/ && go build .")
            return

        cmd = [str(GO_BINARY), "-u", url, "-w", paths_str]

        # Performance
        if self.threads_var.get().strip():
            cmd += ["-t", self.threads_var.get().strip()]
        if self.timeout_var.get().strip():
            cmd += ["-timeout", self.timeout_var.get().strip()]
        if self.delay_var.get().strip() and int(self.delay_var.get()) > 0:
            cmd += ["-delay", self.delay_var.get().strip()]
        if self.retries_var.get().strip():
            cmd += ["-retries", self.retries_var.get().strip()]
        if self.max_rate_var.get().strip() and float(self.max_rate_var.get()) > 0:
            cmd += ["-max-rate", self.max_rate_var.get().strip()]

        # Dictionary
        if self.ext_var.get().strip():
            cmd += ["-e", self.ext_var.get().strip()]
        if self.prefix_var.get().strip():
            cmd += ["-prefixes", self.prefix_var.get().strip()]
        if self.suffix_var.get().strip():
            cmd += ["-suffixes", self.suffix_var.get().strip()]
        if self.wordlist_cat_var.get().strip():
            cmd += ["-wordlist-categories", self.wordlist_cat_var.get().strip()]

        # Request
        if self.method_var.get() != "GET":
            cmd += ["-m", self.method_var.get()]
        if self.user_agent_var.get().strip():
            cmd += ["-user-agent", self.user_agent_var.get().strip()]
        if self.cookie_var.get().strip():
            cmd += ["-cookie", self.cookie_var.get().strip()]
        if self.auth_var.get().strip():
            cmd += ["-auth", self.auth_var.get().strip()]
            cmd += ["-auth-type", self.auth_type_var.get()]

        # Connection
        if self.proxy_var.get().strip():
            cmd += ["-p", self.proxy_var.get().strip()]

        # Filters
        if self.exclude_var.get().strip():
            cmd += ["-x", self.exclude_var.get().strip()]
        if self.include_var.get().strip():
            cmd += ["-i", self.include_var.get().strip()]
        if self.min_size_var.get().strip():
            cmd += ["-min-response-size", self.min_size_var.get().strip()]
        if self.max_size_var.get().strip():
            cmd += ["-max-response-size", self.max_size_var.get().strip()]
        if self.exclude_sizes_var.get().strip():
            cmd += ["-exclude-sizes", self.exclude_sizes_var.get().strip()]
        if self.exclude_text_var.get().strip():
            cmd += ["-exclude-text", self.exclude_text_var.get().strip()]
        if self.exclude_regex_var.get().strip():
            cmd += ["-exclude-regex", self.exclude_regex_var.get().strip()]
        if self.match_status_var.get().strip():
            cmd += ["-match-status", self.match_status_var.get().strip()]
        if self.filter_status_var.get().strip():
            cmd += ["-filter-status", self.filter_status_var.get().strip()]

        # Recursive
        if self.recursive_var.get():
            cmd += ["-r", "-R", self.recursive_depth_var.get().strip()]
        if self.deep_recursive_var.get():
            cmd.append("-deep-recursive")
        if self.force_recursive_var.get():
            cmd.append("-force-recursive")
        if self.subdirs_var.get().strip():
            cmd += ["-subdirs", self.subdirs_var.get().strip()]

        # Output
        if self.output_var.get().strip():
            cmd += ["-o", self.output_var.get().strip()]
            cmd += ["-O", "json"]
        if self.full_url_var.get():
            cmd.append("-full-url")
        if self.quiet_var.get():
            cmd.append("-q")
        if self.verbose_var.get():
            cmd.append("-v")

        # Boolean flags
        bool_map = [
            (self.follow_redirects_var, "-F"),
            (self.random_agent_var, "-random-agent"),
            (self.force_ext_var, "-f"),
            (self.http2_var, "-http2"),
            (self.crawl_var, "-crawl"),
            (self.detect_waf_var, "-detect-waf"),
            (self.detect_tech_var, "-detect-tech"),
            (self.detect_backup_var, "-detect-backup"),
            (self.smart_filter_var, "-smart-filter"),
            (self.extract_js_var, "-extract-js"),
            (self.auto_calibration_var, "-auto-calibration"),
            (self.api_mode_var, "-api-mode"),
            (self.save_session_var, "-save-session"),
            (self.tor_var, "-tor"),
            (self.uppercase_var, "-U"),
            (self.lowercase_var, "-L"),
            (self.capital_var, "-C"),
        ]
        for var, flag in bool_map:
            if var.get():
                cmd.append(flag)

        self.results.clear()
        self._all_items.clear()
        self._scan_progress = 0
        self.running = True
        self.start_time = time.time()
        self.start_btn.config(state=tk.DISABLED, text="\u23f3  RUNNING...")
        self.stop_btn.config(state=tk.NORMAL, text="\u25a0  STOP")
        self.progress.configure(mode="determinate", maximum=total, value=0)
        self.status_var.set(f"Scanning 0/{total}")
        self.progress_label.set("")

        for k in self.stat_labels:
            self.stat_labels[k].set("0")
        self.count_var.set("Found: 0")

        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan started: {url}")
        self._log(f"    Paths: {total} | Threads: {self.threads_var.get()} | Extensions: {self.ext_var.get() or 'none'}")
        if self.detect_waf_var.get():
            self._log("    WAF Detection: ON")
        if self.smart_filter_var.get():
            self._log("    Smart Filtering: ON (soft-404 + honeypot)")
        if self.recursive_var.get():
            self._log(f"    Recursive: ON (depth {self.recursive_depth_var.get()})")
        if self.extract_js_var.get():
            self._log("    JS Endpoint Extraction: ON")
        if self._smart_endpoints:
            self._log(f"    Smart Analysis endpoints: {len(self._smart_endpoints)}")

        for row in self.tree.get_children():
            self.tree.delete(row)

        self._elapsed_id = self.root.after(1000, self._elapsed_loop)
        threading.Thread(target=self._run_scan, args=(cmd, total), daemon=True).start()

    def _run_scan(self, cmd, total):
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            bufsize=1, text=True, encoding="utf-8", errors="replace")
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break
                if not self.running:
                    self.process.kill()
                    break
                self.log_queue.put(line)
            self.process.wait()
        except Exception as e:
            self.log_queue.put(f"[ERROR] {e}\n")
        finally:
            self.log_queue.put(None)

    def _stop(self):
        self.running = False
        if self._elapsed_id:
            self.root.after_cancel(self._elapsed_id)
            self._elapsed_id = None
        if self.process:
            try:
                self.process.kill()
            except Exception:
                pass
        self.start_btn.config(state=tk.NORMAL, text="\u25b6  START SCAN")
        self.stop_btn.config(state=tk.DISABLED, text="\u25a0  STOP")
        self.status_var.set("Stopped")

    def _log(self, msg):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _poll_queue(self):
        try:
            while True:
                item = self.log_queue.get_nowait()
                if item is None:
                    self._finish()
                    return
                line = item.rstrip() if item else ""
                if line:
                    self._log(line)
                    res = self._parse_result(item)
                    if res:
                        self.results.append(res)
                        self._add_tree(res)
                        t = int(self.stat_labels["total"].get()) + 1
                        self.stat_labels["total"].set(str(t))
                        code = res["status"]
                        if 200 <= code <= 299:
                            self.stat_labels["s2xx"].set(str(int(self.stat_labels["s2xx"].get()) + 1))
                        elif 300 <= code <= 399:
                            self.stat_labels["s3xx"].set(str(int(self.stat_labels["s3xx"].get()) + 1))
                        elif 400 <= code <= 499:
                            self.stat_labels["s4xx"].set(str(int(self.stat_labels["s4xx"].get()) + 1))
                        elif 500 <= code <= 599:
                            self.stat_labels["s5xx"].set(str(int(self.stat_labels["s5xx"].get()) + 1))
                        self.count_var.set(f"Found: {len(self.results)}")
                    self._scan_progress += 1
                    self.progress.step(1)
                    pct = int(self._scan_progress / max(int(self.progress["maximum"]), 1) * 100)
                    self.status_var.set(f"Scanning {self._scan_progress}/{int(self.progress['maximum'])} ({pct}%)")
                    self.progress_label.set(f"{pct}%")
        except queue.Empty:
            pass
        if self.running:
            self.root.after(30, self._poll_queue)

    def _parse_result(self, line):
        stripped = strip_ansi(line).strip()
        m = re.match(r'\[\d{2}:\d{2}:\d{2}\]\s+(\d+)\s+-\s+(.*?)\s+-\s+(\S.*?)(?:\s+->\s+(.*?))?(?:\s+/\*\s*(.*?)\s*\*/\s*)?$', stripped)
        if m:
            return {
                "status": int(m.group(1)),
                "size": m.group(2).strip(),
                "path": m.group(3).strip(),
                "redirect": (m.group(4) or "").strip(),
                "title": (m.group(5) or "").strip() if m.lastindex >= 5 else "",
            }
        return None

    def _elapsed_loop(self):
        if not self.running or not self.start_time:
            return
        e = time.time() - self.start_time
        h, r = divmod(int(e), 3600)
        m, s = divmod(r, 60)
        self.stat_elapsed.set(f"Time: {h:02d}:{m:02d}:{s:02d}")
        n = int(self.stat_labels["total"].get())
        rate = n / e if e > 0 else 0
        self.stat_rate.set(f"Rate: {rate:.1f}/s")
        if rate > 0 and self._scan_progress > 0:
            remaining = max(int(self.progress["maximum"]) - self._scan_progress, 0)
            eta = remaining / rate if rate > 0 else 0
            em, es = divmod(int(eta), 60)
            self.status_var.set(f"ETA: {em:02d}:{es:02d} | {self._scan_progress}/{int(self.progress['maximum'])}")
        self._elapsed_id = self.root.after(1000, self._elapsed_loop)

    def _add_tree(self, result):
        tag, color = status_tag(result["status"])
        row_id = self.tree.insert("", tk.END, values=(
            result["status"], result["path"], result["size"],
            result["redirect"], result.get("type", ""), result.get("title", "")), tags=(tag,))
        self._all_items.append((row_id, result["status"], result["path"]))
        self._filter_results_item(row_id, result["status"], result["path"])
        self.tree.see(row_id)

    def _filter_results(self, *_):
        sv = self.search_var.get().lower()
        for row_id, status, path in self._all_items:
            self._filter_results_item(row_id, status, path, sv)

    def _filter_results_item(self, row_id, status, path, sv=None):
        if sv is None:
            sv = self.search_var.get().lower()
        tags = list(self.tree.item(row_id, "tags"))
        tags = [t for t in tags if t != "hidden"]
        if sv and sv not in str(status).lower() and sv not in path.lower():
            tags.append("hidden")
        self.tree.item(row_id, tags=tuple(tags))

    def _on_tree_double(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        t = self.url_var.get().strip().rstrip("/")
        url = f"{t}/{str(vals[1]).lstrip('/')}"
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        self.status_var.set(f"Copied: {url}")

    def _on_tree_right(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        menu = tk.Menu(self.root, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                       activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        menu.add_command(label="Copy URL", command=lambda: self._copy_urls(sel))
        menu.add_command(label="Copy All URLs", command=self._copy_all)
        menu.add_separator()
        menu.add_command(label="Copy as JSON", command=self._copy_json)
        menu.add_separator()
        menu.add_command(label="Export Selected...", command=self._export_sel)
        menu.add_command(label="Open in Browser", command=lambda: self._open_in_browser(sel))
        menu.post(event.x_root, event.y_root)

    def _copy_urls(self, sel):
        t = self.url_var.get().strip().rstrip("/")
        urls = [f"{t}/{str(self.tree.item(item, 'values')[1]).lstrip('/')}" for item in sel]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(urls))
        self.status_var.set(f"Copied {len(urls)} URL(s)")

    def _copy_all(self):
        t = self.url_var.get().strip().rstrip("/")
        urls = [f"{t}/{r['path'].lstrip('/')}" for r in self.results]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(urls))
        self.status_var.set(f"Copied {len(urls)} URL(s)")

    def _copy_json(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(json.dumps(self.results, indent=2))
        self.status_var.set("Copied JSON")

    def _open_in_browser(self, sel):
        t = self.url_var.get().strip().rstrip("/")
        for item in sel:
            vals = self.tree.item(item, "values")
            if vals:
                import webbrowser as wb
                wb.open(f"{t}/{str(vals[1]).lstrip('/')}")

    def _export_sel(self):
        sel = self.tree.selection()
        if not sel:
            return
        path = filedialog.asksaveasfilename(title="Export Selected", defaultextension=".txt",
                                            filetypes=[("Text", "*.txt"), ("CSV", "*.csv")])
        if not path:
            return
        t = self.url_var.get().strip().rstrip("/")
        ext = Path(path).suffix.lower()
        with open(path, "w") as f:
            if ext == ".csv":
                f.write("path,status,size,redirect\n")
                for item in sel:
                    vals = self.tree.item(item, "values")
                    if vals:
                        f.write(f"{vals[1]},{vals[0]},{vals[2]},{vals[3]}\n")
            else:
                for item in sel:
                    vals = self.tree.item(item, "values")
                    if vals:
                        f.write(f"{t}/{str(vals[1]).lstrip('/')}  [{vals[0]}]  {vals[2]}\n")
        self._log(f"Exported {len(sel)} results to {path}")

    def _finish(self):
        self.running = False
        if self._elapsed_id:
            self.root.after_cancel(self._elapsed_id)
            self._elapsed_id = None
        self.progress.configure(value=self.progress["maximum"])
        self.start_btn.config(state=tk.NORMAL, text="\u25b6  START SCAN")
        self.stop_btn.config(state=tk.DISABLED)
        n = len(self.results)
        e = time.time() - self.start_time if self.start_time else 0
        h, r = divmod(int(e), 3600)
        m, s = divmod(r, 60)
        self.status_var.set(f"Done — {n} results in {h:02d}:{m:02d}:{s:02d}")
        self.progress_label.set("100%")
        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan finished. {n} results in {h:02d}:{m:02d}:{s:02d}.")
        if n > 0:
            messagebox.showinfo("Scan Complete", f"{n} results found in {h:02d}:{m:02d}:{s:02d}")

    def _save(self):
        if not self.results:
            messagebox.showinfo("Save", "No results to save.")
            return
        path = filedialog.asksaveasfilename(title="Save Results", defaultextension=".json",
                                            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"),
                                                       ("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        ext = Path(path).suffix.lower()
        t = self.url_var.get().strip()
        ts = datetime.now().isoformat()
        try:
            if ext == ".json":
                with open(path, "w") as f:
                    json.dump({"target": t, "timestamp": ts, "total": len(self.results),
                               "results": self.results}, f, indent=2)
            elif ext == ".csv":
                with open(path, "w", newline="") as f:
                    f.write("path,status,size,redirect,title\n")
                    for r in self.results:
                        f.write(f"{r['path']},{r['status']},{r['size']},{r.get('redirect','')},{r.get('title','')}\n")
            else:
                with open(path, "w") as f:
                    f.write(f"Dir Finder Results - {datetime.now()}\nTarget: {t}\n{'='*60}\n\n")
                    for i, r in enumerate(self.results, 1):
                        f.write(f"{i:4d}.  [{r['status']:3d}]  {r['size']:>8}  /{r['path'].lstrip('/')}")
                        if r.get('redirect'):
                            f.write(f"  ->  {r['redirect']}")
                        f.write("\n")
            self._log(f"[+] Results saved: {path}")
            messagebox.showinfo("Saved", f"Results saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")

    def _export(self, fmt):
        if not self.results:
            messagebox.showinfo("Export", "No results.")
            return
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}",
                                            filetypes=[(fmt.upper(), f"*.{fmt}")])
        if not path:
            return
        self.output_var.set(path)
        # Run with output
        self._log(f"[+] Output set to {path} ({fmt})")

    def _clear(self):
        if self.running:
            self._stop()
        self.results.clear()
        self._all_items.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.progress.configure(value=0)
        self.count_var.set("Found: 0")
        self.status_var.set("Ready")
        self.stat_elapsed.set("Time: 00:00:00")
        self.stat_rate.set("Rate: 0/s")
        self.progress_label.set("")
        for k in self.stat_labels:
            self.stat_labels[k].set("0")

    def _about(self):
        msg = ("Dir Finder v3.0 — HackIT Security Framework\n\n"
               "Go Engine with 9 integrated modules:\n"
               "  - Scanner, Detector, Filter, Wordlist\n"
               "  - Recursive, Reporter, HTTP Engine\n"
               "  - Smart Analysis, Session Manager\n\n"
               "2,382 lines of Go — 59 CLI flags — dirsearch-equivalent\n"
               "30,260+ wordlist entries — 40+ wordlist files\n\n"
               "Smart Analyzer detects 30+ tech stacks,\n"
               "20+ WAFs, JS endpoints, and CMS platforms.")
        messagebox.showinfo("About Dir Finder", msg)

    def _show_help(self):
        msg = ("Keyboard Shortcuts:\n"
               "  F5          Start scan\n"
               "  F6          Smart Analysis\n"
               "  Ctrl+O      Open wordlist\n"
               "  Ctrl+D      Browse DB wordlists\n"
               "  Ctrl+S      Save results\n"
               "  Escape      Stop scan\n"
               "  Ctrl+Shift+C  Clear all\n\n"
               "Tips:\n"
               "  • Run Smart Analysis first to detect tech\n"
               "  • Use --wordlist-categories for tech-specific wordlists\n"
               "  • Enable WAF Detect to show WAF info\n"
               "  • Use filters to reduce noise\n"
               "  • Right-click results for context menu")
        messagebox.showinfo("Help", msg)

    def _on_close(self):
        if self.running:
            self._stop()
        if self._elapsed_id:
            self.root.after_cancel(self._elapsed_id)
        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self._on_close()


def main():
    DirFinderGUI().run()


if __name__ == "__main__":
    main()
