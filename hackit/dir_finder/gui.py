"""
DirFinder HackIT V.2.1 — Professional GUI with full Go engine integration.
Quad-engine: Go core scanner, Python intelligence, Rust turbo, Ruby orchestrator.
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
SESSION_DIR = ENGINE_DIR / "sessions"
SESSION_DIR.mkdir(exist_ok=True)

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
    BLUE      = "#1f6efb"
    DIM       = "#8b949e"
    ORANGE    = "#d47602"
    PINK      = "#f778ba"
    PURPLE    = "#a371f7"
    BORDER    = "#30363d"
    HEADER_BG = "#0d1117"
    INPUT_BG  = "#0d1117"
    SUCCESS   = "#2ea043"
    DANGER    = "#da3633"
    GOLD      = "#ffa657"
    TEAL      = "#56d4dd"
    FONT      = ("Consolas", 10)
    UI_FONT   = ("Segoe UI", 10)
    BOLD      = ("Segoe UI", 10, "bold")
    TITLE_F   = ("Segoe UI", 16, "bold")
    MONO_SM   = ("Consolas", 9)
    MONO_LG   = ("Consolas", 11)

STATUS_RANGES = [
    (200, 299, "s2xx", Palette.GREEN, "2xx Success"),
    (300, 399, "s3xx", Palette.CYAN,  "3xx Redirect"),
    (400, 499, "s4xx", Palette.YELLOW, "4xx Client Error"),
    (500, 599, "s5xx", Palette.RED,    "5xx Server Error"),
]

VULN_KEYWORDS = re.compile(
    r'(admin|login|wp-admin|config|backup|\.env|\.git|\.sql|phpmyadmin|'
    r'dashboard|api|graphql|swagger|debug|test|dev|beta|internal)', re.I
)

PRESET_CONFIGS = {
    "Quick Scan":     {"threads": "20", "ext": "php,asp,html", "recursive": False, "smart_filter": True},
    "Full Scan":      {"threads": "50", "ext": "php,asp,html,txt,jsp", "recursive": True, "max_depth": "5", "smart_filter": True},
    "API Scan":       {"threads": "30", "ext": "json,xml", "api_mode": True, "extract_js": True, "detect_tech": True},
    "CMS Scan":       {"threads": "30", "ext": "php,html", "detect_waf": True, "crawl": True, "recursive": True},
    "JS Deep Scan":   {"threads": "15", "ext": "js,json", "extract_js": True, "js_deep": True, "crawl": True},
}

def strip_ansi(text):
    return ANSI_RE.sub("", text)

def status_tag(code):
    for lo, hi, tag, color, _ in STATUS_RANGES:
        if lo <= code <= hi:
            return tag, color
    return "default", Palette.WHITE

def is_vulnerable(path):
    return bool(VULN_KEYWORDS.search(path))


# ── Smart Analyzer Dialog ────────────────────────────────────────────
class SmartAnalyzerDialog:
    def __init__(self, parent, target_url):
        self.parent = parent
        self.target_url = target_url
        self.result = None
        self._build()

    def _build(self):
        self.win = tk.Toplevel(self.parent)
        self.win.title("Smart Analysis — DirFinder V.2.1")
        self.win.geometry("720x560")
        self.win.configure(bg=Palette.BG)
        self.win.transient(self.parent)
        self.win.grab_set()

        hdr = tk.Frame(self.win, bg=Palette.CARD2, height=50)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="\U0001f50d  Smart Analysis Engine", fg=Palette.CYAN,
                 bg=Palette.CARD2, font=Palette.TITLE_F).place(x=16, rely=0.5, anchor=tk.W)

        sep = tk.Frame(self.win, bg=Palette.BORDER, height=1)
        sep.pack(fill=tk.X)

        f = tk.Frame(self.win, bg=Palette.BG, padx=12, pady=8)
        f.pack(fill=tk.BOTH, expand=True)

        tk.Label(f, text="Target:", fg=Palette.DIM, bg=Palette.BG,
                 font=Palette.UI_FONT).pack(anchor=tk.W)
        self.url_lbl = tk.Label(f, text=self.target_url, fg=Palette.CYAN, bg=Palette.BG,
                                font=Palette.MONO_LG, wraplength=680, anchor=tk.W)
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

        self.status_lbl = tk.Label(bf, text="Ready to analyze", fg=Palette.DIM, bg=Palette.BG)
        self.status_lbl.pack(side=tk.RIGHT)

    def _log(self, msg):
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _run(self):
        self.run_btn.config(state=tk.DISABLED, text="\u23f3  Running...")
        self.status_lbl.config(text="Analyzing...")
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
        self.status_lbl.config(text=f"Done — {len(r['endpoints'])} endpoints", fg=Palette.GREEN)

    def _on_error(self, err):
        self._log(f"[!] Error: {err}")
        self.run_btn.config(text="\u25b6  Retry", state=tk.NORMAL)
        self.status_lbl.config(text="Failed", fg=Palette.RED)

    def _import(self):
        if self.result:
            self.parent.event_generate("<<ImportEndpoints>>")
        self.win.destroy()

    def wait(self):
        self.parent.wait_window(self.win)
        return self.result


# ── Main GUI ─────────────────────────────────────────────────────────
class DirFinderGUI:
    VERSION = "V.2.1"

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"DirFinder HackIT {self.VERSION}")
        self.root.geometry("1440x880")
        self.root.minsize(1100, 720)
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
        self._target_history = self._load_target_history()
        self._debounce_id = None
        self._wl_count = -1
        self._wl_path = ""
        self._parse_re = re.compile(
            r'\[\d{2}:\d{2}:\d{2}\]\s+-?(\d+)\s+(\S+)\s+(\S+?)'
            r'(?:\s+->\s+(\S+?))?(?:\s+/\*\s*(.*?)\s*\*/)?\s*$'
        )
        self._filter_re = re.compile(r'Filtered:\s*(\d+)')
        self._err_re = re.compile(r'Errors:\s*(\d+)')
        self._ip_re = re.compile(r'Target is reachable:.*?\(([\d.]+)\)')
        self._server_re = re.compile(r'Server:\s*(.+?)(?:\s*\||$)')

        # String vars
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
        self.preset_var = tk.StringVar(value="Quick Scan")

        # Bool vars
        self.follow_redirects_var = tk.BooleanVar(value=False)
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
        self.force_ext_var = tk.BooleanVar(value=False)
        self.uppercase_var = tk.BooleanVar(value=False)
        self.lowercase_var = tk.BooleanVar(value=False)
        self.capital_var = tk.BooleanVar(value=False)
        self.api_mode_var = tk.BooleanVar(value=False)
        self.save_session_var = tk.BooleanVar(value=False)
        self.auto_calibration_var = tk.BooleanVar(value=False)
        self.regex_search_var = tk.BooleanVar(value=False)
        self.adaptive_rate_var = tk.BooleanVar(value=False)
        self.detect_login_var = tk.BooleanVar(value=False)
        self.detect_api_var = tk.BooleanVar(value=False)
        self.js_deep_var = tk.BooleanVar(value=False)
        self.swagger_var = tk.BooleanVar(value=False)

        # Cleanup old temp wordlist files
        for f in SESSION_DIR.glob("wl_*.txt"):
            try:
                f.unlink()
            except OSError:
                pass

        self._build_ui()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.wl_var.trace_add("write", self._update_wordlist_info)
        self._update_wordlist_info()
        self.root.after(100, self._poll_queue)

    # ── Style ────────────────────────────────────────────────────────
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

    # ── Build UI ─────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_menu()
        self._build_header()
        self._build_panels()
        self._build_status_bar()

    # ── Menu ─────────────────────────────────────────────────────────
    def _build_menu(self):
        mb = tk.Menu(self.root, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)

        fm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        fm.add_command(label="Open Wordlist...", command=self._browse, accelerator="Ctrl+O")
        fm.add_command(label="Browse DB Wordlists...", command=self._browse_db, accelerator="Ctrl+D")
        fm.add_separator()
        fm.add_command(label="Save Results", command=self._save, accelerator="Ctrl+S")
        fm.add_command(label="Export JSON", command=lambda: self._export("json"))
        fm.add_command(label="Export CSV", command=lambda: self._export("csv"))
        fm.add_command(label="Export HTML Report", command=self._export_html)
        fm.add_separator()
        fm.add_command(label="Load Session...", command=self._load_session, accelerator="Ctrl+L")
        fm.add_command(label="Save Session", command=self._save_session, accelerator="Ctrl+Shift+S")
        fm.add_separator()
        fm.add_command(label="Clear All", command=self._clear, accelerator="Ctrl+Shift+C")
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close, accelerator="Alt+F4")
        mb.add_cascade(label="File", menu=fm)

        tm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        tm.add_command(label="Smart Analysis...", command=self._run_smart_analysis, accelerator="F6")
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
        vm.add_separator()
        vm.add_command(label="Show Vulnerable Only", command=self._filter_vuln)
        mb.add_cascade(label="View", menu=vm)

        pm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        for name in PRESET_CONFIGS:
            pm.add_command(label=name, command=lambda n=name: self._apply_preset(n))
        mb.add_cascade(label="Presets", menu=pm)

        hm = tk.Menu(mb, tearoff=0, bg=Palette.CARD, fg=Palette.WHITE,
                     activebackground=Palette.BLUE, activeforeground=Palette.WHITE)
        hm.add_command(label="About", command=self._about)
        hm.add_command(label="Help", command=self._show_help)
        mb.add_cascade(label="Help", menu=hm)
        self.root.config(menu=mb)

    # ── Header ───────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=Palette.HEADER_BG, height=64)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        left = tk.Frame(hdr, bg=Palette.HEADER_BG)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(16, 0))
        tk.Label(left, text="\U0001f4c1", fg=Palette.CYAN, bg=Palette.HEADER_BG,
                 font=("Segoe UI", 22)).pack(side=tk.LEFT, padx=(0, 10))
        tt = tk.Frame(left, bg=Palette.HEADER_BG)
        tt.pack(side=tk.LEFT)
        tk.Label(tt, text="DirFinder", fg=Palette.CYAN, bg=Palette.HEADER_BG,
                 font=("Segoe UI", 16, "bold")).pack(anchor=tk.W)
        tk.Label(tt, text="Directory & File Scanner — Go Engine", fg=Palette.DIM,
                 bg=Palette.HEADER_BG, font=("Segoe UI", 9)).pack(anchor=tk.W)
        ver = tk.Label(tt, text=f"v{self.VERSION}", fg=Palette.GOLD, bg=Palette.HEADER_BG,
                       font=("Segoe UI", 8, "bold"))
        ver.place(x=104, y=1)

        right = tk.Frame(hdr, bg=Palette.HEADER_BG)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=16)
        self.stat_elapsed = tk.StringVar(value="Time: 00:00:00")
        self.stat_rate = tk.StringVar(value="Rate: 0/s")
        self.stat_found_hdr = tk.StringVar(value="Found: 0")
        for var, label, fg in [
            (self.stat_elapsed, "\u23f1", Palette.DIM),
            (self.stat_rate, "\u26a1", Palette.CYAN),
            (self.stat_found_hdr, "\U0001f50d", Palette.GREEN),
        ]:
            f = tk.Frame(right, bg=Palette.MID, padx=8, pady=2)
            f.pack(side=tk.LEFT, padx=3, pady=8)
            tk.Label(f, text=label, fg=Palette.DIM, bg=Palette.MID,
                     font=("Segoe UI", 9)).pack(side=tk.LEFT)
            tk.Label(f, textvariable=var, fg=fg, bg=Palette.MID,
                     font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(4, 0))

        sep = tk.Frame(self.root, bg=Palette.BORDER, height=1)
        sep.pack(fill=tk.X)

    # ── Panels ───────────────────────────────────────────────────────
    def _build_panels(self):
        pw = tk.PanedWindow(self.root, bg=Palette.BG, sashrelief=tk.FLAT,
                            sashwidth=4, sashpad=0, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(pw, bg=Palette.BG)
        right = tk.Frame(pw, bg=Palette.BG)
        pw.add(left, width=500, minsize=400)
        pw.add(right, width=900, minsize=600)

        self._build_control_panel(left)
        self._build_content_panel(right)

    # ── Control Panel (fully organized sections) ─────────────────────
    def _build_control_panel(self, parent):
        cb = ttk.Frame(parent, padding=4)
        cb.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(cb, bg=Palette.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(cb, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel, add="+")

        sf = scroll_frame
        pd = {"padx": 3, "pady": 1}
        L = tk.Label

        # ── Section 1: Target ────────────────────────────────────────
        g = ttk.LabelFrame(sf, text="\U0001f310  Target", padding=8)
        g.pack(fill=tk.X, **pd)
        r = ttk.Frame(g)
        r.pack(fill=tk.X)
        L(r, text="URL:", width=5).pack(side=tk.LEFT)
        e = ttk.Combobox(r, textvariable=self.url_var, values=self._target_history, width=30)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        tk.Button(r, text="\u2398", font=("Segoe UI", 10),
                  bg=Palette.CARD, fg=Palette.WHITE, relief=tk.FLAT,
                  width=2, cursor="hand2",
                  command=lambda: self.url_var.set(self.root.clipboard_get())).pack(side=tk.LEFT)

        # ── Section 2: Wordlist ────────────────────────────────────
        g = ttk.LabelFrame(sf, text="\U0001f4c4  Wordlist", padding=8)
        g.pack(fill=tk.X, **pd)
        r = ttk.Frame(g)
        r.pack(fill=tk.X)
        L(r, text="File:", width=5).pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=self.wl_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Button(r, text="Browse", width=8, command=self._browse).pack(side=tk.LEFT)
        L(r, textvariable=self.wl_count_var, fg=Palette.DIM,
          font=("Segoe UI", 8)).pack(side=tk.RIGHT, padx=(8, 0))
        r2 = ttk.Frame(g)
        r2.pack(fill=tk.X, pady=(4, 0))
        L(r2, text="Cat:", width=5).pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.wordlist_cat_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Button(r2, text="DB", width=4, command=self._browse_db).pack(side=tk.LEFT)
        L(r2, text="e.g. common,php/wordpress", fg=Palette.DIM,
          font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(6, 0))

        # ── Section 3: Quick Presets ────────────────────────────────
        g = ttk.LabelFrame(sf, text="\u26a1  Quick Presets", padding=8)
        g.pack(fill=tk.X, **pd)
        r = ttk.Frame(g)
        r.pack(fill=tk.X)
        ttk.Combobox(r, textvariable=self.preset_var,
                     values=list(PRESET_CONFIGS.keys()), state="readonly", width=24
                     ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(r, text="Apply Preset", width=14,
                   command=self._apply_current_preset).pack(side=tk.LEFT)
        L(r, text="Auto-configure all scan options", fg=Palette.DIM,
          font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(10, 0))

        # ── Section 4: Scan Options (2-column) ───────────────────────
        g = ttk.LabelFrame(sf, text="\u2699  Scan Options", padding=8)
        g.pack(fill=tk.X, **pd)

        topf = ttk.Frame(g)
        topf.pack(fill=tk.X)

        # Left column: spinboxes
        lc = ttk.Frame(topf)
        lc.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for label, var, lo, hi in [
            ("Threads",   self.threads_var,   1, 999),
            ("Timeout s", self.timeout_var,    1, 300),
            ("Delay ms",  self.delay_var,      0, 60000),
            ("Retries",   self.retries_var,    0, 20),
        ]:
            rf = ttk.Frame(lc)
            rf.pack(fill=tk.X, pady=1)
            L(rf, text=label, width=10, anchor=tk.W).pack(side=tk.LEFT)
            ttk.Spinbox(rf, from_=lo, to=hi, textvariable=var, width=6,
                        font=("Consolas", 9)).pack(side=tk.RIGHT)

        # Right column: text entries
        rc = ttk.Frame(topf)
        rc.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(8, 0))
        for label, var, w in [
            ("Extensions", self.ext_var,       14),
            ("Max Rate/s", self.max_rate_var,   6),
            ("Prefixes",   self.prefix_var,    10),
            ("Suffixes",   self.suffix_var,    10),
        ]:
            rf = ttk.Frame(rc)
            rf.pack(fill=tk.X, pady=1)
            L(rf, text=label, width=12, anchor=tk.W).pack(side=tk.LEFT)
            ttk.Entry(rf, textvariable=var, width=w).pack(side=tk.RIGHT)

        # Method + Subdirs + Depth row
        botf = ttk.Frame(g)
        botf.pack(fill=tk.X, pady=(4, 0))
        L(botf, text="Method:", width=10, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Combobox(botf, textvariable=self.method_var,
                     values=["GET","POST","HEAD","PUT","DELETE","OPTIONS","PATCH"],
                     width=8, state="readonly").pack(side=tk.LEFT, padx=(0, 6))
        L(botf, text="Subdirs:", anchor=tk.W).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Entry(botf, textvariable=self.subdirs_var, width=14
                  ).pack(side=tk.LEFT, padx=(0, 4))
        L(botf, text="Depth:", anchor=tk.W).pack(side=tk.LEFT)
        ttk.Spinbox(botf, from_=1, to=10, textvariable=self.recursive_depth_var,
                    width=3).pack(side=tk.LEFT)

        # ── Section 5: Recursion & Transforms ───────────────────────
        g = ttk.LabelFrame(sf, text="\U0001f504  Recursion & Transforms", padding=8)
        g.pack(fill=tk.X, **pd)
        r1 = ttk.Frame(g)
        r1.pack(fill=tk.X)
        for var, text in [
            (self.recursive_var, "Recursive"),
            (self.deep_recursive_var, "Deep"),
            (self.force_recursive_var, "Force"),
            (self.follow_redirects_var, "Follow"),
            (self.crawl_var, "Crawl"),
        ]:
            ttk.Checkbutton(r1, text=text, variable=var).pack(side=tk.LEFT, padx=3)
        r2 = ttk.Frame(g)
        r2.pack(fill=tk.X, pady=(2, 0))
        for var, text in [
            (self.random_agent_var, "Rand-UA"),
            (self.force_ext_var, "Force-Ext"),
            (self.http2_var, "HTTP/2"),
            (self.uppercase_var, "Upper"),
            (self.lowercase_var, "Lower"),
            (self.capital_var, "Capital"),
        ]:
            ttk.Checkbutton(r2, text=text, variable=var).pack(side=tk.LEFT, padx=3)

        # ── Section 6: Filters (2-column) ──────────────────────────
        g = ttk.LabelFrame(sf, text="\U0001f50d  Filters", padding=8)
        g.pack(fill=tk.X, **pd)

        filt_top = ttk.Frame(g)
        filt_top.pack(fill=tk.X)

        # Left column
        flc = ttk.Frame(filt_top)
        flc.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for label, var, w in [
            ("Exclude Status", self.exclude_var,     8),
            ("Include Status", self.include_var,      8),
            ("Min Size",       self.min_size_var,     8),
            ("Max Size",       self.max_size_var,     8),
        ]:
            rf = ttk.Frame(flc)
            rf.pack(fill=tk.X, pady=1)
            L(rf, text=label, width=16, anchor=tk.W).pack(side=tk.LEFT)
            ttk.Entry(rf, textvariable=var, width=w).pack(side=tk.RIGHT)

        # Right column
        frc = ttk.Frame(filt_top)
        frc.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(8, 0))
        for label, var, w in [
            ("Exclude Sizes", self.exclude_sizes_var, 10),
            ("Exclude Text",  self.exclude_text_var,  12),
            ("Exclude Regex", self.exclude_regex_var, 12),
        ]:
            rf = ttk.Frame(frc)
            rf.pack(fill=tk.X, pady=1)
            L(rf, text=label, width=16, anchor=tk.W).pack(side=tk.LEFT)
            ttk.Entry(rf, textvariable=var, width=w).pack(side=tk.RIGHT)

        filt_bot = ttk.Frame(g)
        filt_bot.pack(fill=tk.X, pady=(4, 0))
        L(filt_bot, text="Match Status:", width=16, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(filt_bot, textvariable=self.match_status_var, width=10
                  ).pack(side=tk.LEFT, padx=(0, 8))
        L(filt_bot, text="Filter Status:", width=16, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(filt_bot, textvariable=self.filter_status_var, width=10
                  ).pack(side=tk.LEFT)

        # ── Section 7: Detection ──────────────────────────────────
        g = ttk.LabelFrame(sf, text="\U0001f4a1  Detection", padding=8)
        g.pack(fill=tk.X, **pd)
        d1 = ttk.Frame(g)
        d1.pack(fill=tk.X)
        for var, text in [
            (self.detect_waf_var, "WAF"),
            (self.detect_tech_var, "Tech"),
            (self.detect_backup_var, "Backup"),
            (self.extract_js_var, "JS Extract"),
            (self.smart_filter_var, "Smart Filter"),
            (self.auto_calibration_var, "Calibrate"),
        ]:
            ttk.Checkbutton(d1, text=text, variable=var).pack(side=tk.LEFT, padx=4)
        d2 = ttk.Frame(g)
        d2.pack(fill=tk.X, pady=(2, 0))
        for var, text in [
            (self.api_mode_var, "API Mode"),
            (self.adaptive_rate_var, "Adaptive"),
            (self.detect_login_var, "Login"),
            (self.detect_api_var, "API Detect"),
            (self.js_deep_var, "JS Deep"),
            (self.swagger_var, "Swagger"),
        ]:
            ttk.Checkbutton(d2, text=text, variable=var).pack(side=tk.LEFT, padx=4)

        # ── Section 8: Connection & Auth ──────────────────────────
        g = ttk.LabelFrame(sf, text="\U0001f4e1  Connection & Auth", padding=8)
        g.pack(fill=tk.X, **pd)

        r1 = ttk.Frame(g)
        r1.pack(fill=tk.X)
        L(r1, text="Proxy:", width=10, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(r1, textvariable=self.proxy_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Checkbutton(r1, text="Tor", variable=self.tor_var).pack(side=tk.LEFT)
        L(r1, text="127.0.0.1:9050", fg=Palette.DIM,
          font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(2, 0))

        r2 = ttk.Frame(g)
        r2.pack(fill=tk.X, pady=(4, 0))
        L(r2, text="User-Agent:", width=10, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.user_agent_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        r3 = ttk.Frame(g)
        r3.pack(fill=tk.X, pady=(4, 0))
        L(r3, text="Cookie:", width=10, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(r3, textvariable=self.cookie_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        r4 = ttk.Frame(g)
        r4.pack(fill=tk.X, pady=(4, 0))
        L(r4, text="Auth:", width=10, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(r4, textvariable=self.auth_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        L(r4, text="Type:", anchor=tk.W).pack(side=tk.LEFT)
        ttk.Combobox(r4, textvariable=self.auth_type_var,
                     values=["basic","digest","bearer","ntlm","jwt"],
                     width=8, state="readonly").pack(side=tk.LEFT, padx=(4, 0))

        # ── Section 9: Output ─────────────────────────────────────
        g = ttk.LabelFrame(sf, text="\U0001f4be  Output", padding=8)
        g.pack(fill=tk.X, **pd)
        r1 = ttk.Frame(g)
        r1.pack(fill=tk.X)
        for var, text in [
            (self.full_url_var, "Full URL"),
            (self.quiet_var, "Quiet"),
            (self.verbose_var, "Verbose"),
            (self.save_session_var, "Save Session"),
        ]:
            ttk.Checkbutton(r1, text=text, variable=var).pack(side=tk.LEFT, padx=4)
        r2 = ttk.Frame(g)
        r2.pack(fill=tk.X, pady=(4, 0))
        L(r2, text="Output File:", width=12, anchor=tk.W).pack(side=tk.LEFT)
        e = ttk.Entry(r2, textvariable=self.output_var)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        def _browse_output():
            p = filedialog.asksaveasfilename(defaultextension=".json",
                filetypes=[("JSON","*.json"),("CSV","*.csv"),("All","*.*")])
            if p:
                self.output_var.set(p)
        ttk.Button(r2, text="Browse", width=8, command=_browse_output).pack(side=tk.LEFT)

        # ── Section 10: Action Buttons ─────────────────────────────
        ab = ttk.Frame(sf)
        ab.pack(fill=tk.X, pady=8)

        self.start_btn = tk.Button(ab, text="\u25b6  START SCAN",
                                   font=("Segoe UI", 11, "bold"),
                                   bg=Palette.SUCCESS, fg=Palette.WHITE, relief=tk.FLAT,
                                   padx=20, pady=10, cursor="hand2",
                                   activebackground=Palette.GREEN,
                                   activeforeground=Palette.WHITE,
                                   command=self._start)
        self.start_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))

        self.stop_btn = tk.Button(ab, text="\u25a0  STOP",
                                  font=("Segoe UI", 11, "bold"),
                                  bg=Palette.DANGER, fg=Palette.WHITE, relief=tk.FLAT,
                                  padx=20, pady=10, cursor="hand2", state=tk.DISABLED,
                                  activebackground=Palette.RED,
                                  activeforeground=Palette.WHITE,
                                  command=self._stop)
        self.stop_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

        sm_btn = tk.Button(ab, text="\U0001f50d  SMART",
                           font=("Segoe UI", 9, "bold"),
                           bg=Palette.PURPLE, fg=Palette.WHITE, relief=tk.FLAT,
                           padx=14, pady=10, cursor="hand2",
                           activebackground="#8256d0",
                           activeforeground=Palette.WHITE,
                           command=self._run_smart_analysis)
        sm_btn.pack(side=tk.RIGHT, padx=(3, 0))

        # ── Section 11: Statistics ─────────────────────────────────
        st = ttk.LabelFrame(sf, text="\U0001f4ca  Statistics", padding=8)
        st.pack(fill=tk.X, **pd)

        sf2 = ttk.Frame(st)
        sf2.pack(fill=tk.X)

        self.stat_labels = {}
        for label, key, color in [
            ("Total", "total", Palette.WHITE),
            ("2xx", "s2xx", Palette.GREEN),
            ("3xx", "s3xx", Palette.CYAN),
            ("4xx", "s4xx", Palette.YELLOW),
            ("5xx", "s5xx", Palette.RED),
            ("Filtered", "filtered", Palette.ORANGE),
            ("Errors", "errors", Palette.PINK),
        ]:
            f = tk.Frame(sf2, bg=Palette.CARD, highlightbackground=Palette.BORDER,
                         highlightthickness=1)
            f.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
            tk.Label(f, text=label, fg=Palette.DIM, bg=Palette.CARD,
                     font=("Segoe UI", 8)).pack(pady=(2, 0))
            v = tk.StringVar(value="0")
            tk.Label(f, textvariable=v, fg=color, bg=Palette.CARD,
                     font=("Segoe UI", 14, "bold")).pack(pady=(1, 2))
            self.stat_labels[key] = v

        sf3 = ttk.Frame(st)
        sf3.pack(fill=tk.X, pady=(4, 0))
        self.progress_pct_var = tk.StringVar(value="0%")
        tk.Label(sf3, textvariable=self.progress_pct_var, fg=Palette.CYAN,
                 bg=Palette.BG, font=Palette.BOLD).pack(side=tk.LEFT)
        tk.Label(sf3, textvariable=self.stat_wl_var, fg=Palette.DIM,
                 bg=Palette.BG).pack(side=tk.RIGHT)
    def _build_content_panel(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        # ── Results Tab ────────────────────────────────────────────
        rf = ttk.Frame(nb)
        nb.add(rf, text="\U0001f4cb  Results")

        sr = ttk.Frame(rf)
        sr.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(sr, text="\U0001f50d  Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        se = ttk.Entry(sr, textvariable=self.search_var)
        se.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Checkbutton(sr, text="Regex", variable=self.regex_search_var).pack(side=tk.LEFT, padx=2)
        ttk.Button(sr, text="Vuln", width=5, command=self._filter_vuln).pack(side=tk.LEFT, padx=2)
        ttk.Button(sr, text="Clear", width=5, command=lambda: self.search_var.set("")).pack(side=tk.LEFT)
        self.count_var = tk.StringVar(value="Found: 0")
        tk.Label(sr, textvariable=self.count_var, fg=Palette.CYAN,
                 bg=Palette.BG, font=Palette.BOLD).pack(side=tk.RIGHT, padx=(6, 0))

        leg = ttk.Frame(rf)
        leg.pack(fill=tk.X, pady=(0, 4))
        for color, text in [(Palette.GREEN, "2xx Success"), (Palette.CYAN, "3xx Redirect"),
                            (Palette.YELLOW, "4xx Client Error"), (Palette.RED, "5xx Server Error"),
                            (Palette.PINK, "Vulnerable Path")]:
            f = tk.Frame(leg, bg=Palette.CARD, highlightbackground=color, highlightthickness=1, padx=6, pady=1)
            f.pack(side=tk.LEFT, padx=(0, 6))
            tk.Label(f, text=text, fg=color, bg=Palette.CARD, font=("Segoe UI", 8, "bold")).pack()

        tf = ttk.Frame(rf)
        tf.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(tf, columns=("status", "path", "size", "redirect", "type", "title"),
                                 show="headings", selectmode="extended")
        for col, h, w, a in [
            ("status", "Status", 55, tk.CENTER),
            ("path", "Path", 380, tk.W),
            ("size", "Size", 75, tk.CENTER),
            ("redirect", "Redirect", 180, tk.W),
            ("type", "Content-Type", 130, tk.W),
            ("title", "Title", 180, tk.W),
        ]:
            self.tree.heading(col, text=h)
            self.tree.column(col, width=w, anchor=a, minwidth=40)

        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        for lo, hi, tag, color, _ in STATUS_RANGES:
            self.tree.tag_configure(tag, foreground=color)
        self.tree.tag_configure("vuln", foreground=Palette.PINK)
        self.tree.tag_configure("hidden", foreground=Palette.DIM)
        self.tree.tag_configure("even", background="#131b26")
        self.tree.tag_configure("odd", background=Palette.MID)
        self.tree.bind("<Double-1>", self._on_tree_double)
        self.tree.bind("<Button-3>", self._on_tree_right)
        self.search_var.trace_add("write", lambda *_: self._debounced_search())

        # ── Log Tab ────────────────────────────────────────────────
        lf = ttk.Frame(nb)
        nb.add(lf, text="\U0001f4dd  Log")
        self.log_text = tk.Text(lf, wrap=tk.WORD, state=tk.DISABLED, bg=Palette.MID,
                                fg=Palette.WHITE, font=Palette.MONO_SM, padx=6, pady=4,
                                relief=tk.FLAT, bd=1)
        lsb = ttk.Scrollbar(lf, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=lsb.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lsb.pack(side=tk.RIGHT, fill=tk.Y)

        # ── Smart Analysis Tab ─────────────────────────────────────
        saf = ttk.Frame(nb)
        nb.add(saf, text="\U0001f50d  Smart Analysis")
        self.sa_text = tk.Text(saf, wrap=tk.WORD, state=tk.DISABLED, bg=Palette.MID,
                               fg=Palette.WHITE, font=Palette.MONO_SM, padx=6, pady=4,
                               relief=tk.FLAT, bd=1)
        sasb = ttk.Scrollbar(saf, orient=tk.VERTICAL, command=self.sa_text.yview)
        self.sa_text.configure(yscrollcommand=sasb.set)
        self.sa_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sasb.pack(side=tk.RIGHT, fill=tk.Y)

        # ── Dashboard Tab ──────────────────────────────────────────
        dsh = ttk.Frame(nb)
        nb.add(dsh, text="\U0001f4ca  Dashboard")
        self._build_dashboard(dsh)

        self.root.bind("<<ImportEndpoints>>", self._on_smart_import)

    # ── Dashboard Tab ───────────────────────────────────────────────
    def _build_dashboard(self, parent):
        f = ttk.Frame(parent, padding=12)
        f.pack(fill=tk.BOTH, expand=True)

        tk.Label(f, text="Scan Dashboard", fg=Palette.CYAN, bg=Palette.BG,
                 font=("Segoe UI", 14, "bold")).pack(anchor=tk.W, pady=(0, 12))

        cards = ttk.Frame(f)
        cards.pack(fill=tk.X)

        for row_data in [
            [("Target URL", "target_url", Palette.CYAN),
             ("Target IP", "target_ip", Palette.WHITE),
             ("Server", "server", Palette.GREEN)],
            [("Elapsed", "elapsed", Palette.DIM),
             ("Rate", "rate", Palette.CYAN),
             ("Remaining", "remaining", Palette.ORANGE),
             ("ETA", "eta", Palette.GOLD)],
        ]:
            rc = ttk.Frame(cards)
            rc.pack(fill=tk.X, pady=2)
            for label, key, color in row_data:
                cf = tk.Frame(rc, bg=Palette.CARD, highlightbackground=Palette.BORDER,
                              highlightthickness=1)
                cf.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
                tk.Label(cf, text=label, fg=Palette.DIM, bg=Palette.CARD,
                         font=("Segoe UI", 8)).pack(pady=(4, 0))
                v = tk.StringVar(value="-")
                tk.Label(cf, textvariable=v, fg=color, bg=Palette.CARD,
                         font=("Segoe UI", 16, "bold")).pack(pady=(0, 4))
                if key == "target_url":
                    self._dash_url = v
                elif key == "target_ip":
                    self._dash_ip = v
                elif key == "server":
                    self._dash_server = v
                elif key == "elapsed":
                    self._dash_elapsed = v
                elif key == "rate":
                    self._dash_rate = v
                elif key == "remaining":
                    self._dash_remaining = v
                elif key == "eta":
                    self._dash_eta = v

        self._dash_url.set("Ready")
        self._dash_ip.set("-")
        self._dash_server.set("-")

    # ── Status Bar ──────────────────────────────────────────────────
    def _build_status_bar(self):
        sb = tk.Frame(self.root, bg=Palette.CARD, height=30)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)

        prf = tk.Frame(sb, bg=Palette.MID)
        prf.pack(fill=tk.X, padx=0, pady=0)
        self.progress = ttk.Progressbar(prf, mode="determinate", style="bar.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, padx=0, pady=0)

        bf = tk.Frame(sb, bg=Palette.CARD)
        bf.pack(fill=tk.X, padx=8, pady=(1, 3))
        self.status_var = tk.StringVar(value="\u25c9  Ready")
        s = ttk.Style()
        s.configure("bar.Horizontal.TProgressbar", background=Palette.GREEN,
                     troughcolor=Palette.MID, bordercolor=Palette.CARD,
                     lightcolor=Palette.GREEN, darkcolor=Palette.GREEN, thickness=6)
        tk.Label(bf, textvariable=self.status_var, fg=Palette.DIM, bg=Palette.CARD,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.progress_label = tk.StringVar(value="")
        tk.Label(bf, textvariable=self.progress_label, fg=Palette.CYAN, bg=Palette.CARD,
                 font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT, padx=(0, 8))

    # ── Keyboard Shortcuts ──────────────────────────────────────────
    def _bind_shortcuts(self):
        self.root.bind("<Control-o>", lambda e: self._browse())
        self.root.bind("<Control-d>", lambda e: self._browse_db())
        self.root.bind("<Control-s>", lambda e: self._save())
        self.root.bind("<Control-l>", lambda e: self._load_session())
        self.root.bind("<Control-Shift-S>", lambda e: self._save_session())
        self.root.bind("<Control-Shift-C>", lambda e: self._clear())
        self.root.bind("<Escape>", lambda e: self._stop() if self.running else None)
        self.root.bind("<F5>", lambda e: self._start() if not self.running else None)
        self.root.bind("<F6>", lambda e: self._run_smart_analysis())

    # ── Presets ─────────────────────────────────────────────────────
    def _apply_preset(self, name):
        cfg = PRESET_CONFIGS.get(name)
        if not cfg:
            return
        self.preset_var.set(name)
        if "threads" in cfg:
            self.threads_var.set(cfg["threads"])
        if "ext" in cfg:
            self.ext_var.set(cfg["ext"])
        if "recursive" in cfg:
            self.recursive_var.set(cfg["recursive"])
        if "max_depth" in cfg:
            self.recursive_depth_var.set(cfg["max_depth"])
        if "smart_filter" in cfg:
            self.smart_filter_var.set(cfg["smart_filter"])
        if "api_mode" in cfg:
            self.api_mode_var.set(cfg["api_mode"])
        if "extract_js" in cfg:
            self.extract_js_var.set(cfg["extract_js"])
        if "detect_tech" in cfg:
            self.detect_tech_var.set(cfg["detect_tech"])
        if "detect_waf" in cfg:
            self.detect_waf_var.set(cfg["detect_waf"])
        if "crawl" in cfg:
            self.crawl_var.set(cfg["crawl"])
        if "js_deep" in cfg:
            self.js_deep_var.set(cfg["js_deep"])
        self._log(f"[+] Preset applied: {name}")

    def _apply_current_preset(self):
        self._apply_preset(self.preset_var.get())

    # ── Target History ──────────────────────────────────────────────
    def _load_target_history(self):
        hist_file = ENGINE_DIR / "target_history.json"
        if hist_file.exists():
            try:
                return json.loads(hist_file.read_text())
            except Exception:
                pass
        return []

    def _save_target_history(self):
        hist_file = ENGINE_DIR / "target_history.json"
        url = self.url_var.get().strip()
        if url:
            history = self._target_history
            if url in history:
                history.remove(url)
            history.insert(0, url)
            self._target_history = history[:20]
            try:
                hist_file.write_text(json.dumps(self._target_history))
            except Exception:
                pass

    # ── Wordlist ────────────────────────────────────────────────────
    def _update_wordlist_info(self, *_):
        n = self._path_count()
        self.wl_count_var.set(f"Paths: {n}")
        self.stat_wl_var.set(f"Wordlist: {n}")

    def _path_count(self):
        wl = self.wl_var.get().strip()
        if wl != self._wl_path or self._wl_count < 0:
            self._wl_path = wl
            self._wl_count = 0
            if wl and os.path.isfile(wl):
                try:
                    with open(wl) as f:
                        self._wl_count = sum(1 for line in f if line.strip() and not line.startswith("#"))
                except Exception:
                    pass
        return self._wl_count + len(self._smart_endpoints)

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
        if self._smart_endpoints:
            paths.extend(self._smart_endpoints)
        if not paths:
            return None
        # Write to temp file so Go's -w can read it as a file path
        tmp = SESSION_DIR / f"wl_{os.getpid()}.txt"
        try:
            tmp.write_text("\n".join(paths) + "\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write temp wordlist: {e}")
            return None
        return str(tmp), len(paths)

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
        w.title("Wordlist Database — DirFinder V.2.1")
        w.geometry("700x520")
        w.configure(bg=Palette.BG)
        w.transient(self.root)

        tk.Label(w, text="\U0001f4c1  Built-in Wordlist Database", fg=Palette.CYAN,
                 bg=Palette.BG, font=("Segoe UI", 13, "bold")).pack(pady=(12, 2))
        tk.Label(w, text="Select a wordlist or browse categories", fg=Palette.DIM,
                 bg=Palette.BG, font=("Segoe UI", 9)).pack(pady=(0, 8))

        nb = ttk.Notebook(w)
        nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        # All files tab
        ftab = ttk.Frame(nb)
        nb.add(ftab, text="All Wordlists")
        cols = ("file", "count")
        tv = ttk.Treeview(ftab, columns=cols, show="headings", selectmode="browse")
        tv.heading("file", text="File Path")
        tv.heading("count", text="Entries")
        tv.column("file", width=500)
        tv.column("count", width=80, anchor=tk.CENTER)
        sc = ttk.Scrollbar(ftab, orient=tk.VERTICAL, command=tv.yview)
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

        # Categories tab
        ctab = ttk.Frame(nb)
        nb.add(ctab, text="Categories")
        cat_dir = DB_DIR / "categories"
        if cat_dir.exists():
            cats = sorted([d.name for d in cat_dir.iterdir() if d.is_dir()]) + \
                    sorted([f.stem for f in cat_dir.glob("*.txt")])
            tv2 = ttk.Treeview(ctab, columns=("category",), show="headings", selectmode="browse")
            tv2.heading("category", text="Category")
            tv2.column("category", width=600)
            sc2 = ttk.Scrollbar(ctab, orient=tk.VERTICAL, command=tv2.yview)
            tv2.configure(yscrollcommand=sc2.set)
            tv2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            sc2.pack(side=tk.RIGHT, fill=tk.Y)
            for c in sorted(set(cats)):
                tv2.insert("", tk.END, values=(c,))

        bf = ttk.Frame(w)
        bf.pack(fill=tk.X, padx=12, pady=8)

        def select():
            sel = tv.selection()
            if sel:
                vals = tv.item(sel[0], "values")
                if vals and vals[0]:
                    full = ENGINE_DIR / vals[0]
                    if full.exists():
                        self.wl_var.set(str(full))
                        self._update_wordlist_info()
                        w.destroy()

        def select_cat():
            sel = tv2.selection()
            if sel:
                vals = tv2.item(sel[0], "values")
                if vals and vals[0]:
                    cur = self.wordlist_cat_var.get().strip()
                    cats = [c.strip() for c in cur.split(",") if c.strip()]
                    if vals[0] not in cats:
                        cats.append(vals[0])
                    self.wordlist_cat_var.set(",".join(cats))
                    w.destroy()

        ttk.Button(bf, text="Select File", command=select).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(bf, text="Select Category", command=select_cat).pack(side=tk.RIGHT, padx=(4, 0))
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

        if self.ext_var.get().strip():
            cmd += ["-e", self.ext_var.get().strip()]
        if self.prefix_var.get().strip():
            cmd += ["-prefixes", self.prefix_var.get().strip()]
        if self.suffix_var.get().strip():
            cmd += ["-suffixes", self.suffix_var.get().strip()]
        if self.wordlist_cat_var.get().strip():
            cmd += ["-wordlist-categories", self.wordlist_cat_var.get().strip()]

        if self.method_var.get() != "GET":
            cmd += ["-m", self.method_var.get()]
        if self.user_agent_var.get().strip():
            cmd += ["-user-agent", self.user_agent_var.get().strip()]
        if self.cookie_var.get().strip():
            cmd += ["-cookie", self.cookie_var.get().strip()]
        if self.auth_var.get().strip():
            cmd += ["-auth", self.auth_var.get().strip(), "-auth-type", self.auth_type_var.get()]

        if self.proxy_var.get().strip():
            cmd += ["-p", self.proxy_var.get().strip()]

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

        if self.recursive_var.get():
            cmd += ["-r", "-R", self.recursive_depth_var.get().strip()]
        if self.deep_recursive_var.get():
            cmd.append("-deep-recursive")
        if self.force_recursive_var.get():
            cmd.append("-force-recursive")
        if self.subdirs_var.get().strip():
            cmd += ["-subdirs", self.subdirs_var.get().strip()]

        if self.output_var.get().strip():
            cmd += ["-o", self.output_var.get().strip(), "-O", "json"]
        if self.full_url_var.get():
            cmd.append("-full-url")
        if self.quiet_var.get():
            cmd.append("-q")
        if self.verbose_var.get():
            cmd.append("-v")

        for var, flag in [
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
            (self.adaptive_rate_var, "-adaptive-rate"),
            (self.detect_login_var, "-detect-login"),
            (self.detect_api_var, "-detect-api"),
            (self.js_deep_var, "-js-deep"),
            (self.swagger_var, "-swagger"),
        ]:
            if var.get():
                cmd.append(flag)

        self._save_target_history()
        self.results.clear()
        self._all_items.clear()
        self._scan_progress = 0
        while not self.log_queue.empty():
            try:
                self.log_queue.get_nowait()
            except queue.Empty:
                break
        self.running = True
        self.start_time = time.time()
        self.start_btn.config(state=tk.DISABLED, text="\u23f3  RUNNING...")
        self.stop_btn.config(state=tk.NORMAL, text="\u25a0  STOP")
        self.progress.configure(mode="determinate", maximum=total, value=0)
        self.status_var.set(f"Scanning 0/{total}")
        self.progress_label.set("")
        self.progress_pct_var.set("0%")

        for k in self.stat_labels:
            self.stat_labels[k].set("0")
        self.count_var.set("Found: 0")
        self.stat_found_hdr.set("Found: 0")
        self._dash_url.set(url)

        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan started: {url}")
        self._log(f"    Paths: {total} | Threads: {self.threads_var.get()} | Extensions: {self.ext_var.get() or 'none'}")
        self.root.after(30, self._poll_queue)
        if self.detect_waf_var.get():
            self._log("    WAF Detection: ON")
        if self.smart_filter_var.get():
            self._log("    Smart Filtering: ON (soft-404 + honeypot)")
        if self.recursive_var.get():
            self._log(f"    Recursive: ON (depth {self.recursive_depth_var.get()})")
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
        if not self.running:
            return
        try:
            for _ in range(50):
                item = self.log_queue.get_nowait()
                if item is None:
                    self._finish()
                    return
                line = item.rstrip() if item else ""
                if not line:
                    continue
                self._log(line)
                stripped = strip_ansi(line).strip()

                # Try parsing as a scan result line
                res = self._parse_result(stripped)
                if res:
                    self.results.append(res)
                    self._add_tree(res)
                    self._scan_progress += 1
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
                    n = len(self.results)
                    self.count_var.set(f"Found: {n}")
                    self.stat_found_hdr.set(f"Found: {n}")
                else:
                    # Parse progress line: [*] [175/4613] 3% | Found: 0 ...
                    if stripped.startswith("[*]") and "/" in stripped:
                        m = re.search(r'\[(\d+)/(\d+)\]', stripped)
                        if m:
                            self._scan_progress = int(m.group(1))
                            total = int(m.group(2))
                            self.progress.configure(maximum=total)
                    # Parse filter/error counts from summary
                    if "iltered" in stripped:
                        m = self._filter_re.search(stripped)
                        if m:
                            self.stat_labels["filtered"].set(m.group(1))
                    if "Errors:" in stripped:
                        m = self._err_re.search(stripped)
                        if m:
                            self.stat_labels["errors"].set(m.group(1))
                    # Parse IP from connectivity line
                    m = self._ip_re.search(stripped)
                    if m:
                        self._dash_ip.set(m.group(1))
                    # Parse server from fingerprint line
                    m = self._server_re.search(stripped)
                    if m:
                        self._dash_server.set(m.group(1).strip())

                total_max = max(int(self.progress["maximum"]), 1)
                self.progress.configure(value=self._scan_progress)
                pct = int(self._scan_progress / total_max * 100)
                self.progress_pct_var.set(f"{pct}%")
                self.status_var.set(f"Scanning {self._scan_progress}/{total_max} ({pct}%)")
                self.progress_label.set(f"{pct}%")
                if self._dash_remaining:
                    self._dash_remaining.set(str(total_max - self._scan_progress))
        except queue.Empty:
            pass
        if self.running:
            self.root.after(30, self._poll_queue)

    def _parse_result(self, stripped):
        m = self._parse_re.match(stripped)
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
        if self._dash_elapsed:
            self._dash_elapsed.set(f"{h:02d}:{m:02d}:{s:02d}")
        n = int(self.stat_labels["total"].get())
        rate = n / e if e > 0 else 0
        self.stat_rate.set(f"Rate: {rate:.1f}/s")
        if self._dash_rate:
            self._dash_rate.set(f"{rate:.1f}/s")
        if rate > 0 and self._scan_progress > 0:
            remaining = max(int(self.progress["maximum"]) - self._scan_progress, 0)
            eta = remaining / rate if rate > 0 else 0
            em, es = divmod(int(eta), 60)
            self.status_var.set(f"ETA: {em:02d}:{es:02d} | {self._scan_progress}/{int(self.progress['maximum'])}")
            if self._dash_eta:
                self._dash_eta.set(f"{em:02d}:{es:02d}")
        self._elapsed_id = self.root.after(1000, self._elapsed_loop)

    # ── Tree Management ─────────────────────────────────────────────
    def _add_tree(self, result):
        tag, color = status_tag(result["status"])
        tags = [tag]
        path = result.get("path", "")
        if is_vulnerable(path):
            tags.append("vuln")
        parity = "even" if len(self._all_items) % 2 == 0 else "odd"
        tags.append(parity)
        row_id = self.tree.insert("", tk.END, values=(
            result["status"], path, result["size"],
            result.get("redirect", ""), result.get("type", ""),
            result.get("title", "")), tags=tuple(tags))
        self._all_items.append((row_id, result["status"], path))

    def _debounced_search(self):
        if self._debounce_id:
            self.root.after_cancel(self._debounce_id)
        self._debounce_id = self.root.after(150, self._filter_results)

    def _filter_results(self, *_):
        sv = self.search_var.get()
        use_regex = self.regex_search_var.get()
        try:
            pattern = re.compile(sv, re.I) if use_regex and sv else None
        except re.error:
            return
        for row_id, status, path in self._all_items:
            self._filter_results_item(row_id, status, path, sv, pattern)

    def _filter_results_item(self, row_id, status, path, sv=None, pattern=None):
        hide = False
        if sv is None:
            sv = self.search_var.get()
            if sv:
                use_regex = self.regex_search_var.get()
                try:
                    pattern = re.compile(sv, re.I) if use_regex else None
                except re.error:
                    pattern = None
        if sv:
            if pattern:
                hide = not bool(pattern.search(str(status)) or pattern.search(path))
            else:
                svl = sv.lower()
                hide = not (svl in str(status).lower() or svl in path.lower())
        tags = list(self.tree.item(row_id, "tags"))
        if hide:
            if "hidden" not in tags:
                tags.append("hidden")
        else:
            tags = [t for t in tags if t != "hidden"]
        self.tree.item(row_id, tags=tuple(tags))

    def _filter_vuln(self):
        self.search_var.set("")
        for row_id, status, path in self._all_items:
            tags = list(self.tree.item(row_id, "tags"))
            tags = [t for t in tags if t != "hidden"]
            if not is_vulnerable(path):
                tags.append("hidden")
            self.tree.item(row_id, tags=tuple(tags))
        self.status_var.set("Filtered: vulnerable paths only")

    # ── Right-Click Menu ────────────────────────────────────────────
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
        menu.add_command(label="Copy Paths Only", command=self._copy_paths)
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

    def _copy_paths(self):
        paths = [r["path"] for r in self.results]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(paths))
        self.status_var.set(f"Copied {len(paths)} paths")

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
                webbrowser.open(f"{t}/{str(vals[1]).lstrip('/')}")

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

    # ── Session Management ──────────────────────────────────────────
    def _save_session(self):
        if not self.results:
            messagebox.showinfo("Session", "No results to save.")
            return
        url = self.url_var.get().strip()
        path = filedialog.asksaveasfilename(
            title="Save Session",
            initialdir=str(SESSION_DIR),
            defaultextension=".json",
            filetypes=[("Session", "*.json")]
        )
        if not path:
            return
        data = {
            "version": self.VERSION,
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "results": self.results,
            "config": {
                "url": url,
                "threads": self.threads_var.get(),
                "extensions": self.ext_var.get(),
                "method": self.method_var.get(),
                "wordlist": self.wl_var.get(),
                "categories": self.wordlist_cat_var.get(),
            }
        }
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            self._log(f"[+] Session saved: {path}")
            messagebox.showinfo("Session", f"Session saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")

    def _load_session(self):
        path = filedialog.askopenfilename(
            title="Load Session",
            initialdir=str(SESSION_DIR),
            filetypes=[("Session", "*.json"), ("All", "*.*")]
        )
        if not path:
            return
        try:
            with open(path) as f:
                data = json.load(f)
            self._clear()
            if "target" in data:
                self.url_var.set(data["target"])
            if "results" in data:
                for r in data["results"]:
                    self.results.append(r)
                    self._add_tree(r)
                self.count_var.set(f"Found: {len(self.results)}")
                self._log(f"[+] Session loaded: {path}")
                self._log(f"    Target: {data.get('target', 'N/A')}")
                self._log(f"    Results: {len(data.get('results', []))}")
                self._log(f"    Timestamp: {data.get('timestamp', 'N/A')}")
                messagebox.showinfo("Session", f"Loaded {len(data['results'])} results from session.")
        except Exception as e:
            messagebox.showerror("Error", f"Load failed: {e}")

    # ── Export HTML Report ──────────────────────────────────────────
    def _export_html(self):
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            filetypes=[("HTML", "*.html")])
        if not path:
            return
        t = self.url_var.get().strip()
        rows = ""
        for i, r in enumerate(self.results, 1):
            color = "#3fb950" if 200 <= r["status"] < 300 else \
                    "#58a6ff" if 300 <= r["status"] < 400 else \
                    "#d29922" if 400 <= r["status"] < 500 else "#f85149"
            vuln = " ⚠️" if is_vulnerable(r.get("path", "")) else ""
            rows += f"""<tr style="color:{color}">
                <td>{i}</td>
                <td>{r['status']}</td>
                <td>{r['size']}</td>
                <td>{t}/{r['path'].lstrip('/')}{vuln}</td>
                <td>{r.get('redirect', '')}</td>
                <td>{r.get('title', '')}</td>
            </tr>\n"""
        html = f"""<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><title>DirFinder Report - {t}</title>
<style>
body {{ background:#0d1117; color:#e6edf3; font-family: 'Segoe UI',sans-serif; margin:20px; }}
h1 {{ color:#58a6ff; }}
table {{ border-collapse:collapse; width:100%; }}
th {{ background:#161b22; color:#58a6ff; padding:8px 12px; text-align:left; }}
td {{ padding:6px 12px; border-bottom:1px solid #30363d; }}
tr:hover {{ background:#1c2333; }}
.meta {{ color:#8b949e; margin:10px 0; }}
</style></head><body>
<h1>\U0001f4c1 DirFinder HackIT V.2.1 — Scan Report</h1>
<div class="meta">Target: {t}</div>
<div class="meta">Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
<div class="meta">Results: {len(self.results)}</div>
<table><thead><tr><th>#</th><th>Status</th><th>Size</th><th>URL</th><th>Redirect</th><th>Title</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
        try:
            with open(path, "w") as f:
                f.write(html)
            self._log(f"[+] HTML report saved: {path}")
            messagebox.showinfo("Exported", f"HTML report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    # ── Lifecycle ───────────────────────────────────────────────────
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
        self.progress_pct_var.set("100%")
        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan finished. {n} results in {h:02d}:{m:02d}:{s:02d}.")
        if n > 0:
            messagebox.showinfo("Scan Complete", f"{n} results found in {h:02d}:{m:02d}:{s:02d}")
        # Cleanup temp wordlist
        for f in SESSION_DIR.glob("wl_*.txt"):
            try:
                f.unlink()
            except OSError:
                pass

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
                    json.dump({"target": t, "version": self.VERSION, "timestamp": ts,
                               "total": len(self.results), "results": self.results}, f, indent=2)
            elif ext == ".csv":
                with open(path, "w", newline="") as f:
                    f.write("path,status,size,redirect,title\n")
                    for r in self.results:
                        f.write(f"{r['path']},{r['status']},{r['size']},{r.get('redirect','')},{r.get('title','')}\n")
            else:
                with open(path, "w") as f:
                    f.write(f"DirFinder HackIT {self.VERSION} - Report\n")
                    f.write(f"Target: {t}\nDate: {datetime.now()}\n{'='*60}\n\n")
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
        self.sa_text.configure(state=tk.NORMAL)
        self.sa_text.delete("1.0", tk.END)
        self.sa_text.configure(state=tk.DISABLED)
        self.progress.configure(value=0)
        self.count_var.set("Found: 0")
        self.status_var.set("Ready")
        self.stat_elapsed.set("Time: 00:00:00")
        self.stat_rate.set("Rate: 0/s")
        self.stat_found_hdr.set("Found: 0")
        self.progress_label.set("")
        self.progress_pct_var.set("0%")
        for k in self.stat_labels:
            self.stat_labels[k].set("0")
        if self._dash_elapsed:
            self._dash_elapsed.set("00:00:00")
        if self._dash_rate:
            self._dash_rate.set("0/s")
        if self._dash_remaining:
            self._dash_remaining.set("0")
        if self._dash_eta:
            self._dash_eta.set("-")

    def _about(self):
        msg = (f"DirFinder HackIT {self.VERSION}\n\n"
               "Quad-Engine Architecture:\n"
               "  \u2022 Go Core — High-performance directory scanner\n"
               "  \u2022 Python — Smart analysis & intelligence\n"
               "  \u2022 Rust — Turbo async engine (optional)\n"
               "  \u2022 Ruby — Multi-engine orchestrator\n\n"
               "32 Integrated Go Engines:\n"
               "  URL, Dictionary, Transform, Recursion, Filter, Match,\n"
               "  Text, Request, Connection, Session, Backup, JS,\n"
               "  Detect, API Spec, Smart, Report\n\n"
               "99 CLI Flags — 30,000+ wordlist entries\n"
               f"\u00a9 HackIT Security Framework")
        messagebox.showinfo(f"About DirFinder {self.VERSION}", msg)

    def _show_help(self):
        msg = (f"DirFinder HackIT {self.VERSION} — Help\n\n"
               "Keyboard Shortcuts:\n"
               "  F5             Start scan\n"
               "  F6             Smart Analysis\n"
               "  Ctrl+O         Open wordlist\n"
               "  Ctrl+D         Browse DB wordlists\n"
               "  Ctrl+S         Save results\n"
               "  Ctrl+L         Load session\n"
               "  Ctrl+Shift+S   Save session\n"
               "  Escape         Stop scan\n"
               "  Ctrl+Shift+C   Clear all\n\n"
               "Quick Presets:\n"
               "  Quick Scan — Fast scan, common extensions\n"
               "  Full Scan  — Deep recursive scan\n"
               "  API Scan   — API endpoint discovery\n"
               "  CMS Scan   — CMS/WordPress detection\n"
               "  JS Deep    — JavaScript endpoint extraction\n\n"
               "Tips:\n"
               "  \u2022 Run Smart Analysis first to auto-detect tech\n"
               "  \u2022 Use presets for common scan configurations\n"
               "  \u2022 Use regex search for advanced filtering\n"
               "  \u2022 Right-click results for context menu\n"
               "  \u2022 Dashboard tab shows real-time stats")
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
