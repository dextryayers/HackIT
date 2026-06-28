"""
Dir Finder GUI — Professional tkinter interface.
"""

import os, sys, re, json, subprocess, threading, queue, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime

ENGINE_DIR = Path(__file__).parent
GO_BINARY = ENGINE_DIR / "go" / "dir_finder"
DB_DIR = ENGINE_DIR / "db"

ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
RESULT_RE = re.compile(
    r'\[\d{2}:\d{2}:\d{2}\]\s+(\d+)\s+-\s+(.*?)\s+-\s+(\S.*?)(?:\s*->\s*(.*))?\s*$'
)

DARK = "#0a0e14"
MID = "#111820"
CARD = "#151d28"
CARD2 = "#18222e"
WHITE = "#e6eef5"
GREEN = "#4ae08a"
RED = "#f05050"
YELLOW = "#f0c040"
CYAN = "#40c0f0"
BLUE = "#5090f0"
DIM = "#607080"
ORANGE = "#f09040"
BORDER = "#1e2a36"

FONT = ("Consolas", 10)
BTN_FONT = ("Segoe UI", 9, "bold")


def strip_ansi(text):
    return ANSI_RE.sub("", text)


def parse_result_line(line):
    stripped = strip_ansi(line).strip()
    m = RESULT_RE.match(stripped)
    if m:
        return {
            "status": int(m.group(1)),
            "size": m.group(2).strip(),
            "path": m.group(3).strip(),
            "redirect": (m.group(4) or "").strip(),
        }
    return None


class DirFinderGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Dir Finder - HackIT")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=DARK)
        self._setup_style()

        self.process = None
        self.running = False
        self.results = []
        self._all_items = []
        self.log_queue = queue.Queue()
        self.start_time = None
        self._scan_progress = 0
        self._elapsed_id = None

        self.wl_count_var = tk.StringVar(value="Paths: 0")
        self.stat_wl_var = tk.StringVar(value="Wordlist: 0")

        self._build_ui()
        self._init_traces()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._update_wordlist_info()
        self.root.after(100, self._poll_queue)

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        bg = DARK
        style.configure(".", background=bg, foreground=WHITE,
                        fieldbackground=MID, selectbackground=BLUE,
                        font=("Segoe UI", 10))
        style.configure("TLabel", background=bg, foreground=WHITE)
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, foreground=CYAN,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)
        style.configure("TLabelframe.Label", background=bg, foreground=CYAN,
                        font=("Segoe UI", 9, "bold"))
        style.configure("TButton", background=CARD, foreground=WHITE,
                        bordercolor=BORDER, focuscolor="none",
                        lightcolor=BORDER, darkcolor=BORDER, font=BTN_FONT)
        style.map("TButton", background=[("active", MID)])
        style.configure("Start.TButton", background="#1a6b3c", foreground=WHITE,
                        bordercolor="#2a8b4c")
        style.map("Start.TButton", background=[("active", "#2a8b4c"),
                                                ("disabled", "#1a3b2c")])
        style.configure("Stop.TButton", background="#801010", foreground=WHITE,
                        bordercolor="#a02020")
        style.map("Stop.TButton", background=[("active", "#a02020"),
                                               ("disabled", "#3a1010")])
        style.configure("Treeview", background=MID, foreground=WHITE,
                        fieldbackground=MID, bordercolor=BORDER)
        style.map("Treeview", background=[("selected", BLUE)])
        style.configure("Treeview.Heading", background=CARD, foreground=CYAN,
                        bordercolor=BORDER, font=("Segoe UI", 9, "bold"))
        style.configure("Horizontal.TProgressbar", background=BLUE,
                        troughcolor=MID, bordercolor=BORDER)
        style.configure("TEntry", fieldbackground=MID, foreground=WHITE,
                        bordercolor=BORDER)
        style.configure("TSpinbox", fieldbackground=MID, foreground=WHITE)
        style.configure("TCombobox", fieldbackground=MID, foreground=WHITE,
                        selectbackground=BLUE, arrowcolor=WHITE)

    def _build_ui(self):
        self._build_menu()
        self._build_header()
        self._build_input_area()
        self._build_action_bar()
        self._build_stats()
        self._build_content()
        self._build_status_bar()

    def _build_menu(self):
        mb = tk.Menu(self.root, bg=CARD, fg=WHITE,
                     activebackground=BLUE, activeforeground=WHITE)
        fm = tk.Menu(mb, tearoff=0, bg=CARD, fg=WHITE,
                     activebackground=BLUE, activeforeground=WHITE)
        fm.add_command(label="Open Wordlist...", command=self._browse,
                       accelerator="Ctrl+O")
        fm.add_separator()
        fm.add_command(label="Save Results", command=self._save,
                       accelerator="Ctrl+S")
        fm.add_command(label="Clear All", command=self._clear)
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close)
        mb.add_cascade(label="File", menu=fm)

        tm = tk.Menu(mb, tearoff=0, bg=CARD, fg=WHITE,
                     activebackground=BLUE, activeforeground=WHITE)
        tm.add_command(label="Browse DB Wordlists", command=self._browse_db)
        mb.add_cascade(label="Tools", menu=tm)

        hm = tk.Menu(mb, tearoff=0, bg=CARD, fg=WHITE,
                     activebackground=BLUE, activeforeground=WHITE)
        hm.add_command(label="About", command=self._about)
        mb.add_cascade(label="Help", menu=hm)
        self.root.config(menu=mb)

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=CARD2, height=48)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        title = tk.Label(hdr, text="DIR FINDER",
                         fg=CYAN, bg=CARD2,
                         font=("Segoe UI", 15, "bold"))
        title.place(x=15, rely=0.5, anchor=tk.W)

        subtitle = tk.Label(hdr, text="Directory & File Scanner",
                            fg=DIM, bg=CARD2,
                            font=("Segoe UI", 9))
        subtitle.place(x=130, rely=0.5, anchor=tk.W)

        ver = tk.Label(hdr, text="v2.2", fg=DIM, bg=CARD2,
                       font=("Segoe UI", 8))
        ver.place(relx=1.0, x=-15, rely=0.5, anchor=tk.E)

        sep = tk.Frame(self.root, bg=BORDER, height=1)
        sep.pack(fill=tk.X)

    def _build_input_area(self):
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        self.left_frame = ttk.Frame(main)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ctrl = ttk.LabelFrame(self.left_frame, text="Target & Wordlist",
                              padding=8)
        ctrl.pack(fill=tk.X, pady=(0, 5))

        r = ttk.Frame(ctrl)
        r.pack(fill=tk.X, pady=1)
        ttk.Label(r, text="URL:", width=6).pack(side=tk.LEFT)
        self.url_var = tk.StringVar()
        e = ttk.Entry(r, textvariable=self.url_var)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Button(r, text="Paste", width=5,
                   command=lambda: self.url_var.set(
                       self.root.clipboard_get())).pack(side=tk.LEFT)

        r = ttk.Frame(ctrl)
        r.pack(fill=tk.X, pady=1)
        ttk.Label(r, text="File:", width=6).pack(side=tk.LEFT)
        self.wl_var = tk.StringVar()
        ttk.Entry(r, textvariable=self.wl_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Button(r, text="Browse", command=self._browse).pack(side=tk.LEFT)
        ttk.Button(r, text="DB", width=3,
                   command=self._browse_db).pack(side=tk.LEFT, padx=(3, 0))

        r = ttk.Frame(ctrl)
        r.pack(fill=tk.X, pady=(3, 0))
        ttk.Label(r, text="Custom:", width=6).pack(side=tk.LEFT)
        self.custom_text = tk.Text(r, height=3, bg=MID, fg=WHITE,
                                   insertbackground=WHITE, font=FONT,
                                   relief=tk.FLAT, bd=1, padx=4, pady=2)
        self.custom_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.custom_text.insert("1.0", "admin\nlogin\nwp-admin\n.php\n.env")
        sb = ttk.Scrollbar(r, orient=tk.VERTICAL,
                           command=self.custom_text.yview)
        self.custom_text.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.LEFT, fill=tk.Y)

        opts = ttk.LabelFrame(self.left_frame, text="Options", padding=8)
        opts.pack(fill=tk.X, pady=(0, 5))

        sf = ttk.Frame(opts)
        sf.pack(fill=tk.X)

        items = [
            ("Threads", "50", 1, 500, lambda: tk.Spinbox(
                sf, from_=1, to=500, textvariable=self.threads_var, width=5)),
            ("Timeout", "10", 1, 120, None),
            ("Delay ms", "0", 0, 10000, None),
        ]
        self.threads_var = tk.StringVar(value="50")
        self.timeout_var = tk.StringVar(value="10")
        self.delay_var = tk.StringVar(value="0")

        ttk.Label(sf, text="Threads", width=8).pack(side=tk.LEFT)
        ttk.Spinbox(sf, from_=1, to=500, textvariable=self.threads_var,
                    width=5).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(sf, text="Timeout", width=8).pack(side=tk.LEFT)
        ttk.Spinbox(sf, from_=1, to=120, textvariable=self.timeout_var,
                    width=5).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(sf, text="Delay", width=6).pack(side=tk.LEFT)
        ttk.Spinbox(sf, from_=0, to=10000, textvariable=self.delay_var,
                    width=5).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(sf, text="Ext", width=5).pack(side=tk.LEFT)
        self.ext_var = tk.StringVar(value="php,asp,html,txt")
        ttk.Entry(sf, textvariable=self.ext_var, width=14).pack(
            side=tk.LEFT, padx=(0, 6))

        ttk.Label(sf, text="Method", width=7).pack(side=tk.LEFT)
        self.method_var = tk.StringVar(value="GET")
        ttk.Combobox(sf, textvariable=self.method_var,
                     values=["GET", "POST", "HEAD"], width=7,
                     state="readonly").pack(side=tk.LEFT)

        sf2 = ttk.Frame(opts)
        sf2.pack(fill=tk.X, pady=(3, 0))

        ttk.Label(sf2, text="X-St", width=8).pack(side=tk.LEFT)
        self.exclude_var = tk.StringVar(value="404")
        ttk.Entry(sf2, textvariable=self.exclude_var, width=10).pack(
            side=tk.LEFT, padx=(0, 6))

        ttk.Label(sf2, text="In-St", width=8).pack(side=tk.LEFT)
        self.include_var = tk.StringVar(value="")
        ttk.Entry(sf2, textvariable=self.include_var, width=10).pack(
            side=tk.LEFT, padx=(0, 8))

        self.follow_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(sf2, text="Follow Redirect",
                        variable=self.follow_var).pack(side=tk.LEFT, padx=(0, 4))
        self.recursive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(sf2, text="Recursive",
                        variable=self.recursive_var).pack(side=tk.LEFT)

    def _init_traces(self):
        self.wl_var.trace_add("write", lambda *_: self._update_wordlist_info())
        self.custom_text.bind("<KeyRelease>",
                              lambda e: self._update_wordlist_info())

    def _build_action_bar(self):
        actions = ttk.Frame(self.left_frame)
        actions.pack(fill=tk.X, pady=(0, 5))

        self.start_btn = ttk.Button(actions, text="\u25b6  START",
                                    command=self._start, style="Start.TButton")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 3))

        self.stop_btn = ttk.Button(actions, text="\u25a0  STOP",
                                   command=self._stop, style="Stop.TButton",
                                   state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(actions, text="\u2399  Save",
                   command=self._save).pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(actions, text="\u2716  Clear",
                   command=self._clear).pack(side=tk.LEFT, padx=(0, 6))

        self.wl_count_lbl = ttk.Label(actions,
                                       textvariable=self.wl_count_var,
                                       foreground=DIM)
        self.wl_count_lbl.pack(side=tk.RIGHT)

    def _build_stats(self):
        st = ttk.LabelFrame(self.left_frame, text="Statistics", padding=6)
        st.pack(fill=tk.X, pady=(0, 5))

        sf = ttk.Frame(st)
        sf.pack(fill=tk.X)

        items = [
            ("Total", "total", WHITE),
            ("2xx", "s2xx", GREEN),
            ("3xx", "s3xx", CYAN),
            ("4xx", "s4xx", YELLOW),
            ("5xx", "s5xx", RED),
        ]
        self.stat_labels = {}
        for label, key, color in items:
            f = tk.Frame(sf, bg=CARD, highlightbackground=BORDER,
                         highlightthickness=1)
            f.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
            tk.Label(f, text=label, fg=DIM, bg=CARD,
                     font=("Segoe UI", 8)).pack(pady=(2, 0))
            v = tk.StringVar(value="0")
            tk.Label(f, textvariable=v, fg=color, bg=CARD,
                     font=("Segoe UI", 13, "bold")).pack(pady=(0, 2))
            self.stat_labels[key] = v

        rsf = ttk.Frame(st)
        rsf.pack(fill=tk.X, pady=(3, 0))

        self.stat_elapsed = tk.StringVar(value="Time: 00:00")
        ttk.Label(rsf, textvariable=self.stat_elapsed,
                  foreground=DIM).pack(side=tk.LEFT, padx=(0, 10))

        self.stat_rate = tk.StringVar(value="Rate: 0/s")
        ttk.Label(rsf, textvariable=self.stat_rate,
                  foreground=DIM).pack(side=tk.LEFT)

        ttk.Label(rsf, textvariable=self.stat_wl_var,
                  foreground=DIM).pack(side=tk.RIGHT)

    def _build_content(self):
        nb = ttk.Notebook(self.left_frame)
        nb.pack(fill=tk.BOTH, expand=True)

        rf = ttk.Frame(nb)
        nb.add(rf, text="Results")

        sr = ttk.Frame(rf)
        sr.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(sr, text="Search:", foreground=DIM).pack(
            side=tk.LEFT, padx=(0, 4))
        self.search_var = tk.StringVar()
        se = ttk.Entry(sr, textvariable=self.search_var)
        se.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(sr, text="Clear", width=5,
                   command=lambda: self.search_var.set("")).pack(
            side=tk.LEFT, padx=(4, 0))

        leg = ttk.Frame(rf)
        leg.pack(fill=tk.X, pady=(0, 4))
        leg_items = [(GREEN, "2xx"), (CYAN, "3xx"), (YELLOW, "4xx"), (RED, "5xx")]
        for color, text in leg_items:
            f = tk.Frame(leg, bg=CARD, highlightbackground=color,
                         highlightthickness=1, padx=6, pady=1)
            f.pack(side=tk.LEFT, padx=(0, 4))
            tk.Label(f, text=text, fg=color, bg=CARD,
                     font=("Segoe UI", 8, "bold")).pack()

        tf = ttk.Frame(rf)
        tf.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            tf, columns=("status", "path", "size", "redirect"),
            show="headings", selectmode="extended"
        )
        headings = {"status": "Status", "path": "Path",
                    "size": "Size", "redirect": "Redirect"}
        widths = {"status": 60, "path": 400, "size": 80, "redirect": 350}
        anchors = {"status": tk.CENTER, "path": tk.W,
                   "size": tk.CENTER, "redirect": tk.W}
        for col, h in headings.items():
            self.tree.heading(col, text=h)
            self.tree.column(col, width=widths[col], anchor=anchors[col])

        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.tag_configure("s2xx", foreground=GREEN)
        self.tree.tag_configure("s3xx", foreground=CYAN)
        self.tree.tag_configure("s4xx", foreground=YELLOW)
        self.tree.tag_configure("s5xx", foreground=RED)
        self.tree.tag_configure("hidden", foreground=DIM)
        self.tree.tag_configure("even", background="#131b26")
        self.tree.tag_configure("odd", background=MID)
        self.tree.bind("<Double-1>", self._on_tree_double)
        self.tree.bind("<Button-3>", self._on_tree_right)

        self.search_var.trace_add("write", lambda *_: self._filter_results())

        lf = ttk.Frame(nb)
        nb.add(lf, text="Log")
        self.log_text = tk.Text(lf, wrap=tk.WORD, state=tk.DISABLED,
                                bg=MID, fg=WHITE, font=FONT,
                                relief=tk.FLAT, bd=1, padx=4, pady=2)
        lsb = ttk.Scrollbar(lf, orient=tk.VERTICAL,
                            command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=lsb.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_status_bar(self):
        sb = tk.Frame(self.root, bg=CARD, height=26)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)

        self.progress = ttk.Progressbar(sb, mode="determinate")
        self.progress.pack(fill=tk.X, pady=(0, 1))

        bf = tk.Frame(sb, bg=CARD)
        bf.pack(fill=tk.X, padx=8)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(bf, textvariable=self.status_var, fg=DIM, bg=CARD,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)

        self.count_var = tk.StringVar(value="Found: 0")
        tk.Label(bf, textvariable=self.count_var, fg=CYAN, bg=CARD,
                 font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT)

    def _bind_shortcuts(self):
        self.root.bind("<Control-o>", lambda e: self._browse())
        self.root.bind("<Control-s>", lambda e: self._save())
        self.root.bind("<Escape>",
                       lambda e: self._stop() if self.running else None)
        self.root.bind("<F5>",
                       lambda e: self._start() if not self.running else None)

    def _update_wordlist_info(self, *_):
        n = self._path_count()
        self.wl_count_var.set(f"Paths: {n}")
        self.stat_wl_var.set(f"Wordlist: {n}")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("Wordlist", "*.lst"),
                       ("All files", "*.*")])
        if path:
            self.wl_var.set(path)

    def _browse_db(self):
        if not DB_DIR.exists():
            messagebox.showinfo("DB", "No wordlists found in db/ directory.")
            return
        w = tk.Toplevel(self.root)
        w.title("DB Wordlists")
        w.geometry("560x440")
        w.configure(bg=DARK)
        w.transient(self.root)

        ttk.Label(w, text="Select Wordlist", foreground=CYAN,
                  font=("Segoe UI", 12, "bold")).pack(pady=(12, 4))
        ttk.Label(w, text="Choose from the built-in wordlist database",
                  foreground=DIM).pack(pady=(0, 8))

        f = ttk.Frame(w)
        f.pack(fill=tk.BOTH, expand=True, padx=12)

        cols = ("file", "count")
        tv = ttk.Treeview(f, columns=cols, show="headings",
                          selectmode="browse")
        tv.heading("file", text="File")
        tv.heading("count", text="Paths")
        tv.column("file", width=380)
        tv.column("count", width=80, anchor=tk.CENTER)
        sc = ttk.Scrollbar(f, orient=tk.VERTICAL, command=tv.yview)
        tv.configure(yscrollcommand=sc.set)
        tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sc.pack(side=tk.RIGHT, fill=tk.Y)

        files = sorted(DB_DIR.rglob("*.txt"))
        if not files:
            tv.insert("", tk.END, values=("(empty)", ""))
        for fpath in files:
            rel = fpath.relative_to(ENGINE_DIR)
            cnt = 0
            if fpath.stat().st_size:
                cnt = sum(1 for l in fpath.read_text().splitlines()
                          if l.strip() and not l.startswith("#"))
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

        ttk.Button(bf, text="Select", command=select).pack(
            side=tk.RIGHT, padx=(4, 0))
        ttk.Button(bf, text="Cancel", command=w.destroy).pack(side=tk.RIGHT)

    def _path_count(self):
        n = 0
        wl = self.wl_var.get().strip()
        if wl and os.path.isfile(wl):
            try:
                with open(wl) as f:
                    n += sum(1 for line in f
                             if line.strip() and not line.startswith("#"))
            except Exception:
                pass
        cust = self.custom_text.get("1.0", tk.END).strip()
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
                messagebox.showerror("Error", f"Failed to read wordlist: {e}")
                return None
        cust = self.custom_text.get("1.0", tk.END).strip()
        if cust:
            for p in cust.split("\n"):
                p = p.strip()
                if p:
                    paths.append(p)
        if not paths:
            return None
        return ",".join(paths), len(paths)

    def _start(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Target URL is required")
            return

        res = self._prepare_wordlist()
        if not res:
            messagebox.showerror("Error",
                                 "No paths to scan.\nSelect a wordlist file "
                                 "or type custom paths.")
            return
        paths_str, total = res

        if not GO_BINARY.exists():
            messagebox.showerror("Error",
                                 f"Go binary not found:\n{GO_BINARY}\n\n"
                                 "Build: cd go/ && go build -o dir_finder .")
            return

        cmd = [str(GO_BINARY), "-u", url, "-w", paths_str]
        if (v := self.threads_var.get().strip()):
            cmd += ["-t", v]
        if (v := self.timeout_var.get().strip()):
            cmd += ["-timeout", v]
        if (v := self.ext_var.get().strip()):
            cmd += ["-e", v]
        if (v := self.method_var.get().strip()):
            cmd += ["-method", v]
        if (v := self.delay_var.get().strip()) and int(v) > 0:
            cmd += ["-delay", v]
        if (v := self.exclude_var.get().strip()):
            cmd += ["-exclude-status", v]
        if (v := self.include_var.get().strip()):
            cmd += ["-include-status", v]
        if self.follow_var.get():
            cmd.append("-follow-redirect")
        if self.recursive_var.get():
            cmd.append("-recursive")

        self.results = []
        self._all_items = []
        self._scan_progress = 0
        self.running = True
        self.start_time = time.time()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.config(mode="determinate", maximum=total, value=0)
        self.status_var.set(f"Scanning 0/{total}")

        for k in self.stat_labels:
            self.stat_labels[k].set("0")
        self.count_var.set("Found: 0")
        self.stat_elapsed.set("Time: 00:00")
        self.stat_rate.set("Rate: 0/s")

        self._log(f"Scan started: {url}")
        self._log(f"Paths: {total}  |  Threads: {cmd[cmd.index('-t')+1] if '-t' in cmd else '50'}"
                  f"  |  Extensions: {cmd[cmd.index('-e')+1] if '-e' in cmd else 'none'}")

        for row in self.tree.get_children():
            self.tree.delete(row)

        self._elapsed_id = self.root.after(1000, self._elapsed_loop)
        threading.Thread(target=self._run_scan, args=(cmd,),
                         daemon=True).start()

    def _run_scan(self, cmd):
        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, text=True, encoding='utf-8', errors='replace')
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
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Stopped")

    def _log(self, msg):
        self.log_text.configure(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _poll_queue(self):
        try:
            while True:
                item = self.log_queue.get_nowait()
                if item is None:
                    self._finish()
                    return
                line = item.rstrip()
                if line:
                    self._log(line)
                    res = parse_result_line(item)
                    if res:
                        self.results.append(res)
                        self._add_tree(res)
                        t = int(self.stat_labels["total"].get()) + 1
                        self.stat_labels["total"].set(str(t))
                        c = res["status"]
                        if 200 <= c <= 299:
                            self.stat_labels["s2xx"].set(
                                str(int(self.stat_labels["s2xx"].get()) + 1))
                        elif 300 <= c <= 399:
                            self.stat_labels["s3xx"].set(
                                str(int(self.stat_labels["s3xx"].get()) + 1))
                        elif 400 <= c <= 499:
                            self.stat_labels["s4xx"].set(
                                str(int(self.stat_labels["s4xx"].get()) + 1))
                        elif 500 <= c <= 599:
                            self.stat_labels["s5xx"].set(
                                str(int(self.stat_labels["s5xx"].get()) + 1))
                        self.count_var.set(f"Found: {len(self.results)}")
                    self._scan_progress += 1
                    self.progress.step(1)
                    self.status_var.set(
                        f"Scanning {self._scan_progress}/"
                        f"{int(self.progress['maximum'])}")
        except queue.Empty:
            pass
        if self.running:
            self.root.after(30, self._poll_queue)

    def _elapsed_loop(self):
        if not self.running or not self.start_time:
            return
        e = time.time() - self.start_time
        m, s = divmod(int(e), 60)
        self.stat_elapsed.set(f"Time: {m:02d}:{s:02d}")
        n = int(self.stat_labels["total"].get())
        self.stat_rate.set(f"Rate: {n/e:.1f}/s" if e > 0 else "Rate: 0/s")
        self._elapsed_id = self.root.after(1000, self._elapsed_loop)

    def _add_tree(self, result):
        tag = "s2xx" if 200 <= result["status"] <= 299 else \
              "s3xx" if 300 <= result["status"] <= 399 else \
              "s4xx" if 400 <= result["status"] <= 499 else \
              "s5xx" if 500 <= result["status"] <= 599 else "default"
        row_id = self.tree.insert("", tk.END, values=(
            result["status"], result["path"], result["size"],
            result["redirect"]), tags=(tag,))
        self._all_items.append((row_id, result["status"], result["path"]))
        sv = self.search_var.get().lower()
        if sv:
            vis = sv in str(result["status"]) or sv in result["path"].lower()
            if not vis:
                self.tree.item(row_id, tags=(tag, "hidden"))
        self.tree.see(row_id)

    def _filter_results(self, *_):
        sv = self.search_var.get().lower()
        for row_id, status, path in self._all_items:
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
        menu = tk.Menu(self.root, tearoff=0, bg=CARD, fg=WHITE,
                       activebackground=BLUE, activeforeground=WHITE)
        menu.add_command(label="Copy URL",
                         command=lambda: self._copy_urls(sel))
        menu.add_command(label="Copy All URLs",
                         command=self._copy_all)
        menu.add_separator()
        menu.add_command(label="Copy as JSON",
                         command=self._copy_json)
        menu.add_separator()
        menu.add_command(label="Export Selected...",
                         command=self._export_sel)
        menu.post(event.x_root, event.y_root)

    def _copy_urls(self, sel):
        t = self.url_var.get().strip().rstrip("/")
        urls = []
        for item in sel:
            vals = self.tree.item(item, "values")
            if vals:
                urls.append(f"{t}/{str(vals[1]).lstrip('/')}")
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
        self.status_var.set("Copied JSON to clipboard")

    def _export_sel(self):
        sel = self.tree.selection()
        if not sel:
            return
        path = filedialog.asksaveasfilename(
            title="Export Selected",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("CSV", "*.csv")])
        if not path:
            return
        t = self.url_var.get().strip().rstrip("/")
        with open(path, "w") as f:
            for item in sel:
                vals = self.tree.item(item, "values")
                if vals:
                    f.write(f"{t}/{str(vals[1]).lstrip('/')}  "
                            f"[{vals[0]}]  {vals[2]}\n")
        self._log(f"Exported {len(sel)} results to {path}")
        self.status_var.set(f"Exported {len(sel)} results")

    def _finish(self):
        self.running = False
        if self._elapsed_id:
            self.root.after_cancel(self._elapsed_id)
            self._elapsed_id = None
        self.progress.config(value=self.progress["maximum"])
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        n = len(self.results)
        e = time.time() - self.start_time if self.start_time else 0
        m, s = divmod(int(e), 60)
        self.status_var.set(f"Done - {n} results in {m:02d}:{s:02d}")
        self.stat_elapsed.set(f"Time: {m:02d}:{s:02d}")
        self._log(f"Scan finished. {n} results in {m:02d}:{s:02d}.")

    def _save(self):
        if not self.results:
            messagebox.showinfo("Save", "No results to save.")
            return
        types = [("JSON", "*.json"), ("CSV", "*.csv"),
                 ("Text", "*.txt"), ("All files", "*.*")]
        path = filedialog.asksaveasfilename(title="Save Results",
                                            defaultextension=".json",
                                            filetypes=types)
        if not path:
            return
        try:
            ext = Path(path).suffix.lower()
            target = self.url_var.get().strip()
            ts = datetime.now().isoformat()
            if ext == ".json":
                with open(path, "w") as f:
                    json.dump({"target": target, "timestamp": ts,
                               "total": len(self.results),
                               "results": self.results}, f, indent=2)
            elif ext == ".csv":
                with open(path, "w", newline="") as f:
                    f.write("path,status,size,redirect\n")
                    for r in self.results:
                        f.write(f"{r['path']},{r['status']},{r['size']},"
                                f"{r['redirect']}\n")
            else:
                with open(path, "w") as f:
                    f.write(f"Dir Finder Results - {datetime.now()}\n")
                    f.write(f"Target: {target}\n")
                    f.write("=" * 60 + "\n\n")
                    for i, r in enumerate(self.results, 1):
                        f.write(f"{i:4d}.  [{r['status']:3d}]  "
                                f"{r['size']:>8}  /{r['path'].lstrip('/')}")
                        if r['redirect']:
                            f.write(f"  ->  {r['redirect']}")
                        f.write("\n")
            self._log(f"Results saved: {path}")
            self.status_var.set(f"Saved: {path}")
            messagebox.showinfo("Save", f"Results saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")

    def _clear(self):
        if self.running:
            if not messagebox.askyesno("Confirm",
                                       "Stop scan and clear all results?"):
                return
            self._stop()
        self.results.clear()
        self._all_items.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.progress.config(value=0)
        self.count_var.set("Found: 0")
        self.status_var.set("Ready")
        self.stat_elapsed.set("Time: 00:00")
        self.stat_rate.set("Rate: 0/s")
        for k in self.stat_labels:
            self.stat_labels[k].set("0")

    def _about(self):
        msg = ("Dir Finder GUI v2.2\n"
               "HackIT Security Framework\n\n"
               "Directory & file brute-force engine.\n"
               "Powered by Go concurrency.\n\n"
               "Features:\n"
               "  - Custom wordlists + inline paths\n"
               "  - Live stats: 2xx/3xx/4xx/5xx\n"
               "  - Search & filter results\n"
               "  - Export JSON/CSV/TXT\n"
               "  - DB wordlist browser\n"
               "  - Right-click context menu")
        messagebox.showinfo("About Dir Finder", msg)

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


if __name__ == "__main__":
    DirFinderGUI().run()
