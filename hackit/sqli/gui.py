"""Tkinter interface for the SQL injection engine.

The interface is a thin desktop client for the same worker used by the command
line. It keeps long running scans off the Tk event loop and streams worker
diagnostics into the log tab.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Sequence

from . import DEFAULT_OPTIONS
from . import report as report_mod
from .go_bridge import GoEngine

BG = "#161b22"
PANEL = "#1f242c"
FIELD = "#0d1117"
FG = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#2f81f7"
ACCENT_HOVER = "#1f6feb"
SUCCESS = "#3fb950"
WARNING = "#d29922"
ERROR = "#f85149"
BORDER = "#30363d"

UI_FONT = ("Segoe UI", 10)
SMALL_FONT = ("Segoe UI", 9)
TITLE_FONT = ("Segoe UI", 18, "bold")
MONO_FONT = ("Consolas", 10)


class SQLiGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.engine = GoEngine()
        self.results: List[Dict[str, Any]] = []
        self.dump_results: List[Dict[str, Any]] = []
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._log_queue: "queue.Queue[str]" = queue.Queue()
        self._started_at = 0.0
        self._busy = False

        self._configure_window()
        self._configure_style()
        self._build_layout()
        self._poll_log()
        self._tick_elapsed()

    # ------------------------------------------------------------------
    # Window and style
    # ------------------------------------------------------------------

    def _configure_window(self) -> None:
        self.root.title("HackIt SQL Injection Console")
        self.root.configure(bg=BG)
        try:
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            width = min(1380, max(1040, screen_width - 100))
            height = min(880, max(680, screen_height - 100))
        except tk.TclError:
            width, height = 1280, 820
        self.root.geometry("%dx%d" % (width, height))
        self.root.minsize(960, 640)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG, font=UI_FONT)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("Panel.TLabel", background=PANEL, foreground=FG)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED)
        style.configure("Title.TLabel", background=BG, foreground=FG, font=TITLE_FONT)
        style.configure("TButton", padding=(10, 6))
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", ACCENT_HOVER)])
        style.configure("Danger.TButton", background="#8b2c2c", foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#a33a3a")])
        style.configure(
            "Treeview",
            background=FIELD,
            fieldbackground=FIELD,
            foreground=FG,
            rowheight=24,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=PANEL,
            foreground=FG,
            relief="flat",
            padding=(6, 4),
        )
        style.map("Treeview", background=[("selected", ACCENT)])
        style.map("Treeview.Heading", background=[("active", BORDER)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 8), background=PANEL)
        style.map(
            "TNotebook.Tab",
            background=[("selected", BG)],
            foreground=[("selected", FG)],
        )
        style.configure("TCheckbutton", background=PANEL, foreground=FG)
        style.map("TCheckbutton", background=[("active", PANEL)])
        style.configure("TEntry", fieldbackground=FIELD, foreground=FG, insertcolor=FG)
        style.configure("TCombobox", fieldbackground=FIELD, foreground=FG)
        style.configure("TSpinbox", fieldbackground=FIELD, foreground=FG)
        style.configure(
            "TProgressbar",
            background=ACCENT,
            troughcolor=FIELD,
            borderwidth=0,
        )

    def _build_layout(self) -> None:
        header = ttk.Frame(self.root, padding=(18, 14, 18, 8))
        header.pack(fill="x")
        ttk.Label(header, text="HackIt SQL Injection Console", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Authorized testing only. Results are stored in memory until you export them.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        self._build_target_panel()
        self._build_body()
        self._build_status_bar()

    def _build_target_panel(self) -> None:
        panel = ttk.Frame(self.root, padding=(18, 4, 18, 8))
        panel.pack(fill="x")

        frame = ttk.Frame(panel, style="Panel.TFrame", padding=12)
        frame.pack(fill="x")
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(4, weight=1)

        ttk.Label(frame, text="Target URL", style="Panel.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 8), pady=4
        )
        self.url_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.url_var).grid(
            row=0, column=1, columnspan=3, sticky="ew", pady=4
        )
        ttk.Label(frame, text="Method", style="Panel.TLabel").grid(
            row=0, column=4, sticky="w", padx=(12, 8), pady=4
        )
        self.method_var = tk.StringVar(value="GET")
        ttk.Combobox(
            frame,
            textvariable=self.method_var,
            values=("GET", "POST", "PUT", "PATCH", "DELETE"),
            width=10,
            state="readonly",
        ).grid(row=0, column=5, sticky="w", pady=4)

        ttk.Label(frame, text="Request body", style="Panel.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 8), pady=4
        )
        self.data_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.data_var).grid(
            row=1, column=1, columnspan=3, sticky="ew", pady=4
        )
        ttk.Label(frame, text="Cookie", style="Panel.TLabel").grid(
            row=1, column=4, sticky="w", padx=(12, 8), pady=4
        )
        self.cookie_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.cookie_var).grid(
            row=1, column=5, sticky="ew", pady=4
        )

        ttk.Label(frame, text="Headers", style="Panel.TLabel").grid(
            row=2, column=0, sticky="w", padx=(0, 8), pady=4
        )
        self.headers_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.headers_var).grid(
            row=2, column=1, columnspan=3, sticky="ew", pady=4
        )
        ttk.Label(frame, text="Proxy", style="Panel.TLabel").grid(
            row=2, column=4, sticky="w", padx=(12, 8), pady=4
        )
        self.proxy_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.proxy_var).grid(
            row=2, column=5, sticky="ew", pady=4
        )

        options = ttk.Frame(frame, style="Panel.TFrame")
        options.grid(row=3, column=0, columnspan=6, sticky="ew", pady=(8, 0))
        for index in range(8):
            options.columnconfigure(index, weight=0)

        ttk.Label(options, text="Technique", style="Panel.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 6)
        )
        self.technique_var = tk.StringVar(value="auto")
        ttk.Combobox(
            options,
            textvariable=self.technique_var,
            values=("auto", "union", "error", "boolean", "time", "stacked"),
            width=10,
            state="readonly",
        ).grid(row=0, column=1, sticky="w", padx=(0, 12))

        ttk.Label(options, text="Extraction", style="Panel.TLabel").grid(
            row=0, column=2, sticky="w", padx=(0, 6)
        )
        self.extract_var = tk.StringVar(value="auto")
        ttk.Combobox(
            options,
            textvariable=self.extract_var,
            values=("auto", "union", "error", "boolean", "blind", "time"),
            width=10,
            state="readonly",
        ).grid(row=0, column=3, sticky="w", padx=(0, 12))

        ttk.Label(options, text="DBMS", style="Panel.TLabel").grid(
            row=0, column=4, sticky="w", padx=(0, 6)
        )
        self.dbms_var = tk.StringVar()
        ttk.Entry(options, textvariable=self.dbms_var, width=14).grid(
            row=0, column=5, sticky="w", padx=(0, 12)
        )

        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options, text="Follow redirects", variable=self.follow_var
        ).grid(row=0, column=6, sticky="w", padx=(0, 12))

        self.bypass_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options, text="WAF bypass", variable=self.bypass_var
        ).grid(row=0, column=7, sticky="w")

        numeric = ttk.Frame(frame, style="Panel.TFrame")
        numeric.grid(row=4, column=0, columnspan=6, sticky="ew", pady=(6, 0))
        self.timeout_var = tk.IntVar(value=15)
        self.threads_var = tk.IntVar(value=10)
        self.delay_var = tk.IntVar(value=0)
        self.level_var = tk.IntVar(value=1)
        self.risk_var = tk.IntVar(value=1)
        self.time_secs_var = tk.IntVar(value=3)
        for column, (label, variable, low, high) in enumerate(
            (
                ("Timeout", self.timeout_var, 1, 300),
                ("Threads", self.threads_var, 1, 100),
                ("Delay ms", self.delay_var, 0, 10000),
                ("Level", self.level_var, 1, 3),
                ("Risk", self.risk_var, 1, 3),
                ("Time delay", self.time_secs_var, 1, 30),
            )
        ):
            ttk.Label(numeric, text=label, style="Panel.TLabel").grid(
                row=0, column=column * 2, sticky="w", padx=(0, 6)
            )
            ttk.Spinbox(
                numeric,
                from_=low,
                to=high,
                textvariable=variable,
                width=6,
            ).grid(row=0, column=column * 2 + 1, sticky="w", padx=(0, 14))

    def _build_body(self) -> None:
        body = ttk.Frame(self.root, padding=(18, 0, 18, 8))
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body, style="Panel.TFrame", padding=12)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.configure(width=270)

        ttk.Label(left, text="Discovery", style="Panel.TLabel", font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        self.action_vars: Dict[str, tk.BooleanVar] = {}
        for key, label in (
            ("fingerprint", "Fingerprint DBMS"),
            ("list_dbs", "List databases"),
            ("list_tables", "List tables"),
            ("list_columns", "List columns"),
            ("schema", "Schema and types"),
            ("count_rows", "Row counts"),
        ):
            variable = tk.BooleanVar(value=False)
            self.action_vars[key] = variable
            ttk.Checkbutton(left, text=label, variable=variable).pack(anchor="w")

        ttk.Separator(left).pack(fill="x", pady=10)
        ttk.Label(left, text="Extraction", style="Panel.TLabel", font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        for key, label in (
            ("dump_all", "Dump all tables"),
            ("current_db", "Current database"),
            ("current_user", "Current user"),
            ("users", "Database users"),
            ("passwords", "Password hashes"),
            ("roles", "Roles"),
        ):
            variable = tk.BooleanVar(value=False)
            self.action_vars[key] = variable
            ttk.Checkbutton(left, text=label, variable=variable).pack(anchor="w")

        ttk.Separator(left).pack(fill="x", pady=10)
        ttk.Label(left, text="Scope", style="Panel.TLabel", font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        self.database_var = tk.StringVar()
        self.table_var = tk.StringVar()
        self.columns_var = tk.StringVar()
        self.search_var = tk.StringVar()
        for label, variable in (
            ("Database", self.database_var),
            ("Table", self.table_var),
            ("Columns", self.columns_var),
            ("Search", self.search_var),
        ):
            ttk.Label(left, text=label, style="PanelMuted.TLabel").pack(anchor="w")
            ttk.Entry(left, textvariable=variable).pack(fill="x", pady=(0, 6))

        ttk.Label(left, text="SQL query", style="PanelMuted.TLabel").pack(anchor="w")
        self.query_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.query_var).pack(fill="x", pady=(0, 8))
        ttk.Button(left, text="Run query", command=self._run_query).pack(fill="x", pady=(0, 6))

        ttk.Separator(left).pack(fill="x", pady=10)
        self.run_button = ttk.Button(
            left, text="Run scan", style="Accent.TButton", command=self._start_scan
        )
        self.run_button.pack(fill="x", pady=(0, 6))
        self.stop_button = ttk.Button(
            left, text="Stop", style="Danger.TButton", command=self._stop_scan, state="disabled"
        )
        self.stop_button.pack(fill="x", pady=(0, 6))
        ttk.Button(left, text="Save report", command=self._save_report).pack(fill="x", pady=(0, 6))
        ttk.Button(left, text="Clear", command=self._clear).pack(fill="x")

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)

        self._build_summary_tab()
        self._build_enumeration_tab()
        self._build_data_tab()
        self._build_log_tab()

    def _build_summary_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(frame, text="Summary")
        frame.rowconfigure(0, weight=3)
        frame.rowconfigure(1, weight=2)
        frame.columnconfigure(0, weight=1)

        columns = ("index", "parameter", "location", "technique", "dbms", "version", "confidence")
        self.summary_tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "index": "#",
            "parameter": "Parameter",
            "location": "Location",
            "technique": "Technique",
            "dbms": "DBMS",
            "version": "Version",
            "confidence": "Confidence",
        }
        widths = {
            "index": 40,
            "parameter": 130,
            "location": 90,
            "technique": 110,
            "dbms": 120,
            "version": 110,
            "confidence": 90,
        }
        for column in columns:
            self.summary_tree.heading(column, text=headings[column])
            self.summary_tree.column(
                column,
                width=widths[column],
                anchor="w" if column not in ("index", "confidence") else "center",
                stretch=column in ("parameter", "dbms"),
            )
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.summary_tree.yview)
        self.summary_tree.configure(yscrollcommand=scrollbar.set)
        self.summary_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.summary_tree.bind("<<TreeviewSelect>>", self._show_finding_details)

        details_frame = ttk.Frame(frame, padding=(0, 8, 0, 0))
        details_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        details_frame.rowconfigure(0, weight=1)
        details_frame.columnconfigure(0, weight=1)
        self.details_text = tk.Text(
            details_frame,
            bg=FIELD,
            fg=FG,
            insertbackground=FG,
            selectbackground=ACCENT,
            relief="flat",
            borderwidth=0,
            font=MONO_FONT,
            wrap="word",
            height=8,
        )
        details_scroll = ttk.Scrollbar(details_frame, orient="vertical", command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scroll.set)
        self.details_text.grid(row=0, column=0, sticky="nsew")
        details_scroll.grid(row=0, column=1, sticky="ns")

    def _build_enumeration_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(frame, text="Enumeration")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        columns = ("section", "object", "value")
        self.enum_tree = ttk.Treeview(frame, columns=columns, show="headings")
        for column, title, width in (
            ("section", "Section", 150),
            ("object", "Object", 220),
            ("value", "Value", 420),
        ):
            self.enum_tree.heading(column, text=title)
            self.enum_tree.column(column, width=width, anchor="w", stretch=column == "value")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.enum_tree.yview)
        self.enum_tree.configure(yscrollcommand=scrollbar.set)
        self.enum_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

    def _build_data_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(frame, text="Data")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        self.table_list = tk.Listbox(
            frame,
            bg=FIELD,
            fg=FG,
            selectbackground=ACCENT,
            selectforeground="#ffffff",
            relief="flat",
            borderwidth=0,
            font=UI_FONT,
            width=28,
            exportselection=False,
        )
        self.table_list.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.table_list.bind("<<ListboxSelect>>", self._select_dump_table)

        data_frame = ttk.Frame(frame)
        data_frame.grid(row=0, column=1, sticky="nsew")
        data_frame.rowconfigure(0, weight=1)
        data_frame.columnconfigure(0, weight=1)
        self.data_tree = ttk.Treeview(data_frame, show="headings")
        data_scroll_y = ttk.Scrollbar(data_frame, orient="vertical", command=self.data_tree.yview)
        data_scroll_x = ttk.Scrollbar(data_frame, orient="horizontal", command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=data_scroll_y.set, xscrollcommand=data_scroll_x.set)
        self.data_tree.grid(row=0, column=0, sticky="nsew")
        data_scroll_y.grid(row=0, column=1, sticky="ns")
        data_scroll_x.grid(row=1, column=0, sticky="ew")

        self.data_status = ttk.Label(frame, text="No table selected.", style="Muted.TLabel")
        self.data_status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

    def _build_log_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(frame, text="Log")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(
            frame,
            bg=FIELD,
            fg=FG,
            insertbackground=FG,
            selectbackground=ACCENT,
            relief="flat",
            borderwidth=0,
            font=MONO_FONT,
            wrap="word",
            state="disabled",
        )
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

    def _build_status_bar(self) -> None:
        bar = ttk.Frame(self.root, padding=(18, 4, 18, 10))
        bar.pack(fill="x")
        self.status_label = ttk.Label(bar, text="Ready", style="Muted.TLabel")
        self.status_label.pack(side="left")
        self.elapsed_label = ttk.Label(bar, text="", style="Muted.TLabel")
        self.elapsed_label.pack(side="right")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=180)
        self.progress.pack(side="right", padx=(0, 12))

    # ------------------------------------------------------------------
    # Logging and state
    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        self._log_queue.put(message)

    def _poll_log(self) -> None:
        try:
            while True:
                message = self._log_queue.get_nowait()
                self.log_text.configure(state="normal")
                self.log_text.insert("end", message.rstrip("\n") + "\n")
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(120, self._poll_log)

    def _tick_elapsed(self) -> None:
        if self._busy and self._started_at:
            elapsed = time.time() - self._started_at
            self.elapsed_label.configure(text="%0.1fs" % elapsed)
        self.root.after(200, self._tick_elapsed)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.run_button.configure(state="disabled" if busy else "normal")
        self.stop_button.configure(state="normal" if busy else "disabled")
        if busy:
            self._started_at = time.time()
            self.progress.start(12)
            self.status_label.configure(text="Scanning", foreground=WARNING)
        else:
            self.progress.stop()
            self.elapsed_label.configure(text="")
            self.status_label.configure(text="Ready", foreground=MUTED)

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def _build_options(self) -> Optional[Dict[str, Any]]:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Target required", "Enter a target URL.")
            return None
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_var.set(url)

        options = dict(DEFAULT_OPTIONS)
        options.update(
            url=url,
            data=self.data_var.get().strip() or None,
            method=self.method_var.get(),
            cookie=self.cookie_var.get().strip() or None,
            headers=(self.headers_var.get().strip(),) if self.headers_var.get().strip() else (),
            proxy=self.proxy_var.get().strip() or None,
            timeout=int(self.timeout_var.get()),
            follow_redirect=bool(self.follow_var.get()),
            threads=int(self.threads_var.get()),
            delay=int(self.delay_var.get()),
            level=int(self.level_var.get()),
            risk_level=int(self.risk_var.get()),
            technique=self.technique_var.get(),
            extract_technique=self.extract_var.get(),
            dbms=self.dbms_var.get().strip(),
            bypass_waf=bool(self.bypass_var.get()),
            time_secs=int(self.time_secs_var.get()),
            database=self.database_var.get().strip(),
            table=self.table_var.get().strip(),
            columns_csv=self.columns_var.get().strip(),
            search=self.search_var.get().strip(),
            sql_query=self.query_var.get().strip(),
        )
        for key, variable in self.action_vars.items():
            options[key] = bool(variable.get())

        if not any(options.get(key) for key in self.action_vars) and not options["sql_query"]:
            options.update(fingerprint=True, list_dbs=True, list_tables=True)
        return options

    def _start_scan(self) -> None:
        if self._busy:
            return
        options = self._build_options()
        if options is None:
            return
        self._clear_results()
        self._stop_event.clear()
        self._set_busy(True)
        self._log("Scan started: %s" % options["url"])
        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(options,), daemon=True
        )
        self._scan_thread.start()

    def _scan_worker(self, options: Dict[str, Any]) -> None:
        kwargs = self._engine_kwargs(options)
        try:
            results = self.engine.run_stream(
                options["url"],
                on_verbose=self._log,
                stop_event=self._stop_event,
                verbose_lvl=2,
                request_timeout=int(options.get("timeout") or 15),
                **kwargs,
            )
        except Exception as exc:
            self.root.after(0, self._scan_finished, None, str(exc))
            return
        self.root.after(0, self._scan_finished, results, None)

    def _engine_kwargs(self, options: Dict[str, Any]) -> Dict[str, Any]:
        keys = {
            "data", "method", "cookie", "agent", "referer", "proxy",
            "follow_redirect", "threads", "delay", "level", "risk_level",
            "technique", "dbms", "prefix", "suffix", "param", "skip_param",
            "encode", "randomize_case", "bypass_waf", "stealth", "time_secs",
            "extract_technique", "extract_charset", "max_length", "list_dbs",
            "list_tables", "list_columns", "schema", "count_rows", "dump_all",
            "dump_table", "database", "table", "column", "columns_csv", "where",
            "search", "sql_query", "rows", "limit", "offset", "current_db",
            "current_user", "hostname", "banner", "privileges", "is_dba",
            "users", "passwords", "roles", "fingerprint", "banner_grab",
            "waf_detect", "file_read", "file_write", "file_exec",
        }
        kwargs: Dict[str, Any] = {}
        for key in keys:
            value = options.get(key)
            if value is None or value is False or value == "":
                continue
            kwargs[key] = value
        headers = options.get("headers") or ()
        if headers:
            kwargs["header"] = ",".join(headers)
        return kwargs

    def _scan_finished(self, results: Optional[List[Dict[str, Any]]], error: Optional[str]) -> None:
        self._set_busy(False)
        if error:
            self.status_label.configure(text="Error", foreground=ERROR)
            self._log("Error: %s" % error)
            messagebox.showerror("Scan failed", error)
            return
        if not results:
            self.status_label.configure(text="No output", foreground=WARNING)
            self._log("The worker returned no results.")
            return
        self.results = results
        fatal = [
            item for item in results
            if item.get("type") == "fatal" or ("error" in item and "type" not in item)
        ]
        if fatal and len(results) == 1:
            message = str(fatal[0].get("payload") or fatal[0].get("error") or "scan failed")
            self.status_label.configure(text="Error", foreground=ERROR)
            self._log("Error: %s" % message)
            messagebox.showerror("Scan failed", message)
            return
        self._populate_results()
        findings = [item for item in results if item.get("type") in report_mod.FINDING_TYPES]
        self.status_label.configure(
            text="Done: %d findings, %d results" % (len(findings), len(results)),
            foreground=SUCCESS if findings else WARNING,
        )
        self._log("Scan finished: %d findings, %d results." % (len(findings), len(results)))

    def _stop_scan(self) -> None:
        if not self._busy:
            return
        self._stop_event.set()
        self.engine.kill()
        self.status_label.configure(text="Stopping", foreground=WARNING)
        self._log("Stop requested.")

    # ------------------------------------------------------------------
    # Result rendering
    # ------------------------------------------------------------------

    def _clear_results(self) -> None:
        self.results = []
        self.dump_results = []
        for tree in (self.summary_tree, self.enum_tree, self.data_tree):
            for item in tree.get_children():
                tree.delete(item)
        self.table_list.delete(0, "end")
        self.details_text.delete("1.0", "end")
        self.data_status.configure(text="No table selected.")

    def _clear(self) -> None:
        if self._busy:
            messagebox.showinfo("Scan running", "Stop the current scan before clearing.")
            return
        self._clear_results()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.status_label.configure(text="Ready", foreground=MUTED)

    def _populate_results(self) -> None:
        self._clear_results()
        findings = [item for item in self.results if item.get("type") in report_mod.FINDING_TYPES]
        for index, item in enumerate(findings, 1):
            self.summary_tree.insert(
                "",
                "end",
                iid="finding-%d" % index,
                values=(
                    index,
                    item.get("parameter", ""),
                    item.get("location", ""),
                    item.get("technique") or item.get("type", ""),
                    item.get("dbms", ""),
                    item.get("dbms_version", ""),
                    "%.0f%%" % (float(item.get("confidence") or 0) * 100),
                ),
            )

        for item in self.results:
            kind = str(item.get("type", ""))
            if kind not in report_mod.LIST_TYPES:
                continue
            label = report_mod.TYPE_LABELS.get(kind, kind)
            details = str(item.get("details", ""))
            for value in report_mod.split_values(item.get("payload")):
                self.enum_tree.insert("", "end", values=(label, details, value))

        self.dump_results = [item for item in self.results if item.get("type") == "dump-table"]
        for item in self.dump_results:
            columns, rows = report_mod.result_table(item)
            self.table_list.insert(
                "end", "%s (%d rows)" % (item.get("details", "table"), len(rows))
            )
        if self.dump_results:
            self.table_list.selection_set(0)
            self._select_dump_table()
        else:
            self.data_status.configure(text="No table data was extracted.")

        if findings:
            self.summary_tree.selection_set("finding-1")
            self._show_finding_details()

    def _show_finding_details(self, _event: Any = None) -> None:
        selection = self.summary_tree.selection()
        if not selection:
            return
        try:
            index = int(selection[0].split("-")[1]) - 1
        except (IndexError, ValueError):
            return
        findings = [item for item in self.results if item.get("type") in report_mod.FINDING_TYPES]
        if index < 0 or index >= len(findings):
            return
        item = findings[index]
        lines = [
            "Parameter : %s" % item.get("parameter", ""),
            "Location  : %s" % item.get("location", ""),
            "Technique : %s" % (item.get("technique") or item.get("type", "")),
            "DBMS      : %s %s" % (item.get("dbms", ""), item.get("dbms_version", "")),
            "Confidence: %.0f%%" % (float(item.get("confidence") or 0) * 100),
            "Prefix    : %r" % item.get("prefix", ""),
            "Suffix    : %r" % item.get("suffix", ""),
            "Columns   : %s" % (item.get("columns", "") or "not determined"),
            "Details   : %s" % item.get("details", ""),
        ]
        self.details_text.delete("1.0", "end")
        self.details_text.insert("end", "\n".join(lines))

    def _select_dump_table(self, _event: Any = None) -> None:
        selection = self.table_list.curselection()
        if not selection:
            return
        index = int(selection[0])
        if index < 0 or index >= len(self.dump_results):
            return
        item = self.dump_results[index]
        columns, rows = report_mod.result_table(item)
        self.data_tree.delete(*self.data_tree.get_children())
        self.data_tree.configure(columns=columns, show="headings")
        for column in columns:
            self.data_tree.heading(column, text=column)
            self.data_tree.column(column, width=max(110, min(260, len(column) * 9 + 30)), stretch=True)
        for row in rows:
            padded = list(row) + [""] * (len(columns) - len(row))
            self.data_tree.insert("", "end", values=padded[: len(columns)])
        self.data_status.configure(
            text="%s: %d rows, %d columns" % (item.get("details", "table"), len(rows), len(columns))
        )

    # ------------------------------------------------------------------
    # Ad hoc query and report export
    # ------------------------------------------------------------------

    def _run_query(self) -> None:
        query = self.query_var.get().strip()
        if not query:
            messagebox.showwarning("Query required", "Enter a scalar SQL query.")
            return
        self.action_vars["fingerprint"].set(False)
        for variable in self.action_vars.values():
            variable.set(False)
        self._start_scan()

    def _save_report(self) -> None:
        if not self.results:
            messagebox.showinfo("No results", "Run a scan before saving a report.")
            return
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".html",
            filetypes=(
                ("HTML report", "*.html"),
                ("JSON report", "*.json"),
                ("CSV report", "*.csv"),
                ("Text report", "*.txt"),
            ),
        )
        if not path:
            return
        extension = os.path.splitext(path)[1].lower().lstrip(".")
        if extension not in ("html", "json", "csv", "txt"):
            extension = "html"
        base = os.path.splitext(path)[0]
        try:
            report_mod.generate_report(
                self.results,
                base,
                formats=(extension,),
                target=self.url_var.get().strip(),
            )
        except Exception as exc:
            messagebox.showerror("Report failed", str(exc))
            return
        self._log("Report written: %s.%s" % (base, extension))
        messagebox.showinfo("Report saved", "%s.%s" % (base, extension))

    def _on_close(self) -> None:
        if self._busy:
            if not messagebox.askyesno("Scan running", "Stop the scan and close the window?"):
                return
            self._stop_event.set()
            self.engine.kill()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def launch_gui() -> None:
    """Create the Tk root and run the interface."""
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise RuntimeError("Tkinter is not available: %s" % exc)
    SQLiGUI(root).run()
