#!/usr/bin/env python3
"""HackIT PortStorm GUI v10 — All-engine, professional, responsive, themed."""

import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
import subprocess, threading, json, os, sys, re, signal, time, socket
from datetime import datetime
from pathlib import Path
from queue import Queue
import tkinter.font as tkfont
import tkinter.scrolledtext as scrolledtext
import selectors, tempfile

class C:
    BG1='#0d1117'; BG2='#0d1117'; CARD='#161b22'; BORD='#30363d'
    TEXT='#f0f6fc'; TEXT2='#8b949e'
    CYAN='#58a6ff'; GREEN='#3fb950'; RED='#f85149'; ORANGE='#d29922'
    YELLOW='#d29922'; PURPLE='#bc8cff'; PINK='#f778ba'
    BTN='#21262d'; HV='#30363d'; SEL='#1f6feb'; DIM='#484f58'
    SEV={'vuln':'#f85149','high':'#d29922','warn':'#d29922','info':'#58a6ff','ok':'#3fb950'}
    _PALETTES = {
        'dark': {
            'BG1':'#0d1117','BG2':'#0d1117','CARD':'#161b22','BORD':'#30363d',
            'TEXT':'#f0f6fc','TEXT2':'#8b949e',
            'CYAN':'#58a6ff','GREEN':'#3fb950','RED':'#f85149','ORANGE':'#d29922',
            'YELLOW':'#d29922','PURPLE':'#bc8cff','PINK':'#f778ba',
            'BTN':'#21262d','HV':'#30363d','SEL':'#1f6feb','DIM':'#484f58',
            'SEV':{'vuln':'#f85149','high':'#d29922','warn':'#d29922','info':'#58a6ff','ok':'#3fb950'},
        },
        'light': {
            'BG1':'#f6f8fa','BG2':'#ffffff','CARD':'#f0f2f5','BORD':'#d0d7de',
            'TEXT':'#1f2328','TEXT2':'#656d76',
            'CYAN':'#0550ae','GREEN':'#116329','RED':'#cf222e','ORANGE':'#953800',
            'YELLOW':'#953800','PURPLE':'#8250df','PINK':'#c62878',
            'BTN':'#d1d9e0','HV':'#c8d1da','SEL':'#0969da','DIM':'#8c959f',
            'SEV':{'vuln':'#cf222e','high':'#953800','warn':'#953800','info':'#0550ae','ok':'#116329'},
        },
    }
    @classmethod
    def apply(cls,name):
        for k,v in cls._PALETTES[name].items(): setattr(cls,k,v)

FONT=('Segoe UI',10); FONT_B=('Segoe UI',10,'bold')
MONO=('Consolas',9); MONO_B=('Consolas',9,'bold'); SMALL=('Segoe UI',8); TINY=('Segoe UI',7)

BANNER="""┌─────────────────────────────────────────────────┐
│ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ │
│ │ P │ │ O │ │ R │ │ T │ │ S │ │ C │ │ A │ │ N │ │
│ └───┘ └───┘ └───┘ └───┘ └───┘ └───┘ └───┘ └───┘ │
├─────────────────────────────────────────────────┤
│  Interface : %-8s  Gateway : %-12s   │
│  Status    : %-8s  Uptime  : %-12s   │
└─────────────────────────────────────────────────┘"""

MODES=[('syn','  SYN'),('connect',' TCP'),('udp',' UDP'),('ack',' ACK'),
       ('fin',' FIN'),('xmas','XMAS'),('null','NULL'),('maimon','MAIMON'),
       ('window',' WIN'),('idle','IDLE'),('protocol','PROTO'),('sweep','SWEEP')]
PROFILES=['quick','stealth','full','web','lan','comprehensive']
CFG_DIR=Path.home()/'.hackit'/'portstorm'

class Tip:
    def __init__(self,w,t):
        self.t,self.i,self.tw=t,None,None
        w.bind('<Enter>',self._e,'+'); w.bind('<Leave>',self._l,'+')
    def _e(self,e):
        self.i=e.widget.after(400,lambda: self._s(e))
    def _l(self,e):
        if self.i: e.widget.after_cancel(self.i); self.i=None
        if self.tw: self.tw.destroy(); self.tw=None
    def _s(self,e):
        self.tw=tk.Toplevel(e.widget)
        self.tw.wm_overrideredirect(1)
        self.tw.wm_geometry(f'+{e.widget.winfo_rootx()+16}+{e.widget.winfo_rooty()+24}')
        tk.Label(self.tw,text=self.t,font=SMALL,fg=C.TEXT,bg='#0d1117',
                 bd=1,relief='solid',padx=8,pady=4).pack()

class VirtualPortList(tk.Canvas):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C.BG2, highlightthickness=0, **kw)
        self.items = []
        self.visible_start = 0
        self.visible_count = 0
        self.row_height = 26
        self._font = MONO
        self._bold_font = MONO_B
        self._sort_reverse = False
        self._sort_col = 0
        self.configure(yscrollincrement=self.row_height)
        self.bind('<Configure>', self._on_resize, '+')
        self.bind('<MouseWheel>', self._on_scroll, '+')
        self.bind('<Button-4>', lambda e: self._scroll(-3), '+')
        self.bind('<Button-5>', lambda e: self._scroll(3), '+')
        self._header_h = 28
        self._draw_header()
        self._redraw_after = None

    def _draw_header(self):
        self.delete('header')
        cols = [('PORT', 70), ('STATUS', 80), ('SERVICE', 100), ('VERSION', 130), ('BANNER', 200)]
        x = 4
        self._col_x = []
        self._col_w = []
        for name, w in cols:
            self._col_x.append(x)
            self._col_w.append(w)
            self.create_text(x + 4, 2, anchor='nw', text=name, font=self._bold_font,
                             fill=C.CYAN, tags='header')
            self.create_line(x + w + 4, 2, x + w + 4, self._header_h - 2, fill=C.BORD, tags='header')
            x += w + 8
        self.create_line(4, self._header_h - 1, x + 4, self._header_h - 1, fill=C.BORD, tags='header')

    def _on_resize(self, e):
        self.visible_count = (e.height - self._header_h) // self.row_height + 1
        if self._redraw_after:
            self.after_cancel(self._redraw_after)
        self._redraw_after = self.after(50, self._render)

    def _on_scroll(self, e):
        self._scroll(-(e.delta // 120))

    def _scroll(self, delta):
        self.visible_start = max(0, min(self.visible_start + delta, max(0, len(self.items) - self.visible_count)))
        self._render()

    def set_items(self, items):
        self.items = items
        self.yview_moveto(0)
        self.visible_start = 0
        self._render()

    def add_item(self, item):
        self.items.append(item)
        if len(self.items) - self.visible_start <= self.visible_count + 1:
            self._render()

    def _color_for_status(self, status):
        s = status.upper() if status else ''
        if s == 'OPEN': return C.GREEN
        if s in ('FILTERED', 'FORBIDDEN'): return C.YELLOW
        if s == 'CLOSED': return C.RED
        return C.TEXT2

    def _render(self):
        self.delete('row')
        w = self.winfo_width()
        y = self._header_h
        end = min(self.visible_start + self.visible_count, len(self.items))
        for i in range(self.visible_start, end):
            item = self.items[i]
            bg = C.BG2 if i % 2 == 0 else '#111'
            if len(item) >= 5:
                p, st, svc, ver, ban = item[:5]
            else:
                continue
            # Background
            self.create_rectangle(0, y, w, y + self.row_height, fill=bg, outline='', tags='row')
            # Port
            pc = self._color_for_status(st)
            self.create_text(self._col_x[0] + 4, y + 2, anchor='nw', text=str(p),
                             font=self._bold_font, fill=pc, tags='row')
            # Status
            self.create_text(self._col_x[1] + 4, y + 2, anchor='nw', text=st.upper() if st else '',
                             font=self._font, fill=pc, tags='row')
            # Service
            self.create_text(self._col_x[2] + 4, y + 2, anchor='nw', text=str(svc)[:18] if svc else '',
                             font=self._font, fill=C.TEXT, tags='row')
            # Version
            self.create_text(self._col_x[3] + 4, y + 2, anchor='nw', text=str(ver)[:22] if ver else '',
                             font=self._font, fill=C.TEXT2, tags='row')
            # Banner
            ban_str = str(ban).replace('\n', ' ').replace('\r', '')[:35] if ban else ''
            self.create_text(self._col_x[4] + 4, y + 2, anchor='nw', text=ban_str,
                             font=self._font, fill=C.DIM, tags='row')
            y += self.row_height
        total = len(self.items)
        self.delete('footer')
        self.create_text(4, max(y, self._header_h + 2), anchor='nw',
                         text=f'{total} ports  |  showing {self.visible_start + 1}-{end}',
                         font=SMALL, fill=C.TEXT2, tags='footer')

class GUI:
    def __init__(self):
        self._theme='dark'
        self.root=tk.Tk()
        self.root.title('HackIT PortStorm — Multi-Engine All-Port Scanner')
        self.root.configure(bg=C.BG1); self.root.minsize(1400,860)
        CFG_DIR.mkdir(parents=True,exist_ok=True)
        self.proc=None; self.q=Queue()
        self.running=False; self.results=[]; self.target_hist=[]
        self.start=None; self.tst_w=[]; self.custom_presets=[]
        self.sc=0; self.rc=0
        self.nse_sel=set()
        self.stages=['Discovery','TCP Scan','UDP Scan',
                     'Service','OS Detect','Vuln Match','Enrich']
        self.si=0; self.ni=0; self.res_cnt=0
        self._spin_idx=0; self._collapsed=False; self._theme='dark'
        self._batch_update=False
        self._after_ids=[]
        self._rate_history = [0] * 120
        self._ctrl_sock = None
        # Master timer tracking (avoids multiple after calls)
        self._mt_tick=0
        # Pre-rendered StringVars
        self._sv_templates={}
        # Pre-create fonts to avoid per-call overhead
        self._fonts={
            'FONT':tkfont.Font(family='Segoe UI',size=10),
            'FONT_B':tkfont.Font(family='Segoe UI',size=10,weight='bold'),
            'MONO':tkfont.Font(family='Consolas',size=9),
            'MONO_B':tkfont.Font(family='Consolas',size=9,weight='bold'),
            'SMALL':tkfont.Font(family='Segoe UI',size=8),
            'TINY':tkfont.Font(family='Segoe UI',size=7),
            'COURIER':tkfont.Font(family='Courier',size=9),
        }
        # Threading lock for UI updates from scan thread
        self._ui_lock=threading.Lock()
        self._load_presets()
        self._disc(); self._style(); self._build()
        self._bind(); self.root.protocol('WM_DELETE_WINDOW',self._close)
        self._startup_animation()
        self._after('master',50,self._master_timer)

    def _after(self,key,ms,func,*args):
        ids=[a for a in self._after_ids if a[0]!=key]
        a_id=self.root.after(ms,lambda: self._after_exec(key,func,*args))
        ids.append((key,a_id))
        self._after_ids=ids
        return a_id

    def _after_exec(self,key,func,*args):
        self._after_ids=[a for a in self._after_ids if a[0]!=key]
        try: func(*args)
        except: pass

    def _cancel_after(self,key):
        for k,i in self._after_ids:
            if k==key:
                try: self.root.after_cancel(i)
                except: pass
        self._after_ids=[a for a in self._after_ids if a[0]!=key]

    def _master_timer(self):
        if self._batch_update:
            self._after('master',50,self._master_timer)
            return
        batch_size = 0
        with self._ui_lock:
            while not self.q.empty() and batch_size < 100:
                typ,data=self.q.get_nowait()
                batch_size += 1
                if typ=='log':
                    txt,tag=data
                    self.log.insert('end',txt+'\n',tag or())
                    self.log.see('end')
                elif typ=='result':
                    p,st,svc,ver,ban=data
                    self._vpl.add_item(data)
                    c=self._vpl.items.__len__()
                    self.cnv.set(f'{c} ports'); self.rcv.set(f'{c} ports')
                    self.res_cnt=c
                    if str(p).isdigit() and c == 1:
                        self.rminv.set(f'\u2193{p}'); self.rmaxv.set(f'\u2191{p}')
                    elif str(p).isdigit():
                        try:
                            cur_min = int(self.rminv.get().replace('\u2193',''))
                            cur_max = int(self.rmaxv.get().replace('\u2191',''))
                            pi = int(p)
                            if pi < cur_min: self.rminv.set(f'\u2193{pi}')
                            if pi > cur_max: self.rmaxv.set(f'\u2191{pi}')
                        except: pass
                elif typ=='st': self.sv.set(f'\u25cf {data}')
                elif typ=='prog':
                    self.prog['value']=data
                    self.pctv.set(f'{int(data)}%')
                elif typ=='cnt': self.cnv.set(f'{data} ports')
                elif typ=='toast': self._show_toast(*data)
                elif typ=='nse_script':
                    p,svc,sc=data
                    name,sev,text=self._parse_script_entry(sc)
                    self._add_nse(name,p,svc,text,sev)
        # Master timer ticks - run periodic tasks
        self._mt_tick+=1
        if self.running:
            if self._mt_tick%4==0:
                chars=['\u25cf ','\u25cb ','\u25d8 ','\u25d9 ']
                self._spin_idx=(self._spin_idx+1)%len(chars)
                self._scan_indicator.config(text=chars[self._spin_idx],fg=C.GREEN)
            if self._mt_tick%20==0:
                self._rate_history.append(self.rc)
                self._rate_history = self._rate_history[-120:]
                self.spv.set(f'{self.rc}/s')
                self._draw_rate_chart()
                self.rc=0
                if self.start:
                    el=time.time()-self.start
                    mins,secs=divmod(int(el),60)
                    self.elv.set(f'{mins}:{secs:02d}')
        self._after('master',50,self._master_timer)

    def _draw_rate_chart(self):
        try:
            cw = self._rate_chart.winfo_width() or 200
            ch = self._rate_chart.winfo_height() or 50
            self._rate_chart.delete('all')
            if not self._rate_history or max(self._rate_history) == 0:
                return
            max_r = max(self._rate_history)
            n = len(self._rate_history)
            points = []
            for i, r in enumerate(self._rate_history):
                x = int(cw * i / n)
                y = int(ch - (ch * r / max_r))
                points.append((x, y))
            if len(points) > 1:
                for i in range(len(points) - 1):
                    x1, y1 = points[i]
                    x2, y2 = points[i + 1]
                    self._rate_chart.create_line(x1, y1, x2, y2, fill=C.CYAN, width=1.5)
                self._rate_chart.create_text(cw - 2, 2, anchor='ne', text=f'{max_r}/s max',
                                             font=TINY, fill=C.TEXT2)
        except: pass

    def _startup_animation(self):
        splash=tk.Frame(self.root,bg=C.BG1,highlightthickness=0)
        splash.place(relx=0.5,rely=0.5,anchor='center')
        tk.Label(splash,text='PortStorm',font=('Segoe UI',28,'bold'),
                 fg=C.CYAN,bg=C.BG1).pack()
        tk.Label(splash,text='Loading...',font=('Segoe UI',12),
                 fg=C.TEXT2,bg=C.BG1).pack(pady=(4,0))
        splash.update_idletasks()
        self.root.after(600,splash.destroy)

    def _disc(self):
        base=Path(__file__).resolve().parent
        self.go=next((str(base/p) for p in ['go/port_scanner','bin/port_scanner']
                      if (base/p).exists()),None)
        global FONT,FONT_B,MONO,MONO_B,SMALL,TINY
        try:
            _fn=tkfont.families()
            _s='DejaVu Sans'if'DejaVu Sans'in _fn else('Liberation Sans'if'Liberation Sans'in _fn else('Segoe UI'if'Segoe UI'in _fn else('Noto Sans'if'Noto Sans'in _fn else'Helvetica')))
            _m='DejaVu Sans Mono'if'DejaVu Sans Mono'in _fn else('Liberation Mono'if'Liberation Mono'in _fn else('Noto Sans Mono'if'Noto Sans Mono'in _fn else('Consolas'if'Consolas'in _fn else'Courier')))
            FONT=(_s,10); FONT_B=(_s,10,'bold'); MONO=(_m,9); MONO_B=(_m,9,'bold')
            SMALL=(_s,8); TINY=(_s,7)
        except: pass
        try:
            r=subprocess.run(['ip','-4','route','show','default'],capture_output=1,text=1,timeout=3)
            p=r.stdout.strip().split()
            self.iface,self.gw=(p[4],p[2]) if len(p)>=5 else('?','?')
        except: self.iface=self.gw='?'
        try:
            with open('/proc/uptime') as f:
                s=float(f.read().split()[0]); h,m=divmod(int(s),3600); m//=60
                self.up=f'{h}h {m}m'
        except: self.up='0h 0m'
        nsd=base.parent/'nse_scripts'
        self.nse_all=sorted(f.stem for f in nsd.iterdir() if f.suffix=='.nse') if nsd.exists() else []

    def _load_presets(self):
        pf=CFG_DIR/'presets.json'
        if pf.exists():
            try: self.custom_presets=json.loads(pf.read_text())
            except: self.custom_presets=[]
        else: self.custom_presets=[
            {'name':'Quick','target':'scanme.nmap.org','ports':'22,80,443'},
            {'name':'Web','target':'scanme.nmap.org','ports':'80,443,8080,8443'},
            {'name':'Local','target':'192.168.1.0/24','ports':'22,80,443,3389'}]

    def _save_presets(self):
        CFG_DIR.mkdir(parents=True,exist_ok=True)
        (CFG_DIR/'presets.json').write_text(json.dumps(self.custom_presets,indent=2))

    def _style(self):
        s=ttk.Style(); s.theme_use('clam')
        for w in('.','TLabel','TFrame','TLabelframe','TLabelframe.Label'):
            s.configure(w,background=C.BG1,foreground=C.TEXT)
        s.configure('TLabelframe',bd=1,relief='solid',background=C.BG1)
        s.configure('TLabelframe.Label',foreground=C.CYAN,font=FONT_B)
        s.configure('TButton',background=C.BTN,foreground=C.CYAN,
                    borderwidth=1,focusthickness=0,font=FONT_B,padding=(10,4))
        s.map('TButton',background=[('active',C.HV),('pressed',C.SEL)])
        s.configure('Treeview',background=C.BG2,foreground=C.TEXT,
                    fieldbackground=C.BG2,rowheight=28,borderwidth=0,font=MONO)
        s.map('Treeview',background=[('selected',C.SEL)])
        s.configure('Treeview.Heading',background=C.BTN,foreground=C.CYAN,
                    borderwidth=1,relief='flat',font=MONO_B)
        s.configure('green.Horizontal.TProgressbar',background=C.GREEN,
                    troughcolor='#0a1525',borderwidth=0,thickness=10)
        s.configure('TCombobox',background=C.BG2,foreground=C.TEXT,
                    fieldbackground=C.BG2,selectbackground=C.SEL,arrowcolor=C.CYAN,
                    padding=(6,2))
        s.map('TCombobox',fieldbackground=[('readonly',C.BG2)])
        s.configure('Vertical.TScrollbar',background=C.BTN,troughcolor=C.BG1,
                    bordercolor=C.BG1,arrowcolor=C.TEXT2,width=14)
        s.map('Vertical.TScrollbar',background=[('active',C.HV),('pressed',C.SEL)])
        s.configure('TNotebook',background=C.BG1,borderwidth=0)
        s.configure('TNotebook.Tab',background=C.BTN,foreground=C.TEXT2,
                    padding=(12,4),font=FONT_B)
        s.map('TNotebook.Tab',background=[('selected',C.BG2),('active',C.HV)],
              foreground=[('selected',C.CYAN)])
        for k in('Text','Entry','Listbox'):
            self.root.option_add(f'*{k}.background',C.BG2)
            self.root.option_add(f'*{k}.foreground',C.TEXT)
            self.root.option_add(f'*{k}.selectbackground',C.SEL)
        self.root.option_add('*Text.selectforeground','#fff')
        self.root.option_add('*Listbox.selectforeground','#fff')
        self.root.option_add('*Entry.insertbackground',C.CYAN)
        self.root.option_add('*Entry.highlightthickness',1)
        self.root.option_add('*Entry.highlightbackground',C.BORD)
        self.root.option_add('*Entry.highlightcolor',C.CYAN)

    def _fcard(self,p):
        f=tk.Frame(p,bg=C.CARD,highlightbackground=C.BORD,highlightthickness=1,
                    relief='solid',bd=1)
        return f
    def _fsec(self,p,t,ico=''):
        f=self._fcard(p); f.pack(fill='x',padx=6,pady=2)
        h=tk.Frame(f,bg=C.CARD); h.pack(fill='x',padx=12,pady=(5,0))
        tk.Label(h,text=f'{ico} {t}',font=FONT_B,fg=C.CYAN,bg=C.CARD).pack(anchor='w')
        tk.Frame(f,bg=C.BORD,height=1).pack(fill='x',padx=12,pady=(3,0))
        b=tk.Frame(f,bg=C.CARD); b.pack(fill='x',padx=12,pady=(5,10))
        return b
    def _pill(self,p,t,cmd,c=C.CYAN):
        f=tk.Frame(p,bg=C.BTN,highlightbackground=c,highlightthickness=2)
        b=tk.Button(f,text=t,font=FONT_B,bg=C.BTN,fg=c,activebackground=C.HV,
                    activeforeground=c,bd=0,relief='flat',cursor='hand2',command=cmd)
        b.pack(fill='both',expand=1,ipadx=20,ipady=10)
        for w in(f,b):
            w.bind('<Enter>',lambda e:f.configure(bg=C.HV)or b.configure(bg=C.HV),'+')
            w.bind('<Leave>',lambda e:f.configure(bg=C.BTN)or b.configure(bg=C.BTN),'+')
        return f
    def _btn(self,p,t,cmd,fg=C.TEXT2):
        b=tk.Button(p,text=t,font=SMALL,bg=C.BTN,fg=fg,activebackground=C.HV,
                    activeforeground=C.TEXT,bd=0,relief='flat',cursor='hand2',padx=8,pady=3,command=cmd)
        b.bind('<Enter>',lambda e:b.configure(bg=C.HV),'+')
        b.bind('<Leave>',lambda e:b.configure(bg=C.BTN),'+')
        return b
    def _ent(self,p,v,pw=None,**kw):
        return tk.Entry(p,textvariable=v,font=FONT,bg=C.BG2,fg=C.TEXT,
                        insertbackground=C.CYAN,relief='flat',bd=4,show=pw,**kw)

    def _build(self):
        self._build_menu()
        self._build_banner()
        body=tk.Frame(self.root,bg=C.BG1)
        body.pack(fill='both',expand=1,padx=14,pady=4)
        body.grid_rowconfigure(0,weight=1)
        body.grid_columnconfigure(0,weight=0)
        body.grid_columnconfigure(1,weight=1)
        self._left_frame=body
        self._side_frame=self._side(body)
        self._side_frame.grid(row=0,column=0,sticky='ns')
        right=self._tabs(body); right.grid(row=0,column=1,sticky='nsew')
        self._status(); self._ks_panel()
        self._nsetags(); self._sync_cmd()

    def _build_menu(self):
        self._menubar=tk.Menu(self.root,bg=C.BTN,fg=C.TEXT,activebackground=C.HV,
                              activeforeground=C.CYAN,relief='flat',bd=0,borderwidth=0,
                              font=FONT)
        # File menu
        fm=tk.Menu(self._menubar,tearoff=0,bg=C.CARD,fg=C.TEXT,
                   activebackground=C.SEL,activeforeground='#fff',font=FONT)
        fm.add_command(label='New Scan',command=lambda:None,accelerator='Ctrl+N')
        fm.add_command(label='Load Config',command=self._load_cfg)
        fm.add_command(label='Save Config',command=self._save_cfg)
        fm.add_separator()
        fm.add_command(label='Export Results',command=self._exp)
        fm.add_separator()
        fm.add_command(label='Exit',command=self._close,accelerator='Ctrl+Q')
        self._menubar.add_cascade(label='File',menu=fm)
        # Edit menu
        em=tk.Menu(self._menubar,tearoff=0,bg=C.CARD,fg=C.TEXT,
                   activebackground=C.SEL,activeforeground='#fff',font=FONT)
        em.add_command(label='Copy',command=lambda:self._cp(self.log.selection_get() if self.log.tag_ranges('sel') else ''),accelerator='Ctrl+C')
        em.add_command(label='Select All',command=lambda:self.log.tag_add('sel','1.0','end'),accelerator='Ctrl+A')
        em.add_command(label='Clear Log',command=lambda:self.log.delete('1.0','end'),accelerator='Ctrl+L')
        self._menubar.add_cascade(label='Edit',menu=em)
        # View menu
        vm=tk.Menu(self._menubar,tearoff=0,bg=C.CARD,fg=C.TEXT,
                   activebackground=C.SEL,activeforeground='#fff',font=FONT)
        vm.add_command(label='Toggle Sidebar',command=self._toggle_sidebar)
        vm.add_command(label='Toggle NSE Log',command=lambda:None)
        vm.add_separator()
        vm.add_command(label='Dark/Light Theme',command=self._toggle_theme)
        self._menubar.add_cascade(label='View',menu=vm)
        # Help menu
        hm=tk.Menu(self._menubar,tearoff=0,bg=C.CARD,fg=C.TEXT,
                   activebackground=C.SEL,activeforeground='#fff',font=FONT)
        hm.add_command(label='About',command=lambda:messagebox.showinfo(
            'About PortStorm','HackIT PortStorm v10\nMulti-Engine All-Port Scanner\n\nGo + Rust + C + C++ + Lua'))
        hm.add_command(label='Keyboard Shortcuts',command=self._show_ks,accelerator='Ctrl+H')
        self._menubar.add_cascade(label='Help',menu=hm)
        self.root.config(menu=self._menubar)

    def _build_banner(self):
        self._banner_canvas=tk.Canvas(self.root,height=110,highlightthickness=0,bg=C.BG1)
        self._banner_canvas.pack(fill='x',padx=14,pady=(10,0))
        self._draw_gradient()
        b=BANNER%(self.iface,self.gw,'Active',self.up)
        self._banner_text=self._banner_canvas.create_text(10,4,anchor='nw',text=b,
            font=self._fonts['COURIER'],fill=C.CYAN,justify='left')

    def _draw_gradient(self):
        w=self._banner_canvas.winfo_width() or 1200
        h=110
        self._banner_canvas.delete('grad')
        for i in range(w):
            r=int(8+4*(1-i/w)); g=int(12+4*(1-i/w)); b=int(20+10*(1-i/w))
            col=f'#{r:02x}{g:02x}{b:02x}'
            self._banner_canvas.create_line(i,0,i,h,fill=col,tags='grad')
        self._banner_canvas.tag_lower('grad')
        self._after('grad',100,self._draw_gradient)

    def _side(self,p):
        c=tk.Frame(p,bg=C.BG1)
        self._cv=tk.Canvas(c,bg=C.BG1,highlightthickness=0,width=420)
        sb=ttk.Scrollbar(c,orient='vertical',command=self._cv.yview,style='Vertical.TScrollbar')
        self._cv.configure(yscrollcommand=sb.set)
        sb.pack(side='right',fill='y'); self._cv.pack(side='left',fill='both',expand=1)
        inner=tk.Frame(self._cv,bg=C.BG1)
        inner.bind('<Configure>',lambda e:self._cv.configure(scrollregion=self._cv.bbox('all')))
        self._inner_id=self._cv.create_window((0,0),window=inner,anchor='nw')
        self._cv.bind('<Configure>',lambda e:self._cv.itemconfig(self._inner_id,width=e.width))
        for evt,delta in [('<MouseWheel>',lambda e:self._cv.yview_scroll(int(-1*(e.delta/120)),'units')),
                         ('<Button-4>',lambda e:self._cv.yview_scroll(-3,'units')),
                         ('<Button-5>',lambda e:self._cv.yview_scroll(3,'units'))]:
            self._cv.bind(evt,delta)
        self._inner_frame=inner
        self._target(inner); self._ports(inner); self._presets(inner)
        self._opts(inner); self._cmd_preview(inner)
        self._mode(inner); self._nse(inner); self._acts(inner)
        return c

    def _toggle_sidebar(self):
        self._collapsed=not self._collapsed
        if self._collapsed:
            self._cv.configure(width=42)
            for w in self._inner_frame.winfo_children()[1:]:
                w.pack_forget()
        else:
            self._cv.configure(width=420)
            self._target(self._inner_frame); self._ports(self._inner_frame)
            self._presets(self._inner_frame); self._opts(self._inner_frame)
            self._cmd_preview(self._inner_frame); self._mode(self._inner_frame)
            self._nse(self._inner_frame); self._acts(self._inner_frame)
        self._sidebar_btn.config(text='\u25b6' if self._collapsed else '\u25c0')

    # ── Target ─────────────────────────────────────────────────────
    def _target(self,p):
        b=self._fsec(p,'TARGET','\U0001f3af')
        self.tv=tk.StringVar()
        self.tc=ttk.Combobox(b,textvariable=self.tv,font=FONT,state='normal')
        self.tc.pack(fill='x',ipady=4)
        self.tc.configure(postcommand=lambda: self.tc.configure(values=list(self.target_hist) or ['']))
        Tip(self.tc,'Hostname, IP, CIDR, or range. Tab to autocomplete from history.')
        self.tc.bind('<Tab>',lambda e:self._tab_target()or'break')
        tk.Label(b,text='scanme.nmap.org  |  192.168.1.0/24  |  10.0.0.1-100',
                 font=TINY,fg=C.TEXT2,bg=C.CARD).pack(anchor='w',pady=(2,0))

    def _tab_target(self):
        tv=self.tv.get().strip().lower()
        if not tv: return
        for h in reversed(self.target_hist):
            if h.startswith(tv) and h!=tv: self.tv.set(h); break

    # ── Ports ──────────────────────────────────────────────────────
    def _ports(self,p):
        b=self._fsec(p,'PORTS','\U0001f50c')
        f=tk.Frame(b,bg=C.CARD); f.pack(fill='x')
        self.ps=tk.StringVar(value='1'); self.pe=tk.StringVar(value='1024')
        self.ps.trace_add('write',lambda *a:self._pupd())
        self.pe.trace_add('write',lambda *a:self._pupd())
        for lbl,v,tip in [('From',self.ps,'Start port'),('To',self.pe,'End port')]:
            c=tk.Frame(f,bg=C.CARD); c.pack(side='left',fill='x',expand=1,padx=(0,6))
            tk.Label(c,text=lbl,font=TINY,fg=C.TEXT2,bg=C.CARD).pack(anchor='w')
            self._ent(c,v,width=6).pack(fill='x',ipady=2)
            Tip(c.winfo_children()[-1],tip)
        tk.Label(f,text='\u2192',font=('Segoe UI',16),fg=C.CYAN,bg=C.CARD
                 ).pack(side='left',padx=2,pady=(10,0))
        self.pst=tk.Label(b,text='1,024 ports',font=TINY,fg=C.CYAN,bg=C.CARD)
        self.pst.pack(anchor='w',pady=(1,0))
        tk.Label(b,text='Comma list (overrides)',font=TINY,fg=C.TEXT2,bg=C.CARD
                 ).pack(anchor='w',pady=(3,0))
        self.pcl=tk.StringVar()
        self.pcl.trace_add('write',lambda *a:self._pupd())
        e=self._ent(b,self.pcl); e.pack(fill='x',ipady=2)
        Tip(e,'e.g. 22,80,443,8080-8090')
        self._pupd()

    def _pupd(self):
        if self.pcl.get().strip():
            n=sum(1 for x in self.pcl.get().split(',') if x.strip())
            self.pst.config(text=f'{n} custom'if n else'?')
            return
        try:
            s=int(self.ps.get()or 1); e=int(self.pe.get()or 1024)
            n=max(0,e-s+1)
            self.pst.config(text=f'{n:,}'if n<10000 else f'{n/1000:.0f}k')
        except: self.pst.config(text='?')

    # ── Custom Presets ─────────────────────────────────────────────
    def _presets(self,p):
        b=self._fsec(p,'QUICK PRESETS','\u26a1')
        pf=tk.Frame(b,bg=C.CARD); pf.pack(fill='x')
        self.preset_frame=pf
        self._rebuild_presets()
        mf=tk.Frame(b,bg=C.CARD); mf.pack(fill='x',pady=(4,0))
        self._btn(mf,'+ Add Preset',self._add_preset).pack(side='left',padx=(0,6))
        self._btn(mf,'Manage',self._manage_presets).pack(side='left')
        self._btn(mf,'Save Config',self._save_cfg).pack(side='right',padx=(6,0))
        self._btn(mf,'Load Config',self._load_cfg).pack(side='right')
        self.cfn=tk.StringVar(value='default')
        e=self._ent(mf,self.cfn,width=10); e.pack(side='right',padx=(0,4))
        Tip(e,'Config name for save/load')

    def _rebuild_presets(self):
        for w in self.preset_frame.winfo_children(): w.destroy()
        for pr in self.custom_presets[:6]:
            c=tk.Frame(self.preset_frame,bg=C.CARD,highlightbackground=C.CYAN,highlightthickness=1,
                       padx=6,pady=4)
            c.pack(side='left',fill='x',expand=1,padx=1)
            tk.Label(c,text=pr['name'],font=FONT_B,fg=C.CYAN,bg=C.CARD,cursor='hand2').pack(anchor='w')
            tk.Label(c,text=pr.get('target',''),font=TINY,fg=C.TEXT2,bg=C.CARD,cursor='hand2').pack(anchor='w')
            tk.Label(c,text=f"\u2192 {pr.get('ports','22,80,443')}",font=('Segoe UI',6,'bold'),
                     fg=C.DIM,bg=C.CARD,cursor='hand2').pack(anchor='w')
            for w in c.winfo_children():
                w.bind('<Button-1>',
                       lambda e,t=pr['target'],pt=pr.get('ports','22,80,443'):self._quick(t,pt),'+')
            c.bind('<Enter>',lambda e,c=c:c.configure(bg=C.BTN,borderwidth=2),'+')
            c.bind('<Leave>',lambda e,c=c:c.configure(bg=C.CARD,borderwidth=1),'+')

    def _add_preset(self):
        name=simpledialog.askstring('Add Preset','Preset name:',parent=self.root,initialvalue='MyScan')
        if not name: return
        target=simpledialog.askstring('Add Preset','Target host:',parent=self.root,initialvalue='scanme.nmap.org')
        if not target: return
        ports=simpledialog.askstring('Add Preset','Ports:',parent=self.root,initialvalue='22,80,443')
        if not ports: return
        self.custom_presets.append({'name':name,'target':target,'ports':ports})
        self._save_presets(); self._rebuild_presets()

    def _manage_presets(self):
        if not self.custom_presets:
            messagebox.showinfo('Presets','No custom presets yet.',parent=self.root)
            return
        names=[p['name']for p in self.custom_presets]
        w=tk.Toplevel(self.root); w.title('Manage Presets')
        w.configure(bg=C.BG1); w.geometry('400x300'); w.transient(self.root)
        lb=tk.Listbox(w,bg=C.BG2,fg=C.TEXT,selectbackground=C.SEL,
                       font=MONO,selectmode='single',bd=0)
        lb.pack(fill='both',expand=1,padx=10,pady=10)
        for n in names: lb.insert('end',n)
        def _del():
            sel=lb.curselection()
            if not sel: return
            idx=sel[0]
            if idx<len(self.custom_presets):
                self.custom_presets.pop(idx)
                self._save_presets(); self._rebuild_presets(); w.destroy()
        tk.Button(w,text='Delete Selected',command=_del,bg=C.RED,fg='#fff',
                  bd=0,relief='flat',cursor='hand2').pack(pady=(0,10))

    def _save_cfg(self):
        name=self.cfn.get().strip() or 'default'
        cfg={
            'target':self.tv.get(),'ports':self.pcl.get(),
            'port_start':self.ps.get(),'port_end':self.pe.get(),
            'mode':';'.join(sorted(self.modes_sel))or'syn','profile':self.pv.get(),
            'timeout':self.tov.get(),'threads':self.twv.get(),
            'deep':self.dv.get(),'os_detect':self.ov.get(),'open_only':self.opv.get(),
            'nse_scripts':sorted(self.nse_sel),
        }
        (CFG_DIR/f'{name}.json').write_text(json.dumps(cfg,indent=2))
        self._toast(f'Config saved: {name}',C.GREEN)

    def _load_cfg(self):
        name=self.cfn.get().strip() or 'default'
        fp=CFG_DIR/f'{name}.json'
        if not fp.exists():
            self._toast(f'Config not found: {name}',C.RED); return
        try:
            cfg=json.loads(fp.read_text())
            self.tv.set(cfg.get('target',''))
            self.pcl.set(cfg.get('ports',''))
            self.ps.set(cfg.get('port_start','1'))
            self.pe.set(cfg.get('port_end','1024'))
            self.modes_sel=set(cfg.get('mode','syn').split(';'))
            self.pv.set(cfg.get('profile','quick'))
            self.tov.set(cfg.get('timeout','1000'))
            self.twv.set(cfg.get('threads','100'))
            self.dv.set(cfg.get('deep',False))
            self.ov.set(cfg.get('os_detect',False))
            self.opv.set(cfg.get('open_only',True))
            self.nse_sel=set(cfg.get('nse_scripts',[]))
            self._sync_cmd(); self._nsetags(); self._nse_filt(); self._upd_mode_labels()
            self._toast(f'Config loaded: {name}',C.CYAN)
        except Exception as e:
            self._toast(f'Load failed: {e}',C.RED)

    # ── Mode ───────────────────────────────────────────────────────
    def _mode(self,p):
        b=self._fsec(p,'SCAN MODE','\u2699\ufe0f')
        mf=tk.Frame(b,bg=C.CARD); mf.pack(fill='x')
        self.modes_sel=set()
        self.mode_btns=[]
        for i,(v,l) in enumerate(MODES):
            r=tk.Checkbutton(mf,text=l,font=('Consolas',8,'bold'),
                             fg=C.TEXT,bg=C.CARD,selectcolor=C.CARD,
                             activebackground=C.CARD,activeforeground=C.CYAN,
                             indicatoron=0,bd=1,relief='flat',
                             highlightbackground=C.BORD,highlightthickness=1,width=6)
            r.configure(command=lambda vv=v:self._mode_toggle(vv))
            r.grid(row=i//4,column=i%4,padx=1,pady=1,sticky='ew')
            mf.grid_columnconfigure(i%4,weight=1)
            self.mode_btns.append(r)
            Tip(r,f'Scan mode: {v.strip()}')
        tk.Label(b,text='PROFILE',font=FONT_B,fg=C.CYAN,bg=C.CARD
                 ).pack(anchor='w',pady=(4,0))
        pf=tk.Frame(b,bg=C.CARD); pf.pack(fill='x')
        self.pv=tk.StringVar(value='quick')
        self.pv.trace_add('write',lambda *a:(self._upd_mode_labels(),self._sync_cmd()))
        self.prof_btns=[]
        for i,p in enumerate(PROFILES):
            r=tk.Radiobutton(pf,text=p,variable=self.pv,value=p,font=SMALL,
                             fg=C.TEXT,bg=C.CARD,selectcolor=C.CARD,
                             activebackground=C.CARD,activeforeground=C.CYAN,
                             indicatoron=0,bd=1,relief='flat',
                             highlightbackground=C.BORD,highlightthickness=1)
            r.grid(row=i//3,column=i%3,padx=1,pady=1,sticky='ew')
            pf.grid_columnconfigure(i%3,weight=1)
            self.prof_btns.append(r)
            Tip(r,f'Profile: {p}')
        self._upd_mode_labels()

    def _mode_toggle(self,v):
        self.modes_sel.discard(v) if v in self.modes_sel else self.modes_sel.add(v)
        self._upd_mode_labels(); self._sync_cmd()

    def _upd_mode_labels(self):
        for r,(v,l) in zip(self.mode_btns,MODES):
            sel=v in self.modes_sel
            r.config(text=('\u2713'+l[1:]if sel else' '+l[1:]),
                     fg=C.BG1 if sel else C.TEXT,
                     bg=C.CYAN if sel else C.CARD,
                     highlightbackground=C.CYAN if sel else C.BORD)
        pv=self.pv.get()
        for r,p in zip(self.prof_btns,PROFILES):
            sel=(p==pv)
            r.config(text=('\u2713 '+p if sel else'  '+p),
                     fg=C.BG1 if sel else C.TEXT,
                     bg=C.CYAN if sel else C.CARD,
                     highlightbackground=C.CYAN if sel else C.BORD)

    # ── Options ────────────────────────────────────────────────────
    def _opts(self,p):
        b=self._fsec(p,'OPTIONS','\U0001f527')
        self.tov=tk.StringVar(value='1000'); self.twv=tk.StringVar(value='100')
        f=tk.Frame(b,bg=C.CARD); f.pack(fill='x')
        for lbl,v,tip in [('Timeout',self.tov,'Per-port timeout (ms)'),
                          ('Threads',self.twv,'Concurrent workers')]:
            c=tk.Frame(f,bg=C.CARD); c.pack(side='left',fill='x',expand=1,padx=(0,6))
            tk.Label(c,text=lbl,font=TINY,fg=C.TEXT2,bg=C.CARD).pack(anchor='w')
            e=self._ent(c,v,width=6); e.pack(fill='x',ipady=2); Tip(e,tip)
            v.trace_add('write',lambda *a:self._sync_cmd())
        f2=tk.Frame(b,bg=C.CARD); f2.pack(fill='x',pady=(4,0))
        self.dv=tk.BooleanVar(); self.ov=tk.BooleanVar(); self.opv=tk.BooleanVar(value=True)
        for v,t,tip in[(self.dv,'Deep','OS+service+vuln fingerprinting'),
                        (self.ov,'OS','TCP/IP stack OS detection'),
                        (self.opv,'Open','Open ports only')]:
            cb=tk.Checkbutton(f2,text=t,variable=v,font=TINY,fg=C.TEXT,
                              bg=C.CARD,selectcolor=C.CARD,activebackground=C.CARD,
                              activeforeground=C.CYAN)
            cb.pack(side='left',padx=(0,8)); Tip(cb,tip)
            v.trace_add('write',lambda *a:self._sync_cmd())

    # ── NSE ────────────────────────────────────────────────────────
    def _nse(self,p):
        b=self._fsec(p,'NSE SCRIPTS','\U0001f4dc')
        h=tk.Frame(b,bg=C.CARD); h.pack(fill='x')
        self._btn(h,'All',lambda:self._nse_set(1)).pack(side='left')
        self._btn(h,'None',lambda:self._nse_set(0)).pack(side='left',padx=(4,0))
        self.nc=tk.StringVar(value=f'0/{len(self.nse_all)}')
        tk.Label(h,textvariable=self.nc,font=TINY,fg=C.TEXT2,bg=C.CARD).pack(side='right')
        self.nsv=tk.StringVar()
        self.nsv.trace_add('write',lambda *a:self._nse_filt())
        e=self._ent(b,self.nsv); e.pack(fill='x',ipady=2,pady=(3,0))
        Tip(e,'Filter \u2014 click to toggle \u2014 Ctrl+A toggle all visible')
        fr=tk.Frame(b,bg=C.CARD,highlightbackground=C.BORD,highlightthickness=1)
        fr.pack(fill='x',pady=(2,0))
        self.nl=tk.Listbox(fr,font=MONO,bg=C.BG2,fg=C.TEXT,selectbackground=C.SEL,
                            selectforeground='#fff',selectmode='multiple',bd=0,height=5,
                            highlightthickness=0,exportselection=0)
        sb=ttk.Scrollbar(fr,orient='vertical',command=self.nl.yview,style='Vertical.TScrollbar')
        self.nl.configure(yscrollcommand=sb.set)
        self.nl.pack(side='left',fill='both',expand=1); sb.pack(side='right',fill='y')
        self.nl.bind('<<ListboxSelect>>',self._nse_click)
        self.nl.bind('<Control-a>',lambda e:self._nse_sel_all())
        for s in self.nse_all: self.nl.insert('end',s)
        tk.Label(b,text='Selected:',font=TINY,fg=C.TEXT2,bg=C.CARD
                 ).pack(anchor='w',pady=(1,0))
        self.ntf=tk.Frame(b,bg=C.CARD); self.ntf.pack(fill='x')

    def _nse_click(self,e):
        sel=self.nl.curselection()
        if not sel: return
        idx=sel[0]
        s=self.nl.get(idx)
        self.nse_sel.discard(s) if s in self.nse_sel else self.nse_sel.add(s)
        self.nl.selection_clear(0,'end')
        self._nsetags(); self._nse_filt()

    def _nse_filt(self):
        q=self.nsv.get().lower()
        scroll=self.nl.yview()
        self.nl.delete(0,'end')
        for s in self.nse_all:
            if q in s.lower():
                disp=('\u2713 'if s in self.nse_sel else'  ')+s
                self.nl.insert('end',disp)
        self.nc.set(f'{len(self.nse_sel)}/{len(self.nse_all)}')
        try: self.nl.yview_moveto(scroll[0])
        except: pass

    def _nse_set(self,v):
        self.nse_sel=set(self.nse_all)if v else set()
        self._nsetags(); self._nse_filt(); self._sync_cmd()

    def _nse_sel_all(self):
        vis=[self.nl.get(i)[2:]for i in range(self.nl.size())]
        av=all(s in self.nse_sel for s in vis)
        for s in vis:
            self.nse_sel.discard(s)if av else self.nse_sel.add(s)
        self._nsetags(); self._nse_filt()

    def _nsetags(self):
        for w in self.ntf.winfo_children(): w.destroy()
        if not self.nse_sel:
            tk.Label(self.ntf,text='(none)',font=TINY,fg=C.DIM,bg=C.CARD).pack(anchor='w')
            return
        row=tk.Frame(self.ntf,bg=C.CARD); row.pack(fill='x')
        for i,s in enumerate(sorted(self.nse_sel)):
            if i and i%6==0:
                row=tk.Frame(self.ntf,bg=C.CARD); row.pack(fill='x')
            chip=tk.Frame(row,bg=C.BTN,highlightbackground=C.CYAN,highlightthickness=1)
            chip.pack(side='left',padx=1,pady=1)
            tk.Label(chip,text=s,font=('Consolas',6),fg=C.CYAN,bg=C.BTN,padx=3).pack(side='left')
            rm=tk.Label(chip,text='\u00d7',font=('Segoe UI',6,'bold'),fg=C.RED,bg=C.BTN,cursor='hand2')
            rm.pack(side='right',padx=(0,1))
            rm.bind('<Button-1>',lambda e,n=s:self._nse_rm(n))

    def _nse_rm(self,n):
        self.nse_sel.discard(n); self._nsetags(); self._nse_filt(); self._sync_cmd()

    # ── Command Preview ────────────────────────────────────────────
    def _cmd_preview(self,p):
        b=self._fsec(p,'COMMAND','\U0001f4bb')
        self.cmdv=tk.StringVar(value='Ready')
        e=tk.Entry(b,textvariable=self.cmdv,font=('Consolas',7),fg=C.GREEN,
                   bg=C.BG2,bd=0,relief='flat',state='readonly')
        e.pack(fill='x',ipady=2)

    def _sync_cmd(self):
        for attr in('tv','pcl','ps','pe','tov','twv','pv','opv','dv','ov','cmdv','modes_sel'):
            if not hasattr(self,attr): return
        target=self.tv.get().strip() or '<target>'
        explicit=self.pcl.get().strip()
        if explicit: ports=explicit
        else: ports=f"{self.ps.get() or '1'}-{self.pe.get() or '1024'}"
        parts=[self.go or 'scanner','-target',target,'-ports',ports,
               '-timeout',self.tov.get()or'1000','-threads',self.twv.get()or'100',
               '-mode',';'.join(sorted(self.modes_sel))or'syn',
               '-profile',self.pv.get()]
        if self.opv.get(): parts.append('--open-only')
        if self.dv.get(): parts.append('--deep')
        if self.ov.get(): parts.append('--os-detect')
        parts.append('--all-engines')
        if self.nse_sel:
            parts.append('--script'); parts.append(';'.join(sorted(self.nse_sel)))
        self.cmdv.set(' '.join(parts))

    # ── Actions ────────────────────────────────────────────────────
    def _acts(self,p):
        b=tk.Frame(p,bg=C.BG1)
        b.pack(fill='x',padx=6,pady=(4,10))
        hf=tk.Frame(b,bg=C.BG1); hf.pack(fill='x')
        self._sidebar_btn=self._btn(hf,'\u25c0',self._toggle_sidebar,fg=C.PURPLE)
        self._sidebar_btn.pack(side='left',padx=(0,4))
        af=tk.Frame(b,bg=C.BG1); af.pack(fill='x',pady=(2,0))
        self.sb=self._pill(af,'\u25b6  START SCAN',self._start,c=C.GREEN)
        self.sb.pack(side='left',fill='x',expand=1,padx=(0,4))
        self.stb=self._pill(af,'\u25a0  STOP',self._stop,c=C.RED)
        self.stb.pack(side='right',fill='x',expand=1,padx=(4,0))
        self.stb.children['!button'].config(state='disabled')

    def _quick(self,h,pts):
        self.tv.set(h); self.pcl.set(pts)
        self.ps.set(''); self.pe.set('')
        self._sync_cmd()
        self._start()

    # ── Keyboard shortcuts panel ──────────────────────────────────
    def _ks_panel(self):
        self._ks_win=None
    def _show_ks(self):
        if self._ks_win and self._ks_win.winfo_exists():
            self._ks_win.lift(); return
        w=tk.Toplevel(self.root); w.title('Keyboard Shortcuts')
        w.configure(bg=C.BG1); w.geometry('400x280')
        w.transient(self.root); w.resizable(0,0)
        self._ks_win=w
        f=tk.Frame(w,bg=C.BG1,padx=16,pady=12); f.pack(fill='both',expand=1)
        tk.Label(f,text='Keyboard Shortcuts',font=FONT_B,fg=C.CYAN,bg=C.BG1
                 ).pack(anchor='w',pady=(0,8))
        shortcuts=[
            ('Enter / Ctrl+S','Start scan'),
            ('Escape','Stop scan'),
            ('Ctrl+L','Clear log'),
            ('Ctrl+Q','Quit'),
            ('Ctrl+H','Show this panel'),
            ('Tab (target)','Autocomplete from history'),
        ]
        for key,desc in shortcuts:
            r=tk.Frame(f,bg=C.BG1); r.pack(fill='x',pady=1)
            tk.Label(r,text=key,font=MONO_B,fg=C.GREEN,bg=C.BG1,width=20,anchor='w'
                     ).pack(side='left')
            tk.Label(r,text=desc,font=SMALL,fg=C.TEXT2,bg=C.BG1,anchor='w'
                     ).pack(side='left',padx=(8,0))

    # ── Tabs ───────────────────────────────────────────────────────
    def _tabs(self,p):
        f=tk.Frame(p,bg=C.BG1)
        nb=ttk.Notebook(f); nb.pack(fill='both',expand=1)
        lt=tk.Frame(nb,bg=C.BG1); nb.add(lt,text='  \U0001f4cb Event Log  ')
        self._log(lt)
        rt=tk.Frame(nb,bg=C.BG1); nb.add(rt,text='  \U0001f310 Port Results  ')
        self._res(rt)
        nt=tk.Frame(nb,bg=C.BG1); nb.add(nt,text='  \U0001f4ca NSE Results  ')
        self._nse_tab(nt)
        nlt=tk.Frame(nb,bg=C.BG1); nb.add(nlt,text='  \U0001f4dd NSE Log  ')
        self._nse_log_tab(nlt)
        return f

    # ── Log ────────────────────────────────────────────────────────
    def _log(self,p):
        h=tk.Frame(p,bg=C.BG1); h.pack(fill='x')
        tk.Label(h,text='Scan Log',font=FONT_B,fg=C.CYAN,bg=C.BG1).pack(side='left')
        self._btn(h,'\u00d7 Clear',lambda:self.log.delete('1.0','end')).pack(side='right')
        self.log=tk.Text(p,font=MONO,wrap='word',bg=C.BG2,fg=C.GREEN,
                          insertbackground=C.CYAN,bd=0,relief='flat')
        sb=ttk.Scrollbar(p,orient='vertical',command=self.log.yview,style='Vertical.TScrollbar')
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side='left',fill='both',expand=1,pady=(4,0))
        sb.pack(side='right',fill='y',pady=(4,0))
        for tag,c in[('ts',C.TEXT2),('cmd',C.CYAN),('err',C.RED),
                     ('ok',C.GREEN),('warn',C.ORANGE),('nse',C.PURPLE)]:
            self.log.tag_config(tag,foreground=c)

    # ── Results ────────────────────────────────────────────────────
    def _res(self,p):
        h=tk.Frame(p,bg=C.BG1); h.pack(fill='x')
        tk.Label(h,text='Port Scan Results',font=FONT_B,fg=C.CYAN,bg=C.BG1).pack(side='left')
        self.rcv=tk.StringVar(value='0 ports')
        tk.Label(h,textvariable=self.rcv,font=SMALL,fg=C.TEXT2,bg=C.BG1
                 ).pack(side='left',padx=(8,0))
        self.rminv=tk.StringVar(); self.rmaxv=tk.StringVar()
        tk.Label(h,textvariable=self.rminv,font=TINY,fg=C.DIM,bg=C.BG1
                 ).pack(side='left',padx=(4,0))
        tk.Label(h,textvariable=self.rmaxv,font=TINY,fg=C.DIM,bg=C.BG1
                 ).pack(side='left',padx=(4,0))
        self._btn(h,'Export',self._exp).pack(side='right',padx=(0,2))
        self._btn(h,'\u00d7 Clear',self._clear_res).pack(side='right')
        # Virtual canvas-based port list (handles 65k+ ports smoothly)
        vp = tk.Frame(p, bg=C.BG2)
        vp.pack(fill='both', expand=1, pady=(4,0))
        self._vpl = VirtualPortList(vp)
        self._vpl.pack(side='left', fill='both', expand=1)
        vsb = tk.Scrollbar(vp, orient='vertical', command=self._vpl.yview,
                           bg=C.BTN, troughcolor=C.BG1, width=14,
                           activebackground=C.HV, highlightbackground=C.BG1)
        self._vpl.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self._vpl.bind('<Button-3>', self._ctx)
        self._vpl.bind('<Button-1>', self._on_vpl_click, '+')
        # Mini rate chart
        cf = tk.Frame(p, bg=C.BG1)
        cf.pack(fill='x', pady=(2, 0))
        tk.Label(cf, text='Scan Rate (ports/s)', font=TINY, fg=C.TEXT2, bg=C.BG1).pack(anchor='w')
        self._rate_chart = tk.Canvas(cf, height=45, bg=C.BG2, highlightthickness=0)
        self._rate_chart.pack(fill='x')

    def _clear_res(self):
        self._vpl.items.clear()
        self._vpl._render()
        self.rcv.set('0 ports'); self.rminv.set(''); self.rmaxv.set('')

    def _res_filter(self):
        pass

    def _ctx(self,e):
        m=tk.Menu(self.root,tearoff=0,bg=C.CARD,fg=C.TEXT,activebackground=C.SEL,activeforeground='#fff')
        m.add_command(label='\U0001f4cb Copy All',command=self._cp_all)
        m.tk_popup(e.x_root,e.y_root)

    def _cp(self,t): self.root.clipboard_clear(); self.root.clipboard_append(t)
    def _cp_all(self):
        rows=[tuple(item[:5])for item in self._vpl.items]
        self._cp('\n'.join('\t'.join(str(c)for c in r)for r in rows))

    def _on_vpl_click(self, e):
        if e.y < 28:  # header click
            idx = 0
            for x, w in zip(self._vpl._col_x, self._vpl._col_w):
                if x <= e.x - 4 <= x + w:
                    self._sort_vpl(idx)
                    return
                idx += 1

    def _sort_vpl(self, col):
        self._vpl._sort_col = col
        self._vpl._sort_reverse = not self._vpl._sort_reverse
        rev = self._vpl._sort_reverse
        def sk(item):
            try: val = item[col]
            except: return ''
            if col == 0:
                try: return (int(val), '') if str(val).isdigit() else (float('inf'), str(val).lower())
                except: return (float('inf'), str(val).lower())
            return str(val).lower()
        self._vpl.items.sort(key=sk, reverse=rev)
        self._vpl._render()

    # ── NSE Results ────────────────────────────────────────────────
    def _nse_tab(self,p):
        h=tk.Frame(p,bg=C.BG1); h.pack(fill='x')
        tk.Label(h,text='NSE Script Results',font=FONT_B,fg=C.PURPLE,bg=C.BG1).pack(side='left')
        self.ncl=tk.StringVar(value='0 results')
        tk.Label(h,textvariable=self.ncl,font=SMALL,fg=C.TEXT2,bg=C.BG1
                 ).pack(side='left',padx=(8,0))
        tk.Label(h,text='Filter:',font=TINY,fg=C.TEXT2,bg=C.BG1).pack(side='right',padx=(0,2))
        self.nsev_f=tk.StringVar(value='ALL')
        sev_f=ttk.Combobox(h,textvariable=self.nsev_f,values=['ALL','VULN','HIGH','WARN','INFO','OK'],
                           font=TINY,state='readonly',width=8)
        sev_f.pack(side='right',padx=(0,2))
        sev_f.bind('<<ComboboxSelected>>',lambda e:self._nse_filter_sev())
        self._btn(h,'Export JSON',self._exp_nse).pack(side='right',padx=(0,2))
        self._btn(h,'\u00d7 Clear',self._clear_nse).pack(side='right')
        cols=('#','Time','Script','Port','Service','Severity','Result')
        self.nt=ttk.Treeview(p,columns=cols,show='headings',selectmode='extended')
        for c in cols:
            self.nt.heading(c,text=c,anchor='w')
            self.nt.column(c,width={'#':30,'Time':70,'Script':160,'Port':50,
                                     'Service':85,'Severity':65,'Result':560}[c],
                           anchor='center'if c in('#','Time','Port','Severity')else'w')
        for k,v in C.SEV.items(): self.nt.tag_configure(f'nse_{k}',foreground=v)
        self.nt.bind('<Double-1>',self._nse_det)
        self.nt.bind('<Button-3>',self._nse_ctx)
        vsb=ttk.Scrollbar(p,orient='vertical',command=self.nt.yview,style='Vertical.TScrollbar')
        self.nt.configure(yscrollcommand=vsb.set)
        self.nt.pack(side='left',fill='both',expand=1,pady=(4,0))
        vsb.pack(side='right',fill='y',pady=(4,0))
        self.ni=0
        self._nse_all_items=[]

    def _nse_filter_sev(self):
        f=self.nsev_f.get()
        for i in self.nt.get_children(): self.nt.delete(i)
        for vals,tag in self._nse_all_items:
            if f=='ALL' or vals[5]==f: self.nt.insert('','end',values=vals,tags=(tag,))
        n=len(self.nt.get_children())
        self.ncl.set(f'{n} results')

    def _clear_nse(self):
        for r in self.nt.get_children(): self.nt.delete(r)
        self.ni=0; self.ncl.set('0 results')
        self._nse_all_items.clear()
        self.nse_log.delete('1.0','end') if hasattr(self,'nse_log') else None

    def _add_nse(self,script,port,svc,text,sev='info'):
        self.ni+=1; ts=datetime.now().strftime('%H:%M:%S')
        su=sev.lower()
        if su not in('vuln','high','warn','info','ok'): su='info'
        vals=(self.ni,ts,script,str(port),svc,su.upper(),text)
        tag=f'nse_{su}'
        self._nse_all_items.append((vals,tag))
        self._nse_filter_sev()
        self.nsv2.set(f'NSE:{self.ni}')
        self.log.insert('end',f'[{ts}] \u25c8 NSE [{script}] port {port}: {text[:120]}\n','nse')
        self.log.see('end')
        # Also add to NSE live log tab
        if hasattr(self,'nse_log'):
            col=C.SEV.get(su,C.CYAN)
            self._nse_log_insert(ts,script,port,text,su,col)

    def _nse_log_insert(self,ts,script,port,text,severity,color):
        self.nse_log.insert('end',f'[{ts}] ','ts')
        self.nse_log.insert('end',f'[{severity.upper():5s}] ',severity)
        self.nse_log.insert('end',f'[{script}] ','script')
        self.nse_log.insert('end',f'port {port}: ','port')
        self.nse_log.insert('end',f'{text}\n','nse_text')
        if hasattr(self,'nse_log_auto') and self.nse_log_auto.get():
            self.nse_log.see('end')
        self.nse_log.update_idletasks()

    def _nse_det(self,e):
        sel=self.nt.identify_row(e.y)
        if not sel: return
        v=self.nt.item(sel,'values')
        if len(v)<7: return
        w=tk.Toplevel(self.root)
        w.title(f'NSE: {v[2]} \u2192 port {v[3]}')
        w.configure(bg=C.BG1); w.geometry('640x440')
        w.transient(self.root)
        f=tk.Frame(w,bg=C.BG1,padx=12,pady=12); f.pack(fill='both',expand=1)
        for lbl,idx in[('Script',2),('Port',3),('Service',4),('Severity',5)]:
            tk.Label(f,text=f'{lbl}: {v[idx]}',font=SMALL,fg=C.TEXT2,bg=C.BG1
                     ).pack(anchor='w',pady=(0,2))
        tk.Label(f,text='Full Output:',font=SMALL,fg=C.TEXT2,bg=C.BG1).pack(anchor='w')
        t=tk.Text(f,font=MONO,bg=C.BG2,fg=C.GREEN,wrap='word',bd=0,relief='flat')
        t.insert('1.0',v[6]); t.config(state='disabled')
        sb=ttk.Scrollbar(f,orient='vertical',command=t.yview,style='Vertical.TScrollbar')
        t.configure(yscrollcommand=sb.set)
        t.pack(side='left',fill='both',expand=1,pady=(4,0))
        sb.pack(side='right',fill='y',pady=(4,0))

    def _nse_ctx(self,e):
        sel=self.nt.identify_row(e.y)
        if not sel: return
        self.nt.selection_set(sel)
        m=tk.Menu(self.root,tearoff=0,bg=C.CARD,fg=C.TEXT,activebackground=C.SEL,activeforeground='#fff')
        v=self.nt.item(sel,'values')[:7]
        m.add_command(label='\U0001f4cb Copy Row',command=lambda:self._cp('\t'.join(v)))
        m.add_command(label='\U0001f4cb Copy Result',command=lambda:self._cp(v[6]if len(v)>6 else''))
        m.add_command(label='\U0001f50d Show Detail',command=lambda:self._nse_det(e))
        m.tk_popup(e.x_root,e.y_root)

    def _exp_nse(self):
        ch=self.nt.get_children()
        if not ch: return
        p=filedialog.asksaveasfilename(defaultextension='.json',filetypes=[('JSON','*.json')])
        if not p: return
        keys=['id','timestamp','script','port','service','severity','result']
        data=[dict(zip(keys,self.nt.item(k,'values')[:7]))for k in ch]
        with open(p,'w')as f: json.dump(data,f,indent=2)
        self._logf(f'[+] Exported {len(data)} NSE \u2192 {Path(p).name}','ok')

    # ── NSE Live Log Tab (NEW) ───────────────────────────────────
    def _nse_log_tab(self,p):
        h=tk.Frame(p,bg=C.BG1); h.pack(fill='x')
        tk.Label(h,text='NSE Live Output',font=FONT_B,fg=C.PURPLE,bg=C.BG1).pack(side='left')
        # Severity legend
        leg=tk.Frame(h,bg=C.BG1); leg.pack(side='left',padx=(8,0))
        for sev,fg in[('VULN','#f85149'),('HIGH','#d29922'),('WARN','#d29922'),
                       ('INFO','#58a6ff'),('OK','#3fb950')]:
            chip=tk.Frame(leg,bg=C.BTN,highlightbackground=fg,highlightthickness=1,
                          padx=4,pady=1)
            chip.pack(side='left',padx=1)
            tk.Label(chip,text=sev,font=TINY,fg=fg,bg=C.BTN).pack()
        self._btn(h,'Export',self._exp_nse).pack(side='right',padx=(0,2))
        self._btn(h,'\u00d7 Clear',self._clear_nse_log).pack(side='right')
        self.nse_log_auto=tk.BooleanVar(value=True)
        toggle_btn=tk.Checkbutton(h,text='Auto-scroll',variable=self.nse_log_auto,
                                   font=SMALL,fg=C.TEXT2,bg=C.BG1,selectcolor=C.BG1,
                                   activebackground=C.BG1,activeforeground=C.CYAN)
        toggle_btn.pack(side='right',padx=(0,6))
        self.nse_log=scrolledtext.ScrolledText(p,font=MONO,wrap='word',bg=C.BG2,
                                                 fg=C.GREEN,insertbackground=C.CYAN,
                                                 bd=0,relief='flat',height=8)
        self.nse_log.pack(fill='both',expand=1,pady=(4,0))
        # Tag configs for severity coloring
        self.nse_log.tag_config('ts',foreground=C.TEXT2)
        self.nse_log.tag_config('vuln',foreground=C.RED,font=MONO_B)
        self.nse_log.tag_config('high',foreground=C.ORANGE,font=MONO_B)
        self.nse_log.tag_config('warn',foreground=C.YELLOW)
        self.nse_log.tag_config('info',foreground=C.CYAN)
        self.nse_log.tag_config('ok',foreground=C.GREEN)
        self.nse_log.tag_config('script',foreground=C.PURPLE)
        self.nse_log.tag_config('port',foreground=C.TEXT2)
        self.nse_log.tag_config('nse_text',foreground=C.TEXT)
        self.nse_log.config(state='normal')

    def _clear_nse_log(self):
        self.nse_log.delete('1.0','end')

    # ── Status bar ─────────────────────────────────────────────────
    def _sep(self,p): tk.Frame(p,width=1,bg=C.BORD).pack(side='left',fill='y',padx=4,pady=4)
    def _status(self):
        bot=tk.Frame(self.root,bg=C.CARD,highlightbackground=C.BORD,highlightthickness=1)
        bot.pack(fill='x',padx=14,pady=(0,6))
        # Status indicator
        self.sv=tk.StringVar(value='\u25cf Ready')
        tk.Label(bot,textvariable=self.sv,font=MONO_B,fg=C.GREEN,bg=C.CARD
                 ).pack(side='left',padx=(12,4),pady=5)
        self._sep(bot)
        # Target info
        self.iv=tk.StringVar()
        tk.Label(bot,textvariable=self.iv,font=SMALL,fg=C.TEXT2,bg=C.CARD
                 ).pack(side='left',padx=6,pady=5)
        self._sep(bot)
        # Stage
        self.stv=tk.StringVar()
        tk.Label(bot,textvariable=self.stv,font=SMALL,fg=C.PURPLE,bg=C.CARD
                 ).pack(side='left',padx=6,pady=5)
        self._sep(bot)
        # Scan speed (ports/sec)
        self.spv=tk.StringVar(value='0 p/s')
        tk.Label(bot,textvariable=self.spv,font=MONO_B,fg=C.ORANGE,bg=C.CARD
                 ).pack(side='left',padx=6,pady=5)
        self._sep(bot)
        # Elapsed time
        tl=tk.Frame(bot,bg=C.CARD); tl.pack(side='left',padx=6,pady=5)
        tk.Label(tl,text='\u23f1',font=SMALL,fg=C.TEXT2,bg=C.CARD).pack(side='left')
        self.elv=tk.StringVar(value='0:00')
        tk.Label(tl,textvariable=self.elv,font=MONO_B,fg=C.CYAN,bg=C.CARD
                 ).pack(side='left',padx=(2,0))
        # Status count
        self._sep(bot)
        cl=tk.Frame(bot,bg=C.CARD); cl.pack(side='left',padx=6,pady=5)
        tk.Label(cl,text='\U0001f310',font=SMALL,bg=C.CARD).pack(side='left')
        self.cnv=tk.StringVar(value='0 ports')
        tk.Label(cl,textvariable=self.cnv,font=SMALL,fg=C.GREEN,bg=C.CARD
                 ).pack(side='left',padx=(2,0))
        # NSE count
        self._sep(bot)
        nl=tk.Frame(bot,bg=C.CARD); nl.pack(side='left',padx=6,pady=5)
        tk.Label(nl,text='\U0001f4dc',font=SMALL,bg=C.CARD).pack(side='left')
        self.nsv2=tk.StringVar(value='0')
        tk.Label(nl,textvariable=self.nsv2,font=SMALL,fg=C.PURPLE,bg=C.CARD
                 ).pack(side='left',padx=(2,0))
        # Animated scanning indicator
        self._scan_indicator=tk.Label(bot,text='  ',font=MONO_B,fg=C.GREEN,bg=C.CARD)
        self._scan_indicator.pack(side='left',padx=2,pady=5)
        # Spacer
        tk.Frame(bot,bg=C.CARD).pack(side='left',fill='x',expand=1)
        # Progress bar + percentage
        self.pctv=tk.StringVar(value='0%')
        tk.Label(bot,textvariable=self.pctv,font=MONO_B,fg=C.CYAN,bg=C.CARD
                 ).pack(side='right',padx=(0,4),pady=5)
        self.prog=ttk.Progressbar(bot,mode='determinate',length=100,
                                  style='green.Horizontal.TProgressbar')
        self.prog.pack(side='right',padx=(0,6),pady=5)
        # Dark/light theme toggle
        self._theme_btn=self._btn(bot,'\u2600 Theme',self._toggle_theme,fg=C.YELLOW)
        self._theme_btn.pack(side='right',padx=(0,6),pady=5)
        # Keyboard shortcuts button
        self._btn(bot,'\u2318 Keys',self._show_ks,fg=C.CYAN).pack(side='right',padx=(0,4),pady=5)

    def _toggle_theme(self):
        self._theme='light' if self._theme=='dark' else 'dark'
        C.apply(self._theme)
        self._theme_btn.config(text='\u263e Dark' if self._theme=='light' else '\u2600 Theme')
        self._style()
        self._toast(f'{self._theme.title()} theme',C.CYAN)

    # ── Keyboard ──────────────────────────────────────────────────
    def _bind(self):
        for seq,cmd in[('<Return>',self._start),('<Control-s>',self._start),
                       ('<Escape>',lambda:self._stop()if self.running else None),
                       ('<Control-l>',lambda:self.log.delete('1.0','end')if hasattr(self,'log')else None),
                       ('<Control-q>',self._close),
                       ('<Control-h>',self._show_ks)]:
            self.root.bind(seq,lambda e,c=cmd:c())

    # ── Queue ──────────────────────────────────────────────────────
    def _ts(self): return datetime.now().strftime('%H:%M:%S')
    def _logf(self,msg,tag=None): self.q.put(('log',(f'[{self._ts()}] {msg}',tag)))
    def _st(self,m): self.q.put(('st',m))
    def _prog(self,v): self.q.put(('prog',v))
    def _cnt(self,c): self.q.put(('cnt',c))
    def _toast(self,m,c=C.ORANGE): self.q.put(('toast',(m,c)))

    # ── Toast ──────────────────────────────────────────────────────
    def _show_toast(self,msg,color):
        self.tst_w=[w for w in self.tst_w if w.winfo_exists()]
        y=0.02+0.035*len(self.tst_w)
        f=tk.Frame(self.root,bg=color,bd=0)
        f.place(relx=0.98,rely=y,anchor='ne')
        tk.Label(f,text=msg,font=SMALL,fg='#fff',bg=color,padx=14,pady=6).pack()
        self.tst_w.append(f)
        self.root.after(3000,f.destroy)

    def _adv(self,n=None):
        if n: self.stv.set(f'\u25b6 {n}')
        else: self.si=(self.si+1)%len(self.stages); self.stv.set(self.stages[self.si])

    # ── Scan ───────────────────────────────────────────────────────
    def _start(self):
        target=self.tv.get().strip()
        if not target: self._toast('Enter a target',C.RED); return
        if target not in self.target_hist:
            self.target_hist.append(target)
            if len(self.target_hist)>50: self.target_hist.pop(0)
            self.tc['values']=list(self.target_hist)
        self.results.clear()
        self._clear_res()
        for t in(self.nt,):
            for r in t.get_children(): t.delete(r)
        self.log.delete('1.0','end')
        self.nse_log.delete('1.0','end') if hasattr(self,'nse_log') else None
        self.start=time.time(); self.sc=0; self.rc=0; self.si=0; self.ni=0; self.res_cnt=0
        self._adv('Discovery'); self._st('Scanning...')
        self._prog(0); self._cnt(0)
        self.spv.set(''); self.elv.set('0:00'); self.nsv2.set('NSE:0'); self.ncl.set('0 results')
        self.rminv.set(''); self.rmaxv.set('')
        self.sb.children['!button'].config(state='disabled',text='\u25c9  SCANNING...')
        self.stb.children['!button'].config(state='normal')
        self.running=1; self._mt_tick=0; self._after('master',50,self._master_timer)
        threading.Thread(target=self._run,args=(target,),daemon=1).start()

    def _run(self,target):
        if self.go: self._go(target)
        else: self._fb(target)

    def _cmd(self,target):
        explicit=self.pcl.get().strip()
        if explicit: ports=explicit
        else:
            s=self.ps.get().strip()or'1'; e=self.pe.get().strip()or'1024'
            ports=f'{s}-{e}'
        cmd=[self.go,'-target',target,'-ports',ports,
             '-timeout',self.tov.get()or'1000','-threads',self.twv.get()or'100',
             '-mode',';'.join(sorted(self.modes_sel))or'syn',
             '-profile',self.pv.get()]
        if self.opv.get(): cmd.append('--open-only')
        if self.dv.get(): cmd.append('--deep')
        if self.ov.get(): cmd.append('--os-detect')
        cmd.append('--all-engines')
        if self.nse_sel: cmd.extend(['--script',';'.join(sorted(self.nse_sel))])
        return cmd

    def _go(self,target):
        cmd=self._cmd(target)
        sock_path = tempfile.mktemp(prefix='pstorm-', suffix='.sock', dir='/tmp')
        cmd.extend(['--control-socket', sock_path])
        self._logf(f'$ {" ".join(cmd)}','cmd')
        self._logf(f'\u2192 Scanning {target} with all engines + NSE...')
        try:
            self._control_sock = self._start_control_socket(sock_path)
            self.proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,text=True,bufsize=1)
            sel = selectors.DefaultSelector()
            sel.register(self.proc.stdout, selectors.EVENT_READ)
            sel.register(self.proc.stderr, selectors.EVENT_READ)
            while self.proc.poll() is None:
                for key, _ in sel.select(timeout=0.1):
                    line = key.fileobj.readline()
                    if not line:
                        sel.unregister(key.fileobj)
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    if key.fileobj is self.proc.stdout:
                        if line.startswith('RESULT:'): self._pr(line[7:])
                        elif line.startswith('NSE:'): self._pn(line[4:])
                        elif line.startswith('STATUS:'): self._ps(line[7:])
                        elif line.startswith('ERROR:'): self._logf(f'[!] {line[6:]}','err')
                        elif line and not line.startswith(('\x1b','\u250c','\u2502','\u251c','\u2514')): self._logf(line)
                    else:
                        if line.strip(): self._logf(f'[stderr] {line.strip()[:200]}','warn')
            remaining_stdout = self.proc.stdout.read()
            for line in remaining_stdout.split('\n'):
                line = line.strip()
                if line.startswith('RESULT:'): self._pr(line[7:])
            self.proc.wait()
        except Exception as e:
            self._logf(f'[!] {e}','err')
        finally:
            if hasattr(self, '_control_sock') and self._control_sock:
                try: self._control_sock.close()
                except: pass
            try:
                os.unlink(sock_path)
            except: pass
        self._done()

    def _start_control_socket(self, path):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(path)
        s.listen(1)
        s.settimeout(1.0)
        return s

    def _send_control(self, command):
        if not hasattr(self, '_control_sock') or not self._control_sock:
            return
        try:
            self._control_sock.settimeout(0.5)
            conn, _ = self._control_sock.accept()
            try:
                conn.sendall((json.dumps({'command': command}) + '\n').encode())
            finally:
                conn.close()
        except (socket.timeout, OSError):
            pass

    def _fb(self,target):
        self._logf('[!] Go binary not found \u2014 Python engine','warn')
        try:
            from core import scan_ports
            for r in scan_ports(target,ports=self.pcl.get()):
                self._pr(json.dumps(r))
        except Exception as e: self._logf(f'[!] {e}','err')
        self._done()

    def _parse_script_entry(self,s):
        s=s.strip()
        m=re.match(r'\[LUA-(\w+)\]\s*(.*)',s)
        if m:
            sev=m.group(1).lower()
            if sev not in('vuln','high','warn','info','ok'): sev='info'
            text=m.group(2).strip() or s
            return 'lua',sev,text
        m=re.match(r'\[([^\]]+)\]\s*(.*)',s)
        if m:
            return m.group(1).strip(),'info',(m.group(2).strip()or s)
        return 'script','info',s

    def _pr(self,raw):
        self.sc+=1; self.rc+=1
        try:
            d=json.loads(raw)
            p=d.get('port','?'); st=d.get('status',d.get('state','?')).upper()
            svc=d.get('service',''); ver=d.get('version','')
            ban=(d.get('banner','')or'')[:80]
            if st=='OPEN': self._logf(f'  {p}/{st}  {svc} {ver}')
            self.q.put(('result',(p,st,svc,ver,ban)))
            for sc in d.get('scripts',[]):
                self.q.put(('nse_script',(p,svc,sc)))
        except: pass

    def _pn(self,raw):
        try:
            d=json.loads(raw)
            s=d.get('script',d.get('id','?')); p=d.get('port','?')
            sv=d.get('service',''); o=d.get('output',d.get('result',''))
            svc=d.get('severity','info')
            self._logf(f'  \u25c8 NSE [{s}] port {p}: {o[:80]}','nse')
            self._add_nse(s,p,sv,o,svc)
        except:
            self._logf(f'  \u25c8 NSE: {raw[:120]}','nse')
            self._add_nse('?','?','',raw[:120],'info')

    def _ps(self,raw):
        try:
            d=json.loads(raw)
            self._prog(d.get('progress',0))
            if d.get('message'): self._st(d['message'])
        except: pass

    def _stop(self):
        self._send_control('stop')
        if self.proc: self.proc.terminate()
        self.running=0; self._logf('[!] Stopped by user','warn'); self._done()

    def _done(self):
        self.running=0
        self.sb.children['!button'].config(state='normal',text='\u25b6  START SCAN')
        self.sb.configure(highlightbackground=C.GREEN)
        self.stb.children['!button'].config(state='disabled')
        self._prog(100)
        c=len(self._vpl.items); nc=len(self.nt.get_children())
        tgt=self.tv.get().strip()
        el=time.time()-(self.start or time.time())
        rate=int(self.sc/el)if el>0 else 0
        self._st(f'Done \u2014 {c} ports, {nc} NSE')
        self.iv.set(f'{tgt}  |  {el:.1f}s  |  {rate} p/s')
        self.stv.set('\u2713 Complete'); self.spv.set(f'{rate} p/s')
        mins,secs=divmod(int(el),60)
        self.elv.set(f'{mins}:{secs:02d}')
        self._scan_indicator.config(text='\u2713 ')
        self._logf(f'[+] Done \u2014 {c} ports, {nc} NSE in {el:.1f}s ({rate} p/s)','ok')
        if c==0 and nc==0: self._toast('Nothing found',C.ORANGE)
        else:
            parts=[]
            if c: parts.append(f'{c} port{"s"if c!=1 else""}')
            if nc: parts.append(f'{nc} NSE result{"s"if nc!=1 else""}')
            self._toast(' + '.join(parts)+' found',C.GREEN)

    # ── Export ─────────────────────────────────────────────────────
    def _exp(self):
        if not self._vpl.items: return
        p=filedialog.asksaveasfilename(defaultextension='.json',filetypes=[('JSON','*.json')])
        if not p: return
        keys=['port','state','service','version','banner']
        data=[dict(zip(keys,item[:5]))for item in self._vpl.items]
        with open(p,'w')as f: json.dump(data,f,indent=2)
        self._logf(f'[+] Exported {len(data)} results \u2192 {Path(p).name}','ok')

    # ── Lifecycle ──────────────────────────────────────────────────
    def _close(self):
        if self.proc:
            try: self.proc.terminate(); self.proc.wait(2)
            except: pass
        for k,i in self._after_ids:
            try: self.root.after_cancel(i)
            except: pass
        self._after_ids.clear()
        signal.signal(signal.SIGINT,signal.SIG_DFL)
        signal.signal(signal.SIGTERM,signal.SIG_DFL)
        signal.signal(signal.SIGTSTP,signal.SIG_DFL)
        try: self.root.destroy()
        except: pass

    def _suspend(self,sig,frame):
        if self.proc: self.proc.terminate()
        if self.running: self._done()
        signal.signal(signal.SIGINT,signal.SIG_DFL)
        signal.signal(signal.SIGTSTP,signal.SIG_DFL)
        os.kill(os.getpid(),signal.SIGSTOP)

    def run(self):
        signal.signal(signal.SIGINT,lambda s,f:self.root.after(0,self._close))
        signal.signal(signal.SIGTERM,lambda s,f:self.root.after(0,self._close))
        signal.signal(signal.SIGTSTP,self._suspend)
        try: self.root.mainloop()
        except KeyboardInterrupt: self._close()

def main(): GUI().run()
if __name__=='__main__': main()
