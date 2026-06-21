import queue
import sys
import threading
import time

from hackit.ui import _colored, GREEN, YELLOW, RED, CYAN, PURPLE, B_GREEN, B_CYAN, B_WHITE, B_RED, DIM

_ANSI_HOME = '\x1b[H'
_ANSI_HIDE = '\x1b[?25l'
_ANSI_SHOW = '\x1b[?25h'


def _term_width():
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except:
        return 80


class Dashboard:
    def __init__(self):
        self._queue = queue.Queue()
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

        self.engines = {}
        self.services = []
        self.os_info = {'name': 'Detecting...', 'confidence': 0}
        self.vulnerabilities = []
        self.open_count = 0
        self.total_scanned = 0
        self.start_time = None
        self.target = ''
        self.status_line = 'Initializing...'

    def start(self, target=''):
        self._running = True
        self.start_time = time.time()
        self.target = target
        sys.stdout.write(_ANSI_HIDE)
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()

    def _render_loop(self):
        while self._running:
            self._drain_queue()
            self._render()
            time.sleep(0.2)

    def _drain_queue(self):
        while True:
            try:
                item = self._queue.get_nowait()
                self._process_item(item)
            except queue.Empty:
                break

    def _process_item(self, item):
        msg_type = item.get('type', '')
        data = item.get('data', {})

        if msg_type == 'engine_status':
            name = data.get('engine', 'unknown')
            if name not in self.engines:
                self.engines[name] = {
                    'status': 'running',
                    'ports_scanned': 0,
                    'open_found': 0,
                    'progress': 0,
                    'last_update': time.time(),
                }
            self.engines[name].update({
                'status': data.get('status', self.engines[name]['status']),
                'ports_scanned': data.get('ports_scanned', self.engines[name]['ports_scanned']),
                'open_found': data.get('open_found', self.engines[name]['open_found']),
                'progress': data.get('progress', self.engines[name]['progress']),
                'last_update': time.time(),
            })

        elif msg_type == 'result':
            port = data.get('port', 0)
            status = data.get('status', '')
            if status == 'open' and port > 0:
                self.open_count += 1
                self.services.append({
                    'port': port,
                    'service': data.get('service', 'unknown'),
                    'banner': data.get('banner', ''),
                    'time': time.time(),
                })
            self.total_scanned += 1

        elif msg_type == 'os':
            self.os_info.update(data)

        elif msg_type == 'vuln':
            if data not in self.vulnerabilities:
                self.vulnerabilities.append(data)

        elif msg_type == 'status':
            self.status_line = data.get('message', '')

    def update(self, msg_type, data):
        self._queue.put({'type': msg_type, 'data': data})

    def _render(self):
        tw = min(_term_width(), 100)
        elapsed = time.time() - (self.start_time or time.time())

        lines = []
        lines.append(_ANSI_HOME)
        lines.append('')
        lines.append('  ' + _colored('\u2554' + '\u2550' * (tw - 2) + '\u2557', B_CYAN))
        title = (' LIVE DASHBOARD \u2014 ' + self.target + ' ').center(tw - 4)
        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' + _colored(title, B_WHITE, bold=True) + '  ' + _colored('\u2551', B_CYAN))
        elapsed_str = 'Elapsed: {:.0f}s  Open: {}  Scanned: {}'.format(elapsed, self.open_count, self.total_scanned)
        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' + _colored(elapsed_str.ljust(tw - 4), DIM) + ' ' + _colored('\u2551', B_CYAN))
        lines.append('  ' + _colored('\u2560' + '\u2550' * (tw - 2) + '\u2563', B_CYAN))

        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' + _colored(' ENGINES', B_WHITE) + ' ' * (tw - 12) + _colored('\u2551', B_CYAN))
        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' * (tw - 4) + _colored('\u2551', B_CYAN))

        if self.engines:
            for name, info in self.engines.items():
                sc = {
                    'running': B_GREEN,
                    'done': CYAN,
                    'error': B_RED,
                    'pending': YELLOW,
                }.get(info['status'], YELLOW)
                ch = {'running': '\u25b6', 'done': '\u2713', 'error': '\u2717', 'pending': '?'}.get(info['status'], '?')
                bar_width = max(tw - 62, 10)
                pct = min(info['progress'], 100)
                filled = int(bar_width * pct / 100)
                bar = '\u2588' * filled + '\u2591' * (bar_width - filled)
                line = (
                    '  ' + _colored('\u2551', B_CYAN)
                    + '  ' + _colored(ch, sc)
                    + ' ' + _colored(name.ljust(10), B_WHITE)
                    + ' ' + _colored(bar, CYAN)
                    + ' ' + _colored('{:>3}%'.format(pct), B_YELLOW)
                    + '  ' + _colored('S:{}'.format(info['ports_scanned']), DIM)
                    + ' ' + _colored('O:{}'.format(info['open_found']), B_GREEN)
                    + '  ' + _colored('\u2551', B_CYAN)
                )
                lines.append(line)
        else:
            lines.append('  ' + _colored('\u2551', B_CYAN) + '  ' + _colored('(awaiting engines...)'.ljust(tw - 7), DIM) + ' ' + _colored('\u2551', B_CYAN))

        status_text = ('  Status: ' + self.status_line) if self.status_line else ''
        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' + _colored(status_text.ljust(tw - 4), DIM) + ' ' + _colored('\u2551', B_CYAN))
        lines.append('  ' + _colored('\u2560' + '\u2550' * (tw - 2) + '\u2563', B_CYAN))

        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' + _colored(' SERVICE DISCOVERY', B_WHITE) + ' ' * (tw - 20) + _colored('\u2551', B_CYAN))
        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' * (tw - 4) + _colored('\u2551', B_CYAN))

        display_services = self.services[-12:]
        for svc in display_services:
            p = _colored(str(svc['port']).ljust(5), B_WHITE, bold=True)
            s = _colored(svc['service'][:16].ljust(16), CYAN)
            raw_b = str(svc.get('banner', ''))[:tw - 58]
            b = _colored(raw_b.ljust(tw - 58), DIM)
            lines.append('  ' + _colored('\u2551', B_CYAN) + '   ' + p + ' ' + _colored('OPEN', B_GREEN) + ' ' + s + ' ' + b + ' ' + _colored('\u2551', B_CYAN))

        if not display_services:
            lines.append('  ' + _colored('\u2551', B_CYAN) + '  ' + _colored('(no services detected yet...)'.ljust(tw - 7), DIM) + ' ' + _colored('\u2551', B_CYAN))

        lines.append('  ' + _colored('\u2560' + '\u2550' * (tw - 2) + '\u2563', B_CYAN))

        os_name = self.os_info.get('name', 'Unknown')
        os_conf = self.os_info.get('confidence', self.os_info.get('accuracy', 0))
        if os_conf < 1.0:
            os_conf = int(os_conf * 100)
        os_line = '  OS: {} (confidence: {}%)'.format(os_name, os_conf)
        lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' + _colored(' OS DETECTION', B_WHITE) + ' ' * (tw - 15) + _colored('\u2551', B_CYAN))
        lines.append('  ' + _colored('\u2551', B_CYAN) + '  ' + _colored(os_line.ljust(tw - 6), B_GREEN) + ' ' + _colored('\u2551', B_CYAN))

        if self.vulnerabilities:
            lines.append('  ' + _colored('\u2560' + '\u2550' * (tw - 2) + '\u2563', B_CYAN))
            lines.append('  ' + _colored('\u2551', B_CYAN) + ' ' + _colored(' VULNERABILITY ALERTS ({})'.format(len(self.vulnerabilities)), B_RED, bold=True) + ' ' * (tw - 32) + _colored('\u2551', B_CYAN))
            for vuln in self.vulnerabilities[-3:]:
                vtext = str(vuln.get('description', vuln.get('name', str(vuln))))[:tw - 10]
                lines.append('  ' + _colored('\u2551', B_CYAN) + '  ' + _colored('\u26a0', RED) + ' ' + _colored(vtext.ljust(tw - 11), YELLOW) + ' ' + _colored('\u2551', B_CYAN))

        lines.append('  ' + _colored('\u255a' + '\u2550' * (tw - 2) + '\u255d', B_CYAN))

        sys.stdout.write('\n'.join(lines))
        sys.stdout.flush()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        self._render()
        sys.stdout.write(_ANSI_SHOW)
        sys.stdout.flush()
        sys.stdout.write('\n')
