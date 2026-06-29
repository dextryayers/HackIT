import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(BASE_DIR, 'bin')
GO_DIR = os.path.join(BASE_DIR, 'go')
GO_BIN_DIR = os.path.join(GO_DIR, 'bin')
RUST_DIR = os.path.join(GO_DIR, 'rustsrc', 'target', 'release')

_cache = {}
_last_mtime = 0

_KNOWN_MAP = {
    # Go
    'port_scanner':      ('go',   'Main Go orchestrator'),
    'dns_resolver':      ('go',   'DNS resolver helper'),
    'geo_enricher':      ('go',   'GeoIP enrichment helper'),
    'output_formatter':  ('go',   'Multi-format output formatter'),
    # Rust
    'hyper_scan':        ('rust', 'Mass TCP scanner'),
    'rust_syn_scanner':  ('rust', 'SYN scanner'),
    'rust_tcp_scanner':  ('rust', 'TCP scanner'),
    'rust_udp_scanner':  ('rust', 'UDP scanner'),
    'rust_service_detect': ('rust', 'Service detection'),
    'rust_os_fingerprint': ('rust', 'OS fingerprinting'),
    'rust_dns_enum':     ('rust', 'DNS enumeration'),
    'rust_vuln_scan':    ('rust', 'Vulnerability scanning'),
    'rust_mass_scan':    ('rust', 'Mass parallel scanner'),
    'os_detect':         ('rust', 'OS detection'),
    'dns_detect':        ('rust', 'DNS enumeration'),
    'web_fingerprint':   ('rust', 'Web fingerprinting'),
    'kernel_detect':     ('rust', 'Kernel detection'),
    # C original
    'syn_scanner':       ('c',    'Raw SYN scanner'),
    'c_syn_scanner':     ('c',    'SYN scan (C)'),
    'c_syn_scanner_v2':  ('c',    'SYN scanner v2 (C)'),
    'c_scanner':         ('c',    'Base scanner (C)'),
    'mass_tcp_scanner':  ('c',    'Mass TCP scanner'),
    'c_mass_tcp_scanner':('c',    'Mass TCP scanner (C)'),
    'udp_scanner':       ('c',    'UDP scanner'),
    'c_udp_scanner':     ('c',    'UDP scanner (C)'),
    'tcp_prober':        ('c',    'TCP prober'),
    'c_tcp_prober':      ('c',    'TCP prober (C)'),
    'udp_prober':        ('c',    'UDP prober (C)'),
    'os_fingerprint':    ('c',    'OS fingerprint'),
    'c_os_fingerprint':  ('c',    'OS fingerprint (C)'),
    'c_os_fingerprint_v2':('c',   'OS fingerprint v2 (C)'),
    'advanced_scanner':  ('c',    'Advanced scanner (C)'),
    'c_advanced_scanner':('c',    'Advanced scanner (C)'),
    'c_evasion':         ('c',    'Stealth evasion engine'),
    'c_epoll_scanner':   ('c',    'Epoll-based scanner'),
    'c_icmp_discovery':  ('c',    'ICMP host discovery'),
    'c_network_path':    ('c',    'Network path tracer'),
    'c_packet_crafter':  ('c',    'Packet crafter'),
    # C new
    'c_full_system_scanner':   ('c', 'Full system scanner'),
    'c_deep_packet_analysis':  ('c', 'Deep packet analysis'),
    'c_service_exploiter':     ('c', 'Service exploitation'),
    'c_network_topology':      ('c', 'Network topology mapper'),
    'c_credential_harvester':  ('c', 'Credential harvester'),
    'c_performance_bench':     ('c', 'Performance benchmark'),
    'c_ssl_deep_scan':         ('c', 'SSL deep scan'),
    'c_web_app_fingerprint':   ('c', 'Web app fingerprint'),
    'c_database_scanner':      ('c', 'Database scanner'),
    'c_iot_scanner':           ('c', 'IoT device scanner'),
    # C++ original
    'tls_scanner':       ('cpp',  'TLS scanner'),
    'tls_analyzer_v2':   ('cpp',  'TLS analyzer v2'),
    'vuln_matcher':      ('cpp',  'Vulnerability matcher'),
    'vuln_matcher_v2':   ('cpp',  'Vulnerability matcher v2'),
    'deep_analyzer':     ('cpp',  'Deep analyzer'),
    'cpp_os_detect':     ('cpp',  'OS detection (C++)'),
    'cpp_deep_analyzer': ('cpp',  'Deep analyzer (C++)'),
    'cpp_vuln_matcher':  ('cpp',  'Vulnerability matcher (C++)'),
    'cpp_vuln_matcher_v2':('cpp', 'Vuln matcher v2 (C++)'),
    'cpp_advanced_scanner':('cpp','Advanced scanner (C++)'),
    'cpp_service_scanner':('cpp', 'Service scanner (C++)'),
    'cpp_results_correlator':('cpp','Results correlator (C++)'),
    'response_parser':   ('cpp',  'Response parser'),
    'results_correlator':('cpp',  'Results correlator'),
    'service_scanner':   ('cpp',  'Service scanner'),
    # C++ new
    'cpp_ai_pattern_analyzer':    ('cpp', 'AI pattern analyzer'),
    'cpp_anomaly_detector':       ('cpp', 'Anomaly detector'),
    'cpp_correlation_engine':     ('cpp', 'Correlation engine'),
    'cpp_report_generator':       ('cpp', 'Report generator'),
    'cpp_risk_calculator':        ('cpp', 'Risk calculator'),
    'cpp_service_classifier':     ('cpp', 'Service classifier'),
    'cpp_stack_fingerprinter':    ('cpp', 'Stack fingerprinter'),
    # Legacy binaries from earlier builds
    'scanner':           ('c',    'Base scanner (legacy)'),
    'syn_scanner_v2':    ('c',    'SYN scanner v2 (legacy)'),
    'epoll_scanner':     ('c',    'Epoll scanner (legacy)'),
    'os_fingerprint_v2': ('c',    'OS fingerprint v2 (legacy)'),
    'banner_grabber':    ('c',    'Banner grabber (legacy)'),
    'service_prober':    ('c',    'Service prober (legacy)'),
    'icmp_discovery':    ('c',    'ICMP discovery (legacy)'),
    'tls_prober':        ('c',    'TLS prober (legacy)'),
    'packet_crafter':    ('c',    'Packet crafter (legacy)'),
    'network_path':      ('c',    'Network path (legacy)'),
    'stealth_evasion':   ('c',    'Stealth evasion (legacy)'),
    'network_oracle':    ('c',    'Network oracle (legacy)'),
}

_NEEDS_ROOT = {
    'syn_scanner', 'rust_syn_scanner', 'c_evasion',
    'os_fingerprint', 'os_detect',
}


_MAIN_BINS = {
    'port_scanner':      ('go',   'Main Go orchestrator'),
    'hyper_scan':        ('rust', 'Mass TCP scanner (Rust)'),
    'os_detect':         ('rust', 'OS detection (Rust)'),
    'mass_tcp_scanner':  ('c',    'Mass TCP scanner (C)'),
    'tls_scanner':       ('cpp',  'TLS scanner (C++)'),
}

_BIN_LOCATIONS = {
    'port_scanner':     None,
    'hyper_scan':       None,
    'os_detect':        None,
    'mass_tcp_scanner': None,
    'tls_scanner':      None,
}


def _locate_bins():
    dirs_to_check = [BIN_DIR, GO_BIN_DIR, RUST_DIR]
    for name in _BIN_LOCATIONS:
        _BIN_LOCATIONS[name] = None
        for d in dirs_to_check:
            if not d:
                continue
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                _BIN_LOCATIONS[name] = p
                break


def _check_version(bin_path):
    if not bin_path:
        return 'unknown'
    for flag in ('--version', '-version', '-v', '--help'):
        try:
            r = subprocess.run([bin_path, flag], capture_output=True, text=True, timeout=1)
            if r.returncode == 0:
                v = (r.stdout.strip() or r.stderr.strip())[:80]
                if v and 'RESULT:' not in v and 'Usage:' not in v and 'flag provided' not in v:
                    return v
        except:
            pass
    return 'unknown'


def discover_engines(force=False):
    global _last_mtime
    if not force and os.path.isdir(BIN_DIR):
        current_mtime = os.path.getmtime(BIN_DIR)
        if _cache and current_mtime == _last_mtime:
            return dict(_cache)
    elif not force and _cache:
        return dict(_cache)

    _locate_bins()

    result = {}
    versions = {}

    with ThreadPoolExecutor(max_workers=8) as ex:
        fut_map = {}
        for name, bin_path in _BIN_LOCATIONS.items():
            if bin_path:
                fut = ex.submit(_check_version, bin_path)
                fut_map[fut] = name
        for fut in as_completed(fut_map):
            versions[fut_map[fut]] = fut.result()

    for name, bin_path in _BIN_LOCATIONS.items():
        info = _MAIN_BINS.get(name)
        if info and bin_path:
            lang, desc = info
            result[name] = {
                'name': name,
                'binary': bin_path,
                'language': lang,
                'description': desc,
                'version': versions.get(name, 'unknown'),
                'available': True,
                'needs_root': name in _NEEDS_ROOT,
            }

    if os.path.isdir(BIN_DIR):
        for name in sorted(os.listdir(BIN_DIR)):
            bin_path = os.path.join(BIN_DIR, name)
            if not (os.path.isfile(bin_path) and os.access(bin_path, os.X_OK)):
                continue
            if name.endswith(('.so', '.dll', '.dylib')):
                continue
            if name in result:
                continue
            lang, desc = _KNOWN_MAP.get(name, ('unknown', f'Binary ({name})'))
            result[name] = {
                'name': name,
                'binary': bin_path,
                'language': lang,
                'description': desc,
                'version': 'unknown',
                'available': True,
                'needs_root': name in _NEEDS_ROOT,
            }

    _cache.clear()
    _cache.update(result)
    if os.path.isdir(BIN_DIR):
        _last_mtime = os.path.getmtime(BIN_DIR)
    return result


def get_available_engines():
    engines = discover_engines()
    by_lang = {'rust': [], 'c': [], 'cpp': [], 'go': [], 'unknown': []}
    for name, info in engines.items():
        by_lang.setdefault(info['language'], []).append(info)
    return by_lang


def needs_compilation(name):
    if name == 'go':
        go_dir = os.path.join(BASE_DIR, 'go')
        bin_path = os.path.join(go_dir, 'port_scanner')
        if not os.path.isdir(go_dir):
            return True
        src_files = []
        for root, dirs, files in os.walk(go_dir):
            for f in files:
                if f.endswith('.go'):
                    src_files.append(os.path.join(root, f))
        if not src_files:
            return True
        if not os.path.exists(bin_path):
            return True
        bin_mtime = os.path.getmtime(bin_path)
        return any(os.path.getmtime(s) > bin_mtime for s in src_files)

    if name in ('rust',):
        rust_dir = os.path.join(BASE_DIR, 'go', 'rust_engine')
        return not os.path.isdir(rust_dir)

    if name in ('c',):
        c_dir = os.path.join(BASE_DIR, 'c')
        return not os.path.isdir(c_dir)

    if name in ('cpp',):
        cpp_dir = os.path.join(BASE_DIR, 'cpp')
        return not os.path.isdir(cpp_dir)

    return True
