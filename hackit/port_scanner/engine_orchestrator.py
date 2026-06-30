import os
import subprocess
import json
import sys
import functools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .engine_profiles import get_profile
from .engine_discovery import discover_engines, get_available_engines
from .go_bridge import get_engine


@functools.lru_cache(maxsize=1)
def _cached_discover_engines():
    return discover_engines()

@functools.lru_cache(maxsize=1)
def _cached_available_engines():
    return get_available_engines()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(BASE_DIR, 'bin')
GO_DIR = os.path.join(BASE_DIR, 'go')
GO_BIN_DIR = os.path.join(GO_DIR, 'bin')
RUST_DIR = os.path.join(GO_DIR, 'rustsrc', 'target', 'release')
_EXTRA_BIN_DIRS = [BIN_DIR, GO_BIN_DIR, RUST_DIR]


def _find_binary(name):
    for d in _EXTRA_BIN_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _run_binary(bin_path, args, timeout=120):
    results = []
    final = {}
    try:
        r = subprocess.run(
            [bin_path] + args,
            capture_output=True, text=True, timeout=timeout
        )
        for line in r.stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('RESULT:'):
                try:
                    results.append(json.loads(line[7:]))
                except:
                    pass
            elif line.startswith('FINAL:'):
                try:
                    final = json.loads(line[6:])
                except:
                    pass
        if not final and results:
            final = {'count': len(results)}
        return results, final, r.stderr.strip()
    except subprocess.TimeoutExpired:
        return results, {'error': 'timeout'}, ''
    except Exception as e:
        return results, {'error': str(e)}, ''


_ENGINE_PRIORITY = {'go': 0, 'rust': 1, 'c': 2, 'cpp': 3}

def _merge_results(results_list):
    """Merge multi-engine results with consensus voting for port status."""
    merged = {}
    for rlist in results_list:
        if not isinstance(rlist, list):
            continue
        for r in rlist:
            if not isinstance(r, dict):
                continue
            port = r.get('port', 0)
            if port == 0:
                continue
            eng = r.get('engine', 'unknown')
            if port not in merged:
                r.setdefault('engines', [eng])
                r.setdefault('status_votes', {'open': 0, 'closed': 0, 'filtered': 0})
                r['status_votes'][r.get('status', 'filtered')] += 1
                merged[port] = r
            else:
                ex = merged[port]
                if 'status_votes' not in ex:
                    ex['status_votes'] = {'open': 0, 'closed': 0, 'filtered': 0}
                ex['status_votes'][r.get('status', 'filtered')] += 1

                eng_list = ex.setdefault('engines', [])
                if eng not in eng_list:
                    eng_list.append(eng)

                for k in ('service', 'version', 'banner', 'service_probe'):
                    if r.get(k) and not ex.get(k):
                        ex[k] = r[k]
                    elif r.get(k) and ex.get(k) and r[k] != ex[k]:
                        if len(r[k]) > len(ex.get(k, '')):
                            ex[k] = r[k]

    result = sorted(merged.values(), key=lambda x: x.get('port', 0))

    # ── Consensus voting: determine final status per port ──
    for r in result:
        votes = r.pop('status_votes', {'open': 0, 'closed': 0, 'filtered': 0})
        total = sum(votes.values())
        if total == 0:
            continue

        open_votes = votes.get('open', 0)
        closed_votes = votes.get('closed', 0)
        filtered_votes = votes.get('filtered', 0)

        # Consensus: at least 2 engines agree, or majority
        if open_votes > closed_votes and open_votes > filtered_votes:
            r['status'] = 'open'
        elif closed_votes > open_votes and closed_votes > filtered_votes:
            r['status'] = 'closed'
        elif filtered_votes > open_votes and filtered_votes > closed_votes:
            r['status'] = 'filtered'
        else:
            # Tie-breaker: prefer open > closed > filtered
            if open_votes > 0:
                r['status'] = 'open'
            elif closed_votes > 0:
                r['status'] = 'closed'
            else:
                r['status'] = 'filtered'

        r.pop('_engine_priority', None)

    return result


def _run_stage_discovery(target, ports, profile):
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '2', target],
            capture_output=True, text=True, timeout=5
        )
        return [{'host': target, 'alive': r.returncode == 0, 'stage': 'discovery'}]
    except:
        return [{'host': target, 'alive': True, 'stage': 'discovery'}]


def _run_stage_tcp_scan(target, ports, profile, engine_name='go'):
    if engine_name == 'go':
        go_engine = get_engine()
        if go_engine.ensure_compiled():
            r = go_engine.run(
                target,
                ports=ports,
                timeout=profile.timeout_ms,
                threads=profile.workers,
                include_closed=True,
                stealth=profile.stealth,
                mode=profile.scan_mode,
            )
            if isinstance(r, dict):
                flat = []
                host_entries = r.get('results', r.get('ports', []))
                if isinstance(host_entries, list):
                    for entry in host_entries:
                        if not isinstance(entry, dict):
                            continue
                        port_entries = entry.get('results', entry.get('ports', []))
                        if isinstance(port_entries, list):
                            for p in port_entries:
                                if isinstance(p, dict):
                                    p.setdefault('engine', 'go')
                                    flat.append(p)
                if flat:
                    return flat
                if host_entries and isinstance(host_entries, list):
                    for item in host_entries:
                        if isinstance(item, dict):
                            item.setdefault('engine', 'go')
                    return host_entries
                return [r] if r.get('port', 0) > 0 else []
            if isinstance(r, list):
                for item in r:
                    if isinstance(item, dict):
                        item.setdefault('engine', 'go')
                return r
            return []

    if engine_name == 'rust':
        bin_path = _find_binary('hyper_scan')
        if bin_path:
            port_str = str(ports) if ports else 'top100'
            timeout_ms = min(profile.timeout_ms, 10000)
            workers = min(profile.workers, 500)
            args = [target, port_str, str(timeout_ms), f'concurrency:{workers}', 'json']
            results, final, err = _run_binary(bin_path, args, timeout=profile.host_timeout)
            for item in results:
                if isinstance(item, dict):
                    item.setdefault('engine', 'rust')
            return results

    if engine_name == 'c':
        bin_path = _find_binary('c_scanner')
        if bin_path:
            port_str = str(ports) if ports else 'top100'
            args = [target, port_str, str(min(profile.timeout_ms, 10000)), str(profile.workers)]
            try:
                r = subprocess.run([bin_path] + args, capture_output=True, text=True, timeout=max(profile.timeout_ms//1000, 5))
                results = []
                for line in r.stdout.strip().split('\n'):
                    line = line.strip()
                    if line.startswith('[SCAN] '):
                        try:
                            parts = dict(kv.split('=') for kv in line[7:].split(' ') if '=' in kv)
                            p = int(parts.get('PORT', 0))
                            st = parts.get('STATE', 'unknown').lower()
                            svc = parts.get('SERVICE', parts.get('PRODUCT', ''))
                            ver = parts.get('VERSION', '')
                            ban = parts.get('BANNER', '').strip('"')
                            if p > 0:
                                results.append({'port': p, 'status': st, 'service': svc, 'version': ver, 'banner': ban, 'engine': 'c'})
                        except:
                            pass
                return results if results else None
            except:
                return None

    if engine_name == 'cpp':
        bin_path = _find_binary('tls_scanner')
        if bin_path:
            args = [target]
            if ports:
                args.extend(['--ports', str(ports)])
            results, final, err = _run_binary(bin_path, args, timeout=profile.host_timeout)
            for item in results:
                if isinstance(item, dict):
                    item.setdefault('engine', 'cpp')
            return results

    from . import fast_port_scan
    pr = ports or '1-1024'
    try:
        return fast_port_scan(target, pr, workers=profile.workers, timeout=max(profile.timeout_ms / 1000, 0.5))
    except:
        return []


def _run_stage_service_detect(target, ports, results):
    enriched = []
    for r in (results or []):
        if isinstance(r, dict) and r.get('status') == 'open':
            port = r.get('port', 0)
            svc_bin = _find_binary('web_fingerprint')
            if svc_bin:
                sresults, sfinal, serr = _run_binary(svc_bin, [target, str(port)], timeout=15)
                for s in sresults:
                    if isinstance(s, dict):
                        for k in ('service', 'banner', 'version'):
                            if s.get(k):
                                r[k] = s.get(k)
        enriched.append(r)
    return enriched


SERVICE_TO_OS = [
    # OpenSSH version → specific OS distribution
    (('ssh', 'openssh'), (1, 3),   'OpenBSD'),
    (('ssh', 'openssh'), (2, 1),   'OpenBSD'),
    (('ssh', 'openssh'), (3, 0),   'OpenBSD'),
    (('ssh', 'openssh'), (3, 8),   'Linux (generic)'),
    (('ssh', 'openssh'), (4, 0),   'Linux (generic)'),
    (('ssh', 'openssh'), (4, 3),   'Linux (generic)'),
    (('ssh', 'openssh'), (4, 7),   'Linux (generic)'),
    (('ssh', 'openssh'), (5, 3),   'Ubuntu 12.04'),
    (('ssh', 'openssh'), (5, 5),   'Ubuntu 12.04'),
    (('ssh', 'openssh'), (5, 8),   'Debian 7'),
    (('ssh', 'openssh'), (5, 9),   'Debian 7'),
    (('ssh', 'openssh'), (6, 0),   'Ubuntu 13.04'),
    (('ssh', 'openssh'), (6, 6),   'Ubuntu 14.04'),
    (('ssh', 'openssh'), (6, 7),   'Debian 8'),
    (('ssh', 'openssh'), (6, 9),   'Ubuntu 16.04'),
    (('ssh', 'openssh'), (7, 2),   'Ubuntu 16.04'),
    (('ssh', 'openssh'), (7, 4),   'Ubuntu 17.04'),
    (('ssh', 'openssh'), (7, 5),   'Debian 10'),
    (('ssh', 'openssh'), (7, 6),   'Ubuntu 18.04'),
    (('ssh', 'openssh'), (7, 9),   'Ubuntu 20.04'),
    (('ssh', 'openssh'), (8, 1),   'Debian 11'),
    (('ssh', 'openssh'), (8, 2),   'Ubuntu 20.04'),
    (('ssh', 'openssh'), (8, 5),   'Fedora'),
    (('ssh', 'openssh'), (8, 7),   'Debian 12'),
    (('ssh', 'openssh'), (8, 8),   'Ubuntu 22.04'),
    (('ssh', 'openssh'), (9, 1),   'Ubuntu 23.04'),
    (('ssh', 'openssh'), (9, 3),   'Ubuntu 24.04'),
    # Apache → specific distro
    (('http', 'apache', 'apache httpd'), (2, 4, 7), 'Ubuntu 14.04'),
    (('http', 'apache', 'apache httpd'), (2, 4, 10), 'Debian 8'),
    (('http', 'apache', 'apache httpd'), (2, 4, 18), 'Ubuntu 16.04'),
    (('http', 'apache', 'apache httpd'), (2, 4, 25), 'Debian 9'),
    (('http', 'apache', 'apache httpd'), (2, 4, 29), 'Ubuntu 18.04'),
    (('http', 'apache', 'apache httpd'), (2, 4, 37), 'Debian 10'),
    (('http', 'apache', 'apache httpd'), (2, 4, 41), 'Ubuntu 20.04'),
    (('http', 'apache', 'apache httpd'), (2, 4, 48), 'Debian 11'),
    (('http', 'apache', 'apache httpd'), (2, 4, 52), 'Ubuntu 22.04'),
    (('http', 'apache', 'apache httpd'), (2, 4, 54), 'Debian 12'),
    (('http', 'apache', 'apache httpd'), (2, 4, 57), 'Ubuntu 24.04'),
    # Nginx → specific distro
    (('http', 'nginx'), (1, 10), 'Ubuntu 16.04'),
    (('http', 'nginx'), (1, 14), 'Ubuntu 18.04'),
    (('http', 'nginx'), (1, 15), 'Debian 10'),
    (('http', 'nginx'), (1, 18), 'Ubuntu 20.04'),
    (('http', 'nginx'), (1, 20), 'Debian 11'),
    (('http', 'nginx'), (1, 22), 'Ubuntu 22.04'),
    (('http', 'nginx'), (1, 25), 'Ubuntu 24.04'),
    # LiteSpeed → web hosting specific
    (('http', 'litespeed'), None, 'CloudLinux (cPanel)'),
    # Lighttpd → Linux
    (('http', 'lighttpd'), None, 'Linux (generic)'),
    # Caddy → Linux
    (('http', 'caddy'), None, 'Linux (generic)'),
    # Pure-FTPd → Linux
    (('ftp', 'pure-ftpd'), None, 'Linux (generic)'),
    (('ftp', 'vsftpd'), (3, 0), 'Ubuntu'),
    (('ftp', 'vsftpd'), (2, 0), 'Linux (generic)'),
    (('ftp', 'proftpd'), None, 'Linux/Unix'),
    # Dovecot → Linux (typically part of mail server stack)
    (('imap', 'dovecot'), None, 'Linux (generic)'),
    (('pop3', 'dovecot'), None, 'Linux (generic)'),
    (('imap', 'courier'), None, 'Linux (generic)'),
    # MySQL/MariaDB with version-specific distro detection
    # "cll" suffix → CloudLinux LVE hosting
    (('mysql', 'mariadb'), None, 'Linux (generic)'),
    # PostgreSQL → Linux
    (('postgresql',), (9,), 'Linux (generic)'),
    (('postgresql',), (10,), 'Linux (generic)'),
    (('postgresql',), (11,), 'Linux (generic)'),
    (('postgresql',), (12,), 'Linux (generic)'),
    (('postgresql',), (13,), 'Linux (generic)'),
    (('postgresql',), (14,), 'Linux (generic)'),
    (('postgresql',), (15,), 'Linux (generic)'),
    (('postgresql',), (16,), 'Linux (generic)'),
    # Redis → Linux
    (('redis',), None, 'Linux (generic)'),
    # MongoDB → Linux
    (('mongodb',), None, 'Linux (generic)'),
    # IIS → Windows Server specific
    (('http', 'iis'), (7, 0), 'Windows Server 2008'),
    (('http', 'iis'), (7, 5), 'Windows Server 2008 R2'),
    (('http', 'iis'), (8, 0), 'Windows Server 2012'),
    (('http', 'iis'), (8, 5), 'Windows Server 2012 R2'),
    (('http', 'iis'), (10, 0), 'Windows Server 2016/2019/2022'),
    # SMTP → specific
    (('smtp', 'postfix'), None, 'Linux (generic)'),
    (('smtp', 'sendmail'), None, 'Linux/Unix'),
    (('smtp', 'exim'), None, 'Linux (generic)'),
    # RDP → Windows
    (('ms-wbt-server', 'rdp', 'terminal'), None, 'Windows Server'),
    # SMB → Windows
    (('smb', 'microsoft-ds', 'netbios'), None, 'Windows'),
]

# Keyword-to-OS mapping with specificity weighting
BANNER_OS_KEYWORDS = [
    ('cloudlinux', 'CloudLinux', 10),
    ('cloud linux', 'CloudLinux', 10),
    ('ubuntu 24', 'Ubuntu 24.04', 9),
    ('ubuntu 23', 'Ubuntu 23.04', 9),
    ('ubuntu 22', 'Ubuntu 22.04', 9),
    ('ubuntu 21', 'Ubuntu 21.04', 9),
    ('ubuntu 20', 'Ubuntu 20.04', 9),
    ('ubuntu 18', 'Ubuntu 18.04', 9),
    ('ubuntu 16', 'Ubuntu 16.04', 9),
    ('ubuntu 14', 'Ubuntu 14.04', 9),
    ('ubuntu', 'Ubuntu', 6),
    ('debian 12', 'Debian 12', 9),
    ('debian 11', 'Debian 11', 9),
    ('debian 10', 'Debian 10', 9),
    ('debian 9', 'Debian 9', 9),
    ('debian 8', 'Debian 8', 9),
    ('debian', 'Debian', 6),
    ('centos 9', 'CentOS 9', 9),
    ('centos 8', 'CentOS 8', 9),
    ('centos 7', 'CentOS 7', 9),
    ('centos', 'CentOS', 6),
    ('rhel 9', 'RHEL 9', 9),
    ('rhel 8', 'RHEL 8', 9),
    ('rhel 7', 'RHEL 7', 9),
    ('red hat', 'RHEL', 6),
    ('fedora 40', 'Fedora 40', 9),
    ('fedora 39', 'Fedora 39', 9),
    ('fedora', 'Fedora', 6),
    ('alpine', 'Alpine Linux', 7),
    ('arch linux', 'Arch Linux', 8),
    ('gentoo', 'Gentoo Linux', 8),
    ('opensuse', 'openSUSE', 7),
    ('suse', 'SUSE Linux', 6),
    ('freebsd', 'FreeBSD', 8),
    ('openbsd', 'OpenBSD', 8),
    ('netbsd', 'NetBSD', 8),
    ('windows server 2022', 'Windows Server 2022', 10),
    ('windows server 2019', 'Windows Server 2019', 10),
    ('windows server 2016', 'Windows Server 2016', 10),
    ('windows server 2012', 'Windows Server 2012', 10),
    ('windows server 2008', 'Windows Server 2008', 10),
    ('windows 11', 'Windows 11', 9),
    ('windows 10', 'Windows 10', 9),
    ('windows', 'Windows', 5),
    ('microsoft', 'Windows', 5),
    ('iis 10', 'Windows Server 2016/2019/2022', 9),
    ('iis 8', 'Windows Server 2012', 9),
    ('iis 7', 'Windows Server 2008', 9),
    ('iis', 'Windows Server', 6),
    ('cisco ios', 'Cisco IOS', 9),
    ('cisco', 'Cisco IOS', 6),
    ('mikrotik', 'MikroTik RouterOS', 8),
    ('juniper', 'Juniper Junos', 8),
    ('fortinet', 'Fortinet FortiOS', 8),
    ('macos', 'macOS', 8),
    ('darwin', 'macOS', 8),
    ('solaris', 'Solaris', 8),
    ('aix', 'AIX', 8),
    ('hp-ux', 'HP-UX', 8),
    ('hpux', 'HP-UX', 8),
    ('openwrt', 'OpenWrt', 8),
    ('dd-wrt', 'DD-WRT', 8),
    ('pfsense', 'pfSense', 8),
    ('synology', 'Synology DSM', 8),
    ('qnap', 'QNAP', 8),
    ('vmware', 'VMware ESXi', 7),
    ('esxi', 'VMware ESXi', 8),
    ('proxmox', 'Proxmox VE', 8),
    ('docker', 'Linux (Container)', 6),
    ('kubernetes', 'Linux (Kubernetes)', 6),
    ('android', 'Android', 7),
]

# Version suffix → OS detection for MySQL/MariaDB
MYSQL_VERSION_OS = [
    ('cll', 'CloudLinux'),
    ('cloudlinux', 'CloudLinux'),
    ('lve', 'CloudLinux'),
    ('cpanel', 'CloudLinux'),
    ('deb', 'Debian'),
    ('ubu', 'Ubuntu'),
    ('centos', 'CentOS'),
    ('rhel', 'RHEL'),
]

def _check_mysql_version_os(version):
    """Check MySQL/MariaDB version string for OS hints (e.g. 'cll' → CloudLinux)."""
    ver_lower = version.lower()
    for suffix, os_name in MYSQL_VERSION_OS:
        if suffix in ver_lower:
            return os_name
    return None

def _parse_version(ver_str):
    parts = []
    for p in str(ver_str).split('.'):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts)

def _match_service_to_os(service, version):
    svc_lower = service.lower()
    ver_tuple = _parse_version(version)
    for (svcs, ver_hint, os_name) in SERVICE_TO_OS:
        if not any(s in svc_lower for s in svcs):
            continue
        if ver_hint is None:
            return os_name, 'banner'
        if ver_tuple and len(ver_tuple) >= len(ver_hint):
            if all(v == h for v, h in zip(ver_tuple[:len(ver_hint)], ver_hint)):
                return os_name, 'banner'
    return None, None

FINGERPRINT_FIELDS = [
    'name', 'version', 'family', 'accuracy', 'confidence', 'fingerprint',
    'kernel', 'arch', 'ipid', 'ttl', 'window', 'mss', 'wscale',
    'df', 'timestamps', 'sack', 'device_type', 'tcp_options', 'signature', 'banner_hint',
    'os_name', 'os_version', 'os_family', 'window_size',
]

def _gather_binary_fingerprint(bin_path, target):
    """Run a binary and return ALL fingerprint fields."""
    result = {}
    bin_results, final, err = _run_binary(bin_path, [target], timeout=30)
    sources = []
    if final and isinstance(final, dict):
        sources.append(final)
    for r in (bin_results or []):
        if isinstance(r, dict):
            sources.append(r)
    for src in sources:
        for key in FINGERPRINT_FIELDS:
            if key in src:
                result[key] = src[key]
    return result

def _run_stage_os_detect(target, results=None):
    os_info = {'name': 'Unknown', 'confidence': 0, 'accuracy': 0, 'evidence': []}
    fp_evidence = []
    
    # Phase 1: Service-to-OS correlation from scan results (most accurate)
    if results:
        os_votes = {}
        for r in results:
            if isinstance(r, dict) and r.get('status') == 'open':
                svc = r.get('service', r.get('service_probe', ''))
                ver = r.get('version', '')
                banner = r.get('banner', '')
                port = r.get('port', 0)
                
                # Try version-specific MySQL detection first
                if any(k in svc.lower() for k in ('mysql', 'mariadb')):
                    mysql_os = _check_mysql_version_os(ver)
                    if mysql_os:
                        os_votes[mysql_os] = os_votes.get(mysql_os, 0) + 3
                        fp_evidence.append(f"Port {port}: MySQL {ver} → {mysql_os}")
                
                # Service-to-OS mapping
                matched_os, source = _match_service_to_os(svc, ver)
                if matched_os:
                    os_votes[matched_os] = os_votes.get(matched_os, 0) + 1
                    fp_evidence.append(f"Port {port}: {svc} {ver} → {matched_os}")
                
                # Check banner for OS distribution keywords (weighted)
                banner_lower = (banner or '').lower()
                for keyword, os_name, weight in BANNER_OS_KEYWORDS:
                    if keyword in banner_lower:
                        os_votes[os_name] = os_votes.get(os_name, 0) + weight
                        fp_evidence.append(f"Port {port} banner: \"{keyword}\" → {os_name}")
    
        if os_votes:
            # Find best match
            best_os = max(os_votes, key=os_votes.get)
            total_votes = sum(os_votes.values())
            confidence = min(int(os_votes[best_os] / max(total_votes, 1) * 100), 95)
            
            # Refine generic "Linux" to show distribution set
            os_info['name'] = best_os
            os_info['confidence'] = confidence
            os_info['accuracy'] = confidence
            os_info['fingerprint'] = ' | '.join(fp_evidence)
            os_info['source'] = 'service_banner'
            os_info['evidence'] = fp_evidence
            os_info['os_votes'] = dict(sorted(os_votes.items(), key=lambda x: -x[1]))
    
    # Phase 2: Run external binaries and pass ALL fields through
    for binary in ('os_detect', 'os_fingerprint', 'cpp_os_detect'):
        bin_path = _find_binary(binary)
        if bin_path:
            bin_fp = _gather_binary_fingerprint(bin_path, target)
            if bin_fp:
                bin_name = str(bin_fp.get('name', bin_fp.get('os_name', ''))).strip()
                bin_conf_raw = bin_fp.get('confidence', bin_fp.get('accuracy', 0))
                if isinstance(bin_conf_raw, float) and bin_conf_raw < 1.0:
                    bin_conf = int(bin_conf_raw * 100)
                else:
                    bin_conf = int(bin_conf_raw) if bin_conf_raw else 0
                
                # Merge: prefer service-based, but keep binary data as fallback
                if os_info.get('name') == 'Unknown' or os_info.get('confidence', 0) < 30:
                    if bin_name:
                        os_info['name'] = bin_name
                        os_info['confidence'] = max(os_info.get('confidence', 0), bin_conf)
                        os_info['accuracy'] = max(os_info.get('accuracy', 0), bin_conf)
                elif bin_name and bin_conf > os_info.get('confidence', 0):
                    os_info['name'] = bin_name
                    os_info['confidence'] = bin_conf
                    os_info['accuracy'] = bin_conf
                
                # Pass ALL fingerprint fields through from binary
                for key in FINGERPRINT_FIELDS:
                    if key in bin_fp and key not in ('name', 'confidence', 'accuracy'):
                        if bin_fp[key] is not None and bin_fp[key] != '' and bin_fp[key] != 0:
                            os_info[key] = bin_fp[key]
                
                if bin_fp.get('fingerprint'):
                    os_info['fingerprint'] = bin_fp['fingerprint']
                if bin_fp.get('signature'):
                    os_info['signature'] = bin_fp['signature']
                os_info['engine'] = binary
                break
    
    return os_info


def _run_stage_vuln_scan(target, results):
    for r in (results or []):
        if isinstance(r, dict) and r.get('status') == 'open':
            port = r.get('port', 0)
            for binary in ('vuln_matcher', 'vuln_matcher_v2'):
                bin_path = _find_binary(binary)
                if bin_path:
                    vresults, vfinal, verr = _run_binary(bin_path, [target, str(port)], timeout=30)
                    vulns = [v for v in vresults if isinstance(v, dict)]
                    if vulns:
                        r['vulnerabilities'] = vulns
                        break
    return results


_PIPELINE_STAGES = {
    'discovery': _run_stage_discovery,
    'tcp_scan': _run_stage_tcp_scan,
    'service_detect': _run_stage_service_detect,
    'os_detect': _run_stage_os_detect,
    'vuln_scan': _run_stage_vuln_scan,
}


class PortOrchestrator:
    def __init__(self):
        self.engines = _cached_discover_engines()
        self.by_lang = _cached_available_engines()
        self.go_engine = get_engine()
        self._results_event = threading.Event()

    def _profile_engine_selector(self, profile):
        name = profile.name.lower()
        if name == 'quick':
            return ['go']
        if name == 'full':
            return ['rust'] if self.by_lang.get('rust') else ['go']
        if name == 'comprehensive':
            available = []
            for lang in ('go', 'rust', 'c', 'cpp'):
                if lang == 'go' and self.go_engine.available:
                    available.append('go')
                elif self.by_lang.get(lang):
                    available.append(lang)
            return available or ['go']
        if name == 'web':
            return ['go']
        if name == 'lan':
            if self.by_lang.get('c'):
                return ['go', 'c']
            return ['go']
        if name == 'stealth':
            return ['go']
        return ['go']

    def run_scan(self, target, ports='top100', profile=None, engines=None, stages=None, callback=None):
        if isinstance(profile, str):
            profile = get_profile(profile)
        if profile is None:
            profile = get_profile('quick')

        if engines is None:
            engines = self._profile_engine_selector(profile)
        if stages is None:
            stages = profile.stages

        profile.engines = engines
        port_results = []

        for stage in stages:
            stage_fn = _PIPELINE_STAGES.get(stage)
            if not stage_fn:
                continue

            if stage == 'discovery':
                stage_fn(target, ports, profile)

            elif stage == 'tcp_scan':
                all_port_results = []
                with ThreadPoolExecutor(max_workers=len(engines)) as executor:
                    fut_to_eng = {
                        executor.submit(stage_fn, target, ports, profile, eng): eng
                        for eng in engines
                    }
                    for fut in as_completed(fut_to_eng):
                        eng = fut_to_eng[fut]
                        try:
                            res = fut.result()
                            if isinstance(res, list):
                                all_port_results.append(res)
                                self._results_event.set()
                                if callback:
                                    callback('engine_results', {
                                        'engine': eng, 'count': len(res)
                                    })
                        except:
                            pass
                port_results = _merge_results(all_port_results) if all_port_results else []

            elif stage == 'service_detect':
                port_results = stage_fn(target, ports, port_results)

            elif stage == 'os_detect':
                os_info = stage_fn(target, port_results)
                if callback:
                    callback('os', os_info)

            elif stage == 'vuln_scan':
                port_results = stage_fn(target, port_results)
                for pr in port_results:
                    if pr.get('vulnerabilities') and callback:
                        for v in pr['vulnerabilities']:
                            callback('vuln', v)

            if callback:
                callback('status', {'message': f'Stage: {stage}', 'stage': stage})

        os_info = os_info if 'os_detect' in stages else {}
        for pr in port_results:
            if isinstance(pr, dict) and callback:
                callback('result', pr)

        return {
            'host': target,
            'results': port_results,
            'os': os_info if isinstance(os_info, dict) else {'name': 'Unknown'},
            'profile': profile.name,
            'engines': engines,
            'stages': stages,
            'open_count': sum(1 for p in port_results if isinstance(p, dict) and p.get('status') == 'open'),
            'total_count': len(port_results),
        }
