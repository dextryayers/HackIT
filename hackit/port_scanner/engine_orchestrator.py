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


def _run_stage_os_detect(target):
    os_info = {'name': 'Unknown', 'confidence': 0, 'accuracy': 0}
    for binary in ('os_detect', 'os_fingerprint', 'cpp_os_detect'):
        bin_path = _find_binary(binary)
        if bin_path:
            results, final, err = _run_binary(bin_path, [target], timeout=30)
            if final and isinstance(final, dict):
                os_info.update(final)
                break
            for r in results:
                if isinstance(r, dict) and r.get('name', r.get('os_name', '')):
                    os_info.update(r)
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
                os_info = stage_fn(target)
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
