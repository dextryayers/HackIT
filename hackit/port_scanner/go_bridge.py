import os
import subprocess
import sys
import shutil
import json
from hackit.ui import _colored, GREEN, RED, BLUE

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.source_file = os.path.join(self.go_dir, 'main.go')
        self.binary_name = 'port_scanner.exe' if os.name == 'nt' else 'port_scanner'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.available = self._check_go_installed()

    def _check_go_installed(self):
        return shutil.which('go') is not None

    def ensure_compiled(self):
        if not self.available: return False
        if not os.path.exists(self.source_file): return False
        
        needs_compile = False
        if not os.path.exists(self.binary_path):
            needs_compile = True
        else:
            bin_mtime = os.path.getmtime(self.binary_path)
            for root, dirs, files in os.walk(self.go_dir):
                for f in files:
                    if f.endswith('.go'):
                        src_path = os.path.join(root, f)
                        if os.path.getmtime(src_path) > bin_mtime:
                            needs_compile = True
                            break
                if needs_compile: break

        if needs_compile:
            print(_colored("[*] Compiling Go Port Scanner Engine...", BLUE))
            try:
                cmd = ['go', 'build', '-o', self.binary_path, '.']
                subprocess.check_call(cmd, cwd=self.go_dir)
                print(_colored("[+] Engine compiled successfully!", GREEN))
                return True
            except subprocess.CalledProcessError as e:
                print(_colored(f"[!] Compilation failed: {e}", RED))
                return False
        return True

    def run(self, target, ports=None, timeout=1000, threads=100, include_closed=True, stealth=False, mode="connect", callback=None, **kwargs):
        if not self.ensure_compiled():
            raise RuntimeError("Go engine compilation failed")

        cmd = [self.binary_path, '-target', target]

        cmd.extend(['-format', 'json'])
        cmd.extend(['-quiet-json=true'])
        
        # Target & Core Settings
        if ports:
            if isinstance(ports, list):
                ports_str = ",".join(map(str, ports))
                cmd.extend(['-ports', ports_str])
            else:
                cmd.extend(['-ports', str(ports)])
                
        cmd.extend(['-timeout', str(timeout)])
        cmd.extend(['-threads', str(threads)])
        cmd.extend(['-mode', str(mode)])
        
        # Output & Format
        if kwargs.get('output'):
            cmd.extend(['-output', str(kwargs.get('output'))])
        if kwargs.get('output_format'):
            cmd.extend(['-format', str(kwargs.get('output_format'))])
        if kwargs.get('open_only'):
            cmd.extend(['-open-only=true'])
        
        # Stealth & Evasion Layer
        if kwargs.get('ghost_protocol'):
            cmd.extend(['-ghost-protocol=true'])
        if kwargs.get('chaos'):
            cmd.extend(['-chaos=true'])
        if kwargs.get('adaptive'):
            cmd.extend(['-adaptive=true'])
        if kwargs.get('quantum'):
            cmd.extend(['-quantum=true'])
        if kwargs.get('decoy'):
            cmd.extend(['-decoy', str(kwargs.get('decoy'))])
        if kwargs.get('zombie'):
            cmd.extend(['-zombie', str(kwargs.get('zombie'))])
        if kwargs.get('spoof_ip'):
            cmd.extend(['-spoof-ip', str(kwargs.get('spoof_ip'))])
        if kwargs.get('source_port'):
            cmd.extend(['-source-port', str(kwargs.get('source_port'))])
        if kwargs.get('frag'):
            cmd.extend(['-frag=true'])
        if kwargs.get('frag_size'):
            cmd.extend(['-frag-size', str(kwargs.get('frag_size'))])
        if kwargs.get('mtu'):
            cmd.extend(['-mtu', str(kwargs.get('mtu'))])
        if kwargs.get('ttl'):
            cmd.extend(['-ttl', str(kwargs.get('ttl'))])
            
        # Intelligence Layer
        if kwargs.get('os_detect'):
            cmd.extend(['-os-detect=true'])
        if kwargs.get('deep'):
            cmd.extend(['-deep=true'])
        if kwargs.get('passive'):
            cmd.extend(['-passive=true'])
        if kwargs.get('smart_probe'):
            cmd.extend(['-smart-probe=true'])
        if kwargs.get('fingerprint_intensity'):
            cmd.extend(['-fingerprint-intensity', str(kwargs.get('fingerprint_intensity'))])
        if kwargs.get('script'):
            cmd.extend(['-script', str(kwargs.get('script'))])
        if kwargs.get('script_args'):
            cmd.extend(['-script-args', str(kwargs.get('script_args'))])
            
        # Timing & Discovery Layer
        if kwargs.get('min_rate'):
            cmd.extend(['-min-rate', str(kwargs.get('min_rate'))])
        if kwargs.get('max_rate'):
            cmd.extend(['-max-rate', str(kwargs.get('max_rate'))])
        if kwargs.get('max_retries'):
            cmd.extend(['-max-retries', str(kwargs.get('max_retries'))])
        if kwargs.get('host_timeout'):
            cmd.extend(['-host-timeout', str(kwargs.get('host_timeout'))])
        if kwargs.get('scan_delay'):
            cmd.extend(['-scan-delay', str(kwargs.get('scan_delay'))])
        if kwargs.get('randomize_targets'):
            cmd.extend(['-randomize-targets=true'])
        if kwargs.get('randomize_ports'):
            cmd.extend(['-randomize-ports=true'])
        if kwargs.get('no_ping'):
            cmd.extend(['-no-ping=true'])
        if kwargs.get('ping_method'):
            cmd.extend(['-ping-method', str(kwargs.get('ping_method'))])
        if kwargs.get('resolve'):
            cmd.extend(['-resolve', str(kwargs.get('resolve'))])
        if kwargs.get('dns_server'):
            cmd.extend(['-dns-server', str(kwargs.get('dns_server'))])

        # Pipeline & Profile
        if kwargs.get('pipeline'):
            cmd.extend(['-pipeline', str(kwargs.get('pipeline'))])
        if kwargs.get('profile'):
            cmd.extend(['-profile', str(kwargs.get('profile'))])
            
        # HackIT Aliases (sS, sV, O, A, etc.)
        if kwargs.get('scan_syn') or kwargs.get('sS'):
            cmd.extend(['-mode', 'syn'])
        if kwargs.get('scan_version') or kwargs.get('sV'):
            cmd.extend(['-smart-probe=true']) # Go uses smart-probe for versioning
        if kwargs.get('os_detection') or kwargs.get('O') or kwargs.get('os_detect'):
            cmd.extend(['-os-detect=true'])
        if kwargs.get('aggressive_scan') or kwargs.get('A'):
            cmd.extend(['-os-detect=true', '-smart-probe=true', '-deep=true'])
        if kwargs.get('ping_only') or kwargs.get('Pn'):
            # In our scanner, Pn often means skip host discovery (always scan)
            pass
        if include_closed:
            cmd.extend(['-include-closed=true'])
        else:
            cmd.extend(['-include-closed=false'])
            
        if stealth:
            cmd.extend(['-stealth=true'])
        else:
            cmd.extend(['-stealth=false'])
        
        final_result = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Use a more robust reading loop
            while True:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                line = line.strip()
                if not line: continue
                
                if line.startswith("RESULT:"):
                    try:
                        res = json.loads(line[7:])
                        if callback: callback("result", res)
                    except Exception: pass
                    continue # Do not print the RESULT: line itself
                elif line.startswith("STATUS:"):
                    try:
                        status = json.loads(line[7:])
                        if callback: callback("status", status)
                    except Exception: pass
                    continue # Do not print the STATUS: line itself
                elif line.startswith("ERROR:"):
                    try:
                        err = json.loads(line[6:])
                        if callback: callback("error", err)
                    except Exception: pass
                elif line.startswith("FINAL:"):
                    try:
                        final_result = json.loads(line[6:])
                    except Exception as e:
                        if final_result is None: # Only error if we didn't get results
                            print(_colored(f"[!] Error parsing FINAL JSON: {e}", RED))
                else:
                    # Silence all unknown output to keep tactical UI clean
                    pass
            
            process.wait()
            
            if process.returncode != 0 and not final_result:
                try:
                    stderr = process.stderr.read()
                    return {'error': stderr.strip()}
                except:
                    return {'error': 'Process exited with non-zero code'}
            
            # If we got a list of results (multiple targets), return the first one if only one was requested
            # or return the whole thing but handle it in __init__.py
            if isinstance(final_result, list) and len(final_result) == 1:
                return final_result[0]
            
            return final_result or {'error': 'No final result received'}

        except Exception as e:
            return {'error': str(e)}

def get_engine():
    return GoEngine()
