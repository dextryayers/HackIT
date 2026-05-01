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
        cmd.extend(['-quiet-json', 'true'])
        
        if ports:
            if isinstance(ports, list):
                ports_str = ",".join(map(str, ports))
                cmd.extend(['-ports', ports_str])
            else:
                cmd.extend(['-ports', str(ports)])
                
        cmd.extend(['-timeout', str(timeout)])
        cmd.extend(['-threads', str(threads)])
        cmd.extend(['-mode', str(mode)])
        
        # Profile mapping
        if kwargs.get('fast'):
            cmd.extend(['-profile', 'fast'])
        
        # Service & OS detection
        if kwargs.get('identify_os') or kwargs.get('os_detection'):
            cmd.extend(['-identify-os', 'true'])
        if kwargs.get('detect_service') or kwargs.get('grab_banner'):
            cmd.extend(['-detect-service', 'true'])
        if kwargs.get('auto_vuln'):
            cmd.extend(['-enrich', 'true'])
        
        # New Nmap parity flags
        if kwargs.get('script'):
            cmd.extend(['-script', str(kwargs.get('script'))])
        if kwargs.get('script_args'):
            cmd.extend(['-script-args', str(kwargs.get('script_args'))])
        if kwargs.get('mtu'):
            cmd.extend(['-mtu', str(kwargs.get('mtu'))])
        if kwargs.get('data_length'):
            cmd.extend(['-data-length', str(kwargs.get('data_length'))])
        if kwargs.get('source_port'):
            cmd.extend(['-source-port', str(kwargs.get('source_port'))])
        if kwargs.get('custom_ttl'):
            cmd.extend(['-custom-ttl', str(kwargs.get('custom_ttl'))])
        if kwargs.get('mask_ip'):
            cmd.extend(['-mask-ip', str(kwargs.get('mask_ip'))])
        if kwargs.get('spoof_mac'):
            cmd.extend(['-spoof-mac', str(kwargs.get('spoof_mac'))])
        if kwargs.get('packet_split'):
            cmd.extend(['-packet-split', 'true'])
        if kwargs.get('badsum'):
            cmd.extend(['-badsum', 'true'])
        if kwargs.get('traceroute'):
            cmd.extend(['-traceroute', 'true'])
        if kwargs.get('dns_info'):
            cmd.extend(['-dns-info', 'true'])
        if kwargs.get('reverse_lookup'):
            cmd.extend(['-reverse-lookup', 'true'])
        if kwargs.get('sub_enum'):
            cmd.extend(['-sub-enum', 'true'])
        if kwargs.get('whois_info'):
            cmd.extend(['-whois-info', 'true'])
        if kwargs.get('geo_info'):
            cmd.extend(['-geo-info', 'true'])
        if kwargs.get('asn_info'):
            cmd.extend(['-asn-info', 'true'])
        if kwargs.get('http_inspect'):
            cmd.extend(['-http-inspect', 'true'])
        if kwargs.get('tech_analyze'):
            cmd.extend(['-tech-analyze', 'true'])
        if kwargs.get('tls_analyze'):
            cmd.extend(['-tls-analyze', 'true'])
        if kwargs.get('cert_view'):
            cmd.extend(['-cert-view', 'true'])
        if kwargs.get('show_title'):
            cmd.extend(['-show-title', 'true'])
        if kwargs.get('auto_vuln'):
            cmd.extend(['-auto-vuln', 'true'])
            
        # New Advanced Evasion & Timing flags
        if kwargs.get('detect_honeypot'):
            cmd.extend(['-detect-honeypot', 'true'])
        if kwargs.get('smart_bypass'):
            cmd.extend(['-smart-bypass', 'true'])
        if kwargs.get('random_order'):
            cmd.extend(['-random-order', 'true'])
        if kwargs.get('decoy_ip'):
            cmd.extend(['-decoy-ip', str(kwargs.get('decoy_ip'))])
        if kwargs.get('use_proxy'):
            cmd.extend(['-use-proxy', str(kwargs.get('use_proxy'))])
        if kwargs.get('use_tor'):
            cmd.extend(['-use-tor', 'true'])
        if kwargs.get('version_intensity'):
            cmd.extend(['-version-intensity', str(kwargs.get('version_intensity'))])
        if kwargs.get('osscan_limit'):
            cmd.extend(['-osscan-limit', 'true'])
        if kwargs.get('osscan_guess'):
            cmd.extend(['-osscan-guess', 'true'])
        if kwargs.get('host_timeout'):
            cmd.extend(['-host-timeout', str(kwargs.get('host_timeout'))])
        if kwargs.get('scan_delay'):
            cmd.extend(['-scan-delay', str(kwargs.get('scan_delay'))])
        if kwargs.get('max_scan_delay'):
            cmd.extend(['-max-scan-delay', str(kwargs.get('max_scan_delay'))])
        if kwargs.get('defeat_rst_ratelimit'):
            cmd.extend(['-defeat-rst-ratelimit', 'true'])
        if kwargs.get('defeat_icmp_ratelimit'):
            cmd.extend(['-defeat-icmp-ratelimit', 'true'])
        if kwargs.get('nsock_engine'):
            cmd.extend(['-nsock-engine', str(kwargs.get('nsock_engine'))])
            
        # Nmap Aliases (sS, sV, O, A, etc.)
        if kwargs.get('scan_syn') or kwargs.get('sS'):
            cmd.extend(['-mode', 'syn'])
        if kwargs.get('scan_version') or kwargs.get('sV'):
            cmd.extend(['-detect-service', 'true'])
        if kwargs.get('os_detection_nmap') or kwargs.get('O'):
            cmd.extend(['-identify-os', 'true'])
        if kwargs.get('aggressive_scan') or kwargs.get('A'):
            cmd.extend(['-identify-os', 'true', '-detect-service', 'true', '-traceroute', 'true'])
        if kwargs.get('ping_only') or kwargs.get('Pn'):
            # In our scanner, Pn often means skip host discovery (always scan)
            pass
        if include_closed:
            cmd.extend(['-include-closed', 'true'])
        else:
            cmd.extend(['-include-closed', 'false'])
            
        if stealth:
            cmd.extend(['-stealth', 'true'])
        else:
            cmd.extend(['-stealth', 'false'])
        
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
