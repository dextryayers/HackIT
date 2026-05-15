"""
Subdomain Enumeration Module (Go-Powered)
"""
import click
import os
import tempfile
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE, YELLOW
from .go_bridge import get_engine

import re
import requests
from urllib.parse import urlparse

# Suppress insecure request warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import threading

def passive_recon(domain):
    """
    Query multiple passive sources for subdomains using a multi-threaded architecture.
    Sources: HackerTarget, crt.sh, AlienVault OTX, Anubis, ThreatMiner, RapidDNS.
    """
    subs = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
    lock = threading.Lock()

    def fetch_crtsh():
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=25, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                with lock:
                    for entry in data:
                        name = entry.get('name_value', '').lower()
                        for s in name.split('\n'):
                            if domain in s:
                                subs.add(s.strip("*.").strip())
        except Exception: pass

    def fetch_hackertarget():
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                with lock:
                    for line in resp.text.splitlines():
                        if ',' in line:
                            subs.add(line.split(',')[0].lower().strip())
        except Exception: pass

    def fetch_alienvault():
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                with lock:
                    for record in data.get('passive_dns', []):
                        hostname = record.get('hostname', '').lower()
                        if domain in hostname:
                            subs.add(hostname.strip())
        except Exception: pass

    def fetch_anubis():
        try:
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                with lock:
                    for s in data:
                        subs.add(s.lower().strip())
        except Exception: pass

    def fetch_threatminer():
        try:
            url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                with lock:
                    for s in data.get('results', []):
                        subs.add(s.lower().strip())
        except Exception: pass

    def fetch_rapiddns():
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                pattern = re.compile(rf'([a-zA-Z0-9-]+\.)+{re.escape(domain)}')
                matches = pattern.findall(resp.text)
                with lock:
                    for m in matches:
                        if isinstance(m, tuple):
                            subs.add(m[0].lower().strip("."))
                        else:
                            subs.add(m.lower().strip("."))
        except Exception: pass

    def fetch_wayback():
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
            resp = requests.get(url, timeout=25, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                # Skip header row
                for entry in data[1:]:
                    raw_url = entry[2]
                    hostname = urlparse(raw_url).hostname
                    if hostname and domain in hostname:
                        with lock:
                            subs.add(hostname.lower().strip())
        except Exception: pass

    def fetch_certspotter():
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                with lock:
                    for entry in data:
                        for name in entry.get('dns_names', []):
                            if domain in name:
                                subs.add(name.strip("*.").strip())
        except Exception: pass

    def fetch_subdomaincenter():
        try:
            url = f"https://subdomain.center/api/index.php?domain={domain}"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                with lock:
                    for s in data:
                        if domain in s:
                            subs.add(s.strip())
        except Exception: pass

    def fetch_urlscan():
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                with lock:
                    for result in data.get('results', []):
                        hostname = result.get('page', {}).get('domain', '').lower()
                        if domain in hostname:
                            subs.add(hostname.strip())
        except Exception: pass

    # Launch all workers
    workers = [
        threading.Thread(target=fetch_crtsh),
        threading.Thread(target=fetch_hackertarget),
        threading.Thread(target=fetch_alienvault),
        threading.Thread(target=fetch_anubis),
        threading.Thread(target=fetch_threatminer),
        threading.Thread(target=fetch_rapiddns),
        threading.Thread(target=fetch_wayback),
        threading.Thread(target=fetch_certspotter),
        threading.Thread(target=fetch_subdomaincenter),
        threading.Thread(target=fetch_urlscan)
    ]
    
    for w in workers: w.start()
    for w in workers: w.join()

    # Final cleanup & Rapid-Probe Optimization
    import socket
    from concurrent.futures import ThreadPoolExecutor
    final_results = []
    
    def probe_host(s):
        s = s.lower().strip(".")
        if not (s.endswith("." + domain) or s == domain): return None
        
        # 1. IP Resolution (Ultra-fast)
        ip = "N/A"
        try:
            socket.setdefaulttimeout(1.5)
            ip = socket.gethostbyname(s)
        except Exception: pass
        
        # 2. HTTP Status Code Probe (Aggressive)
        sc = "OFF"
        try:
            # We use a very short timeout for rapid feedback
            r = requests.get(f"http://{s}", timeout=2, verify=False, headers=headers)
            sc = str(r.status_code)
        except Exception: pass
            
        return {
            "sub": s,
            "ip": ip,
            "sc": sc,
            "mode": "Passive"
        }

    unique_subs = list(set(subs))
    # Aggressively probe up to 300 interesting subdomains to keep response time < 10s
    targets = unique_subs[:300]
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(probe_host, targets))
        for r in results:
            if r: final_results.append(r)

    # Add remaining without probing to ensure "entire" list is returned instantly
    for s in unique_subs[300:]:
        final_results.append({
            "sub": s.lower().strip("."),
            "ip": "Pending...",
            "sc": "---",
            "mode": "Passive"
        })

    return final_results

def extract_from_web(domain):
    """
    Extract subdomains from the target's main page and JS files.
    """
    subs = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    
    try:
        # Try both http and https
        for proto in ["https://", "http://"]:
            url = f"{proto}{domain}"
            try:
                resp = requests.get(url, timeout=15, verify=False, headers=headers)
                if resp.status_code == 200:
                    # Find subdomains in page content (more aggressive regex)
                    pattern = re.compile(rf'([a-zA-Z0-9-]+\.)+{re.escape(domain)}')
                    matches = pattern.findall(resp.text)
                    for m in matches:
                        if isinstance(m, tuple):
                            subs.add(m[0].lower().strip("."))
                        else:
                            subs.add(m.lower().strip("."))
                    
                    # Search in comments and script tags
                    soup_pattern = re.compile(r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}')
                    all_matches = soup_pattern.finditer(resp.text)
                    for match in all_matches:
                        found = match.group(0).lower()
                        if found.endswith("." + domain) or found == domain:
                            subs.add(found)

                    # Find JS files
                    js_pattern = re.compile(r'src=["\'](.*?\.js)["\']')
                    js_files = js_pattern.findall(resp.text)
                    for js in js_files:
                        if js.startswith("/"):
                            js_url = f"{proto}{domain}{js}"
                        elif js.startswith("http"):
                            js_url = js
                        else:
                            js_url = f"{proto}{domain}/{js}"
                        
                        try:
                            js_resp = requests.get(js_url, timeout=10, verify=False, headers=headers)
                            if js_resp.status_code == 200:
                                js_matches = pattern.findall(js_resp.text)
                                for jm in js_matches:
                                    if isinstance(jm, tuple):
                                        subs.add(jm[0].lower().strip("."))
                                    else:
                                        subs.add(jm.lower().strip("."))
                        except Exception:
                            continue
            except Exception:
                continue
    except Exception:
        pass
    
    # Filter out junk
    valid_subs = set()
    for s in subs:
        s = s.lower().strip(".")
        if s.endswith("." + domain) or s == domain:
            valid_subs.add(s)
            
    return list(valid_subs)

@click.command()
@click.option('-d', '--domain', required=True, help='Target domain (e.g. example.com)')
@click.option('-w', '--wordlist', type=click.Path(exists=True), help='Wordlist for active brute force')
@click.option('--passive-only', is_flag=True, help='Run only passive enumeration (fast)')
@click.option('--active-only', is_flag=True, help='Run only active brute force')
@click.option('--permutations', is_flag=True, help='Run permutation scanning (Altdns style)')
@click.option('--takeover', is_flag=True, help='Check for subdomain takeover vulnerabilities')
@click.option('--recursive', '--deep', is_flag=True, help='Enable deep recursive scanning (scans found subdomains)')
@click.option('--stealth', is_flag=True, help='Enable stealth mode (random UA, public resolvers, traffic shaping)')
@click.option('--fast', is_flag=True, help='Enable Fast Mode (Higher concurrency, shorter timeouts)')
@click.option('--sc', is_flag=True, help='Display Status Code (200, 301, 403, etc)')
@click.option('--ip', is_flag=True, help='Display IP Address')
@click.option('--title', is_flag=True, help='Display Web Page Title')
@click.option('--server', '--web-server', is_flag=True, help='Display Web Server Header')
@click.option('--tech-detect', '--tech', is_flag=True, help='Detect Technologies (CMS, Frameworks, Servers)')
@click.option('--asn', is_flag=True, help='Display ASN Information')
@click.option('--probe', is_flag=True, help='Display Probe Status (Alive/Dead)')
@click.option('-fc', '--filter-codes', help='Filter response with specified status code (e.g. 403,401)')
@click.option('-t', '--threads', default=100, help='Number of threads (Go routines)')
@click.option('-o', '--output', help='Save output to JSON file')
@click.option('-v', '--verbose', is_flag=True, help='Show verbose output (debug logs)')
def enumerate(domain, wordlist, passive_only, active_only, permutations, takeover, recursive, stealth, fast, sc, ip, title, server, tech_detect, asn, probe, filter_codes, threads, output, verbose):
    """
    Advanced Subdomain Enumeration & Takeover Scanner (Go-Powered).
    Combines passive sources, active brute forcing, permutations, recursion, zone transfers, and HTTP probing.
    Powered by a high-performance Golang engine.
    """
    display_tool_banner('Subdomain Scanner')
    
    engine = get_engine()
    
    if not engine.available:
        click.echo(_colored("[!] Go is not installed or not found in PATH.", RED))
        click.echo("    Please install Go (Golang) to use this module.")
        return

    click.echo(f"[*] Target: {_colored(domain, BLUE, bold=True)}")
    click.echo(f"[*] Engine: {_colored('HackIT', GREEN)}")
    
    # Mode Summary
    modes = []
    if not active_only: modes.append("Passive")
    if not passive_only: modes.append("Active")
    if permutations: modes.append("Permutations")
    if recursive: modes.append("Deep Scan")
    if takeover: modes.append("Takeover")
    if probe or sc or title or tech_detect: modes.append("Probing")
    
    click.echo(f"[*] Modes: {', '.join(modes)}")
    if fast: click.echo(f"[*] Fast Mode: {_colored('ON', YELLOW)}")
    if stealth: click.echo(f"[*] Stealth Mode: {_colored('ON', YELLOW)}")

    # Compile if needed
    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go worker.", RED))
        return

    # 1. Passive Recon (APIs)
    all_passive_subs = set()
    if not active_only:
        click.echo(f"[*] Querying passive sources (HackerTarget, crt.sh, AlienVault, CertSpotter, etc.)...")
        passive_subs = passive_recon(domain)
        if passive_subs:
            click.echo(f"[*] Found {len(passive_subs)} subdomains from passive APIs")
            # FIX: Only update with the subdomain strings, not the result dicts
            all_passive_subs.update(r['sub'] for r in passive_subs)

    # 2. Python Smart Intelligence: Extract subdomains from web
    temp_wordlist_path = None
    web_subs = extract_from_web(domain)
    if web_subs:
        click.echo(f"[*] Found {len(web_subs)} subdomains in target web and JS files")
        all_passive_subs.update(web_subs)

    if all_passive_subs:
        # Create a temp file for Go to read
        temp_wordlist = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w")
        for s in all_passive_subs:
            # We only need the part before the domain
            sub = s.replace(f".{domain}", "")
            temp_wordlist.write(sub + "\n")
        temp_wordlist.close()
        temp_wordlist_path = temp_wordlist.name
        
        # Merge with user wordlist if exists
        if wordlist:
            with open(wordlist, "r") as f:
                with open(temp_wordlist_path, "a") as tf:
                    tf.write(f.read())
        wordlist = temp_wordlist_path

    success = engine.run(
        domain=domain,
        wordlist=wordlist,
        passive_only=passive_only,
        active_only=active_only,
        permutations=permutations,
        takeover=takeover,
        recursive=recursive,
        stealth=stealth,
        fast=fast,
        sc=sc,
        ip=ip,
        title=title,
        server=server,
        tech_detect=tech_detect,
        asn=asn,
        probe=probe,
        filter_codes=filter_codes,
        threads=threads,
        output=output,
        verbose=verbose
    )
    
    # Cleanup temp file
    if temp_wordlist_path and os.path.exists(temp_wordlist_path):
        os.remove(temp_wordlist_path)

    click.echo("-" * 60)
    
    if success:
        click.echo(_colored("[+] Scan Completed Successfully.", GREEN))
        if output:
            click.echo(f"[+] Results saved to: {output}")
    else:
        click.echo(_colored("[!] Scan encountered errors.", RED))

if __name__ == '__main__':
    enumerate()
