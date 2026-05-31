"""
Subdomain Enumeration Module (Go-Powered) - Hackit SubOver
"""
import click
import os
import tempfile
import json
import re
import requests
from urllib.parse import urlparse
import threading
import socket
from concurrent.futures import ThreadPoolExecutor

from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE, YELLOW
from .go_bridge import get_engine

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    banner = """[bold cyan]
      ███████╗██╗   ██╗██████╗  ██████╗ ██╗   ██╗███████╗██████╗ 
      ██╔════╝██║   ██║██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔══██╗
      ███████╗██║   ██║██████╔╝██║   ██║██║   ██║█████╗  ██████╔╝
      ╚════██║██║   ██║██╔══██╗██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
      ███████║╚██████╔╝██████╔╝╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
      ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝
[/bold cyan][bold magenta]                    HACKIT ENGINE v3.0                    [/bold magenta]
[bold white]              Deep Crawl | Hyper-Spider | High Precision[/bold white]
    """
    console.print(Panel.fit(banner, border_style="bright_blue", padding=(1, 2)))

def passive_recon(domain):
    """
    Query multiple passive sources for subdomains using a highly concurrent architecture.
    Sources (No API Key Required): HackerTarget, crt.sh, AlienVault OTX, Anubis, ThreatMiner, RapidDNS, Wayback, CertSpotter, URLScan, ThreatCrowd, Riddler, SiteDossier.
    """
    subs = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    lock = threading.Lock()

    def fetch_source(url, parser_func):
        try:
            resp = requests.get(url, timeout=15, headers=headers, verify=False)
            if resp.status_code == 200:
                extracted = parser_func(resp)
                if extracted:
                    with lock:
                        for s in extracted:
                            s = s.lower().strip("*.").strip()
                            if s.endswith("." + domain) or s == domain:
                                subs.add(s)
        except Exception:
            pass

    # Parsers
    def parse_crtsh(resp):
        res = set()
        try:
            for entry in resp.json():
                for s in entry.get('name_value', '').split('\n'): res.add(s)
        except: pass
        return res

    def parse_lines(resp): return set(line.split(',')[0] for line in resp.text.splitlines() if domain in line)
    
    def parse_alienvault(resp):
        try: return set(r.get('hostname', '') for r in resp.json().get('passive_dns', []))
        except: return set()

    def parse_json_list(resp):
        try: return set(resp.json())
        except: return set()

    def parse_threatminer(resp):
        try: return set(resp.json().get('results', []))
        except: return set()

    def parse_regex(resp):
        pattern = re.compile(rf'([a-zA-Z0-9-]+\.)+{re.escape(domain)}')
        return set(m[0] if isinstance(m, tuple) else m for m in pattern.findall(resp.text))

    def parse_wayback(resp):
        res = set()
        try:
            for entry in resp.json()[1:]:
                h = urlparse(entry[2]).hostname
                if h: res.add(h)
        except: pass
        return res

    def parse_certspotter(resp):
        res = set()
        try:
            for entry in resp.json():
                for name in entry.get('dns_names', []): res.add(name)
        except: pass
        return res

    def parse_urlscan(resp):
        try: return set(r.get('page', {}).get('domain', '') for r in resp.json().get('results', []))
        except: return set()

    def parse_threatcrowd(resp):
        try: return set(resp.json().get('subdomains', []))
        except: return set()

    tasks = [
        (f"https://crt.sh/?q=%.{domain}&output=json", parse_crtsh),
        (f"https://api.hackertarget.com/hostsearch/?q={domain}", parse_lines),
        (f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", parse_alienvault),
        (f"https://jldc.me/anubis/subdomains/{domain}", parse_json_list),
        (f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", parse_threatminer),
        (f"https://rapiddns.io/subdomain/{domain}?full=1", parse_regex),
        (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey", parse_wayback),
        (f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", parse_certspotter),
        (f"https://urlscan.io/api/v1/search/?q=domain:{domain}", parse_urlscan),
        (f"https://subdomain.center/api/index.php?domain={domain}", parse_json_list),
        (f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", parse_threatcrowd),
        (f"https://riddler.io/search/exportcsv?q=pld:{domain}", parse_lines)
    ]

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
        progress.add_task(description=f"Querying {len(tasks)} deep passive OSINT sources...", total=None)
        with ThreadPoolExecutor(max_workers=15) as executor:
            for url, parser in tasks:
                executor.submit(fetch_source, url, parser)

    # Initial ultra-fast resolution to weed out junk if too many results
    final_results = []
    unique_subs = list(subs)
    
    # We don't probe passively here anymore, we let the Go Engine handle it for insane speed!
    # We just return the list of raw subdomains
    for s in unique_subs:
        final_results.append({"sub": s, "mode": "Passive"})

    return final_results

def extract_from_web(domain):
    """
    Deep spidering of the main domain to find hidden subdomains in JS, HTML, and API endpoints.
    """
    subs = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    
    def scrape_url(url):
        try:
            resp = requests.get(url, timeout=10, verify=False, headers=headers)
            if resp.status_code == 200:
                pattern = re.compile(rf'([a-zA-Z0-9-]+\.)+{re.escape(domain)}')
                for m in pattern.findall(resp.text):
                    s = (m[0] if isinstance(m, tuple) else m).lower().strip(".")
                    if s.endswith("." + domain) or s == domain: subs.add(s)
                return resp.text
        except: pass
        return ""

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
        progress.add_task(description="Extracting domains from Web & JS files...", total=None)
        html = scrape_url(f"https://{domain}")
        if not html: html = scrape_url(f"http://{domain}")

        if html:
            # Extract JS links and scrape them concurrently
            js_pattern = re.compile(r'src=["\']([^"\']*?\.js)["\']')
            js_files = js_pattern.findall(html)
            
            js_urls = []
            for js in js_files:
                if js.startswith("http"): js_urls.append(js)
                elif js.startswith("//"): js_urls.append(f"https:{js}")
                elif js.startswith("/"): js_urls.append(f"https://{domain}{js}")
                else: js_urls.append(f"https://{domain}/{js}")

            with ThreadPoolExecutor(max_workers=10) as executor:
                list(executor.map(scrape_url, js_urls[:30])) # Limit to 30 JS files to avoid hanging

    return list(subs)

@click.command()
@click.option('-d', '--domain', required=True, help='Target domain (e.g. example.com)')
@click.option('-w', '--wordlist', type=click.Path(exists=True), help='Wordlist for active brute force')
@click.option('--passive-only', is_flag=True, help='Run only passive enumeration (fast)')
@click.option('--active-only', is_flag=True, help='Run only active brute force')
@click.option('--hyper', is_flag=True, help='Enable Hyper-Crawler (Massive API-less Scraping)')
@click.option('--permutations', is_flag=True, help='Run deep permutation scanning')
@click.option('--takeover', is_flag=True, help='Check for high-precision subdomain takeover')
@click.option('--recursive', '--deep', is_flag=True, help='Enable adaptive depth recursive scanning')
@click.option('--stealth', is_flag=True, help='Enable stealth mode (random UA, resolver rotation)')
@click.option('--fast', is_flag=True, help='Enable Fast Mode (Higher concurrency)')
@click.option('--sc', is_flag=True, help='Display Status Code (200, 301, 403, etc)')
@click.option('--ip', is_flag=True, help='Display IP Address')
@click.option('--title', is_flag=True, help='Display Web Page Title')
@click.option('--server', '--web-server', is_flag=True, help='Display Web Server Header')
@click.option('--tech-detect', '--tech', is_flag=True, help='Detect Technologies (CMS, Frameworks)')
@click.option('--asn', is_flag=True, help='Display ASN Information')
@click.option('--probe', is_flag=True, help='Display Probe Status (Alive/Dead)')
@click.option('-fc', '--filter-codes', help='Filter response with specified status code (e.g. 403,401)')
@click.option('-t', '--threads', default=100, help='Number of threads (Go routines)')
@click.option('-o', '--output', help='Save output to JSON file')
@click.option('-v', '--verbose', is_flag=True, help='Show verbose output (debug logs)')
def enumerate(domain, wordlist, passive_only, active_only, hyper, permutations, takeover, recursive, stealth, fast, sc, ip, title, server, tech_detect, asn, probe, filter_codes, threads, output, verbose):
    """
    Hackit SubOver: Deep Subdomain Enumeration & Takeover Scanner
    """
    print_banner()
    
    engine = get_engine()
    
    if not engine.available:
        console.print("[bold red][!] Go is not installed or not found in PATH.[/bold red]")
        console.print("    Please install Go (Golang) to use this module.")
        return

    # Mode Summary Table
    table = Table(show_header=False, border_style="blue")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Target", f"[bold green]{domain}[/bold green]")
    
    modes = []
    if not active_only: modes.append("Passive (Deep OSINT)")
    if not passive_only: modes.append("Active (Bruteforce)")
    if permutations: modes.append("Permutations")
    if recursive: modes.append("Recursive (Adaptive)")
    if takeover: modes.append("Takeover (High Precision)")
    if probe or sc or title or tech_detect: modes.append("Live Probing")
    
    table.add_row("Modes", ", ".join(modes))
    if fast: table.add_row("Fast Mode", "[bold yellow]ON[/bold yellow]")
    if stealth: table.add_row("Stealth Mode", "[bold yellow]ON[/bold yellow]")
    if threads != 100: table.add_row("Threads", str(threads))
    
    console.print(table)
    console.print()

    if not engine.ensure_compiled():
        console.print("[bold red][!] Failed to compile Go worker.[/bold red]")
        return

    # 1. Passive Recon & Web Extraction (Python side)
    all_passive_subs = set()
    if not active_only:
        if hyper:
            from .hyper_crawler import run_hyper_crawler
            console.print("[bold magenta][*][/bold magenta] Initiating Massive Hyper-Crawler (API-less Scraper)...")
            hyper_subs = run_hyper_crawler(domain)
            for s in hyper_subs: all_passive_subs.add(s)
            console.print(f"[bold green][+][/bold green] Hyper-Crawler harvested [bold white]{len(hyper_subs)}[/bold white] unique subdomains.")
            
        console.print("[bold blue][*][/bold blue] Initiating Deep Passive Reconnaissance...")
        passive_subs = passive_recon(domain)
        web_subs = extract_from_web(domain)
        
        for s in passive_subs: all_passive_subs.add(s['sub'])
        for s in web_subs: all_passive_subs.add(s)
            
        console.print(f"[bold green][+][/bold green] Found [bold white]{len(all_passive_subs)}[/bold white] total unique subdomains from python intelligence.")

    # Prepare temporary wordlist for Go Engine combining user wordlist and passive results
    temp_wordlist_path = None
    if all_passive_subs or wordlist:
        temp_wordlist = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w")
        for s in all_passive_subs:
            sub = s.replace(f".{domain}", "")
            temp_wordlist.write(sub + "\n")
        
        if wordlist and os.path.exists(wordlist):
            with open(wordlist, "r") as f:
                temp_wordlist.write("\n" + f.read())
                
        temp_wordlist.close()
        temp_wordlist_path = temp_wordlist.name
        wordlist_arg = temp_wordlist_path
    else:
        wordlist_arg = None

    console.print("[bold blue][*][/bold blue] Handing over to High-Speed Go Engine...")
    console.print("-" * 60)
    
    success = engine.run(
        domain=domain,
        wordlist=wordlist_arg,
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

    console.print("-" * 60)
    
    if success:
        console.print("[bold green][+] SubOver Engine Execution Completed Successfully.[/bold green]")
        if output:
            console.print(f"[bold green][+][/bold green] Results saved to: [bold white]{output}[/bold white]")
    else:
        console.print("[bold red][!] Execution encountered errors.[/bold red]")

if __name__ == '__main__':
    enumerate()
