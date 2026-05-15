"""
Web Fuzzer (Directory/File Bruteforcer) Module
"""
import click
import json
import os
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE
from .go_bridge import GoEngine

@click.group()
def fuzzer():
    """Industrial-Grade Web Fuzzer Suite (Go, Rust, C++, C)"""
    pass

@fuzzer.command()
@click.option('-d', '--domain', required=True, help='Target domain to harvest')
@click.option('-o', '--output', help='Output file to save results')
@click.option('-l', '--list', 'list_only', is_flag=True, help='List all harvested URLs only')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.option('--deep', is_flag=True, help='Perform recursive Deep JS and endpoint discovery')
@click.option('--subs', is_flag=True, help='Include all subdomains in the reconnaissance pool')
@click.option('--mask', is_flag=True, help='Enable high-anonymity masking technique')
def spider(domain, output, list_only, verbose, mask, deep, subs):
    """
    ParamSpider-like Parameter Harvester (Dual-Engine: Go & Rust).
    Surgically scrapes historical URLs, extracts actionable parameters, and performs Deep JS analysis.
    """
    # Parallel Recon Cluster
    from concurrent.futures import ThreadPoolExecutor
    from .rust_bridge import RustEngine
    from .go_bridge import GoEngine
    
    display_tool_banner('Penta-Engine Spider (Go + Rust)')
    
    click.echo(_colored(f"[*] Starting Elite Dual-Engine Recon for: {domain}", CYAN))
    if deep: click.echo(_colored("[*] DEEP MODE: Recursive JS and endpoint analysis enabled.", YELLOW))
    if subs: click.echo(_colored("[*] SUB MODE: Including subdomains in discovery cluster.", YELLOW))
    
    rust_engine = RustEngine()
    go_engine = GoEngine()
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_rust = executor.submit(rust_engine.run, domain, verbose=verbose, mask=mask)
        future_go = executor.submit(go_engine.harvest, domain)
        
        rust_urls = future_rust.result()
        go_urls = future_go.result()
    
    # Merge and Deduplicate
    all_urls = list(set(rust_urls + go_urls))
    
    if all_urls:
        if list_only:
            for url in all_urls: print(url)
            return
            
        for url in all_urls:
            click.echo(_colored(url, GREEN))
            
        click.echo("-" * 60)
        click.echo(_colored(f"[+] Total unique tactical targets found : {len(all_urls)}", GREEN))
        
        if output:
            with open(output, 'w') as f:
                for url in all_urls: f.write(url + '\n')
            click.echo(_colored(f"[*] Output is saved here    : {output}", CYAN))
    else:
        click.echo(_colored("[!] No parameters found. Defaulting to standard neural probe.", RED))

@fuzzer.command()
@click.option('-d', '--url', required=True, help='Target URL (marker FUZZ is optional, will auto-append if missing)')
@click.option('-p', '--payloads', help='Custom payload file')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.option('--mask', is_flag=True, help='Enable high-anonymity masking technique')
def fast(url, payloads, verbose, mask):
    """
    Ultra-Fast Neural Fuzzer (Go, Rust, C++, C).
    Automatically crawls, shapes, and injects payloads into tactical targets.
    """
    from .rust_bridge import RustEngine
    from .cpp_bridge import CPPEngine
    display_tool_banner('Neural Fuzzer (Full-Cycle Pipeline)')
    
    targets = []
    
    # Check if we need to perform automated reconnaissance (no FUZZ and looks like a domain)
    if 'FUZZ' not in url and ('.' in url and '/' not in url.replace('://', '')):
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        click.echo(_colored(f"[*] Neural Mode: Orchestrating Polyglot Recon for {domain}...", CYAN))
        
        # Step 1: Elite Recon (Go + Rust)
        rust_engine = RustEngine()
        go_engine = GoEngine()
        
        # Concurrent harvesting
        rust_urls = rust_engine.run(domain, verbose=verbose, mask=mask)
        go_urls = go_engine.harvest(domain)
        
        all_recon_urls = list(set(rust_urls + go_urls))
        
        if all_recon_urls:
            click.echo(_colored(f"[+] Discovered {len(all_recon_urls)} tactical targets. Processing pipeline...", GREEN))
            
            # Step 2: Go Shaper (Prioritization & WAF Check)
            shaped_data = go_engine.shape(json.dumps(all_recon_urls))
            
            # Step 3: C++ Injection
            click.echo(f"[+] INJECTOR: Launching high-frequency injection for {len(shaped_data)} targets...")
            cpp_engine = CPPEngine()
            for item in shaped_data:
                target_url = item.get('url')
                if not target_url: continue
                cpp_engine.run(target_url, payloads or "default", verbose=False, mask=mask)
        else:
            click.echo(_colored("[!] No parameters found. Defaulting to standard neural probe.", YELLOW))
            targets = [f"http://{domain}/?id=FUZZ", f"http://{domain}/?page=FUZZ", f"http://{domain}/?debug=FUZZ"]
    else:
        # Standard mode if FUZZ is present or it's a specific path
        if 'FUZZ' not in url: url += "?id=FUZZ"
        targets = [url]

    # If targets were not processed in the recon block, process them here
    if targets:
        cpp_engine = CPPEngine()
        for t in targets:
            cpp_engine.run(t, payloads or "default", verbose=verbose, mask=mask)
