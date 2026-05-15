import click
import json
import os
import sys

try:
    from pygments import highlight
    from pygments.lexers import JsonLexer
    from pygments.formatters import TerminalFormatter
    PYGMENTS_AVAILABLE = True
except ImportError:
    PYGMENTS_AVAILABLE = False

from .go_bridge import run_go_engine

# --- AESTHETIC COLORS ---
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
B_RED = '\033[1;91m'
B_CYAN = '\033[1;96m'
RESET = '\033[0m'

def _colored(text, color_code):
    return f"{color_code}{text}{RESET}"

# --- [ AUTOMATED FLAG INTEGRATION ] ---
FLAG_GROUPS = {
    "CORE": ["threads", "timeout", "debug"],
    "TARGET IDENTITY": ["whois", "whois-full", "registrar", "org", "contacts"],
    "DNS ENUMERATION": ["dns", "dns-bruteforce", "dns-zone-transfer", "dns-history", "passive-dns"],
    "NETWORK": ["port-scan", "udp", "service-detect", "banner", "os-detect", "traceroute"],
    "WEB & TLS": ["http", "headers", "tls", "tls-deep", "ciphers", "ssl-cert", "cert-transparency"],
    "TECHNOLOGY": ["tech", "tech-deep", "cms-detect", "framework-detect", "js-libs"],
    "SUBDOMAIN & ASSET": ["subdomains", "sub-passive", "sub-active", "sub-bruteforce", "sub-takeover", "asset-discovery"],
    "FILE & DIRECTORY": ["fuzz", "dirscan", "filescan", "sensitive-files", "backup-files"],
    "AUTH": ["auth-detect", "session-analysis", "jwt-analysis", "oauth-check", "mfa-detect"],
    "API": ["api", "api-discovery", "graphql", "swagger", "postman-leak", "api-auth"],
    "CLOUD": ["cloud", "s3-scan", "firebase", "azure", "gcp", "third-party", "cdn-detect", "waf-detect", "origin-ip"],
    "JAVASCRIPT": ["js", "js-endpoints", "js-secrets", "js-map"],
    "BEHAVIOR": ["behavior", "rate-limit-detect", "anomaly-detect", "logic-analysis"],
    "OSINT": ["osint", "employees", "emails", "github", "leaks", "darkweb"],
    "MODES": ["quick", "recon", "full", "stealth", "aggressive"],
}

FLAG_DESCRIPTIONS = {
    "threads": "Number of parallel workers for high-speed processing",
    "timeout": "Tactical timeout duration per request (seconds)",
    "debug": "Enable debug mode for deep diagnostics",
    "whois": "Retrieve deep WHOIS target data",
    "whois-full": "Recursive and full WHOIS data extraction",
    "registrar": "Identify Registrar & IANA ID",
    "org": "Registrant Organization Information",
    "contacts": "Extract administrative emails & contacts",
    "dns": "Basic DNS queries (A, MX, NS, TXT)",
    "dns-bruteforce": "Subdomain enumeration via DNS brute-force",
    "dns-zone-transfer": "AXFR zone transfer vulnerability audit",
    "dns-history": "Passive DNS history audit",
    "passive-dns": "DNS data correlation from passive sources",
    "port-scan": "Fast port scanning & service discovery",
    "udp": "Tactical UDP protocol scanning",
    "service-detect": "Identify service versions & banners",
    "banner": "Raw service banner grabbing",
    "os-detect": "OS fingerprinting & heuristics",
    "traceroute": "Map network path to target",
    "http": "Advanced HTTP/S protocol audit",
    "headers": "Tactical security header analysis",
    "tls": "Basic TLS/SSL forensic audit",
    "tls-deep": "Deep TLS protocol & cipher analysis",
    "ciphers": "Audit supported cipher suites",
    "ssl-cert": "Full SSL certificate chain analysis",
    "cert-transparency": "Certificate Transparency (CT) log audit",
    "tech": "Technology stack mapping",
    "tech-deep": "Deep technology & version analysis",
    "cms-detect": "Identify CMS (WordPress, etc.)",
    "framework-detect": "Backend framework & library detection",
    "js-libs": "Identify client-side JavaScript libraries",
    "subdomains": "Comprehensive subdomain enumeration",
    "sub-passive": "Passive subdomain discovery",
    "sub-active": "Active verification of discovered subdomains",
    "sub-bruteforce": "Advanced subdomain brute-force",
    "sub-takeover": "Check for potential subdomain takeover",
    "asset-discovery": "Related digital asset discovery",
    "fuzz": "Fuzz URL paths & hidden endpoints",
    "dirscan": "Tactical web directory scanning",
    "filescan": "Scan for sensitive files & configs",
    "sensitive-files": "Search for credentials & sensitive files",
    "backup-files": "Detect public backup files",
    "auth-detect": "Identify login & authentication mechanisms",
    "session-analysis": "Session & cookie security analysis",
    "jwt-analysis": "JWT token security audit",
    "oauth-check": "OAuth/OpenID configuration check",
    "mfa-detect": "Detect presence of MFA/2FA protection",
    "api": "Detect target API stack",
    "api-discovery": "Hidden API endpoint discovery",
    "graphql": "Audit & detect GraphQL endpoints",
    "swagger": "Check API documentation (Swagger/OAS)",
    "postman-leak": "Search for Postman collection leaks",
    "api-auth": "API authentication mechanism analysis",
    "cloud": "Detect cloud infrastructure (AWS, Azure, GCP)",
    "s3-scan": "Audit S3 bucket/Cloud Storage permissions",
    "firebase": "Firebase database security check",
    "azure": "Discover assets in Azure ecosystem",
    "gcp": "Discover assets in GCP ecosystem",
    "third-party": "Identify third-party integrations",
    "cdn-detect": "Identify CDN & WAF edge nodes",
    "waf-detect": "Identify WAF/IPS/IDS systems",
    "origin-ip": "Search for real origin IP behind CDN",
    "js": "Static analysis of JavaScript files",
    "js-endpoints": "Extract endpoints from JS code",
    "js-secrets": "Detect secrets/tokens in JS files",
    "js-map": "JavaScript source map analysis",
    "behavior": "Analyze server response behavior patterns",
    "rate-limit-detect": "Detect rate limiting mechanisms",
    "anomaly-detect": "Identify tactical response anomalies",
    "logic-analysis": "Surface application logic analysis",
    "osint": "Open source intelligence gathering",
    "employees": "Public employee profile information",
    "emails": "Extract target-related email addresses",
    "github": "Audit related public GitHub repositories",
    "leaks": "Historical data leak & credential audit",
    "darkweb": "Search for target references in Dark Web",
    "quick": "Fast & lightweight scanning mode",
    "recon": "Industry standard reconnaissance mode",
    "full": "Comprehensive intelligence execution (Full Module)",
    "stealth": "Silent operation mode (Ghost Mode)",
    "aggressive": "High intensity tactical audit",
}

def add_tactical_flags(cmd):
    """Surgically injects all tactical flags into the provided command."""
    for group_name, flags in FLAG_GROUPS.items():
        for flag in flags:
            desc = FLAG_DESCRIPTIONS.get(flag, "Dynamic tactical flag")
            
            # Numeric values for performance controls, others are boolean flags
            if flag in ['threads', 'timeout']:
                cmd = click.option(f'--{flag}', type=int, help=desc)(cmd)
            else:
                cmd = click.option(f'--{flag}', is_flag=True, help=desc)(cmd)
    return cmd

@click.group(invoke_without_command=True)
@click.pass_context
def hunter_cli(ctx):
    if ctx.invoked_subcommand is None:
        _show_banner_internal()
        print(ctx.get_help())

def _show_banner_internal():
    banner = f"""{MAGENTA}
   ╦ ╦ ╦ ╦ ╔╗╔ ╔╦╗ ╔═╗ ╦═╗
   ╠═╣ ║ ║ ║║║  ║  ║╣  ╠╦╝
   ╩ ╩ ╚═╝ ╝╚╝  ╩  ╚═╝ ╩╚═
   {CYAN}[ NEXT-GEN HYBRID RECONNAISSANCE ENGINE V3.0 ]{RESET}
    """
    print(banner)

@hunter_cli.command(name='banner')
def banner_command():
    """Show the Tech Hunter banner."""
    _show_banner_internal()

# --- CORE RECONNAISSANCE LOGIC (RAW FUNCTION) ---
def run_tactical_engine(target, **opts):
    """Pure logic to trigger the Go/Rust/C++ engines."""
    _show_banner_internal()
    click.secho(f"[*] Initiating Tech Hunter on: {target}", fg='cyan', bold=True)
    
    # Trigger Bridge to Go/Rust/C++ Engine
    result = run_go_engine(target, **opts)
    
    if isinstance(result, dict) and "error" in result:
        click.secho(f"[!] Engine Error: {result['error']}", fg='red', bold=True)
        return

    # Display Intelligence Map
    click.secho("\n[!] INTELLIGENCE MAP GENERATED:", fg='green', bold=True)
    
    if isinstance(result, str):
        print(result)
    else:
        formatted_json = json.dumps(result, indent=2)
        if PYGMENTS_AVAILABLE:
            print(highlight(formatted_json, JsonLexer(), TerminalFormatter()))
        else:
            print(formatted_json)

# --- FRAMEWORK INTEGRATION CALLBACK ---
@click.option('-t', '--target', required=True, help=_colored('Primary target (domain or IP)', BLUE))
def detect_callback(target, **opts):
    """Industrial-grade Hybrid Reconnaissance Engine"""
    run_tactical_engine(target, **opts)

# Apply tactical flags
detect_callback = add_tactical_flags(detect_callback)

# Create the command for framework
detect = click.command(name='tech-hunter')(detect_callback)

# --- STANDALONE CLI CALLBACK ---
@click.option('-t', '--target', required=True, help=_colored('Primary target (domain or IP)', BLUE))
def standalone_callback(target, **opts):
    """Comprehensive Infrastructure Audit"""
    run_tactical_engine(target, **opts)

# Apply tactical flags
standalone_callback = add_tactical_flags(standalone_callback)

# Register with hunter_cli
hunter_cli.add_command(click.command(name='scan')(standalone_callback))

if __name__ == '__main__':
    hunter_cli()
