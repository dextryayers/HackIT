# HackIt Framework - Module Reference & API Guide

## 📚 Complete Module Inventory

### Python Modules (Direct Import)

#### 1. CLI Module (`hackit.cli`)
```python
# Entry point - All CLI commands defined here
from hackit.cli import cli

# Global Options
cli(proxy=None, no_verify=False, no_banner=False, verbose=False)

# Command Groups
hackit.cli.ports      # Port scanning group
hackit.cli.web        # Web tools group  
hackit.cli.vuln       # Vulnerability group
hackit.cli.recon      # Reconnaissance group
hackit.cli.ssl        # SSL/TLS group
hackit.cli.util       # Utility group
```

---

#### 2. Configuration (`hackit.config`)
```python
from hackit.config import (
    load_config,          # Load ~/.hackit_config.json
    save_config,          # Save config to disk
    get_theme,            # Get current theme
    set_theme,            # Update theme
    get_user_info         # Get (user, hostname)
)

# Functions
load_config() → Dict
    Returns: {theme, user, hostname, aggressive_default, stealth_default, ai_keys, ai_provider}

save_config(config: Dict) → bool
    Returns: True if successful, False on error

get_theme() → str
    Returns: Current theme name (default: "kali")

set_theme(theme_name: str) → None

get_user_info() → Tuple[str, str]
    Returns: (username, hostname)
```

---

#### 3. Port Scanner (`hackit.port_scanner`)
```python
from hackit.port_scanner.core import PortScanner

class PortScanner:
    def __init__(self) → None
    
    def scan_port(host: str, port: int, timeout: float) → Dict
        Returns: {port, status, service, banner}
        
    def scan(host: str, ports=None, timeout=1, threads=100) → List[Dict]
        Arguments:
            host: Target hostname/IP
            ports: None (1-1024), "range" (e.g., "80-443"), or str comma-separated
            timeout: Seconds per port (default: 1)
            threads: Thread pool size (default: 100)
        Returns: List of open port dicts

# Example
from hackit.port_scanner.core import PortScanner
scanner = PortScanner()
results = scanner.scan("example.com", ports="80,443,8080", timeout=2, threads=50)
print(results)
# [{port: 80, status: "open", service: "http", banner: "..."},
#  {port: 443, status: "open", service: "https", banner: "..."}]
```

---

#### 4. Directory Finder (`hackit.dir_finder`)
```python
from hackit.dir_finder.analyzer import SmartAnalyzer

class SmartAnalyzer:
    def __init__(self, target_url: str) → None
    
    def detect_tech(self) → None
        # Populates self.tech_stack with detected technologies
        
    def extract_js_endpoints(self) → None
        # Populates self.found_endpoints from JavaScript files
        
    def detect_waf(self) → str
        Returns: WAF name or "None Detected"
        
    def find_backups(self) → None
        # Searches for backup files (.zip, .tar.gz, .sql, etc.)
        
    def run(self) → None
        # Execute all analyses

# Example
analyzer = SmartAnalyzer("https://target.com")
analyzer.run()
print(f"Tech Stack: {analyzer.tech_stack}")
print(f"Endpoints: {analyzer.found_endpoints}")
print(f"Backups: {analyzer.found_endpoints}")
```

---

#### 5. Tech Hunter (`hackit.tech_hunter`)
```python
from hackit.tech_hunter.brain import correlate, extract_intelligence

# Functions
correlate(results: List[Dict]) → str
    Generates intelligence reports from scan results
    
extract_intelligence(target_url: str) → Dict
    Returns full intelligence: tech, whois, dns, network, etc.

# Supported Technologies (200+)
CMS:             WordPress, Drupal, Ghost, TYPO3, Wix, Squarespace
Frontend:        React, Vue, Angular, Astro, Svelte, Next.js
Backend:         Node.js, Django, Rails, Laravel, FastAPI
Database:        MySQL, PostgreSQL, MongoDB, Redis
Hosting:         AWS, Azure, Google Cloud, Vercel, Netlify, Cloudflare
JS Libraries:    GSAP, Alpine.js, Preact, Solid.js, htmx
```

---

#### 6. NSE Scripts Engine (`hackit.nse_engine`)
```python
from hackit.nse_engine import load_scripts, run_scripts_for_port

def load_scripts() → List[str]
    # Auto-discovers scripts in hackit/nse_scripts/
    Returns: List of script module names

def run_scripts_for_port(script_names: List[str], host: str, port: int, info: Dict) → List[Dict]
    Arguments:
        script_names: List of script names to run
        host: Target host
        port: Target port
        info: Port info {status, banner, service, ...}
    Returns: List of finding dicts

# Script Template (in hackit/nse_scripts/my_script.py)
def run(host: str, port: int, info: Dict):
    findings = []
    if info.get('service') == 'http':
        findings.append({
            'vuln': 'CVE-2021-12345',
            'severity': 'high',
            'description': 'Example vulnerability'
        })
    return findings

# Usage
scripts = load_scripts()  # ['http_server_info']
findings = run_scripts_for_port(scripts, 'target.com', 80, {...})
```

---

#### 7. AI Agent (`hackit.agent`)
```python
from hackit.agent.brain import AIHyperBrain
from hackit.agent.commands import COMMAND_MODES

class AIHyperBrain:
    def __init__(self) → None
        # Loads config and initializes AI provider
        
    def chat(prompt: str) → str
        # Send prompt to AI, returns response
        # Supports command routing (/mode, /payload, etc.)
        
    def _invoke_engine(prompt: str, system_prompt: str, mode: str) → str
        # Internal: Calls Go engine for provider handling

# Command Modes
/risk       Risk assessment
/attack     Attack vector suggestions
/vuln       Vulnerability analysis
/payload    Payload generation
/build      Build programs from scratch
/analyze    Security analysis

# Example
brain = AIHyperBrain()
response = brain.chat("/payload xss traditional")
print(response)
```

---

#### 8. NSE Script Loader (`hackit.nse_engine`)
```python
from hackit.nse_engine import run_scripts_for_port

# Built-in scripts
hackit.nse_scripts.http_server_info
    # Detection of HTTP server software and version

# Usage
findings = run_scripts_for_port(['http_server_info'], 'target.com', 80, {...})
```

---

#### 9. Console (`hackit.console`)
```python
from hackit.console import start_console

def start_console(cli_group) → None
    # Start interactive console with given CLI group
    # Features: Tab completion, history, themed prompts

# Example from cli.py
if ctx.invoked_subcommand is None:
    from hackit.console import start_console
    start_console(cli)
```

---

#### 10. UI Utilities (`hackit.ui`)
```python
from hackit.ui import (
    _colored,              # Color text
    display_banner,        # Show ASCII banner
    B_GREEN, YELLOW, RED,  # Color constants
    DIM, BOLD
)

# Functions
_colored(text: str, color: str) → str
    Returns: Color-formatted text for terminal

display_banner() → None
    Prints HackIt ASCII banner

# Colors
B_GREEN, B_CYAN, B_MAGENTA, B_BLUE, WHITE, YELLOW, RED, DIM, BOLD
```

---

### Bridge Modules (Python to Go/C/C++/Rust)

#### Go Bridges (Pattern)
All modules with Go implementations use this pattern:

```python
import os
import subprocess
from typing import List, Dict, Any

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.binary_name = 'worker.exe' if os.name == 'nt' else 'worker'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.source_path = os.path.join(self.go_dir, 'main.go')

    def ensure_compiled(self) -> bool:
        """Check if binary is up-to-date, compile if needed"""
        if not os.path.exists(self.binary_path) or \
           os.path.getmtime(self.source_path) > os.path.getmtime(self.binary_path):
            try:
                subprocess.run(['go', 'build', '-o', self.binary_name, '.'], 
                             cwd=self.go_dir, check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError:
                return False
        return True

    def run(self, *args, **kwargs) -> Any:
        """Execute the Go binary with arguments"""
        if not self.ensure_compiled():
            raise RuntimeError("Go compilation failed")
        
        cmd = [self.binary_path] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
```

**Modules Using GoEngine:**
- `hackit.port_scanner` → Port scanning
- `hackit.subdomain` → Subdomain enumeration
- `hackit.xss` → XSS detection
- `hackit.web_fuzzer` → Web fuzzing
- `hackit.header_audit` → HTTP header analysis
- `hackit.js` → JavaScript analysis
- `hackit.redirect` → Redirect following
- `hackit.cve` → CVE correlation
- `hackit.network_scanner` → Network scanning
- `hackit.agent` → AI provider routing

---

### CLI Commands Reference

```bash
# PORT SCANNING
hackit ports scan -p 80,443 --targets example.com
hackit ports scan -p 1-10000 --targets 192.168.1.1 --timeout 2 --threads 200

# DIRECTORY FINDING
hackit dirfinder --url https://target.com --wordlist common.txt

# TECHNOLOGY DETECTION
hackit web tech --url https://target.com
hackit recon tech-hunter --url https://target.com

# HTTP HEADER ANALYSIS
hackit web headers --url https://target.com

# WEB FUZZING
hackit web fuzz --url https://target.com/FUZZ --wordlist common.txt

# SUBDOMAIN ENUMERATION
hackit recon subdomains -d target.com --passive-only
hackit recon subdomains -d target.com --active-only -w subdomains.txt

# XSS SCANNING
hackit vuln xss --url https://target.com/page.php?id=1

# SQL INJECTION
hackit vuln sqli --url https://target.com --param id

# SSL/TLS ANALYSIS
hackit ssl check --host target.com --port 443

# CVE checking
hackit util cve --tech wordpress --version 6.0

# IP RANGE SCANNING
hackit recon ips --range 192.168.1.0/24

# JavaScript Analysis
hackit web js --url https://target.com

# Redirect Detection
hackit vuln redirect --url https://target.com

# AI AGENT
hackit agent
hackit agent "How do I bypass WAF?"
hackit agent "/payload xss"
```

---

## 🔧 Go Binary Interface

### Common Patterns

**Argument-based Configuration:**
```bash
./worker -domain target.com -wordlist subs.txt -threads 100 -verbose
./worker -url https://target.com/page.php?id=1
./worker -host target.com -port 443
```

**Output Format:** Always JSON
```json
{
    "domain": "target.com",
    "subdomains": [
        {"name": "www.target.com", "ip": "1.2.3.4", "status": 200},
        {"name": "api.target.com", "ip": "1.2.3.5", "status": 200}
    ]
}
```

**Error Handling:**
```json
{"error": "Connection timeout"}
{"error": "Invalid domain format"}
```

---

## 🐍 Python Function Signatures (All Modules)

### Port Scanner
```python
PortScanner().scan(
    host: str,           # e.g., "example.com" or "192.168.1.1"
    ports: str|List = None,  # "80,443" or [80, 443]
    timeout: float = 1,  # Seconds
    threads: int = 100   # Thread workers
) → List[Dict]
```

### Directory Finder
```python
SmartAnalyzer(target_url: str).run() → None
# Populates:
#   .tech_stack: List[str]
#   .found_endpoints: Set[str]
```

### Tech Hunter
```python
correlate(results: List[Dict]) → str  # Intelligence report

extract_intelligence(url: str) → Dict  # Full analysis
```

### NSE Engine
```python
load_scripts() → List[str]  # Available script names

run_scripts_for_port(
    names: List[str],
    host: str,
    port: int,
    info: Dict
) → List[Dict]  # Findings
```

### AI Agent
```python
AIHyperBrain().chat(prompt: str) → str  # AI response
```

---

## 🔐 Environment Variables

Set by CLI globally:

```python
os.environ['HACKIT_PROXY']   # e.g., 'http://127.0.0.1:8080'
os.environ['HACKIT_VERIFY']  # '1' (verify SSL) or '0' (skip)
os.environ['HACKIT_NO_BANNER'] # '1' to disable banner
```

Modules can access:
```python
import os
proxy = os.environ.get('HACKIT_PROXY')
verify = os.environ.get('HACKIT_VERIFY') == '1'
```

---

## 🎨 Configuration Schema

`~/.hackit_config.json`:
```json
{
    "theme": "kali",
    "user": "username",
    "hostname": "computer-name",
    "aggressive_default": true,
    "stealth_default": true,
    "ai_keys": {
        "gemini": "your-key-here",
        "groq": "your-key-here",
        "openai": "your-key-here",
        "claude": "your-key-here",
        "deepseek": "your-key-here",
        "openrouter": "your-key-here"
    },
    "ai_provider": "gemini"
}
```

---

## 🚀 Performance Benchmarks

| Module | Language | Speed | Concurrency |
|--------|----------|-------|-------------|
| Port Scanner (Python) | Python | ~100 ports/sec | 100 threads |
| Port Scanner (Go) | Go | ~10,000/sec | Goroutines |
| Dir Finder (Python) | Python | ~50 req/sec | 100 threads |
| Dir Finder (Rust) | Rust | ~5,000 req/sec | Unlimited |
| Tech Detection | Python | Real-time | Single |
| Subdomain Enum (Go) | Go | ~1,000/sec | 100 goroutines |
| Web Fuzzer (Rust) | Rust | ~10,000/sec | Unlimited |
| SQL Injection (C++) | C++ | Raw performance | Single |

---

## 🔍 Error Handling Patterns

### Try-Except in Python Modules:
```python
try:
    result = module_function(args)
except subprocess.CalledProcessError as e:
    print(f"[!] Error: {e}")
    return None or []
except Exception as e:
    print(f"[!] Unexpected error: {e}")
    return None or []
```

### Graceful Degradation:
```python
# AI Agent Failover
if AI_Provider_1_fails:
    try AI_Provider_2
    if Provider_2_fails:
        try AI_Provider_3
        # ... continue or inform user
```

### NSE Script Isolation:
```python
# One script error doesn't crash engine
try:
    findings = script.run(host, port, info)
except Exception:
    findings = [{'script': name, 'error': 'execution failed'}]
```

---

## 📊 Data Structures

### Port Scan Result
```python
{
    'port': int,
    'status': 'open' | 'closed',
    'service': str,           # e.g., 'ssh', 'http'
    'banner': str            # Service banner
}
```

### Subdomain Result
```python
{
    'sub': str,              # Subdomain name
    'ip': str,               # Resolved IP
    'port': int,
    'status': int,           # HTTP status
    'server': str,           # Server header
    'title': str,            # HTML title
    'tech': List[str],       # Detected technologies
    'asn': str,
    'whois': Dict,
    'geo': str,
    'cname': str,
    'ptr': str,
    'service': str
}
```

### Tech Detection Result
```python
{
    'url': str,
    'technologies': [
        {
            'name': str,           # e.g., 'WordPress'
            'category': str,       # e.g., 'CMS'
            'version': str|None,
            'confidence': float    # 0.0-1.0
        }
    ],
    'waf': str|None,
    'endpoints': List[str],
    'tech_stack': List[str]
}
```

### AI Agent Response
```python
{
    'text': str,             # Response content
    'model': str,            # Model used
    'provider': str,         # AI provider
    'tokens': {
        'input': int,
        'output': int
    }
}
```

---

## Next Steps for Analysis
See [CODEBASE_ANALYSIS.md](CODEBASE_ANALYSIS.md) for architecture overview or continue with specific module exploration.
