# HackIt Framework - Quick Reference Guide

## 🚀 Quick Start

### Installation
```bash
pip install -r requirements.txt
python setup.py install
# or
pip install -e .
```

### First Run
```bash
hackit --version  # Should print 2.1.0
hackit ports scan -p 80 localhost  # Test basic functionality
```

### Interactive Console
```bash
hackit  # Enter interactive console (no subcommand)
```

---

## 📋 Common Command Patterns

### Port Scanning
```bash
# Basic scan
hackit ports scan -p 80,443 target.com

# Full range
hackit ports scan -p 1-10000 192.168.1.1

# With custom timeout
hackit ports scan -p 1-1000 target.com --timeout 5 --threads 200
```

### Directory Discovery
```bash
hackit dirfinder --url https://target.com --wordlist wordlists/common.txt
```

### Technology Detection
```bash
# Web tech
hackit web tech --url https://target.com

# Tech hunter (OSINT)
hackit recon tech-hunter --url https://target.com
```

### Subdomain Enumeration
```bash
# Passive only
hackit recon subdomains -d target.com --passive-only

# Active with wordlist
hackit recon subdomains -d target.com -w wordlists/subdomains.txt

# Aggressive with takeover check
hackit recon subdomains -d target.com --active-only --takeover --recursive
```

### Vulnerability Scanning
```bash
# XSS Detection
hackit vuln xss --url https://target.com/page?id=1

# SQL Injection
hackit vuln sqli --url https://target.com --param id

# Open redirects
hackit vuln redirect --url https://target.com
```

### Web Analysis
```bash
# HTTP Headers
hackit web headers --url https://target.com

# JavaScript analysis
hackit web js --url https://target.com

# Web fuzzing
hackit web fuzz --url https://target.com/admin/FUZZ --wordlist common.txt
```

### SSL/TLS Analysis
```bash
hackit ssl check --host target.com --port 443
```

### AI Agent
```bash
# Interactive agent
hackit agent

# Query with prompt
hackit agent "What are the CVEs for WordPress 6.0?"

# Specialized modes
hackit agent "/payload xss"
hackit agent "/risk high-value-target"
hackit agent "/build scanner for API endpoints"
```

---

## ⚙️ Global Options (Available for all commands)

```bash
hackit [GLOBAL_OPTIONS] [COMMAND]

--proxy PROXY_URL          # Set proxy (e.g., http://127.0.0.1:8080)
--no-verify               # Disable SSL certificate verification
--no-banner               # Suppress startup banner
--verbose                 # Enable debug logging
--version                 # Show version
--help                    # Show help
```

### Example with Global Options
```bash
hackit --proxy http://127.0.0.1:8080 --no-verify ports scan -p 80 target.com
hackit --verbose web tech --url https://target.com
```

---

## 🔧 Configuration File

**Location:** `~/.hackit_config.json`

**View Configuration:**
```bash
cat ~/.hackit_config.json
```

**Edit Configuration:**
```json
{
    "theme": "kali",
    "user": "your-username",
    "hostname": "machine-name",
    "aggressive_default": true,
    "stealth_default": true,
    "ai_keys": {
        "gemini": "YOUR_GEMINI_KEY",
        "groq": "YOUR_GROQ_KEY",
        "openai": "YOUR_OPENAI_KEY",
        "claude": "YOUR_CLAUDE_KEY",
        "deepseek": "YOUR_DEEPSEEK_KEY",
        "openrouter": "YOUR_OPENROUTER_KEY"
    },
    "ai_provider": "gemini"
}
```

**To add AI key:**
```bash
# Manual: Edit ~/.hackit_config.json and add your key
# Or via code:
from hackit.config import load_config, save_config
config = load_config()
config['ai_keys']['gemini'] = 'your_key_here'
save_config(config)
```

---

## 🎯 Module Reference

### Module Organization
```
hackit/
├── cli.py              # Entry point
├── config.py           # Configuration
├── ui.py               # Display/colors
├── console.py          # Interactive shell
├── nse_engine.py       # Script engine
├── agent/              # AI integration
├── port_scanner/       # Port scanning
├── dir_finder/         # Directory brute-force
├── subdomain/          # Subdomain enumeration
├── tech_hunter/        # Technology detection
├── web_fuzzer/         # Web fuzzing
├── xss/                # XSS detection
├── sqli/               # SQL injection testing
├── ssl_tool/           # SSL/TLS analysis
├── header_audit/       # HTTP header analysis
├── js/                 # JavaScript analysis
├── redirect/           # Redirect detection
├── cve/                # CVE correlation
├── params/             # Parameter fuzzing
├── network_scanner/    # Network scanning
└── nse_scripts/        # Custom probes
```

---

## 🐍 Python API (For Scripts)

### Import and Use Modules Directly
```python
from hackit.port_scanner.core import PortScanner
from hackit.dir_finder.analyzer import SmartAnalyzer
from hackit.tech_hunter.brain import correlate
from hackit.agent.brain import AIHyperBrain
from hackit.nse_engine import load_scripts, run_scripts_for_port

# Port scan
scanner = PortScanner()
results = scanner.scan("target.com", ports="80,443", timeout=2)
print(results)

# Directory finder
analyzer = SmartAnalyzer("https://target.com")
analyzer.run()
print(analyzer.tech_stack)
print(analyzer.found_endpoints)

# Tech detection
tech_results = correlate([...])

# AI chat
brain = AIHyperBrain()
response = brain.chat("Tell me about WordPress vulnerabilities")
```

---

## 🔍 Troubleshooting

### Go Compilation Fails
```
[!] Compilation failed: command not found: go

Solution:
1. Install Go 1.21+: https://golang.org/dl/
2. Verify: go version
3. Restart terminal if just installed
```

### SSL Certificate Errors
```
[!] SSL certificate verify failed

Solution:
# Option 1: Use --no-verify flag
hackit --no-verify ports scan -p 443 target.com

# Option 2: Update certificates
pip install --upgrade certifi
```

### Module Import Errors
```
[!] ModuleNotFoundError: No module named 'hackit.module'

Solution:
1. Reinstall: pip install -e .
2. Check Python version: python --version (must be ≥ 3.8)
3. Virtual environment: source venv/bin/activate
```

### AI Agent Errors
```
[!] All providers exhausted

Solution:
1. Check API keys: cat ~/.hackit_config.json
2. Verify API key validity
3. Check internet connection
4. Try different provider: Edit config.json and set ai_provider
```

### Timeout Issues
```
[!] Connection timeout

Solution:
# Increase timeout
hackit ports scan -p 80 target.com --timeout 10

# Reduce threads to avoid network congestion  
hackit ports scan -p 1-1000 target.com --threads 50
```

---

## 📊 Output Formats

### Default Output (Colored Text)
```
[+] Open Ports on target.com
  Port 80   : HTTP
  Port 443  : HTTPS
  Port 3306 : MySQL
```

### JSON Output (for parsing)
```json
[
  {"port": 80, "status": "open", "service": "http", "banner": "..."},
  {"port": 443, "status": "open", "service": "https", "banner": "..."}
]
```

### Table Output
```
┌───────┬────────┬─────────┬──────────┐
│ Port  │ Status │ Service │ Banner   │
├───────┼────────┼─────────┼──────────┤
│ 80    │ open   │ http    │ Apache.. │
│ 443   │ open   │ https   │ nginx    │
└───────┴────────┴─────────┴──────────┘
```

---

## 🔐 Best Practices

### Reconnaissance Safety
1. **Always get authorization** before testing
2. **Use stealth mode** for reconnaissance
3. **Scan slowly** to avoid detection (timeout=5, threads=10)
4. **Rotate user-agents** for web requests
5. **Use proxy** to mask your IP (--proxy flag)

### Data Protection
1. **Store results securely** (chmod 600 on files)
2. **Encrypt sensitive data**
3. **Clear history** after sensitive scans
4. **Don't hardcode credentials** in scripts

### Performance Optimization
1. **Use Rust engine** for brute-forcing (100x faster)
2. **Go modules** for concurrent operations
3. **Batch tests** when possible
4. **Cache DNS** results between runs

---

## 🚀 Advanced Usage

### Custom NSE Script
Create `hackit/nse_scripts/my_check.py`:
```python
def run(host: str, port: int, info: dict):
    """
    Custom vulnerability check.
    Returns list of finding dicts or empty list.
    """
    findings = []
    
    # Custom logic here
    if "vulnerable_banner" in info.get("banner", ""):
        findings.append({
            "vuln": "Custom_Vuln_001",
            "severity": "high",
            "description": "Custom vulnerability detected"
        })
    
    return findings
```

Then run:
```bash
# Script runs automatically as part of port scan
hackit ports scan -p 80 target.com
```

### Chaining Commands (Console Mode)
```
hackit> ports scan -p 80,443 target.com
hackit> subdomain enumerate -d target.com
hackit> web tech --url https://target.com
hackit> agent "Analyze results and suggest next steps"
```

### Programmatic Usage
```python
#!/usr/bin/env python3
from hackit.cli import cli
from click.testing import CliRunner

runner = CliRunner()
result = runner.invoke(cli, ['ports', 'scan', '-p', '80', 'target.com'])
print(result.output)
print(result.exit_code)
```

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| [CODEBASE_ANALYSIS.md](CODEBASE_ANALYSIS.md) | Complete codebase overview |
| [MODULE_API_REFERENCE.md](MODULE_API_REFERENCE.md) | Detailed module APIs |
| [DATAFLOW_ARCHITECTURE.md](DATAFLOW_ARCHITECTURE.md) | Data flow & execution diagrams |
| [QUICK_REFERENCE.md](QUICK_REFERENCE.md) | This file |

---

## 🎓 Learning Path

1. **Start:** Read [CODEBASE_ANALYSIS.md](CODEBASE_ANALYSIS.md) for overview
2. **Explore:** Review [MODULE_API_REFERENCE.md](MODULE_API_REFERENCE.md) for specific modules
3. **Understand:** Study [DATAFLOW_ARCHITECTURE.md](DATAFLOW_ARCHITECTURE.md) for execution flow
4. **Practice:** Use commands from this quick reference guide
5. **Build:** Create custom NSE scripts or extend modules

---

## 🔗 Quick Links

- **Repository:** `d:\web\hacks\hackstools\`
- **Entry Point:** `hackit/cli.py`
- **Configuration:** `~/.hackit_config.json`
- **Scripts:** `hackit/nse_scripts/`
- **Wordlists:** `wordlists/`
- **History:** `~/.hackit_history` (console commands)

---

## 💡 Tips & Tricks

### Speed Up Scanning
```bash
# Rust engine is fastest for fuzzing
hackit web fuzz --url target.com/FUZZ --wordlist large.txt  # Uses Rust

# Go is best for concurrency
hackit recon subdomains -d target.com --threads 500  # Uses Go
```

### Save Results
```bash
# Redirect to file (shell capability)
hackit ports scan -p 80 target.com > results.json

# Agent can format results
hackit agent "Format these port scan results as a CSV: ..."
```

### Combine Tools
```bash
# Scan, detect tech, find CVEs
hackit ports scan -p 80 target.com
hackit web tech --url https://target.com
hackit util cve --tech wordpress --version 6.0
```

### Debug Execution
```bash
# Enable verbose logging
hackit --verbose ports scan -p 80 target.com

# Check if Go is compiled
ls hackit/port_scanner/go/worker.exe

# Manually compile
cd hackit/port_scanner/go && go build -o worker.exe .
```

---

**Framework Version:** 2.1.0
**Last Updated:** 2026-05-15
**Author:** AniipID
