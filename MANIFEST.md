# HackIt - Complete Tools Manifest & Documentation

## Project Information
- **Name**: HackIt
- **Version**: 1.0.0
- **Type**: Security Testing CLI Tool Suite
- **Author**: Security Researcher
- **Python Version**: 3.8+
- **Location**: `/home/aniipid/tools/tools2`

---

## 📋 All Available Tools

### PORTS GROUP - Port Scanning
```
hackit ports scan
├── --host [REQUIRED]        Target host
├── --ports [default: 1-1000] Port range (e.g., 1-1000 or 22,80,443)
├── --timeout [default: 3]    Timeout per port in seconds
├── --threads [default: 100]  Number of concurrent workers
├── --open-only [FLAG]        Show only open ports
└── --output                  Save results to JSON file
```
**Features**: Async TCP scanning, multi-threaded, JSON export

---

### WEB GROUP - Web Vulnerability & Analysis Tools

#### web headers - HTTP Security Headers & TLS Analysis
```
hackit web headers
├── --url [REQUIRED]    Target URL
├── --headers [FLAG]    Check security headers
├── --tls [FLAG]        Check TLS/SSL info
├── --all [FLAG]        Check both headers and TLS
└── --output            Save results to JSON
```
**Checks**: HSTS, CSP, XFO, Server banner, TLS version, Weak protocols

#### web tech - Technology Detection
```
hackit web tech
├── --url [REQUIRED]    Target URL
└── --output            Save results to JSON
```
**Detects**: CMS (WordPress, Drupal, Joomla), Frameworks (Laravel, Django, React, Vue), Servers (Apache, Nginx, IIS)

#### web dirs - Directory Bruteforcer
```
hackit web dirs
├── --url [REQUIRED]         Target URL
├── --wordlist [REQUIRED]    Wordlist file
├── --extensions             File extensions (.php,.html,.txt)
├── --timeout [default: 10]  Request timeout
├── --delay [default: 0]     Delay between requests
├── --recursive [FLAG]       Enable recursive scanning
├── --max-depth [default: 2] Max recursion depth
├── --status-codes           Status codes to report
├── --threads [default: 50]  Concurrent requests
├── --proxy                  Proxy URL
└── --output                 Save results to JSON
```
**Features**: Async scanning, recursion, status filtering, extension testing

#### web fuzz - HTTP Parameter Fuzzer
```
hackit web fuzz
├── --url [REQUIRED]         Target URL
├── --method [default: GET]  GET or POST or BOTH
├── --params [REQUIRED]      Parameters to test
├── --payloads [REQUIRED]    Payloads file
├── --timeout [default: 10]  Request timeout
└── --output                 Save results to JSON
```
**Features**: Reflection detection, length analysis, anomaly detection

#### web js - JavaScript Analyzer
```
hackit web js
├── --url [REQUIRED]         Target URL
├── --max-files [default: 50] Max JS files to analyze
├── --timeout [default: 10]  Request timeout
└── --output                 Save results to JSON
```
**Extracts**: API endpoints, secrets, tokens, configuration data

---

### VULN GROUP - Vulnerability Scanners

#### vuln xss - XSS Scanner
```
hackit vuln xss
├── --url [REQUIRED]         Target URL with parameter
├── --params [REQUIRED]      Parameters to test
├── --encoding-test [FLAG]   Test encoding bypasses
├── --timeout [default: 10]  Request timeout
└── --output                 Save results to JSON
```
**Payloads**: Basic, encoded, event handlers, double-encoded

#### vuln sqli - SQL Injection Tester
```
hackit vuln sqli
├── --url [REQUIRED]         Target URL
├── --params [REQUIRED]      Parameters to test
├── --timeout [default: 10]  Request timeout
└── --output                 Save results to JSON
```
**Method**: Boolean-based detection, response diff analysis

#### vuln redirect - Open Redirect Finder
```
hackit vuln redirect
├── --url [REQUIRED]         Target URL
├── --params                 Parameters to test (default: common params)
├── --timeout [default: 10]  Request timeout
└── --output                 Save results to JSON
```
**Features**: Parameter enumeration, redirect chain detection

---

### RECON GROUP - Reconnaissance Tools

#### recon subdomains - Subdomain Brute Forcer
```
hackit recon subdomains
├── --domain [REQUIRED]      Target domain
├── --wordlist [REQUIRED]    Wordlist file
├── --timeout [default: 5]   DNS timeout
├── --check-wildcard [FLAG]  Check for wildcard DNS
└── --output                 Save results to JSON
```
**Features**: Async DNS resolution, wildcard detection

#### recon ips - IP Range Scanner
```
hackit recon ips
├── --cidr [REQUIRED]        CIDR range (e.g., 192.168.1.0/24)
├── --timeout [default: 2]   Ping timeout
└── --output                 Save results to JSON
```
**Features**: CIDR parsing, ping sweep, alive host detection

---

### SSL GROUP - SSL/TLS Analysis

#### ssl check - Certificate Analyzer
```
hackit ssl check
├── --host [REQUIRED]        Target host
├── --port [default: 443]    Port number
├── --timeout [default: 10]  Connection timeout
└── --output                 Save results to JSON
```
**Checks**: Certificate validity, TLS version, cipher strength, expiration, weak protocols

---

### UTIL GROUP - Utility Tools

#### util cve - CVE Vulnerability Checker
```
hackit util cve
├── --software [REQUIRED]        Software name
├── --version [REQUIRED]         Version number
├── --severity [OPTIONAL]        Filter by severity (Critical/High/Medium/Low)
└── --output                     Save results to JSON
```
**Database**: WordPress, Drupal, Apache, Nginx, PHP, and more

---

## 📊 Statistics

- **Total Tools**: 14
- **Tool Groups**: 8
- **Lines of Code**: ~5,000+
- **Supported Modules**: 16
- **Wordlists**: 4
- **Dependencies**: 11

---

## 🗂️ Project Structure

```
/home/aniipid/tools/tools2/
├── hackit/
│   ├── __init__.py
│   ├── cli.py                      # Main CLI interface
│   ├── port_scanner.py             # Async port scanning
│   ├── header_checker.py           # HTTP header analysis
│   ├── subdomain_bruteforcer.py    # DNS enumeration
│   ├── ip_scanner.py               # IP range scanning
│   ├── tech_detector.py            # Technology detection
│   ├── ssl_analyzer.py             # SSL/TLS analysis
│   ├── dir_bruteforcer.py          # Directory brute force
│   ├── param_fuzzer.py             # Parameter fuzzing
│   ├── xss_scanner.py              # XSS detection
│   ├── sqli_tester.py              # SQLi detection
│   ├── redirect_finder.py          # Open redirect detection
│   ├── js_analyzer.py              # JavaScript analysis
│   └── cve_checker.py              # CVE database matching
├── wordlists/
│   ├── common.txt                  # Common directories
│   ├── subdomains.txt              # Common subdomains
│   ├── xss_payloads.txt            # XSS payloads
│   └── fuzzing_payloads.txt        # Fuzzing payloads
├── main.py                         # Entry point
├── hackit.sh                       # Bash wrapper
├── setup.py                        # Installation script
├── requirements.txt                # Python dependencies
├── README.md                       # Main documentation
├── QUICKSTART.md                   # Quick start guide
├── EXAMPLES.md                     # Comprehensive examples
├── CONFIG.md                       # Configuration guide
└── This file                       # Tools manifest
```

---

## 🔧 Dependencies

- **click** (8.1.7) - CLI framework
- **aiohttp** (3.9.1) - Async HTTP
- **asyncio-timeout** (4.0.3) - Async utilities
- **dnspython** (2.4.2) - DNS operations
- **requests** (2.31.0) - HTTP library
- **beautifulsoup4** (4.12.2) - HTML parsing
- **cryptography** (41.0.7) - SSL/TLS handling
- **certifi** (2023.7.22) - SSL certificates
- **urllib3** (2.1.0) - HTTP utilities
- **pysocks** (1.7.1) - SOCKS proxy support
- **jinja2** (3.1.2) - Template engine

---

## 📖 Documentation Files

| File | Purpose |
|------|---------|
| [README.md](README.md) | Main project documentation |
| [QUICKSTART.md](QUICKSTART.md) | Quick start guide & basic usage |
| [EXAMPLES.md](EXAMPLES.md) | Comprehensive tool examples |
| [CONFIG.md](CONFIG.md) | Configuration & optimization guide |
| [TOOLS_REFERENCE.txt](TOOLS_REFERENCE.txt) | Quick reference card |

---

## 🚀 Quick Start

### Installation
```bash
cd /home/aniipid/tools/tools2
pip install -r requirements.txt
```

### Usage
```bash
# Show all tools
python main.py --help

# Show examples
python main.py examples

# Show tool help
python main.py <group> <tool> --help
```

### Common Commands
```bash
# Check CVEs
python main.py util cve --software wordpress --version 5.0.0

# Scan ports
python main.py ports scan --host 192.168.1.1 --ports 1-1000 --open-only

# Find subdomains
python main.py recon subdomains --domain example.com --wordlist wordlists/subdomains.txt

# Check headers
python main.py web headers --url https://example.com --all

# Scan for XSS
python main.py vuln xss --url "http://example.com/search.php" --params q

# Test SQL injection
python main.py vuln sqli --url "http://example.com/product.php?id=1" --params id
```

---

## 🎯 Tool Categories by Use Case

### Reconnaissance Phase
- recon subdomains
- recon ips
- web tech
- ssl check

### Scanning Phase
- ports scan
- web dirs
- web js

### Vulnerability Assessment
- web headers
- web fuzz
- vuln xss
- vuln sqli
- vuln redirect

### Post-Exploitation
- util cve
- web tech (identify patches needed)

---

## ⚙️ System Requirements

- **OS**: Linux, macOS, or Windows with WSL
- **Python**: 3.8 or higher
- **RAM**: 512MB minimum
- **Network**: Internet access (for remote targets)

---

## 🔒 Security & Compliance

- **Authorization Required**: All tools require explicit permission to test targets
- **No Warranty**: Used as-is, author assumes no liability
- **Responsible Disclosure**: Report findings responsibly
- **Legal Use Only**: For authorized testing only

---

## 🎓 Learning Resources

Each tool includes:
- Help text (`--help`)
- Example usage in EXAMPLES.md
- Configuration tips in CONFIG.md
- Source code documentation

---

## 📞 Support & Troubleshooting

See CONFIG.md for:
- Troubleshooting common issues
- Performance tuning
- Advanced configuration
- Integration with other tools

---

## 🔄 Update & Extend

### Add New CVE to Database
Edit `hackit/cve_checker.py` and update `CVE_DATABASE`

### Add New Wordlist
Create file in `wordlists/` directory with one entry per line

### Create Custom Tool
Follow pattern of existing tools and add to `hackit/cli.py`

---

## 📝 Version History

- **1.0.0** (Feb 2026) - Initial release with 14 tools

---

## 📄 License

MIT License - See project files for details

---

**Happy Security Testing!** 🎯

Last Updated: February 7, 2026
