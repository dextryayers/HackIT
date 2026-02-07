# HackIt - Security Testing CLI Tool Suite

A comprehensive **penetration testing and security research toolkit** with Python, featuring automated vulnerability scanning, reconnaissance, and exploitation testing tools.

## 🎯 Features

### 📡 Port Scanning
- **Async Port Scanner** - Multi-threaded TCP port scanning with asyncio
  - Timeout configuration
  - JSON export
  - Filter open ports only
  - Fast scanning with 100+ concurrent workers

### 🔍 Reconnaissance
- **Subdomain Brute Forcer** - DNS enumeration
  - Wordlist-based DNS brute force
  - Wildcard DNS detection
  - Async resolution
  
- **IP Range Scanner** - CIDR scanning
  - Ping sweep for alive host detection
  - IP range enumeration

### 🌐 Web Tools
- **HTTP Header Checker** - Security header analysis
  - HSTS, CSP, XFO detection
  - Server banner fingerprinting
  - TLS version checking

- **Tech Stack Detector** - Framework and CMS identification
  - Header fingerprinting
  - HTML content analysis
  - CMS detection (WordPress, Drupal, etc.)

- **Directory Bruteforcer** - Recursive path scanning
  - Status code filtering
  - File extension testing
  - Recursive directory traversal
  - Delay and proxy support

- **JavaScript Analyzer** - Source code analysis
  - JS file crawling
  - API endpoint extraction
  - Secret pattern detection
  - Token and key discovery

### 🔐 SSL/TLS Analysis
- **SSL/TLS Info Tool** - Certificate analysis
  - Certificate information extraction
  - Expiry date checking
  - Weak protocol detection
  - Cipher suite analysis

### 💉 Vulnerability Scanners
- **HTTP Parameter Fuzzer** - Parameter testing
  - GET/POST fuzzing
  - Response length analysis
  - Payload reflection detection

- **XSS Scanner** - Reflected XSS detection
  - Multiple payload encoding tests
  - Event handler testing
  - Reflection validation

- **SQL Injection Tester** - Boolean-based SQLi detection
  - True/false payload testing
  - Response diff analysis
  - Time-based blind SQLi

- **Open Redirect Finder** - Redirect vulnerability detection
  - Parameter enumeration
  - Redirect chain detection
  - Multiple payload testing

### 📚 Utility Tools
- **CVE Checker** - Vulnerability database matching
  - Version fingerprinting
  - CVE matching
  - Severity filtering

## 🚀 Installation

### Requirements
- Python 3.8+
- pip

### Setup

```bash
# Clone the repository
cd /home/aniipid/tools/tools2

# Install dependencies
pip install -r requirements.txt

# Install the tool
pip install -e .

# Or run directly
python main.py --help
```

## 📖 Usage Examples

### Port Scanning
```bash
# Scan top 1000 ports
hackit ports scan --host scanme.nmap.org --ports 1-1000 --open-only

# Scan specific ports with output
hackit ports scan --host 192.168.1.1 --ports 22,80,443,3306 --output results.json
```

### Subdomain Enumeration
```bash
hackit recon subdomains --domain target.com --wordlist wordlist.txt --check-wildcard
```

### HTTP Header Analysis
```bash
hackit web headers --url https://example.com --all
```

### SSL/TLS Analysis
```bash
hackit ssl check --host example.com --timeout 10
```

### Technology Detection
```bash
hackit web tech --url https://example.com
```

### Directory Bruteforce
```bash
hackit web dirs --url http://example.com/ --wordlist words.txt --recursive --max-depth 2
```

### Parameter Fuzzing
```bash
hackit web fuzz --url "http://example.com/search.php" --method GET --params q,search --payloads fuzz.txt
```

### XSS Scanning
```bash
hackit vuln xss --url "http://example.com/search.php" --params q --encoding-test
```

### SQL Injection Testing
```bash
hackit vuln sqli --url "http://example.com/product.php?id=1" --params id
```

### Open Redirect Finding
```bash
hackit vuln redirect --url "http://example.com/login.php"
```

### JavaScript Analysis
```bash
hackit web js --url https://example.com --max-files 100
```

### IP Range Scanning
```bash
hackit recon ips --cidr 192.168.1.0/24 --timeout 2
```

### CVE Checking
```bash
hackit util cve --software wordpress --version 5.0.0 --severity Critical
```

## 🛠️ Tool Structure

```
hackit/
├── cli.py                 # Main CLI interface
├── port_scanner.py        # Async port scanning
├── header_checker.py      # HTTP header analysis
├── subdomain_bruteforcer.py  # DNS enumeration
├── ip_scanner.py          # IP range scanning
├── tech_detector.py       # Technology detection
├── ssl_analyzer.py        # SSL/TLS analysis
├── dir_bruteforcer.py     # Directory brute forcing
├── param_fuzzer.py        # HTTP parameter fuzzing
├── xss_scanner.py         # XSS detection
├── sqli_tester.py         # SQL injection testing
├── redirect_finder.py     # Open redirect detection
├── js_analyzer.py         # JavaScript analysis
└── cve_checker.py         # CVE database matching
```

## ⚙️ Configuration

### Wordlists
Create wordlist files for directory and subdomain brute forcing:

```bash
# Example: common.txt
admin
test
api
config
backup
...
```

## 🔒 Security Notes

- **Legal Use Only**: Use this tool only on systems you own or have permission to test
- **Responsible Disclosure**: If you find vulnerabilities, report them responsibly
- **No Warranty**: This tool is provided as-is without any warranty

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse or damage caused by this tool.

## 🎓 Educational Purpose

HackIt is designed for security researchers, penetration testers, and security enthusiasts to learn about web security and vulnerability detection methodologies.

---

**Happy Hacking!** 🎯
