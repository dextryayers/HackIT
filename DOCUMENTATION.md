# HackIt - Complete Tool Suite Documentation

## Project Overview

**HackIt** is a comprehensive Python-based security testing CLI toolkit designed for penetration testers, security researchers, and bug hunters. It provides 13+ integrated tools for reconnaissance, scanning, and vulnerability testing.

### Project Structure

```
tools2/
├── hackit/                    # Main package
│   ├── __init__.py
│   ├── cli.py                # Main CLI interface
│   ├── port_scanner.py       # Async TCP port scanning
│   ├── header_checker.py     # HTTP header analysis
│   ├── subdomain_bruteforcer.py  # DNS enumeration
│   ├── ip_scanner.py         # IP range/CIDR scanning
│   ├── tech_detector.py      # Technology fingerprinting
│   ├── ssl_analyzer.py       # SSL/TLS analysis
│   ├── dir_bruteforcer.py    # Directory bruteforcing
│   ├── param_fuzzer.py       # Parameter fuzzing
│   ├── xss_scanner.py        # XSS detection
│   ├── sqli_tester.py        # SQL injection testing
│   ├── redirect_finder.py    # Open redirect detection
│   ├── js_analyzer.py        # JavaScript analysis
│   └── cve_checker.py        # CVE database matching
├── wordlists/                 # Payload and wordlist files
│   ├── common.txt
│   ├── subdomains.txt
│   ├── xss_payloads.txt
│   └── fuzzing_payloads.txt
├── main.py                   # Entry point
├── setup.py                  # Installation script
├── requirements.txt          # Dependencies
├── README.md                 # Full documentation
├── QUICKSTART.md            # Quick start guide
└── CONFIG.md                # Configuration guide
```

## Tool Descriptions

### 1. Port Scanner (`ports scan`)

**Features:**
- Async multi-threaded scanning using asyncio
- Configurable timeout (default: 3s)
- Up to 200+ concurrent workers
- Service identification for common ports
- JSON export support
- Filter open ports only

**Key Options:**
- `--host`: Target hostname/IP
- `--ports`: Port range (e.g., 1-1000 or 22,80,443)
- `--timeout`: Seconds per port (default: 3)
- `--threads`: Concurrent workers (default: 100)
- `--open-only`: Show only open ports
- `--output`: Save to JSON file

**Technical Details:**
- Uses `asyncio.open_connection()` for speed
- Service name mapping for 15+ common ports
- Returns status: open, closed, filtered
- Handles timeouts and connection errors gracefully

### 2. Subdomain Brute Forcer (`recon subdomains`)

**Features:**
- Async DNS resolution
- Wordlist-based enumeration
- Wildcard DNS detection
- Multiple record types (A records)
- JSON output with IP mapping

**Key Options:**
- `--domain`: Target domain
- `--wordlist`: Wordlist file
- `--timeout`: DNS timeout (default: 5s)
- `--check-wildcard`: Detect wildcard DNS
- `--output`: Save results to JSON

**Technical Details:**
- Uses `dnspython` library
- Async DNS resolver with executor
- Detects wildcard by checking random subdomain
- Returns all A record IPs for each domain

### 3. HTTP Header Checker (`web headers`)

**Features:**
- Security header detection
- TLS/SSL protocol version check
- Cipher suite analysis
- Server banner enumeration
- Certificate extraction
- Weak protocol detection

**Detected Headers:**
- HSTS (HTTP Strict Transport Security)
- CSP (Content Security Policy)
- X-Frame-Options (XFO)
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

**Key Options:**
- `--url`: Target URL
- `--tls`: Check TLS info
- `--headers`: Check HTTP headers
- `--all`: Check both

### 4. Technology Stack Detector (`web tech`)

**Features:**
- Header-based fingerprinting
- HTML content analysis
- CMS detection (WordPress, Drupal, Joomla, Magento, Shopify)
- Framework identification (Django, Flask, Laravel, React, Vue, Angular, ASP.NET)
- Server detection (Apache, Nginx, IIS, Tomcat)
- Language detection (PHP, Java, Python, Node.js)

**Detection Methods:**
- Regex patterns matching
- Meta tag analysis
- Response header inspection
- Common file/directory detection

### 5. SSL/TLS Analyzer (`ssl check`)

**Features:**
- Certificate information extraction
- Subject and issuer details
- Certificate expiry tracking
- Days remaining calculation
- TLS protocol version verification
- Cipher strength analysis
- Weak protocol detection (SSLv3, TLSv1.0, TLSv1.1)
- Subject Alternative Names (SAN) extraction

**Key Options:**
- `--host`: Target hostname
- `--port`: SSL port (default: 443)
- `--timeout`: Connection timeout
- `--output`: Save to JSON

### 6. Directory Brute Forcer (`web dirs`)

**Features:**
- Async multi-threaded scanning
- Recursive directory traversal
- Status code filtering
- File extension testing
- Configurable delays (anti-blocking)
- Proxy support
- JSON export
- Depth limiting for recursion

**Key Options:**
- `--url`: Base URL
- `--wordlist`: Dictionary file
- `--extensions`: File extensions to test
- `--timeout`: Request timeout
- `--delay`: Delay between requests
- `--recursive`: Enable recursion
- `--max-depth`: Maximum recursion depth
- `--status-codes`: HTTP codes to report
- `--threads`: Concurrent requests
- `--proxy`: HTTP proxy URL

**Status Codes:**
- 200: Found content
- 301/302: Redirects
- 401/403: Access denied but exists
- 404: Not found

### 7. Parameter Fuzzer (`web fuzz`)

**Features:**
- GET and POST parameter fuzzing
- Reflection detection
- Response length anomaly detection
- Payload testing
- Encoded payload support
- JSON reporting

**Key Options:**
- `--url`: Target URL
- `--method`: GET/POST/BOTH
- `--params`: Parameter names
- `--payloads`: Payload file
- `--timeout`: Request timeout
- `--output`: Save results

### 8. XSS Scanner (`vuln xss`)

**Features:**
- Reflected XSS detection
- Multiple payload encoding tests
- Event handler payload testing
- HTML escaping detection
- Exploitability assessment

**Payload Categories:**
- Basic script tags
- HTML entity encoding
- URL encoding
- Event handlers (onclick, onfocus, etc.)

**Key Options:**
- `--url`: Target URL
- `--params`: Parameters to test
- `--encoding-test`: Test encoding bypasses
- `--timeout`: Request timeout

### 9. SQL Injection Tester (`vuln sqli`)

**Features:**
- Boolean-based blind SQLi detection
- Response length comparison
- True/false condition testing
- Response similarity analysis
- Multiple payload testing

**Detection Method:**
- Sends TRUE condition payload
- Sends FALSE condition payload
- Compares response lengths
- Calculates similarity ratio
- If >10% difference: potential SQLi

**Key Options:**
- `--url`: Target URL
- `--params`: Parameters to test
- `--timeout`: Request timeout
- `--output`: Save results

### 10. Open Redirect Finder (`vuln redirect`)

**Features:**
- Common redirect parameter testing
- 17+ parameter variations
- Multiple payload types
- Redirect detection
- Location header analysis
- Chain detection

**Common Parameters:**
- url, redirect, return, returnurl
- next, from, origin, destination
- continue, page, goto, link, ref

**Key Options:**
- `--url`: Target URL
- `--params`: Specific parameters
- `--timeout`: Request timeout
- `--output`: Save results

### 11. JavaScript Analyzer (`web js`)

**Features:**
- JavaScript file crawling
- API endpoint extraction
- Secret pattern detection
- Token discovery
- Configuration extraction
- Multiple pattern matching

**Extraction Patterns:**
- RESTful endpoints
- Fetch/axios calls
- AWS keys (AKIA...)
- Private keys
- API tokens and bearers
- URLs and credentials

**Key Options:**
- `--url`: Target URL
- `--max-files`: Max JS files to analyze
- `--timeout`: Request timeout
- `--output`: Save results

### 12. IP Range Scanner (`recon ips`)

**Features:**
- CIDR notation support
- Ping sweep for alive hosts
- Async ping checking
- JSON output
- Host enumeration

**Key Options:**
- `--cidr`: CIDR range (e.g., 192.168.1.0/24)
- `--timeout`: Ping timeout
- `--output`: Save results

### 13. CVE Checker (`util cve`)

**Features:**
- Version fingerprinting
- CVE database matching
- Severity filtering (Critical, High, Medium, Low)
- Exact and minor version matching
- Vulnerability descriptions
- JSON export

**Included CVEs:**
- WordPress 5.0, 5.1, 5.2
- Drupal 7, 8, 9
- Apache 2.4.x
- Nginx 1.10.x
- PHP 7.2, 7.4

**Key Options:**
- `--software`: Software name
- `--version`: Version number
- `--severity`: Filter by severity
- `--output`: Save results

## Installation & Setup

### Prerequisites
- Python 3.8+
- pip package manager
- Linux/macOS/Windows

### Installation Steps

```bash
cd /home/aniipid/tools/tools2

# Install dependencies
pip install -r requirements.txt

# Or using the setup script
python setup.py install

# Make executable
chmod +x main.py
```

### Quick Test

```bash
# Show help
python main.py --help

# Show examples
python main.py examples

# Test CVE checker
python main.py util cve --software wordpress --version 5.0.0
```

## Usage Workflow

### 1. Reconnaissance Phase
```bash
# Enumerate subdomains
python main.py recon subdomains --domain target.com --wordlist wordlists/subdomains.txt

# Scan IP ranges
python main.py recon ips --cidr 192.168.1.0/24
```

### 2. Network Scanning
```bash
# Port scanning
python main.py ports scan --host target.com --ports 1-10000 --open-only
```

### 3. Service Enumeration
```bash
# Detect technologies
python main.py web tech --url https://target.com

# Check SSL certificates
python main.py ssl check --host target.com

# Analyze HTTP headers
python main.py web headers --url https://target.com --all
```

### 4. Web Application Testing
```bash
# Enumerate directories
python main.py web dirs --url http://target.com/ --wordlist wordlists/common.txt

# Analyze JavaScript
python main.py web js --url https://target.com

# Fuzz parameters
python main.py web fuzz --url http://target.com/search --params q --method GET
```

### 5. Vulnerability Testing
```bash
# Test for XSS
python main.py vuln xss --url http://target.com/search --params q

# Test for SQLi
python main.py vuln sqli --url http://target.com/product?id=1 --params id

# Check open redirects
python main.py vuln redirect --url http://target.com/login
```

### 6. Vulnerability Assessment
```bash
# Check known CVEs
python main.py util cve --software wordpress --version 5.0.0 --severity Critical
```

## Performance Considerations

### Memory Usage
- Port scanner: ~50MB (100 workers)
- Directory bruteforcer: ~20-50MB (50 threads)
- JavaScript analyzer: ~100MB+ (large JS files)

### Speed Optimization
- Increase threads/workers for faster networks
- Decrease timeout for known-good targets
- Use smaller wordlists for initial scans
- Limit recursion depth

### Network Impact
- Port scanner: High (multiple concurrent connections)
- Directory bruteforcer: Medium-High (configurable)
- Subdomain enumeration: Low-Medium (DNS queries)

## Error Handling

### Common Issues

**Connection Refused:**
- Target not responding
- Port filtering in firewall
- Service not running

**Timeout Errors:**
- Network latency too high
- Increase `--timeout` value
- Check connectivity

**SSL Certificate Errors:**
- Tools ignore cert validation by design
- For production: use proper cert verification

**No Results:**
- Check wordlist formatting
- Verify target accessibility
- Try smaller test case first

## Output Formats

### Console Output
Real-time progress with color coding:
- `[+]` Success/Found
- `[*]` Info/Progress
- `[!]` Warning/Critical

### JSON Export
All tools support `--output filename.json` for structured data export

**Example Structure:**
```json
{
  "target": "example.com",
  "timestamp": "2024-01-01T12:00:00",
  "results": [
    {
      "item": "value",
      "status": "open"
    }
  ]
}
```

## Integration

### With Other Tools
- Results can feed into exploitation frameworks
- JSON output for custom analysis pipelines
- Compatible with ELK Stack, Splunk

### Automation
- Chain tools together in shell scripts
- Use cron for scheduled scanning
- Parse JSON for automated reporting

## Security & Legal

### Legal Use
- Obtain written authorization before testing
- Define scope clearly with clients
- Respect privacy and data protection laws
- Follow responsible disclosure practices

### Ethical Considerations
- Don't access unauthorized data
- Avoid DoS attacks
- Report vulnerabilities responsibly
- Use appropriate delays to avoid disruption

## Support & Troubleshooting

### Getting Help
```bash
# Tool-specific help
python main.py <group> <tool> --help

# Show examples
python main.py examples

# Show tool info
python main.py help-tools
```

### Debug Mode
Add verbose output:
```bash
python main.py <command> -vvv 2>&1 | tee debug.log
```

## Advanced Topics

### Custom Wordlists
Create optimized lists for specific targets:
```bash
cat wordlists/*.txt > combined.txt
sort combined.txt | uniq > final.txt
```

### Scripting
Automate common workflows:
```bash
#!/bin/bash
target=$1
python main.py recon subdomains --domain $target --wordlist wordlists/subdomains.txt | tee scan_$target.log
```

### Tool Integration
Chain with other utilities:
```bash
python main.py ports scan --host target.com --output ports.json | \
  jq '.results[] | select(.status=="open") | .port' | \
  xargs -I {} python main.py util cve --software ...
```

## Version Information

- **HackIt Version:** 1.0.0
- **Python:** 3.8+
- **Platform:** Linux/macOS/Windows
- **License:** MIT

## Dependencies

- **click** - CLI framework
- **aiohttp** - Async HTTP
- **requests** - HTTP library
- **beautifulsoup4** - HTML parsing
- **dnspython** - DNS operations
- **cryptography** - SSL/TLS handling

## FAQ

**Q: Can I use this on other people's websites?**
A: Only with explicit written permission.

**Q: Will my traffic be detected?**
A: Tools use standard HTTP/DNS, but may trigger security appliances.

**Q: Can I modify the tools?**
A: Yes, they're MIT licensed. Share improvements!

**Q: How accurate are the detection methods?**
A: Tools provide indicators; manual verification recommended.

**Q: Can I use a proxy?**
A: Some tools support it; use for traffic analysis only.

---

**Created:** February 2024
**Status:** Production Ready
**Support:** See documentation files
