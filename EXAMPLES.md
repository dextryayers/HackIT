# HackIt - Comprehensive Examples & Demos

## Installation & Setup

```bash
cd /home/aniipid/tools/tools2
pip install -r requirements.txt
chmod +x hackit.sh
```

## Running Commands

### Option 1: Using the Python entry point
```bash
python main.py <command>
```

### Option 2: Using the bash wrapper
```bash
./hackit.sh <command>
```

---

## 📡 PORT SCANNING EXAMPLES

### Basic Port Scan
```bash
python main.py ports scan --host 192.168.1.1 --ports 22,80,443
```

### Scan Port Range with Filters
```bash
python main.py ports scan --host target.local --ports 1-1000 --open-only
```

### Fast Scan with Custom Timeout
```bash
python main.py ports scan --host scanme.nmap.org --ports 1-65535 --threads 200 --timeout 2
```

### Save Results to JSON
```bash
python main.py ports scan --host 192.168.1.1 --ports 1-1000 --output port_scan.json
```

---

## 🔍 RECONNAISSANCE

### Subdomain Enumeration
```bash
# Basic subdomain brute force
python main.py recon subdomains --domain example.com --wordlist wordlists/subdomains.txt

# With wildcard detection
python main.py recon subdomains --domain target.com --wordlist wordlists/subdomains.txt --check-wildcard

# Save findings
python main.py recon subdomains --domain example.com --wordlist wordlists/subdomains.txt --output subs.json
```

### IP Range Scanning
```bash
# Scan local network
python main.py recon ips --cidr 192.168.1.0/24

# Scan with custom timeout
python main.py recon ips --cidr 10.0.0.0/24 --timeout 3

# Save alive hosts
python main.py recon ips --cidr 172.16.0.0/16 --output alive_hosts.json
```

---

## 🌐 WEB TOOLS

### HTTP Security Headers Check
```bash
# Check headers only
python main.py web headers --url https://example.com --headers

# Check TLS only
python main.py web headers --url https://example.com --tls

# Check everything
python main.py web headers --url https://example.com --all

# Save report
python main.py web headers --url https://example.com --all --output headers_report.json
```

### Technology Detection
```bash
# Detect web stack
python main.py web tech --url https://example.com

# Save tech findings
python main.py web tech --url https://target.com --output tech_stack.json

# Identify CMS
python main.py web tech --url https://wordpress.site --output cms_detection.json
```

### SSL/TLS Certificate Analysis
```bash
# Check certificate info
python main.py ssl check --host example.com

# Check with custom timeout
python main.py ssl check --host api.example.com --port 8443 --timeout 15

# Save certificate details
python main.py ssl check --host example.com --output ssl_report.json
```

### Directory Brute Forcing
```bash
# Basic directory scan
python main.py web dirs --url http://example.com/ --wordlist wordlists/common.txt

# Recursive scan with depth limit
python main.py web dirs --url http://example.com/ --wordlist wordlists/common.txt --recursive --max-depth 2

# With specific status codes
python main.py web dirs --url http://example.com/ --wordlist wordlists/common.txt --status-codes 200,301,302

# With file extensions
python main.py web dirs --url http://example.com/ --wordlist wordlists/common.txt --extensions .php,.html,.txt

# Slow scan with delay (stealth)
python main.py web dirs --url http://example.com/ --wordlist wordlists/common.txt --delay 0.5 --threads 10

# Save results
python main.py web dirs --url http://example.com/ --wordlist wordlists/common.txt --output directories.json
```

### JavaScript Analysis
```bash
# Extract endpoints from JS
python main.py web js --url https://example.com

# Analyze with custom limits
python main.py web js --url https://example.com --max-files 100

# Find secrets and API keys
python main.py web js --url https://example.com --max-files 50 --output js_analysis.json
```

### Parameter Fuzzing
```bash
# Fuzz GET parameter
python main.py web fuzz --url "http://example.com/search.php" --method GET --params q --payloads wordlists/fuzzing_payloads.txt

# Fuzz multiple parameters
python main.py web fuzz --url "http://example.com/api/user" --method POST --params username,password --payloads wordlists/fuzzing_payloads.txt

# Detect reflection and length differences
python main.py web fuzz --url "http://example.com/profile?user=" --method GET --params user --payloads wordlists/fuzzing_payloads.txt --output fuzz_results.json
```

---

## 💉 VULNERABILITY SCANNING

### XSS Scanning
```bash
# Simple XSS test
python main.py vuln xss --url "http://example.com/search.php" --params q

# Test multiple parameters
python main.py vuln xss --url "http://example.com/user?name=" --params name,email

# Advanced encoding tests
python main.py vuln xss --url "http://example.com/search" --params q --encoding-test

# Save XSS findings
python main.py vuln xss --url "http://example.com/search.php" --params q --encoding-test --output xss_findings.json
```

### SQL Injection Testing
```bash
# Test single parameter
python main.py vuln sqli --url "http://example.com/product.php?id=1" --params id

# Test multiple parameters
python main.py vuln sqli --url "http://example.com/api/search" --params q,filter,sort

# Long timeout for slow responses
python main.py vuln sqli --url "http://example.com/product.php?id=1" --params id --timeout 15

# Save SQLi test results
python main.py vuln sqli --url "http://example.com/product.php?id=1" --params id --output sqli_test.json
```

### Open Redirect Detection
```bash
# Scan with default parameters
python main.py vuln redirect --url "http://example.com/login.php"

# Test custom parameters
python main.py vuln redirect --url "http://example.com/redirect" --params target,url,redirect_to

# Check redirect chains
python main.py vuln redirect --url "http://example.com/" --output redirects.json

# Combined vulnerability scan
python main.py vuln redirect --url "http://example.com/auth" --params next,return_url --timeout 15 --output open_redirects.json
```

---

## 📚 UTILITY TOOLS

### CVE Database Checking
```bash
# Check WordPress CVEs
python main.py util cve --software wordpress --version 5.0.0

# Check Drupal vulnerabilities
python main.py util cve --software drupal --version 7.0.0

# Filter by severity
python main.py util cve --software wordpress --version 5.2.0 --severity Critical

# Check Apache
python main.py util cve --software apache --version 2.4.49

# Check PHP version
python main.py util cve --software php --version 7.4.0

# Save CVE report
python main.py util cve --software wordpress --version 5.0.0 --severity High --output cve_report.json
```

---

## 🔗 COMBINED SCANNING WORKFLOWS

### Complete Web Application Assessment
```bash
#!/bin/bash
TARGET="https://example.com"
DOMAIN="example.com"

echo "[*] Starting complete web assessment..."

# Reconnaissance
echo "[1] Reconnaissance"
python main.py web tech --url $TARGET --output 1_tech_stack.json
python main.py web headers --url $TARGET --all --output 2_headers.json

# Certificate analysis
echo "[2] SSL/TLS Analysis"
python main.py ssl check --host $DOMAIN --output 3_ssl_cert.json

# Content discovery
echo "[3] Directory Enumeration"
python main.py web dirs --url $TARGET/ --wordlist wordlists/common.txt --output 4_directories.json

# JavaScript analysis
echo "[4] JavaScript Analysis"
python main.py web js --url $TARGET --max-files 50 --output 5_js_endpoints.json

# Vulnerability scanning
echo "[5] Vulnerability Assessment"
python main.py vuln xss --url "$TARGET/search.php" --params q --encoding-test --output 6_xss.json
python main.py vuln sqli --url "$TARGET/product.php?id=1" --params id --output 7_sqli.json
python main.py vuln redirect --url $TARGET --output 8_redirects.json

echo "[+] Assessment complete! Results saved."
```

### Reconnaissance Workflow
```bash
#!/bin/bash
DOMAIN="example.com"

echo "[*] Full Reconnaissance on $DOMAIN"

# Find subdomains
python main.py recon subdomains --domain $DOMAIN --wordlist wordlists/subdomains.txt --check-wildcard --output recon_subs.json

# Check each subdomain
while read subdomain; do
    echo "[*] Checking $subdomain"
    python main.py web tech --url https://$subdomain --output tech_$subdomain.json
done < <(cat recon_subs.json | grep subdomain | cut -d'"' -f4)

echo "[+] Reconnaissance complete"
```

### Network Scanning Workflow
```bash
#!/bin/bash
NETWORK="192.168.1.0/24"

echo "[*] Network Assessment on $NETWORK"

# Find alive hosts
echo "[1] Scanning for alive hosts..."
python main.py recon ips --cidr $NETWORK --output alive_hosts.json

# Port scan each host
echo "[2] Port scanning..."
for host in $(seq 1 254); do
    IP="192.168.1.$host"
    python main.py ports scan --host $IP --ports 1-1000 --output ports_$IP.json &
done
wait

echo "[+] Network scan complete"
```

---

## 📊 Output Analysis

### Parse JSON Results
```bash
# Count found directories
cat directories.json | python -c "import json, sys; print(len(json.load(sys.stdin)['results']))"

# Extract URLs
cat directories.json | python -c "import json, sys; data = json.load(sys.stdin); [print(r['url']) for r in data['results'] if r['status'] == 200]"

# Find critical CVEs
cat cve_report.json | python -c "import json, sys; data = json.load(sys.stdin); [print(v) for v in data['vulnerabilities'] if v['severity'] == 'Critical']"
```

### Create Combined Report
```bash
python3 << 'EOF'
import json
import glob
from datetime import datetime

report = {
    "timestamp": datetime.now().isoformat(),
    "findings": {}
}

# Load all JSON results
for file in glob.glob("*.json"):
    with open(file) as f:
        report["findings"][file] = json.load(f)

# Save combined report
with open("full_assessment_report.json", "w") as f:
    json.dump(report, f, indent=2)

print("[+] Combined report saved to full_assessment_report.json")
EOF
```

---

## ⚙️ Advanced Options

### Using Timeouts
```bash
# Quick scan (risky)
python main.py ports scan --host target.com --ports 1-1000 --timeout 1

# Thorough scan (slow)
python main.py ports scan --host target.com --ports 1-1000 --timeout 10
```

### Controlling Concurrency
```bash
# Fast with many threads
python main.py web dirs --url http://example.com --wordlist words.txt --threads 100

# Slow with few threads (stealth)
python main.py web dirs --url http://example.com --wordlist words.txt --threads 5 --delay 1.0
```

### Custom Status Codes
```bash
# All responses
python main.py web dirs --url http://example.com --wordlist words.txt --status-codes 200,301,302,401,403,404,500

# Only successful
python main.py web dirs --url http://example.com --wordlist words.txt --status-codes 200
```

---

## 🎯 Testing Against Local Services

### Setup Local Test Target
```bash
# Simple HTTP server
cd /tmp && python3 -m http.server 8080

# In another terminal
python main.py web dirs --url http://localhost:8080 --wordlist wordlists/common.txt
```

### Docker Test Environment
```bash
# Run DVWA
docker run -p 80:80 vulnerables/web-dvwa

# Scan it
python main.py web dirs --url http://localhost/ --wordlist wordlists/common.txt
```

---

## 📝 Tips & Best Practices

1. **Always start with reconnaissance** - Gather as much info as possible before testing
2. **Use wordlists strategically** - Start small and expand as needed
3. **Monitor responses** - Check for WAF or rate limiting
4. **Save results** - Always use `--output` flag for compliance
5. **Respect timeouts** - Adjust based on target response time
6. **Check scope** - Verify you have permission before testing
7. **Use JSON** - Parse results programmatically for reporting

---

## 🚨 Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Connection timeout | Increase `--timeout` value |
| Too slow | Increase `--threads` or reduce wordlist size |
| False positives | Adjust `--status-codes` filter |
| Rate limited | Add `--delay` between requests |
| SSL errors | Tool ignores certificate validation by default |
| No results | Check URL/host accessibility and verify wordlist |

---

For more information, see README.md and CONFIG.md
