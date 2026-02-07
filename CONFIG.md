# HackIt Configuration Guide

## Tool Configuration

### 1. Port Scanner Configuration

**Default Settings:**
- Timeout: 3 seconds
- Max workers: 100 concurrent threads
- Port range: configurable

**Optimization Tips:**
- Increase workers for fast networks (150-200)
- Decrease timeout for unreliable connections
- Use port ranges instead of individual ports for speed

```bash
python main.py ports scan --host target.com --ports 1-65535 --threads 200 --timeout 2
```

### 2. Subdomain Bruteforcer Configuration

**Optimizing wordlists:**
- Start with smaller lists for speed tests
- Use DNS timeout of 3-5 seconds
- Check for wildcard DNS to avoid false positives

```bash
# With wildcard checking
python main.py recon subdomains --domain example.com --wordlist wordlists/subdomains.txt --check-wildcard
```

### 3. Directory Bruteforcer Configuration

**Key Settings:**
- Max depth: 1-3 (deeper = slower)
- Delay: Add delay to avoid blocking (e.g., 0.1 seconds)
- Threads: 20-50 per host

**Status Codes to Detect:**
- 200: Found
- 301/302: Redirects
- 401/403: Access restricted but exists
- 404: Not found

```bash
python main.py web dirs --url http://target.com/ --wordlist wordlists/common.txt \
  --recursive --max-depth 2 --status-codes 200,301,302,401,403 --delay 0.1
```

### 4. Vulnerability Scanner Configuration

**XSS Scanner:**
- Test basic payloads first
- Enable encoding test for WAF detection
- Check for escaped output

**SQLi Tester:**
- Use boolean-based detection
- Check response length differences
- Requires baseline response

**Parameter Fuzzer:**
- Test both GET and POST
- Monitor response length changes (10%+ = anomaly)
- Check for reflection

### 5. SSL/TLS Checker Configuration

**What it checks:**
- Certificate validity
- Protocol version (TLS 1.2 required, TLS 1.3 preferred)
- Cipher strength
- Expiration date

### 6. JavaScript Analyzer Configuration

**Extraction patterns:**
- API endpoints from fetch/axios calls
- Secrets (API keys, tokens, passwords)
- Configuration URLs
- Authentication tokens

**Performance:**
- Limit to 50-100 files for speed
- Process larger sites in batches

### 7. CVE Checker Configuration

**Current Database Includes:**
- WordPress 5.0, 5.1, 5.2
- Drupal 7, 8, 9
- Apache 2.4
- Nginx 1.10
- PHP 7.2, 7.4

**For Custom CVE Database:**
Edit `cve_checker.py` and update `CVE_DATABASE` dictionary

## Proxy Configuration

Some tools support proxy configuration for traffic analysis:

```bash
python main.py web dirs --url http://target.com/ --proxy http://127.0.0.1:8080 --wordlist words.txt
```

Tested with:
- Burp Suite
- OWASP ZAP
- Fiddler
- Mitmproxy

## Wordlist Management

### Using Custom Wordlists

```bash
python main.py web dirs --url http://target.com/ --wordlist my_custom_list.txt
```

### Wordlist Format
One entry per line:
```
admin
test
api
backup
config
...
```

### Combining Wordlists
```bash
cat wordlists/common.txt wordlists/subdomains.txt > combined.txt
sort combined.txt | uniq > final.txt
```

## Performance Tuning

### For Speed
```bash
# Port scanning
--threads 200 --timeout 1

# Directory brute force
--status-codes 200,301 --threads 100

# Subdomain enumeration
--timeout 3

# Parameter fuzzing
--threads 50
```

### For Accuracy
```bash
# Port scanning
--threads 50 --timeout 5

# Directory brute force
--status-codes 200,301,302,401,403 --delay 0.1 --threads 20

# Subdomain enumeration
--timeout 10 --check-wildcard

# Web scanning
--timeout 15
```

### For Stealth
```bash
# Add delays to avoid detection
--delay 0.5  # 500ms between requests

# Reduce concurrent requests
--threads 10

# Longer timeouts
--timeout 30
```

## Output and Analysis

### JSON Output Structure

**Port Scanner:**
```json
{
  "target": "example.com",
  "timestamp": "2024-01-01T12:00:00",
  "summary": {
    "open": 3,
    "closed": 10,
    "filtered": 987
  },
  "results": [...]
}
```

### Processing JSON Results

```bash
# Extract open ports
cat scan.json | python -m json.tool | grep -i "open"

# Count findings
cat results.json | python -c "import json, sys; data = json.load(sys.stdin); print(len(data.get('results', [])))"
```

## Logging and Reporting

### Save All Tool Output
```bash
python main.py <command> 2>&1 | tee output.log
```

### Create Report
```bash
# Run multiple tools
python main.py util cve --software wordpress --version 5.0.0 --output report_cve.json
python main.py web tech --url https://example.com --output report_tech.json
python main.py ssl check --host example.com --output report_ssl.json
```

## Troubleshooting Configuration

### Connection Timeouts
- Increase `--timeout` value
- Check network connectivity
- Verify firewall rules

### Too Slow
- Increase `--threads`
- Reduce `--timeout`
- Use smaller wordlists
- Decrease `--max-depth`

### Memory Issues
- Reduce `--threads`
- Process in smaller batches
- Check available RAM

### False Positives
- Check wordlist quality
- Adjust status code filters
- Use response length filtering
- Enable wildcard detection

## Security Considerations

### Avoiding Detection
1. Use appropriate delays
2. Rotate user agents (built-in)
3. Use proxy for anonymity
4. Monitor for rate limiting

### Responsible Use
1. Get written permission first
2. Define scope clearly
3. Limit to agreed targets
4. Report findings responsibly
5. Don't access data unnecessarily

## Advanced Usage

### Chaining Tools

```bash
#!/bin/bash
target=$1

# Reconnaissance
python main.py recon subdomains --domain $target --wordlist wordlists/subdomains.txt

# Technology detection
python main.py web tech --url https://$target

# SSL analysis
python main.py ssl check --host $target

# Web enumeration
python main.py web dirs --url https://$target/ --wordlist wordlists/common.txt
```

### Automated Scanning

Create a scan profile script to automate common reconnaissance

### Integration with Other Tools

Results are JSON-compatible, easily integrate with:
- ELK Stack
- Splunk
- Custom dashboards
- Other security tools

---

For tool-specific help:
```bash
python main.py <group> <tool> --help
```
