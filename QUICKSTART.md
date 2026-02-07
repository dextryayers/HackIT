# HackIt - Quick Start Guide

## Installation

```bash
cd /home/aniipid/tools/tools2
pip install -r requirements.txt
# Or use the installed setup
python main.py --help
```

## Quick Tests

### 1. Check Available Tools
```bash
python main.py help-tools
python main.py examples
```

### 2. CVE Database Check
```bash
# Check WordPress vulnerabilities
python main.py util cve --software wordpress --version 5.0.0

# Check by severity
python main.py util cve --software drupal --version 7.0.0 --severity Critical

# Save results
python main.py util cve --software apache --version 2.4.49 --output cve_results.json
```

### 3. Port Scanning
```bash
# Scan a host (adjust host and ports)
python main.py ports scan --help
# Real example: python main.py ports scan --host 192.168.1.1 --ports 1-1000 --open-only

# With JSON output
# python main.py ports scan --host target.com --ports 22,80,443 --output scan.json
```

### 4. Technology Detection
```bash
# Detect tech stack
python main.py web tech --help
# Example: python main.py web tech --url https://example.com --output tech.json
```

### 5. HTTP Headers Analysis
```bash
# Check security headers
python main.py web headers --help
# Example: python main.py web headers --url https://example.com --all
```

### 6. SSL/TLS Analysis
```bash
# Check SSL certificate info
python main.py ssl check --help
# Example: python main.py ssl check --host example.com
```

### 7. Directory Bruteforcing
```bash
# Enumerate directories
python main.py web dirs --help
# Example: python main.py web dirs --url http://example.com/ --wordlist wordlists/common.txt
```

### 8. Subdomain Enumeration
```bash
# Brute force subdomains
python main.py recon subdomains --help
# Example: python main.py recon subdomains --domain example.com --wordlist wordlists/subdomains.txt
```

### 9. XSS Detection
```bash
# Scan for XSS vulnerabilities
python main.py vuln xss --help
# Example: python main.py vuln xss --url "http://example.com/search.php" --params q
```

### 10. SQL Injection Testing
```bash
# Test for SQL injection
python main.py vuln sqli --help
# Example: python main.py vuln sqli --url "http://example.com/product.php?id=1" --params id
```

### 11. Open Redirect Finding
```bash
# Find open redirects
python main.py vuln redirect --help
# Example: python main.py vuln redirect --url http://example.com/login.php
```

### 12. JavaScript Analysis
```bash
# Extract endpoints and secrets from JS
python main.py web js --help
# Example: python main.py web js --url https://example.com --max-files 50
```

### 13. Parameter Fuzzing
```bash
# Fuzz HTTP parameters
python main.py web fuzz --help
# Example: python main.py web fuzz --url "http://example.com/search" --params q,search --method GET
```

### 14. IP Range Scanning
```bash
# Scan CIDR range
python main.py recon ips --help
# Example: python main.py recon ips --cidr 192.168.1.0/24 --timeout 2
```

## Tool Categories

### Reconnaissance (`recon` group)
- **subdomains**: Find subdomains of target
- **ips**: Scan IP ranges for alive hosts

### Port Scanning (`ports` group)
- **scan**: Multi-threaded async port scanner

### Web Tools (`web` group)
- **headers**: Check security headers and TLS
- **tech**: Detect technology stack
- **dirs**: Bruteforce directories
- **fuzz**: Fuzz HTTP parameters
- **js**: Analyze JavaScript files

### Vulnerability Scanning (`vuln` group)
- **xss**: Find reflected XSS
- **sqli**: Test SQL injection
- **redirect**: Find open redirects

### SSL/TLS (`ssl` group)
- **check**: Analyze SSL certificates

### Utilities (`util` group)
- **cve**: Check CVE database

## Wordlists Included

Located in `wordlists/` directory:
- **common.txt** - Common directories and files
- **subdomains.txt** - Common subdomains
- **xss_payloads.txt** - XSS test payloads
- **fuzzing_payloads.txt** - General fuzzing payloads

## Output Formats

Most tools support JSON export:
```bash
python main.py <group> <tool> --output results.json
```

## Common Options

- `--timeout` - Request/connection timeout
- `--output` - Save results to JSON file
- `--help` - Show command help
- `--version` - Show version

## Important Notes

⚠️ **Legal Disclaimer**
- Only use on systems you own or have explicit permission to test
- Unauthorized access is illegal
- Always practice responsible disclosure

## Troubleshooting

### Module not found errors
```bash
python -m pip install -r requirements.txt
```

### SSL certificate errors
Tools are configured to ignore SSL certificate validation for testing purposes

### No results returned
- Check the target is accessible
- Verify wordlists are in correct format
- Check timeout settings
- Use `--output` flag to save partial results

## Next Steps

1. Explore individual tool help: `python main.py <group> <tool> --help`
2. Start with reconnaissance tools
3. Use port scanning for network mapping
4. Move to web vulnerability scanning
5. Check CVEs for found services

---

For more information, see README.md
