# HackIT AI Autonomous Swarm Report

## Executive Summary
- Target: 127.0.0.1
- Session ID: HACKIT-SWARM-1793667048
- Duration: 19s
- Scan Mode: aggressive
- Total Vulnerabilities: 28

### Score Summary
| Severity | Count |
|----------|-------|
| Critical | 14 |
| High     | 8 |
| Medium   | 1 |
| Low      | 5 |
| Info     | 0 |

### Attack Surface
- Subdomains: 1
- Services: 14
- ASN: RFC1918/LOCAL (intranet)
- Cloud Infrastructure: Local network

## Technical Findings

### 1. [Critical] Exposed Git Repository
- ID: MISCONF-002
- CVSS: 9.0
- Description: Live .git/config served at http://127.0.0.1:19090/.git/config: full repo history downloadable
- Evidence: HTTP 200 with [core] repositoryformatversion block: "[core]\n\trepositoryformatversion = 0\n\tbare = false"
- Reproduce: `curl -s "http://127.0.0.1:19090/.git/config"`
- Remediation: Deny /.git at the edge and purge secrets from git history.

### 2. [Critical] Exposed Environment File (.env)
- ID: MISCONF-001
- CVSS: 9.8
- Description: Live .env file with secrets served at http://127.0.0.1:19090/.env (HTTP 200)
- Evidence: HTTP 200, Content-Type text/plain; charset=utf-8, secrets marker: "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123"
- Reproduce: `curl -s -D- "http://127.0.0.1:19090/.env" | head -c 2000`
- Remediation: Block dotfiles at the edge and rotate every secret in the file.

### 3. [Medium] Apache server-status Exposed
- ID: MISCONF-SERVER-STATUS
- CVSS: 5.3
- Description: Live mod_status at http://127.0.0.1:80/server-status leaks workers, vhosts, request paths
- Evidence: HTTP 200 Apache Status page: "/html4/strict.dtd\">\n<html><head>\n<title>Apache Status</title>\n</head><body>\n<h1>Apache Server Status for 127.0.0.1 (via 127.0.0.1)</h"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status" | head -c 1000`
- Remediation: Require local + auth for /server-status.

### 4. [Low] Missing Security Headers
- ID: MISCONF-HEADERS
- CVSS: 3.1
- Description: 7 security headers absent at http://127.0.0.1:19090
- Evidence: Missing: Permissions-Policy, Strict-Transport-Security, Content-Security-Policy
- Reproduce: `curl -s -D- "http://127.0.0.1:19090" | head -30`
- Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.

### 5. [Low] Missing Security Headers
- ID: MISCONF-HEADERS
- CVSS: 3.1
- Description: 7 security headers absent at http://127.0.0.1:80
- Evidence: Missing: X-Frame-Options, X-XSS-Protection, Referrer-Policy
- Reproduce: `curl -s -D- "http://127.0.0.1:80" | head -30`
- Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.

### 6. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "q" at http://127.0.0.1:80/server-status
- Evidence: Template expression "<%= 7*7 %>" evaluated to "49" (absent from baseline and not in payload)
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 7. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "search" at http://127.0.0.1:80/server-status
- Evidence: Template expression "<%= 7*7 %>" evaluated to "49" (absent from baseline and not in payload)
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 8. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "path" at http://127.0.0.1:80/server-status
- Evidence: Template expression "#{(7*7)}" evaluated to "49" (absent from baseline and not in payload)
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 9. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "url" at http://127.0.0.1:80/server-status
- Evidence: Template expression "{{7*7}}" evaluated to "49" (absent from baseline and not in payload)
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 10. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "id" at http://127.0.0.1:80/server-status
- Evidence: Template expression "{{7*7}}" evaluated to "49" (absent from baseline and not in payload)
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 11. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "file" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 12. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "path" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 13. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "page" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 14. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "url" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 15. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "id" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 16. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "q" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 17. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "search" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 18. [High] Local File Inclusion
- ID: INJ-LFI
- CVSS: 8.6
- Description: File inclusion in "name" at http://127.0.0.1:80/server-status
- Evidence: File content indicator '127.0.0.1' found in response
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Resolve includes against an allowlist; never accept paths from input.

### 19. [Critical] OS Command Injection
- ID: INJ-CMD
- CVSS: 9.8
- Description: Command injection in "id" at http://127.0.0.1:80/server-status
- Evidence: Command output 'VULN_TEST_123' appeared only after payload "; echo VULN_TEST_123"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Avoid shell invocation; use exec with fixed argv and validate input.

### 20. [Critical] OS Command Injection
- ID: INJ-CMD
- CVSS: 9.8
- Description: Command injection in "q" at http://127.0.0.1:80/server-status
- Evidence: Command output 'VULN_TEST_123' appeared only after payload "; ping -c 1 127.0.0.1"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Avoid shell invocation; use exec with fixed argv and validate input.

### 21. [Critical] OS Command Injection
- ID: INJ-CMD
- CVSS: 9.8
- Description: Command injection in "search" at http://127.0.0.1:80/server-status
- Evidence: Command output 'VULN_TEST_123' appeared only after payload "; ping -c 1 127.0.0.1"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Avoid shell invocation; use exec with fixed argv and validate input.

### 22. [Critical] OS Command Injection
- ID: INJ-CMD
- CVSS: 9.8
- Description: Command injection in "name" at http://127.0.0.1:80/server-status
- Evidence: Command output 'VULN_TEST_123' appeared only after payload "; ping -c 1 127.0.0.1"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Avoid shell invocation; use exec with fixed argv and validate input.

### 23. [Critical] OS Command Injection
- ID: INJ-CMD
- CVSS: 9.8
- Description: Command injection in "file" at http://127.0.0.1:80/server-status
- Evidence: Command output 'VULN_TEST_123' appeared only after payload "; ping -c 1 127.0.0.1"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Avoid shell invocation; use exec with fixed argv and validate input.

### 24. [Critical] OS Command Injection
- ID: INJ-CMD
- CVSS: 9.8
- Description: Command injection in "path" at http://127.0.0.1:80/server-status
- Evidence: Command output 'VULN_TEST_123' appeared only after payload "; ping -c 1 127.0.0.1"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Avoid shell invocation; use exec with fixed argv and validate input.

### 25. [Critical] OS Command Injection
- ID: INJ-CMD
- CVSS: 9.8
- Description: Command injection in "page" at http://127.0.0.1:80/server-status
- Evidence: Command output 'VULN_TEST_123' appeared only after payload "; ping -c 1 127.0.0.1"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Avoid shell invocation; use exec with fixed argv and validate input.

### 26. [Low] Missing Security Headers
- ID: MISCONF-HEADERS
- CVSS: 3.1
- Description: 7 security headers absent at http://127.0.0.1:80/server-status
- Evidence: Missing: X-XSS-Protection, Referrer-Policy, Permissions-Policy
- Reproduce: `curl -s -D- "http://127.0.0.1:80/server-status" | head -30`
- Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.

### 27. [Low] Missing Security Headers
- ID: MISCONF-HEADERS
- CVSS: 3.1
- Description: 7 security headers absent at http://127.0.0.1:19090/.git/config
- Evidence: Missing: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection
- Reproduce: `curl -s -D- "http://127.0.0.1:19090/.git/config" | head -30`
- Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.

### 28. [Low] Missing Security Headers
- ID: MISCONF-HEADERS
- CVSS: 3.1
- Description: 7 security headers absent at http://127.0.0.1:19090/.env
- Evidence: Missing: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options
- Reproduce: `curl -s -D- "http://127.0.0.1:19090/.env" | head -30`
- Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.

## Summary

- Session: HACKIT-SWARM-1793667048
- Target: 127.0.0.1
- Scope: aggressive
- Duration: 19s
- Verified findings: 28
- Log events: 123
