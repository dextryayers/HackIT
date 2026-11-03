# HackIT AI Autonomous Swarm Report

## Executive Summary
- Target: 127.0.0.1
- Session ID: HACKIT-SWARM-1793667382
- Duration: 19s
- Scan Mode: aggressive
- Total Vulnerabilities: 10

### Score Summary
| Severity | Count |
|----------|-------|
| Critical | 7 |
| High     | 0 |
| Medium   | 1 |
| Low      | 2 |
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

### 5. [Critical] SQL Injection
- ID: INJ-SQLI
- CVSS: 9.8
- Description: Parameter "id" injectable at http://127.0.0.1:19090/api/user?id=1
- Evidence: Database error signature "you have an error in your sql syntax" appeared after injection (HTTP 200 -> 500)
- Reproduce: `curl -s "http://127.0.0.1:19090/api/user?id=1"`
- Remediation: Use parameterized queries; never concatenate input into SQL.

### 6. [Low] Missing Security Headers
- ID: MISCONF-HEADERS
- CVSS: 3.1
- Description: 7 security headers absent at http://127.0.0.1:80
- Evidence: Missing: X-Frame-Options, X-XSS-Protection, Referrer-Policy
- Reproduce: `curl -s -D- "http://127.0.0.1:80" | head -30`
- Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.

### 7. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "file" at http://127.0.0.1:80/server-status
- Evidence: Payload "<%= 7*7 %>" produced "49" while control "<%= 8*8 %>" did not produce "64"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 8. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "path" at http://127.0.0.1:80/server-status
- Evidence: Payload "#set($x=7*7)$x" produced "49" while control "#set($x=8*8)$x" did not produce "64"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 9. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "page" at http://127.0.0.1:80/server-status
- Evidence: Payload "{{7*7}}" produced "49" while control "{{8*8}}" did not produce "64"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

### 10. [Critical] Server-Side Template Injection
- ID: INJ-SSTI
- CVSS: 9.1
- Description: Template expression evaluated in "id" at http://127.0.0.1:80/server-status
- Evidence: Payload "${7*7}" produced "49" while control "${8*8}" did not produce "64"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status"`
- Remediation: Do not render user input as template source; use sandboxed contexts.

## Summary

- Session: HACKIT-SWARM-1793667382
- Target: 127.0.0.1
- Scope: aggressive
- Duration: 19s
- Verified findings: 10
- Log events: 105
