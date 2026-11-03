# HackIT AI Autonomous Swarm Report

## Executive Summary
- Target: 127.0.0.1
- Session ID: HACKIT-SWARM-1793666500
- Duration: 18s
- Scan Mode: aggressive
- Total Vulnerabilities: 3

### Score Summary
| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 0 |
| Medium   | 1 |
| Low      | 0 |
| Info     | 0 |

### Attack Surface
- Subdomains: 1
- Services: 13
- ASN: RFC1918/LOCAL (intranet)
- Cloud Infrastructure: Local network

## Technical Findings

### 1. [Critical] Exposed Environment File (.env)
- ID: MISCONF-001
- CVSS: 9.8
- Description: Live .env file with secrets served at http://127.0.0.1:18080/.env (HTTP 200)
- Evidence: HTTP 200, Content-Type text/plain; charset=utf-8, secrets marker: "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123"
- Reproduce: `curl -s -D- "http://127.0.0.1:18080/.env" | head -c 2000`
- Remediation: Block dotfiles at the edge and rotate every secret in the file.

### 2. [Critical] Exposed Git Repository
- ID: MISCONF-002
- CVSS: 9.0
- Description: Live .git/config served at http://127.0.0.1:18080/.git/config: full repo history downloadable
- Evidence: HTTP 200 with [core] repositoryformatversion block: "[core]\n\trepositoryformatversion = 0\n\tbare = false"
- Reproduce: `curl -s "http://127.0.0.1:18080/.git/config"`
- Remediation: Deny /.git at the edge and purge secrets from git history.

### 3. [Medium] Apache server-status Exposed
- ID: MISCONF-SERVER-STATUS
- CVSS: 5.3
- Description: Live mod_status at http://127.0.0.1:80/server-status leaks workers, vhosts, request paths
- Evidence: HTTP 200 Apache Status page: "/html4/strict.dtd\">\n<html><head>\n<title>Apache Status</title>\n</head><body>\n<h1>Apache Server Status for 127.0.0.1 (via 127.0.0.1)</h"
- Reproduce: `curl -s "http://127.0.0.1:80/server-status" | head -c 1000`
- Remediation: Require local + auth for /server-status.

## Summary

- Session: HACKIT-SWARM-1793666500
- Target: 127.0.0.1
- Scope: aggressive
- Duration: 18s
- Verified findings: 3
- Log events: 96
