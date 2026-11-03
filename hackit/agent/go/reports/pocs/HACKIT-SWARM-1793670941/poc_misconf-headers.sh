#!/bin/bash
# PoC: Missing Security Headers (MISCONF-HEADERS)  CVSS 3.1
# Target: 127.0.0.1
# Verified evidence: Missing: Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection
# Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.
set -u
curl -s -D- "http://127.0.0.1:80" | head -30
