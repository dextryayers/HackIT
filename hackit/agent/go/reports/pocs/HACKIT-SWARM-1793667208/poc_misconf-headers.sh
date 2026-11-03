#!/bin/bash
# PoC: Missing Security Headers (MISCONF-HEADERS)  CVSS 3.1
# Target: 127.0.0.1
# Verified evidence: Missing: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options
# Remediation: Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.
set -u
curl -s -D- "http://127.0.0.1:19090/.env" | head -30
