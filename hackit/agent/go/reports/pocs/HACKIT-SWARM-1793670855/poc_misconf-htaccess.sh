#!/bin/bash
# PoC: Apache .htaccess Exposed (MISCONF-HTACCESS)  CVSS 5.3
# Target: 127.0.0.1
# Verified evidence: HTTP 200 — Apache .htaccess directives — body: "RewriteEngine On"
# Remediation: Deny dotfiles at the edge.
set -u
curl -s -D- "http://127.0.0.1:18080/.htaccess" | head -c 2000
