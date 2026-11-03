#!/bin/bash
# PoC: Docker Compose Manifest Exposed (MISCONF-COMPOSE)  CVSS 5.3
# Target: 127.0.0.1
# Verified evidence: HTTP 200 — docker-compose manifest — body: "services:\n  web:\n    image: nginx:1.25"
# Remediation: Remove deployment manifests from the web root.
set -u
curl -s -D- "http://127.0.0.1:18080/docker-compose.yml" | head -c 2000
