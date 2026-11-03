#!/bin/bash
# PoC: Dockerfile Exposed (MISCONF-DOCKERFILE)  CVSS 5.3
# Target: 127.0.0.1
# Verified evidence: HTTP 200 — Dockerfile build recipe — body: "FROM node:20-alpine\nRUN npm ci --omit=dev\nCOPY . /app"
# Remediation: Remove build files from the web root.
set -u
curl -s -D- "http://127.0.0.1:18080/Dockerfile" | head -c 2000
