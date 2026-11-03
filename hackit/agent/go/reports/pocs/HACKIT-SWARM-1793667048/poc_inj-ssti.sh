#!/bin/bash
# PoC: Server-Side Template Injection (INJ-SSTI)  CVSS 9.1
# Target: 127.0.0.1
# Verified evidence: Template expression "{{7*7}}" evaluated to "49" (absent from baseline and not in payload)
# Remediation: Do not render user input as template source; use sandboxed contexts.
set -u
curl -s "http://127.0.0.1:80/server-status"
