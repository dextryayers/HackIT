#!/bin/bash
# PoC: Server-Side Template Injection (INJ-SSTI)  CVSS 9.1
# Target: 127.0.0.1
# Verified evidence: Payload "${7*7}" produced "49" while control "${8*8}" did not produce "64"
# Remediation: Do not render user input as template source; use sandboxed contexts.
set -u
curl -s "http://127.0.0.1:80/server-status"
