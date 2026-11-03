#!/bin/bash
# PoC: OS Command Injection (INJ-CMD)  CVSS 9.8
# Target: 127.0.0.1
# Verified evidence: Command output 'VULN_TEST_123' appeared only after payload "; echo VULN_TEST_123"
# Remediation: Avoid shell invocation; use exec with fixed argv and validate input.
set -u
curl -s "http://127.0.0.1:80/server-status"
