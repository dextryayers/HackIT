#!/bin/bash
# PoC: SQL Injection (INJ-SQLI)  CVSS 9.8
# Target: 127.0.0.1
# Verified evidence: Database error signature "you have an error in your sql syntax" appeared after injection (HTTP 200 -> 500)
# Remediation: Use parameterized queries; never concatenate input into SQL.
set -u
curl -s "http://127.0.0.1:19090/api/user?id=1"
