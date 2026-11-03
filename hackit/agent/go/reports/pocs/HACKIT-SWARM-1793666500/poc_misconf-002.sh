#!/bin/bash
# PoC: Exposed Git Repository (MISCONF-002)  CVSS 9.0
# Target: 127.0.0.1
# Verified evidence: HTTP 200 with [core] repositoryformatversion block: "[core]\n\trepositoryformatversion = 0\n\tbare = false"
# Remediation: Deny /.git at the edge and purge secrets from git history.
set -u
curl -s "http://127.0.0.1:18080/.git/config"
