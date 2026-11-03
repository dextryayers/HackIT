#!/bin/bash
# PoC: Apache server-status Exposed (MISCONF-SERVER-STATUS)  CVSS 5.3
# Target: 127.0.0.1
# Verified evidence: HTTP 200 Apache Status page: "/html4/strict.dtd\">\n<html><head>\n<title>Apache Status</title>\n</head><body>\n<h1>Apache Server Status for 127.0.0.1 (via 127.0.0.1)</h"
# Remediation: Require local + auth for /server-status.
set -u
curl -s "http://127.0.0.1:80/server-status" | head -c 1000
