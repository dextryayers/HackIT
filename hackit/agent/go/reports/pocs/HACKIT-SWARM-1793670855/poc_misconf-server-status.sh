#!/bin/bash
# PoC: Apache server-status Exposed (MISCONF-SERVER-STATUS)  CVSS 5.3
# Target: 127.0.0.1
# Verified evidence: HTTP 200 — Apache mod_status output — body: "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n<html><head>\n<title>Apache Status</title>\n</head><body>\n<h1>Apache Server Status for 127.0.0.1 (via 127.0.0.1..."
# Remediation: Require local + auth for /server-status.
set -u
curl -s -D- "http://127.0.0.1:80/server-status" | head -c 2000
