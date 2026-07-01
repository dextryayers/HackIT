import httpx
import asyncio
import re
import json
from urllib.parse import quote, urlparse
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

DORK_GROUPS = {
    "Sensitive Directories": [
        'intitle:"index of" "parent directory" site:{}',
        'intitle:"index of" "name" "size" "description" site:{}',
        'intitle:"index of" ".env" site:{}',
        'intitle:"index of" "backup" site:{}',
        'intitle:"index of" "admin" site:{}',
        'intitle:"index of" "config" site:{}',
        'intitle:"index of" "password" site:{}',
        'intitle:"index of" "private" site:{}',
        'intitle:"index of" "database" site:{}',
        'intitle:"index of" "sql" site:{}',
    ],
    "Configuration Files": [
        'filetype:env DB_PASSWORD site:{}',
        'filetype:yml database_password site:{}',
        'filetype:yaml database_password site:{}',
        'filetype:json "db_password" site:{}',
        'filetype:xml "password" site:{}',
        'filetype:ini "mysql" site:{}',
        'filetype:cfg "password" site:{}',
        'filetype:conf "password" site:{}',
        'filetype:properties "password" site:{}',
        'filetype:cnf "password" site:{}',
    ],
    "Credentials & Secrets": [
        '"email":"*@*" "password" site:{}',
        '"username":"*" "password" site:{}',
        'intext:"password" intext:"login" site:{}',
        'intext:"api_key" intext:"secret" site:{}',
        'intext:"AWS_SECRET_ACCESS_KEY" site:{}',
        'intext:"-----BEGIN RSA PRIVATE KEY-----" site:{}',
        'intext:"-----BEGIN OPENSSH PRIVATE KEY-----" site:{}',
        'intext:"-----BEGIN DSA PRIVATE KEY-----" site:{}',
        'intext:"-----BEGIN EC PRIVATE KEY-----" site:{}',
        'intext:"-----BEGIN PGP PRIVATE KEY BLOCK-----" site:{}',
    ],
    "Database Exposures": [
        'filetype:sql "password" site:{}',
        'filetype:sql "INSERT INTO" site:{}',
        'filetype:sql "CREATE TABLE" site:{}',
        'filetype:sql "DROP TABLE" site:{}',
        'filetype:sql "admin" site:{}',
        'filetype:sql "user" "pass" site:{}',
        'filetype:sql "customer" site:{}',
        'filetype:sql "credit" site:{}',
        'filetype:sql "email" site:{}',
        'filetype:sql "phone" site:{}',
    ],
    "Exposed Documents": [
        'filetype:xls "password" site:{}',
        'filetype:xlsx "password" site:{}',
        'filetype:doc "password" site:{}',
        'filetype:docx "password" site:{}',
        'filetype:pdf "password" site:{}',
        'filetype:csv "credit card" site:{}',
        'filetype:csv "ssn" site:{}',
        'filetype:csv "email" "password" site:{}',
        'filetype:txt "password" "admin" site:{}',
        'filetype:rtf "password" site:{}',
    ],
    "Security Vulnerabilities": [
        '"SQL injection" site:{}',
        '"XSS" site:{}',
        '"CSRF" site:{}',
        '"SSRF" site:{}',
        '"RCE" site:{}',
        '"LFI" site:{}',
        '"RFI" site:{}',
        '"path traversal" site:{}',
        '"insecure deserialization" site:{}',
        '"security vulnerability" site:{}',
    ],
    "Exposed Services": [
        'intitle:"Dashboard" "PHP" site:{}',
        'intitle:"phpMyAdmin" site:{}',
        'intitle:"MySQL" site:{}',
        'intitle:"phpinfo" site:{}',
        'intitle:"Apache Stats" site:{}',
        'intitle:"Tomcat" site:{}',
        'intitle:"Jenkins" site:{}',
        'intitle:"Grafana" site:{}',
        'intitle:"Kibana" site:{}',
        'intitle:"Prometheus" site:{}',
    ],
}

ADDITIONAL_DORK_GROUPS = {
    "Open Redirects": [
        'inurl:"redirect=" site:{}',
        'inurl:"url=" site:{}',
        'inurl:"next=" site:{}',
        'inurl:"return=" site:{}',
        'inurl:"dest=" site:{}',
        'inurl:"goto=" site:{}',
        'inurl:"target=" site:{}',
        'inurl:"out=" site:{}',
        'inurl:"view=" site:{}',
        'inurl:"dir=" site:{}',
    ],
    "Error Messages": [
        'intext:"warning" intext:"mysql" site:{}',
        'intext:"fatal error" intext:"line" site:{}',
        'intext:"PHP Error" site:{}',
        'intext:"stack trace" site:{}',
        'intext:"exception" intext:"line" site:{}',
        'intext:"syntax error" site:{}',
        'intext:"undefined index" site:{}',
        'intext:"division by zero" site:{}',
        'intext:"parse error" site:{}',
        'intext:"server error" site:{}',
    ],
    "Login Pages": [
        'inurl:admin login site:{}',
        'inurl:login.aspx site:{}',
        'inurl:signin site:{}',
        'inurl:auth site:{}',
        'inurl:user/login site:{}',
        'intitle:"login" "password" site:{}',
        'inurl:"member" "login" site:{}',
        'inurl:"secure" "login" site:{}',
        'inurl:"portal" "login" site:{}',
        'inurl:"account" "login" site:{}',
    ],
    "Webcam / IoT": [
        'intitle:"webcam" "live" site:{}',
        'intitle:"cam" "live" site:{}',
        'intitle:"IP Camera" site:{}',
        'intitle:"DVR" "login" site:{}',
        'intitle:"Network Camera" site:{}',
        'inurl:"view/view.shtml" site:{}',
        'intitle:"WVC" "IP Camera" site:{}',
        'inurl:"/cgi-bin/" "camera" site:{}',
        'intitle:"SNC" "Sony" site:{}',
        'intitle:"Airlive" "Camera" site:{}',
    ],
    "Backup / Log Files": [
        'filetype:log "password" site:{}',
        'filetype:log "admin" site:{}',
        'filetype:log "login" site:{}',
        'filetype:log "error" site:{}',
        'filetype:log "access" site:{}',
        'filetype:bak "config" site:{}',
        'filetype:bak "database" site:{}',
        'filetype:bz2 "backup" site:{}',
        'filetype:gz "backup" site:{}',
        'filetype:tgz "backup" site:{}',
    ],
}

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    total_dorks = sum(len(dorks) for dorks in DORK_GROUPS.values())
    findings.append(IntelligenceFinding(
        entity=f"Google Dorks: {total_dorks} dork queries in {len(DORK_GROUPS)} categories",
        type="Google Dorks: Configuration",
        source="GoogleDorksDeep",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        status="Configured",
        resolution=t,
        tags=["dorks", "google", "configuration"]
    ))

    for group_name, dorks in DORK_GROUPS.items():
        findings.append(IntelligenceFinding(
            entity=f"Dork group: {group_name} ({len(dorks)} dorks)",
            type=f"Google Dorks: {group_name}",
            source="GoogleDorksDeep",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Available",
            resolution=t,
            tags=["dorks", "group", group_name.lower().replace(" ", "-")]
        ))
        for i, dork in enumerate(dorks[:3]):
            example = dork.replace("site:{}", f"site:{t}")
            findings.append(IntelligenceFinding(
                entity=f"Example dork [{i+1}]: {example[:150]}",
                type=f"Google Dorks: {group_name} Example",
                source="GoogleDorksDeep",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Ready",
                resolution=t,
                tags=["dorks", "example", group_name.lower().replace(" ", "-")]
            ))

    for group_name, dorks in ADDITIONAL_DORK_GROUPS.items():
        findings.append(IntelligenceFinding(
            entity=f"Extra dork group: {group_name} ({len(dorks)} dorks)",
            type=f"Google Dorks: {group_name}",
            source="GoogleDorksDeep",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Available",
            resolution=t,
            tags=["dorks", "group", "extra", group_name.lower().replace(" ", "-")]
        ))
        for i, dork in enumerate(dorks[:2]):
            example = dork.replace("site:{}", f"site:{t}")
            findings.append(IntelligenceFinding(
                entity=f"Dork [{i+1}]: {example[:150]}",
                type=f"Google Dorks: {group_name} Example",
                source="GoogleDorksDeep",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Ready",
                resolution=t,
                tags=["dorks", "example", "extra"]
            ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="Google dorks engine configured",
            type="Google Dorks: Ready",
            source="GoogleDorksDeep",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Ready",
            resolution=t,
            tags=["dorks", "ready"]
        ))

    return findings
