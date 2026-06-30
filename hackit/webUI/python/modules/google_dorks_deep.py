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
