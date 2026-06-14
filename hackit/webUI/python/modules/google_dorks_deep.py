import httpx
import asyncio
import re
import random
from urllib.parse import quote, urlparse, parse_qs
from models import IntelligenceFinding
from typing import List, Dict, Optional

DORK_PATTERNS = {
    "Sensitive Files": [
        'filetype:sql "INSERT INTO"|"CREATE TABLE"',
        'filetype:env "DB_PASSWORD"|"DB_USERNAME"|"API_KEY"',
        'filetype:xml "password"|"credentials" "username"',
        'filetype:ini "password"|"admin" "config"',
        'filetype:conf "server" "password"|"secret"',
        'filetype:cfg "password"|"pass" "connection"',
        'filetype:dat "username"|"password" "admin"',
        'filetype:log "password"|"Failed password"|"error"',
        'filetype:key "PRIVATE KEY"|"BEGIN RSA"',
        'filetype:pem "PRIVATE KEY"|"CERTIFICATE"',
        'filetype:cert "BEGIN CERTIFICATE" "PRIVATE"',
        'filetype:p12 "PKCS12"|"certificate"',
        'filetype:pfx "PKCS12"|"certificate"',
        'filetype:ovpn "client" "cert"|"key"',
        'filetype:rdp "full address"|"username"',
        'filetype:reg "password"|"username" "HKEY"',
        'filetype:pwd "password"|"login"',
        'filetype:snk "password"|"domain"',
        'filetype:config "connectionString"|"password"',
        'filetype:yml "database" "password"|"secret"',
        'filetype:yaml "database" "password"|"secret"',
        'filetype:json "password"|"secret"|"token"|"api"',
        'filetype:txt "password"|"login" "admin" "email"',
        'filetype:csv "username"|"password"|"email"',
        'filetype:pdf "confidential" "password"|"secret"',
        'filetype:xlsx "password" "admin" "users"',
        'filetype:xls "password" "admin" "users"',
        'filetype:doc "confidential" "internal" "password"',
        'filetype:docx "confidential" "internal" "password"',
    ],
    "Exposed Configurations": [
        'filetype:env "DB_HOST"|"DB_PORT"|"DB_DATABASE"',
        'filetype:env "APP_ENV"|"APP_KEY"|"APP_URL"',
        'filetype:env "MAIL_HOST"|"MAIL_USERNAME"|"MAIL_PASSWORD"',
        'filetype:env "AWS_ACCESS"|"AWS_SECRET"|"S3_BUCKET"',
        'filetype:env "REDIS_HOST"|"REDIS_PASSWORD"',
        'filetype:env "STRIPE_KEY"|"STRIPE_SECRET"',
        'filetype:env "JWT_SECRET"|"JWT_KEY"',
        'filetype:env "SENDGRID_API"|"MAILGUN_API"',
        'filetype:env "DOCKER_HOST"|"DOCKER_PASS"',
        'filetype:yml "connection_string" "password"',
        'filetype:yaml "secret" "token" "key" "password"',
        'filetype:xml "connectionString" "data source"',
        '"define("DB_PASSWORD"|"DB_USER"|"DB_NAME"',
        'filetype:php "$db_pass"|"$db_user"|"$db_host"',
        'filetype:py "os.environ.get" "DB_PASSWORD"',
        'filetype:rb "ENV[" "DATABASE_URL"',
        'filetype:java "jdbc:mysql" "password"',
        'filetype:ts "DATABASE_URL"|"DB_PASSWORD"',
        'filetype:go "db.password"|"db.user"',
    ],
    "Admin Panels": [
        'intitle:"login" "admin" "panel"',
        'intitle:"admin" "login" "portal"',
        'intitle:"control panel" "login"',
        'intitle:"administration" "login"',
        'intitle:"management" "console" "login"',
        'intitle:"web admin" "login"',
        'intitle:"site admin" "login"',
        'intitle:"system administration"',
        'inurl:admin intitle:login',
        'inurl:admin inurl:login',
        'inurl:administrator inurl:login',
        'inurl:cp inurl:login',
        'inurl:portal inurl:login',
        'inurl:panel inurl:login',
        'inurl:dashboard inurl:login',
        'inurl:admin intitle:"admin"',
        'inurl:admin.php intext:login',
        'inurl:admin/login',
        'inurl:wp-admin inurl:login',
        'inurl:joomla/administrator',
    ],
    "Login Pages": [
        'intitle:"sign in" "email" "password"',
        'intitle:"log in" "username" "password"',
        'intitle:"user login" "password"',
        'intitle:"member login" "password"',
        'intitle:"employee login"',
        'intitle:"customer login"',
        'intitle:"secure login"',
        'intitle:"partner login"',
        'intitle:"client login"',
        'inurl:signin inurl:login',
        'inurl:logon inurl:login',
        'inurl:auth inurl:login',
        'inurl:signin intitle:login',
        'inurl:login.asp intext:password',
        'inurl:login.php intext:password',
        'inurl:login.aspx intext:password',
        'inurl:sign_in inurl:login',
    ],
    "Error Messages": [
        'intitle:"index of" "error_log"',
        'intitle:"PHP Error" "line"',
        'intitle:"Warning" "mysql_error"',
        'intitle:"Warning: mysql_connect"',
        'intitle:"SQL Error" "syntax"',
        'intitle:"Parse error" "unexpected"',
        'intitle:"Fatal error" "exception"',
        'intext:"mysql_fetch_array"|"mysql_num_rows"',
        'intext:"Warning: include_once"',
        'intext:"Warning: require_once"',
        'intext:"Call to undefined function"',
        'intext:"Stack trace:"',
        'intext:"exception" "Stack trace" "file"',
        'intext:"DEBUG" "ERROR" "WARNING" "INFO"',
        'intext:"Traceback (most recent call last)"',
        'intext:"java.lang.NullPointerException"',
        'intext:"ORA-" intext:"ERROR"',
        'intext:"ASP.NET_SessionId" "error"',
        'intext:"404 Not Found" nginx|apache',
        'intext:"500 Internal Server Error"',
    ],
    "Directory Listings": [
        'intitle:"index of" "parent directory"',
        'intitle:"index of" "backup"',
        'intitle:"index of" "config"',
        'intitle:"index of" "admin"',
        'intitle:"index of" "private"',
        'intitle:"index of" "secret"',
        'intitle:"index of" "conf"',
        'intitle:"index of" "downloads"',
        'intitle:"index of" "uploads"',
        'intitle:"index of" "database"',
        'intitle:"index of" "sql"',
        'intitle:"index of" "db"',
        'intitle:"index of" "tmp"',
        'intitle:"index of" "logs"',
        'intitle:"index of" "images" "uploads"',
        'intitle:"index of" "server-status"',
        'intitle:"listing" "directory" "parent"',
        '"directory listing" "parent directory"',
    ],
    "Vulnerability Indicators": [
        'intext:"phpinfo()" "PHP Version"',
        'intext:"phpinfo" "PHP License"',
        'intext:"ServerStatus" "Apache" "Version"',
        'intext:"Server: Apache" "ServerVersion"',
        'intext:"SERVER_SOFTWARE" "SERVER_ADMIN"',
        'inurl:phpinfo.php intext:"PHP Version"',
        'inurl:info.php intext:"PHP Version"',
        'inurl:test.php intext:phpinfo',
        'inurl:.git intext:"ref: refs/heads"',
        'inurl:.svn intext:"svn:this"',
        'inurl:.env intext:"APP_ENV"',
        'inurl:wp-config.bak intext:"DB_PASSWORD"',
        'inurl:config.php.bak intext:password',
        'inurl:config.bak intext:password',
        'inurl:robots.txt intitle:"robots.txt"',
        'inurl:sitemap.xml intitle:sitemap',
        'inurl:crossdomain.xml intext:allow',
        'inurl:clientaccesspolicy.xml',
    ],
    "Backups": [
        'filetype:bak "password"|"admin"|"config"',
        'filetype:backup "database"|"dump"',
        'filetype:old "admin"|"password"|"config"',
        'filetype:orig "password"|"config"',
        'filetype:swp "password"|"login"|"admin"',
        'filetype:sav "password"|"config"',
        'filetype:tmp "admin"|"password"',
        'filetype:sql "INSERT INTO" "VALUES"',
        'filetype:sql "CREATE TABLE" "INSERT"',
        'filetype:sql DROP TABLE "CREATE TABLE"',
        'filetype:sql "STRUCTURE" "TABLE"',
        'filetype:sql dump "INSERT INTO"',
        'filetype:sql "MySQL dump"',
        'filetype:sql "PostgreSQL database dump"',
        'filetype:sql "Dumping data for table"',
        'filetype:bak "wp-config"|"config"',
        'filetype:old "wp-config"|"config"',
        'filetype:backup "wp-config"|"config"',
    ],
    "Databases": [
        'filetype:sql "localhost" "root" "password"',
        'filetype:sql "CREATE DATABASE"',
        'filetype:sql "mysql" "password"',
        'filetype:sql "DB_HOST"|"DB_NAME"',
        'filetype:mdb "admin" "user" "password"',
        'filetype:accdb "admin" "user"',
        'filetype:db "password"|"login"',
        'filetype:dbf "password"|"login"',
        'filetype:sqlite "password"|"login"',
        'filetype:sqlite3 "password"|"login"',
        'filetype:sqlitedb "password"|"login"',
        'filetype:sdb "password"|"login"',
        'inurl:"phpmyadmin" "Welcome to"',
        'inurl:phpmyadmin inurl:index',
        'inurl:phpPgAdmin inurl:login',
        'inurl:adminer inurl:login',
        'inurl:mysql inurl:admin',
        'inurl:"/db/" intitle:"phpMyAdmin"',
    ],
    "Logs": [
        'filetype:log "GET /" "HTTP/1.1" 200',
        'filetype:log "POST /" "HTTP/1.1"',
        'filetype:log "admin" "login" "failed"',
        'filetype:log "password" "failed"',
        'filetype:log "error" "fatal" "exception"',
        'filetype:log "ERROR" "WARN" "DEBUG"',
        'filetype:log "access" "GET" "POST"',
        'filetype:log "sshd" "Failed password"',
        'filetype:log "apache" "error" "client"',
        'filetype:log "nginx" "error" "client"',
        'filetype:log "mysql" "error" "query"',
        'filetype:log "PHP" "Stack trace"',
        'filetype:log "java" "exception"',
        'filetype:log "[crit]" "[alert]" "[error]"',
        'filetype:log "Fatal" "Exception"',
        'filetype:log "authorized_keys"',
        'filetype:log "lastlog" "wtmp"',
        'filetype:gz inurl:log "error"',
        'filetype:gz inurl:access "GET"',
    ],
    "Emails": [
        'intext:"@" "mail." "password"',
        'intext:"@" "smtp" "password"',
        'intext:"@" "pop3" "password"',
        'intext:"@" "imap" "password"',
        'intext:"email" "password" "admin"',
        'intext:"e-mail" "password" "admin"',
        'intext:"mailto:" intext:password',
        'intext:"sendmail" "password"',
        'intext:"mailgun" "password"|"api"',
        'intext:"sendgrid" "password"|"api"',
        'intext:"postmark" "token"|"password"',
        'intext:"ses" "aws" "secret" "email"',
        'intext:"smtp_host" "smtp_user" "smtp_pass"',
        'intext:"mail_host" "mail_user" "mail_pass"',
        'intext:"EMAIL_HOST" "EMAIL_PORT" "EMAIL_USE"',
        'filetype:log "email" "password" "login"',
        'filetype:csv "@" "password"',
        'filetype:xls "@" "email" "password"',
    ],
    "Credentials": [
        'intext:"password" "username" "admin"',
        'intext:"passwd" "login" "admin"',
        'intext:"DB_PASSWORD" "DB_USERNAME"',
        'intext:"db_password" "db_user"',
        'intext:"database_password" "database_user"',
        'intext:"mysql_password" "mysql_user"',
        'intext:"postgres" "password" "user"',
        'intext:"oracle" "password" "username"',
        'intext:"mongodb" "password" "user"',
        'intext:"redis" "password" "requirepass"',
        'intext:"ldap" "password" "admin"',
        'intext:"ftp" "password" "username"',
        'intext:"ssh" "password" "private"',
        'intext:"Authorization: Basic" base64',
        'intext:"api_key"|"api_key" "secret"',
        'intext:"API_KEY"|"API_SECRET"|"API_TOKEN"',
        'intext:"AWS_SECRET_ACCESS_KEY"',
        'intext:"aws_secret_access_key"',
        'intext:"-----BEGIN RSA PRIVATE KEY-----"',
        'intext:"-----BEGIN DSA PRIVATE KEY-----"',
    ],
    "Documents": [
        'filetype:pdf "confidential" "internal"',
        'filetype:pdf "proprietary" "company"',
        'filetype:pdf "NDA" "non-disclosure"',
        'filetype:pdf "salary" "employee"',
        'filetype:pdf "financial" "report"',
        'filetype:pdf "security" "audit"',
        'filetype:pdf "penetration test" "report"',
        'filetype:pdf "vulnerability" "assessment"',
        'filetype:doc "confidential" "internal use"',
        'filetype:doc "proprietary" "trade secret"',
        'filetype:doc "employee" "ssn"|"social"',
        'filetype:docx "confidential" "internal"',
        'filetype:xls "salary" "total" "employee"',
        'filetype:xls "budget" "financial" "FY"',
        'filetype:xlsx "budget" "financial" "FY"',
        'filetype:ppt "confidential" "internal"',
        'filetype:pptx "confidential" "internal"',
    ],
    "Source Code": [
        'filetype:php "<?php" "define(" "DB_"',
        'filetype:php "$_SERVER" "$_ENV"',
        'filetype:php "function" "password"',
        'filetype:asp "<%" "password" "connection"',
        'filetype:aspx "Page_Load" "password"',
        'filetype:jsp "<%" "password" "connection"',
        'filetype:py "def " "password" "login"',
        'filetype:js "function" "password" "auth"',
        'filetype:ts "function" "password" "auth"',
        'filetype:rb "def " "password" "login"',
        'filetype:java "class" "Password"|"password"',
        'filetype:go "func" "Password"|"password"',
        'filetype:c "password"|"strcmp" "login"',
        'filetype:cpp "password"|"Password" "login"',
        'filetype:cs "Password"|"password" "login"',
        'filetype:swift "password" "login"',
        'filetype:kt "password" "login"',
        'filetype:scala "password" "login"',
    ],
    "Open S3 Buckets": [
        'site:s3.amazonaws.com intext:target inurl:s3',
        'site:s3.amazonaws.com intitle:"bucket" target',
        'inurl:s3.amazonaws.com intext:target',
        'site:storage.googleapis.com intitle:target',
        'inurl:storage.googleapis.com target',
        'site:digitaloceanspaces.com target',
        'site:blob.core.windows.net target',
        'site:wasabisys.com target',
        'site:backblazeb2.com target',
    ],
    "IOT / Devices": [
        'inurl:""cgi-bin" inurl:"webif"',
        'inurl:":8080" intitle:"web administration"',
        'inurl:":8443" intitle:login',
        'intitle:"router" "administration" "login"',
        'intitle:"NVR" "login" "admin"',
        'intitle:"DVR" "login" "admin"',
        'intitle:"webcam" "login" "admin"',
        'intitle:"network camera" "live"',
        'intitle:"Axis" "video server"',
        'intitle:"Hikvision" "login"',
        'intitle:"TP-LINK" "login" "admin"',
        'intitle:"D-Link" "login" "router"',
        'intitle:"Netgear" "login" "router"',
        'inurl:":554" intext:rtsp',
        'intitle:"NAS" "login" "admin"',
        'intitle:"Synology" "login" "DSM"',
    ],
    "Exposed APIs": [
        'inurl:/api/v1 intext:"swagger" "target"',
        'inurl:/api intext:"documentation" target',
        'inurl:/swagger-ui target',
        'inurl:/api-docs target',
        'inurl:/graphql intext:"query" target',
        'inurl:/rest intext:"api" target',
        'inurl:/v1 intext:"api" target',
        'inurl:openapi.json target',
        'inurl:api.php intext:key|token',
        'inurl:api inurl:key intext:password',
    ],
    "Cloud Services": [
        'site:amazonaws.com "target" inurl:.s3',
        'site:cloudfront.net target',
        'site:azurewebsites.net target',
        'site:azureedge.net target',
        'site:herokuapp.com target',
        'site:firebaseio.com target',
        'site:netlify.app target',
        'site:vercel.app target',
        'site:pages.dev target',
        'site:fly.dev target',
        'site:render.com target',
        'site:railway.app target',
    ],
    "Exposed Git/Dev": [
        'inurl:/.git config intitle:"git"',
        'inurl:/.git/config intext:"repository"',
        'inurl:/.svn/entries intext:"svn:this"',
        'inurl:/.DS_Store intext:"folder"',
        'inurl:/.hg intext:"repository"',
        'inurl:/CVS/Root intext:pserver',
        'inurl:/.gitignore intext:node_modules',
        'inurl:/.gitattributes intext:merge',
        'inurl:/.env intext:"APP_KEY"',
        'inurl:/.env.example intext:"DB_"',
        'inurl:/.env.production',
        'inurl:/.env.development',
    ],
    "Exposed WordPress": [
        'inurl:wp-content/uploads intext:target',
        'inurl:wp-includes intext:target',
        'inurl:wp-json intext:target',
        'inurl:wp-admin/admin-ajax.php',
        'inurl:wp-config.php.bak intext:password',
        'inurl:wp-config.php.old intext:password',
        'inurl:wp-config.php~ intext:password',
        'inurl:wp-config.php.save intext:password',
        'inurl:wp-config.php.swp intext:password',
    ],
    "Shodan / Internet Scans": [
        'inurl:shodan intitle:"target"',
        'inurl:shodan.io "target" "host"',
        'site:shodan.io "target"',
        'site:censys.io "target"',
        'site:zoomeye.org "target"',
        'site:fofa.info "target"',
        'site:binaryedge.io "target"',
        'site:onyphe.io "target"',
    ],
}

SENSITIVITY_SCORES = {
    "Credentials": 10,
    "Sensitive Files": 9,
    "Exposed Configurations": 9,
    "Backups": 8,
    "Databases": 8,
    "Exposed Git/Dev": 8,
    "Logs": 7,
    "Exposed APIs": 7,
    "Emails": 6,
    "Source Code": 6,
    "Admin Panels": 5,
    "Login Pages": 5,
    "Documents": 5,
    "Error Messages": 4,
    "Directory Listings": 4,
    "Vulnerability Indicators": 4,
    "Open S3 Buckets": 8,
    "Cloud Services": 3,
    "IOT / Devices": 4,
    "Exposed WordPress": 7,
    "Shodan / Internet Scans": 2,
}

THREAT_MAP = {
    10: "Critical",
    9: "High Risk",
    8: "High Risk",
    7: "Elevated Risk",
    6: "Elevated Risk",
    5: "Elevated Risk",
    4: "Informational",
    3: "Informational",
    2: "Informational",
    1: "Informational",
}

CERTAINTY_THRESHOLDS = {
    "Credentials": 0.7,
    "Sensitive Files": 0.5,
    "Exposed Configurations": 0.6,
    "Backups": 0.6,
    "Databases": 0.6,
    "Logs": 0.5,
    "Source Code": 0.5,
    "Emails": 0.4,
    "Admin Panels": 0.5,
    "Login Pages": 0.5,
}


def classify_search_result(url: str, title: str, snippet: str) -> List[str]:
    categories = []
    combined = f"{url} {title} {snippet}".lower()
    if any(ext in url.lower() for ext in [".sql", ".dump", ".mdb", ".accdb", ".db", ".dbf", ".sqlite"]):
        categories.append("Databases")
    if any(ext in url.lower() for ext in [".env", ".yml", ".yaml", ".xml", ".ini", ".cfg", ".conf"]):
        categories.append("Exposed Configurations")
    if any(ext in url.lower() for ext in [".bak", ".backup", ".old", ".orig", ".swp", ".sav", ".tmp"]):
        categories.append("Backups")
    if any(ext in url.lower() for ext in [".log", ".gz", ".zip"]):
        categories.append("Logs")
    if any(ext in url.lower() for ext in [".php", ".asp", ".aspx", ".jsp", ".py", ".js", ".ts", ".java", ".go", ".rb", ".c", ".cpp", ".cs"]):
        categories.append("Source Code")
    if any(ext in url.lower() for ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]):
        categories.append("Documents")
    if any(ext in url.lower() for ext in [".key", ".pem", ".cert", ".p12", ".pfx", ".crt"]):
        categories.append("Sensitive Files")
    if "admin" in url.lower() and "login" in combined:
        categories.append("Admin Panels")
    if "login" in url.lower() or "signin" in url.lower():
        categories.append("Login Pages")
    if "password" in combined or "credentials" in combined:
        categories.append("Credentials")
    if "@" in combined and ("smtp" in combined or "mail" in combined or "email" in combined):
        categories.append("Emails")
    if "error" in combined and ("warning" in combined or "fatal" in combined or "exception" in combined):
        categories.append("Error Messages")
    if "index of" in title.lower() or "parent directory" in combined:
        categories.append("Directory Listings")
    if "api" in url.lower() or "graphql" in url.lower() or "swagger" in combined:
        categories.append("Exposed APIs")
    if ".git" in url.lower() or ".svn" in url.lower() or ".hg" in url.lower():
        categories.append("Exposed Git/Dev")
    if any(kw in combined for kw in ["phpinfo", "php version"]):
        categories.append("Vulnerability Indicators")
    if "wp-content" in url.lower() or "wp-includes" in url.lower() or "wp-admin" in url.lower():
        categories.append("Exposed WordPress")
    if "s3.amazonaws.com" in url.lower() or "storage.googleapis.com" in url.lower():
        categories.append("Open S3 Buckets")
    if any(cloud in url.lower() for cloud in ["amazonaws", "cloudfront", "azure", "heroku", "firebase", "netlify", "vercel"]):
        categories.append("Cloud Services")
    if any(device in url.lower() for device in ["router", "webcam", "camera", "nvr", "dvr", "nas", "synology", "hikvision"]):
        categories.append("IOT / Devices")
    if "shodan" in combined or "censys" in combined:
        categories.append("Shodan / Internet Scans")
    return categories if categories else ["General Discovery"]


def calculate_confidence(snippet: str, category: str) -> str:
    confidence_signals = 0
    signal_patterns = {
        "password": 3, "credentials": 3, "secret": 3, "key": 2,
        "token": 2, "admin": 1, "login": 1, "mysql": 3, "database": 2,
        "api_key": 3, "private": 2, "confidential": 2, "internal": 1,
        "username": 2, "connection": 1, "host": 1, "port": 1,
    }
    for word, weight in signal_patterns.items():
        if word in snippet.lower():
            confidence_signals += weight
    threshold = CERTAINTY_THRESHOLDS.get(category, 0.3)
    if confidence_signals >= 6:
        return "High"
    elif confidence_signals >= 3:
        return "Medium"
    return "Low"


def get_threat_level(score: int) -> str:
    return THREAT_MAP.get(score, "Informational")


def parse_google_serp(html: str) -> List[Dict]:
    results = []
    result_divs = re.split(r'<div[^>]*class="[^"]*g[^"]*"[^>]*>', html, flags=re.I)
    for div in result_divs[1:]:
        link_match = re.search(r'href="(https?://[^"]+)"', div)
        title_match = re.search(r'<h3[^>]*>(.*?)</h3>', div, re.DOTALL)
        snippet_match = re.search(r'<div[^>]*class="[^"]*(?:IsZvec|snippet|VwiC3b)[^"]*"[^>]*>(.*?)</div>', div, re.DOTALL)
        if link_match:
            url = link_match.group(1).split('&')[0]
            url = url.replace('/url?q=', '')
            url = parse_qs(urlparse(url).query).get('q', [url])[0]
            title = title_match.group(1) if title_match else ""
            title = re.sub(r'<[^>]+>', '', title).strip()
            snippet = snippet_match.group(1) if snippet_match else ""
            snippet = re.sub(r'<[^>]+>', '', snippet).strip()
            if url and not url.startswith('http'):
                continue
            results.append({"url": url, "title": title, "snippet": snippet})
    return results


async def execute_dork(client: httpx.AsyncClient, target: str, dork_pattern: str, category: str, category_index: int, dork_index: int) -> List[IntelligenceFinding]:
    findings = []
    query = dork_pattern.replace("target", target)
    encoded_query = quote(query)

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

    try:
        headers = {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache",
        }

        delay = random.uniform(2.0, 5.0)
        await asyncio.sleep(delay)

        for start in [0, 10, 20]:
            search_url = f"https://www.google.com/search?q={encoded_query}&start={start}"
            resp = await client.get(search_url, headers=headers, timeout=20.0, follow_redirects=True)

            resp_html = resp.text

            if "Our systems have detected unusual traffic" in resp_html or "Please show you" in resp_html:
                findings.append(IntelligenceFinding(
                    entity=f"CAPTCHA detected for category: {category}",
                    type="Google Dorks: Rate Limit",
                    source="GoogleDorks",
                    confidence="Medium",
                    color="red",
                    threat_level="Informational",
                    tags=["rate-limit", "captcha", "google-dorks"]
                ))
                break

            results = parse_google_serp(resp_html)
            for result in results:
                result_url = result["url"]
                if not result_url or not any(domain in result_url.lower() for domain in [target.lower(), f".{target.lower()}", f"{target.lower()}/"]):
                    continue

                matched_categories = classify_search_result(result_url, result["title"], result["snippet"])
                primary_category = matched_categories[0] if matched_categories else category
                score = SENSITIVITY_SCORES.get(primary_category, 3)
                threat = get_threat_level(score)
                conf = calculate_confidence(result["snippet"], primary_category)

                findings.append(IntelligenceFinding(
                    entity=result_url[:200],
                    type=f"Dork: {primary_category}",
                    source=f"GoogleDorks/{category}",
                    confidence=conf,
                    color="red" if score >= 8 else ("orange" if score >= 5 else "blue"),
                    threat_level=threat,
                    raw_data=f"Query: {query[:100]}\nTitle: {result['title'][:200]}\nSnippet: {result['snippet'][:300]}",
                    tags=[category, primary_category, "dork", "google-hacking"]
                ))

            if resp.status_code != 200 or len(results) == 0:
                break

    except httpx.TimeoutException:
        pass
    except Exception:
        pass

    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    dork_tasks = []
    for category_index, (category, patterns) in enumerate(DORK_PATTERNS.items()):
        for dork_index, dork in enumerate(patterns[:5]):
            dork_tasks.append(execute_dork(client, domain, dork, category, category_index, dork_index))
            if len(dork_tasks) >= 15:
                break
        if len(dork_tasks) >= 15:
            break

    dork_results = await asyncio.gather(*dork_tasks, return_exceptions=True)
    for result in dork_results:
        if isinstance(result, list):
            findings.extend(result)

    category_summary = {}
    for f in findings:
        cat = f.type.replace("Dork: ", "")
        category_summary[cat] = category_summary.get(cat, 0) + 1

    summary_lines = []
    for cat, count in sorted(category_summary.items(), key=lambda x: -x[1]):
        score = SENSITIVITY_SCORES.get(cat, 3)
        summary_lines.append(f"{cat}: {count} hits (sensitivity: {score}/10)")

    if summary_lines:
        findings.append(IntelligenceFinding(
            entity=f"Google Dorks Summary: {len(findings)} total findings across {len(category_summary)} categories",
            type="Google Dorks: Summary",
            source="GoogleDorks",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data="\n".join(summary_lines),
            tags=["summary", "google-dorks", "statistics"]
        ))

    return findings
