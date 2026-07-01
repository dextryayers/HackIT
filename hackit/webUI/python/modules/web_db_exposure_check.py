import httpx
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

DB_INTERFACES = {
    "phpMyAdmin": {
        "paths": ["/phpmyadmin", "/phpMyAdmin", "/pma", "/admin/phpmyadmin", "/mysql", "/db/phpmyadmin"],
        "type": "MySQL",
        "login_pattern": r"phpMyAdmin|phpmyadmin",
        "default_creds": ["root:''", "root:root", "admin:admin", "admin:''", "mysql:mysql"],
    },
    "phpPgAdmin": {
        "paths": ["/phppgadmin", "/phpPgAdmin", "/pga", "/postgresql", "/pgadmin"],
        "type": "PostgreSQL",
        "login_pattern": r"phpPgAdmin|phppgadmin",
        "default_creds": ["postgres:''", "postgres:postgres", "admin:admin"],
    },
    "Adminer": {
        "paths": ["/adminer.php", "/adminer", "/editor.php", "/adminer-4.8.1.php", "/adminer-4.7.8.php"],
        "type": "Multi-DB",
        "login_pattern": r"Adminer|adminer",
        "default_creds": [],
    },
    "MongoDB Express": {
        "paths": ["/mongodb", "/mongo", "/express", "/mongoadmin"],
        "type": "MongoDB",
        "login_pattern": r"MongoDB Express|mongodb-express",
        "default_creds": ["admin:''", "admin:pass"],
    },
    "Redis Commander": {
        "paths": ["/redis", "/redis-commander", "/redisadmin", "/redmin"],
        "type": "Redis",
        "login_pattern": r"Redis Commander|redis-commander",
        "default_creds": ["admin:admin"],
    },
    "pgAdmin4": {
        "paths": ["/pgadmin4", "/pgadmin", "/pga4"],
        "type": "PostgreSQL",
        "login_pattern": r"pgAdmin|pgadmin",
        "default_creds": ["admin@admin.com:admin", "postgres:postgres"],
    },
    "MySQL Workbench HTTP": {
        "paths": ["/mysql", "/mysqlworkbench", "/mysql-admin"],
        "type": "MySQL",
        "login_pattern": r"MySQL|mysql",
        "default_creds": [],
    },
    "CouchDB Futon": {
        "paths": ["/_utils", "/couchdb/_utils", "/couchdb", "/futon"],
        "type": "CouchDB",
        "login_pattern": r"CouchDB|Futon|futon",
        "default_creds": ["admin:''"],
    },
    "Elasticsearch Head": {
        "paths": ["/_plugin/head", "/elasticsearch/_plugin/head", "/es/_plugin/head"],
        "type": "Elasticsearch",
        "login_pattern": r"elasticsearch-head|Elasticsearch",
        "default_creds": [],
    },
    "Kibana": {
        "paths": ["/kibana", "/kibana/app/kibana", "/app/kibana"],
        "type": "Elasticsearch",
        "login_pattern": r"Kibana|kibana",
        "default_creds": ["elastic:changeme", "kibana:kibana"],
    },
    "Grafana": {
        "paths": ["/grafana", "/graphana", "/monitoring"],
        "type": "Time Series DB",
        "login_pattern": r"Grafana|grafana",
        "default_creds": ["admin:admin"],
    },
    "Cloudant Dashboard": {
        "paths": ["/dashboard", "/cloudant/_dashboard"],
        "type": "CouchDB/Cloudant",
        "login_pattern": r"Cloudant|cloudant",
        "default_creds": [],
    },
    "Neo4j Browser": {
        "paths": ["/browser", "/neo4j/browser"],
        "type": "Neo4j",
        "login_pattern": r"Neo4j|neo4j",
        "default_creds": ["neo4j:neo4j", "neo4j:password"],
    },
    "ArangoDB Web UI": {
        "paths": ["/_db/_system/_admin/aardvark", "/arangodb"],
        "type": "ArangoDB",
        "login_pattern": r"ArangoDB|arangodb",
        "default_creds": ["root:''"],
    },
    "RethinkDB Admin": {
        "paths": ["/#", "/rethinkdb_admin", "/rethinkdb"],
        "type": "RethinkDB",
        "login_pattern": r"RethinkDB|rethinkdb",
        "default_creds": ["admin:''"],
    },
    "OrientDB Studio": {
        "paths": ["/studio", "/orientdb/studio"],
        "type": "OrientDB",
        "login_pattern": r"OrientDB|orientdb",
        "default_creds": ["admin:admin", "root:root"],
    },
    "Cassandra Cluster Manager": {
        "paths": ["/ccm", "/cassandra", "/cassandra-admin"],
        "type": "Cassandra",
        "login_pattern": r"Cassandra|cassandra",
        "default_creds": ["cassandra:cassandra"],
    },
}

DB_CONFIG_FILES = [
    "wp-config.php", "config.php", "configuration.php", "settings.php",
    "db.php", "database.php", "dbconfig.php", "db_config.php",
    "config/database.yml", "config/database.php", "config/db.php",
    ".env", "env.php", "app/etc/env.php",
    "sites/default/settings.php", "sites/default/default.settings.php",
    "protected/config/database.php", "include/config.php",
    "inc/db.php", "lib/config.php", "config.inc.php",
]

async def check_path(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    result = {"path": path, "status": 0, "accessible": False, "content_snippet": ""}
    try:
        resp = await client.get(f"{base_url}{path}", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
        result["status"] = resp.status_code
        if resp.status_code in (200, 401, 403):
            result["accessible"] = True
            result["content_snippet"] = resp.text[:200]
    except Exception:
        pass
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    for proto in ["https", "http"]:
        try:
            r = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            if r.status_code == 200:
                base_url = f"{proto}://{domain}"
                break
        except Exception:
            continue

    findings.append(IntelligenceFinding(
        entity=f"Checking for exposed database interfaces on {domain}",
        type="DB: Scan Started",
        source="DBExposureCheck",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        tags=["database", "exposure", "scan"]
    ))

    exposed_interfaces = []

    for db_name, db_info in DB_INTERFACES.items():
        for path in db_info["paths"]:
            result = await check_path(client, base_url, path)
            if result["accessible"]:
                exposed_interfaces.append({
                    "name": db_name,
                    "type": db_info["type"],
                    "path": path,
                    "status": result["status"],
                    "content": result["content_snippet"],
                    "default_creds": db_info["default_creds"],
                    "login_pattern": db_info["login_pattern"],
                })
                break

    for db_interface in exposed_interfaces:
        findings.append(IntelligenceFinding(
            entity=f"Exposed DB Interface: {db_interface['name']} ({db_interface['type']}) at {db_interface['path']} (HTTP {db_interface['status']})",
            type="DB: Exposed Interface",
            source="DBExposureCheck",
            confidence="High",
            color="red",
            threat_level="Critical",
            status="Exposed",
            raw_data=f"interface={db_interface['name']}, path={db_interface['path']}, status={db_interface['status']}, type={db_interface['type']}",
            tags=["database", "exposure", "critical", db_interface["name"].lower().replace(" ", "-")]
        ))

        if db_interface["default_creds"]:
            findings.append(IntelligenceFinding(
                entity=f"Default credentials possible for {db_interface['name']}: {', '.join(db_interface['default_creds'][:5])}",
                type="DB: Default Credentials",
                source="DBExposureCheck",
                confidence="Medium",
                color="red",
                threat_level="Critical",
                raw_data=f"default_creds={', '.join(db_interface['default_creds'])}",
                tags=["database", "default-creds", "critical"]
            ))

    config_files_found = []
    for cf in DB_CONFIG_FILES:
        result = await check_path(client, base_url, cf)
        if result["status"] == 200:
            config_files_found.append(cf)
            findings.append(IntelligenceFinding(
                entity=f"Database config file accessible: /{cf} ({len(result['content_snippet'])} chars)",
                type="DB: Config File Exposed",
                source="DBExposureCheck",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Exposed",
                raw_data=f"file=/{cf}, snippet={result['content_snippet'][:100]}",
                tags=["database", "config-file", "exposure", "critical"]
            ))

    if not exposed_interfaces and not config_files_found:
        findings.append(IntelligenceFinding(
            entity=f"No exposed database interfaces or config files found on {domain}",
            type="DB: No Exposure",
            source="DBExposureCheck",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["database", "secure"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"Database Exposure: {len(exposed_interfaces)} interface(s), {len(config_files_found)} config file(s) exposed",
            type="DB: Summary",
            source="DBExposureCheck",
            confidence="High",
            color="red",
            threat_level="Critical",
            raw_data=f"interfaces={len(exposed_interfaces)}, config_files={len(config_files_found)}",
            tags=["database", "exposure", "summary"]
        ))

    return findings
