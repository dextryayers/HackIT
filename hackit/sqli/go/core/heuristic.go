package core

import (
	"fmt"
	"strings"
)

type HeuristicResult struct {
	LikelyDBMS    string
	InjectionType string
	Confidence    float64
	WAFPresent    bool
	WAFName       string
	Charset       string
	DebugInfo     []string
}

func (e *Engine) HeuristicScan(param string, payload string, body string, bodyLen int) *HeuristicResult {
	r := &HeuristicResult{
		DebugInfo: []string{},
	}
	e.logInfo(fmt.Sprintf("Heuristic analysis for parameter '%s'...", param))

	clues := map[string]int{}
	bodyLower := strings.ToLower(body)

	dbClues := map[string][]string{
		"MySQL":      {"mysql", "maria", "innodb", "myisam"},
		"PostgreSQL": {"pg_", "postgres", "psql", "plpgsql"},
		"MSSQL":      {"microsoft", "sql server", "oledb", "driver"},
		"Oracle":     {"oracle", "ora-", "oci_", "plsql"},
		"SQLite":     {"sqlite", "unrecognized token"},
	}
	for db, patterns := range dbClues {
		for _, p := range patterns {
			if strings.Contains(bodyLower, p) {
				clues[db]++
			}
		}
	}

	maxClue := 0
	bestDB := "Unknown"
	for db, count := range clues {
		if count > maxClue {
			maxClue = count
			bestDB = db
		}
	}
	r.LikelyDBMS = bestDB
	r.DebugInfo = append(r.DebugInfo, fmt.Sprintf("DBMS heuristic: %s (%d clues)", bestDB, maxClue))

	payloadLen := len(payload)
	if payloadLen > 0 && bodyLen > 0 {
		ratio := float64(bodyLen) / float64(payloadLen)
		if ratio > 100 {
			r.DebugInfo = append(r.DebugInfo, fmt.Sprintf("Response/payload ratio: %.1f (reflective)", ratio))
		}
	}

	charsetDetect := []string{}
	if strings.Contains(bodyLower, "select") {
		charsetDetect = append(charsetDetect, "SELECT")
	}
	if strings.Contains(bodyLower, "from") {
		charsetDetect = append(charsetDetect, "FROM")
	}
	if strings.Contains(bodyLower, "where") {
		charsetDetect = append(charsetDetect, "WHERE")
	}
	if len(charsetDetect) > 0 {
		r.Charset = strings.Join(charsetDetect, ",")
		r.DebugInfo = append(r.DebugInfo, fmt.Sprintf("Query keywords in response: %s", r.Charset))
	}

	return r
}

func (e *Engine) SuggestInjectionType(responses []int) string {
	if len(responses) < 4 {
		return "auto"
	}

	stableCount := 0
	for i := 1; i < len(responses); i++ {
		diff := absInt(responses[i] - responses[i-1])
		if diff < 10 {
			stableCount++
		}
	}

	stableRatio := float64(stableCount) / float64(len(responses)-1)

	if stableRatio > 0.8 {
		return "boolean"
	}
	return "time"
}

func (e *Engine) DetectEncoding(body string) string {
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "charset=utf-8") || strings.Contains(bodyLower, "utf-8") {
		return "UTF-8"
	}
	if strings.Contains(bodyLower, "charset=iso") || strings.Contains(bodyLower, "iso-8859") {
		return "ISO-8859-1"
	}
	if strings.Contains(bodyLower, "charset=gbk") || strings.Contains(bodyLower, "gb2312") {
		return "GBK"
	}
	return "UTF-8"
}
