package modules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"hackit/sqli/go/utils"
)

// SensitiveScanner detects sensitive data patterns in database content
type SensitiveScanner struct {
	engine EngineInterface
	log    *utils.Logger
	mu     sync.Mutex
}

// SensitivePattern defines a data pattern to detect
type SensitivePattern struct {
	Name    string
	Regex   *regexp.Regexp
	Weight  int
	Context string
}

var sensitivePatterns []*SensitivePattern

func init() {
	sensitivePatterns = []*SensitivePattern{
		{Name: "CreditCard", Regex: regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`), Weight: 10, Context: "payment"},
		{Name: "SSN", Regex: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), Weight: 10, Context: "pii"},
		{Name: "Email", Regex: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`), Weight: 5, Context: "contact"},
		{Name: "PhoneUS", Regex: regexp.MustCompile(`\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`), Weight: 5, Context: "contact"},
		{Name: "APIKey", Regex: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret)[=:]\s*['"]?[A-Za-z0-9_\-]{16,64}['"]?`), Weight: 9, Context: "auth"},
		{Name: "Password", Regex: regexp.MustCompile(`(?i)(?:password|passwd|pwd)[=:]\s*['"]?[^'"]{4,50}['"]?`), Weight: 10, Context: "auth"},
		{Name: "Token", Regex: regexp.MustCompile(`(?i)(?:token|jwt|bearer|auth)[=:]\s*['"]?[A-Za-z0-9_\-\.]{8,256}['"]?`), Weight: 8, Context: "auth"},
		{Name: "IPAddress", Regex: regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`), Weight: 3, Context: "network"},
		{Name: "PrivateKey", Regex: regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`), Weight: 10, Context: "crypto"},
		{Name: "BitcoinAddr", Regex: regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`), Weight: 7, Context: "crypto"},
		{Name: "CVE", Regex: regexp.MustCompile(`\bCVE-\d{4}-\d{4,7}\b`), Weight: 4, Context: "vuln"},
		{Name: "Base64", Regex: regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`), Weight: 2, Context: "encoded"},
	}
}

func NewSensitiveScanner(e EngineInterface) *SensitiveScanner {
	return &SensitiveScanner{engine: e, log: e.GetLogger()}
}

// ScanResult represents a sensitive data finding
type ScanResult struct {
	Database string `json:"database"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	Pattern  string `json:"pattern"`
	Sample   string `json:"sample"`
	Count    int    `json:"count"`
	Risk     string `json:"risk"`
}

// ScanData checks extracted data for sensitive patterns
func (ss *SensitiveScanner) ScanData(database, table, column, data string) []ScanResult {
	var results []ScanResult
	for _, p := range sensitivePatterns {
		matches := p.Regex.FindAllString(data, -1)
		if len(matches) > 0 {
			sample := matches[0]
			if len(sample) > 60 {
				sample = sample[:60] + "..."
			}
			risk := "LOW"
			if p.Weight >= 8 {
				risk = "HIGH"
			} else if p.Weight >= 5 {
				risk = "MEDIUM"
			}
			results = append(results, ScanResult{
				Database: database,
				Table:    table,
				Column:   column,
				Pattern:  p.Name,
				Sample:   sample,
				Count:    len(matches),
				Risk:     risk,
			})
		}
	}
	return results
}

// ScanExtractedData scans all extracted data from a dump
func (ss *SensitiveScanner) ScanExtractedData(database, table string, columns []string, rows []map[string]string) []ScanResult {
	var all []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, row := range rows {
		wg.Add(1)
		go func(r map[string]string) {
			defer wg.Done()
			for _, col := range columns {
				if val, ok := r[col]; ok {
					found := ss.ScanData(database, table, col, val)
					mu.Lock()
					all = append(all, found...)
					mu.Unlock()
				}
			}
		}(row)
	}
	wg.Wait()

	return all
}

// ScanResultsToCore converts scan results to Result
func (ss *SensitiveScanner) ScanResultsToCore(results []ScanResult) []Result {
	var out []Result
	for _, r := range results {
		out = append(out, Result{
			Parameter:  "sensitive-scan",
			Type:       "sensitive-" + r.Risk,
			Payload:    fmt.Sprintf("%s/%s/%s", r.Database, r.Table, r.Column),
			DBMS:       r.Pattern,
			Details:    fmt.Sprintf("[%s] %d matches — sample: %s", r.Risk, r.Count, r.Sample),
			Confidence: float64(r.Count) / 100.0,
		})
	}
	return out
}

// ClassifyRisk returns risk level for a column name
func ClassifyRisk(columnName string) string {
	lower := strings.ToLower(columnName)
	high := []string{"password", "passwd", "secret", "credit", "cvv", "pin", "ssn", "token", "authkey"}
	med := []string{"email", "phone", "address", "salary", "ssn", "bank", "account", "salary"}
	for _, h := range high {
		if strings.Contains(lower, h) {
			return "HIGH"
		}
	}
	for _, m := range med {
		if strings.Contains(lower, m) {
			return "MEDIUM"
		}
	}
	return "LOW"
}
