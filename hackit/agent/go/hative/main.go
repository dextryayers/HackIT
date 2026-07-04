package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"hackit_ai_engine/native"
)

type ModuleResult struct {
	Module  string      `json:"module"`
	Target  string      `json:"target"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   string      `json:"error,omitempty"`
	Elapsed float64     `json:"elapsed_seconds"`
}

type ProgressEvent struct {
	Event   string `json:"event"`
	Module  string `json:"module"`
	Message string `json:"message"`
	Pct     int    `json:"pct"`
}

func progress(event, module, msg string, pct int) {
	e := ProgressEvent{Event: event, Module: module, Message: msg, Pct: pct}
	out, _ := json.Marshal(e)
	fmt.Fprintln(os.Stderr, string(out))
}

func runModule(name, target string, fn func(string) ModuleResult) ModuleResult {
	progress("start", name, fmt.Sprintf("Starting %s on %s", name, target), 0)
	start := time.Now()

	maxAttempts := maxRetriesVal + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var result ModuleResult
	timeoutDur := time.Duration(moduleTimeoutVal) * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			progress("retry", name, fmt.Sprintf("Retry %d/%d for %s...", attempt, maxAttempts-1, name), 50)
		}

		resultCh := make(chan ModuleResult, 1)
		go func() {
			resultCh <- fn(target)
		}()

		select {
		case res := <-resultCh:
			result = res
		case <-time.After(timeoutDur):
			result = ModuleResult{
				Module:  name,
				Target:  target,
				Success: false,
				Error:   fmt.Sprintf("Module timed out after %ds", moduleTimeoutVal),
			}
		}

		if result.Success {
			break
		}
	}

	result.Elapsed = time.Since(start).Seconds()

	if result.Success {
		progress("done", name, fmt.Sprintf("%s completed in %.1fs", name, result.Elapsed), 100)
	} else {
		progress("error", name, fmt.Sprintf("%s failed: %s", name, result.Error), 0)
	}
	return result
}

func runModuleParallel(name, target string, fn func(string) ModuleResult, results chan<- ModuleResult, wg *sync.WaitGroup) {
	defer wg.Done()
	results <- runModule(name, target, fn)
}

var httpClient = &http.Client{Timeout: 15 * time.Second}
var moduleTimeoutVal = 120
var maxRetriesVal = 1

func main() {
	// Handle SIGINT gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		progress("interrupted", "", "Scan interrupted by user", 0)
		fmt.Println(`[]`)
		os.Exit(130)
	}()
	portScan := flag.String("portscan", "", "Run port scan")
	subdomain := flag.String("subdomain", "", "Run subdomain enum")
	sqli := flag.String("sqli", "", "Run SQLi test")
	xss := flag.String("xss", "", "Run XSS test")
	ssrf := flag.String("ssrf", "", "Run SSRF test")
	redirect := flag.String("redirect", "", "Run redirect test")
	bypass403 := flag.String("bypass403", "", "Run 403 bypass")
	tech := flag.String("tech", "", "Run tech fingerprinting")
	waf := flag.String("waf", "", "Run WAF detection")
	takeover := flag.String("takeover", "", "Run takeover check")
	ssl := flag.String("ssl", "", "Run SSL audit")
	headers := flag.String("headers", "", "Run header audit")
	fuzz := flag.String("fuzz", "", "Run directory fuzzing")
	js := flag.String("js", "", "Run JS analysis")
	param := flag.String("param", "", "Run param discovery")
	cors := flag.String("cors", "", "Run CORS misconfiguration test")
	csrf := flag.String("csrf", "", "Run CSRF test")
	lfi := flag.String("lfi", "", "Run LFI test")
	ssti := flag.String("ssti", "", "Run SSTI test")
	xxe := flag.String("xxe", "", "Run XXE test")
	cmd := flag.String("cmd", "", "Run command injection test")
	jwt := flag.String("jwt", "", "Run JWT analysis (token as argument)")
	nosqli := flag.String("nosqli", "", "Run NoSQL injection test")
	ldap := flag.String("ldap", "", "Run LDAP injection test")
	graphql := flag.String("graphql", "", "Run GraphQL introspection test")
	all := flag.String("all", "", "Run ALL modules on target")
	report := flag.Bool("report", false, "Generate HTML+Markdown+Mermaid report after scan")
	concurrent := flag.Bool("concurrent", false, "Run modules concurrently")
	maxParallel := flag.Int("max-parallel", 5, "Max concurrent modules (when --concurrent)")
	moduleTimeout := flag.Int("module-timeout", 120, "Per-module timeout in seconds")
	maxRetries := flag.Int("max-retries", 1, "Max retries per failed module")
	flag.Parse()

	moduleTimeoutVal = *moduleTimeout
	maxRetriesVal = *maxRetries

	allResults := make([]ModuleResult, 0)

	singleFn := func(name, target string, fn func(string) ModuleResult) {
		if target == "" {
			return
		}
		allResults = append(allResults, runModule(name, target, fn))
	}

	if *all != "" {
		target := *all
		domain := extractDomain(target)
		baseURL := ensureScheme(target)

		if *concurrent {
			var wg sync.WaitGroup
			ch := make(chan ModuleResult, 20)
			sem := make(chan struct{}, *maxParallel)

			addModule := func(name, arg string, fn func(string) ModuleResult) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					ch <- runModule(name, arg, fn)
				}()
			}

			addModule("portscan", domain, doPortScan)
			addModule("subdomain", domain, doSubdomain)
			addModule("ssl", domain+":443", doSSL)
			addModule("headers", baseURL, doHeaders)
			addModule("tech", domain+":443", doTech)
			addModule("waf", domain+":443", doWAF)
			addModule("fuzz", baseURL, doFuzz)
			addModule("js", baseURL, doJS)
			addModule("param", baseURL, doParam)
			addModule("cors", baseURL, doCORS)
			addModule("csrf", baseURL, doCSRF)
			addModule("xxe", baseURL, doXXE)
			addModule("graphql", baseURL, doGraphQL)
			addModule("nosqli", baseURL, doNoSQLi)
			addModule("ldap", baseURL, doLDAP)
			if strings.Contains(baseURL, "?") {
				addModule("sqli", baseURL, doSQLi)
				addModule("xss", baseURL, doXSS)
				addModule("ssrf", baseURL, doSSRF)
				addModule("redirect", baseURL, doRedirect)
				addModule("lfi", baseURL, doLFI)
				addModule("ssti", baseURL, doSSTI)
				addModule("cmd", baseURL, doCmdInjection)
			}
			go func() {
				wg.Wait()
				close(ch)
			}()
			for r := range ch {
				allResults = append(allResults, r)
			}

			takeoverResults := doTakeover(domain)
			allResults = append(allResults, takeoverResults)
		} else {
			allResults = append(allResults, runModule("portscan", domain, doPortScan))
			allResults = append(allResults, runModule("subdomain", domain, doSubdomain))
			allResults = append(allResults, runModule("tech", domain+":443", doTech))
			allResults = append(allResults, runModule("waf", domain+":443", doWAF))
			allResults = append(allResults, runModule("ssl", domain+":443", doSSL))
			allResults = append(allResults, runModule("headers", baseURL, doHeaders))
			allResults = append(allResults, runModule("fuzz", baseURL, doFuzz))
			allResults = append(allResults, runModule("js", baseURL, doJS))
			allResults = append(allResults, runModule("param", baseURL, doParam))
			allResults = append(allResults, runModule("cors", baseURL, doCORS))
			allResults = append(allResults, runModule("csrf", baseURL, doCSRF))
			allResults = append(allResults, runModule("xxe", baseURL, doXXE))
			allResults = append(allResults, runModule("graphql", baseURL, doGraphQL))
			allResults = append(allResults, runModule("nosqli", baseURL, doNoSQLi))
			allResults = append(allResults, runModule("ldap", baseURL, doLDAP))
			if strings.Contains(baseURL, "?") {
				allResults = append(allResults, runModule("sqli", baseURL, doSQLi))
				allResults = append(allResults, runModule("xss", baseURL, doXSS))
				allResults = append(allResults, runModule("ssrf", baseURL, doSSRF))
				allResults = append(allResults, runModule("redirect", baseURL, doRedirect))
				allResults = append(allResults, runModule("lfi", baseURL, doLFI))
				allResults = append(allResults, runModule("ssti", baseURL, doSSTI))
				allResults = append(allResults, runModule("cmd", baseURL, doCmdInjection))
			}
			allResults = append(allResults, runModule("bypass403", baseURL, doBypass403))
			allResults = append(allResults, runModule("takeover", domain, doTakeover))
		}

		progress("complete", "all", fmt.Sprintf("All modules finished. %d results.", len(allResults)), 100)
	} else {
		if *portScan != "" {
			singleFn("portscan", *portScan, doPortScan)
		}
		if *subdomain != "" {
			singleFn("subdomain", *subdomain, doSubdomain)
		}
		if *sqli != "" {
			singleFn("sqli", *sqli, doSQLi)
		}
		if *xss != "" {
			singleFn("xss", *xss, doXSS)
		}
		if *ssrf != "" {
			singleFn("ssrf", *ssrf, doSSRF)
		}
		if *redirect != "" {
			singleFn("redirect", *redirect, doRedirect)
		}
		if *bypass403 != "" {
			singleFn("bypass403", *bypass403, doBypass403)
		}
		if *tech != "" {
			singleFn("tech", *tech, doTech)
		}
		if *waf != "" {
			singleFn("waf", *waf, doWAF)
		}
		if *takeover != "" {
			singleFn("takeover", *takeover, doTakeover)
		}
		if *ssl != "" {
			singleFn("ssl", *ssl, doSSL)
		}
		if *headers != "" {
			singleFn("headers", *headers, doHeaders)
		}
		if *fuzz != "" {
			singleFn("fuzz", *fuzz, doFuzz)
		}
		if *js != "" {
			singleFn("js", *js, doJS)
		}
		if *param != "" {
			singleFn("param", *param, doParam)
		}
		if *cors != "" {
			singleFn("cors", *cors, doCORS)
		}
		if *csrf != "" {
			singleFn("csrf", *csrf, doCSRF)
		}
		if *lfi != "" {
			singleFn("lfi", *lfi, doLFI)
		}
		if *ssti != "" {
			singleFn("ssti", *ssti, doSSTI)
		}
		if *xxe != "" {
			singleFn("xxe", *xxe, doXXE)
		}
		if *cmd != "" {
			singleFn("cmd", *cmd, doCmdInjection)
		}
		if *jwt != "" {
			singleFn("jwt", *jwt, doJWT)
		}
		if *nosqli != "" {
			singleFn("nosqli", *nosqli, doNoSQLi)
		}
		if *ldap != "" {
			singleFn("ldap", *ldap, doLDAP)
		}
		if *graphql != "" {
			singleFn("graphql", *graphql, doGraphQL)
		}
	}

	if len(allResults) == 0 {
		fmt.Println(`[]`)
		return
	}

	if *report && *all != "" {
		target := *all
		var totalDuration float64
		for _, r := range allResults {
			totalDuration += r.Elapsed
		}
		generateReport(target, allResults, totalDuration)
	}

	out, _ := json.MarshalIndent(allResults, "", "  ")
	fmt.Println(string(out))
}

func ensureScheme(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "https://" + raw
}

func extractDomain(rawURL string) string {
	if strings.Contains(rawURL, "://") {
		u, err := url.Parse(rawURL)
		if err == nil {
			return u.Hostname()
		}
	}
	return strings.Split(rawURL, ":")[0]
}

func parseParamsFromURL(rawURL string) map[string]string {
	params := make(map[string]string)
	u, err := url.Parse(rawURL)
	if err != nil {
		return params
	}
	for k, v := range u.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	if len(params) == 0 {
		params["url"] = rawURL
	}
	return params
}

func doCORS(target string) ModuleResult {
	baseURL := ensureScheme(target)
	data := native.TestCORS(baseURL)
	return ModuleResult{Module: "cors", Target: target, Success: true, Data: data}
}

func doCSRF(target string) ModuleResult {
	baseURL := ensureScheme(target)
	data := native.TestCSRF(baseURL)
	return ModuleResult{Module: "csrf", Target: target, Success: true, Data: data}
}

func doLFI(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestLFI(baseURL, params)
	return ModuleResult{Module: "lfi", Target: target, Success: true, Data: data}
}

func doSSTI(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestSSTI(baseURL, params)
	return ModuleResult{Module: "ssti", Target: target, Success: true, Data: data}
}

func doXXE(target string) ModuleResult {
	baseURL := ensureScheme(target)
	data := native.TestXXE(baseURL)
	return ModuleResult{Module: "xxe", Target: target, Success: true, Data: data}
}

func doCmdInjection(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestCmdInjection(baseURL, params)
	return ModuleResult{Module: "cmd", Target: target, Success: true, Data: data}
}

func doJWT(target string) ModuleResult {
	data := native.TestJWT(target)
	return ModuleResult{Module: "jwt", Target: target, Success: true, Data: data}
}

func doNoSQLi(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestNoSQLi(baseURL, params)
	return ModuleResult{Module: "nosqli", Target: target, Success: true, Data: data}
}

func doLDAP(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestLDAP(baseURL, params)
	return ModuleResult{Module: "ldap", Target: target, Success: true, Data: data}
}

func doGraphQL(target string) ModuleResult {
	baseURL := ensureScheme(target)
	data := native.TestGraphQL(baseURL)
	return ModuleResult{Module: "graphql", Target: target, Success: true, Data: data}
}

func doPortScan(target string) ModuleResult {
	host := target
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	ports := native.TopPorts
	if len(ports) > 200 {
		ports = ports[:200]
	}
	data := native.ScanPorts(host, ports, 50, 2*time.Second)
	return ModuleResult{Module: "portscan", Target: target, Success: true, Data: data}
}

func doSubdomain(target string) ModuleResult {
	data, err := native.EnumerateSubdomains(target)
	if err != nil {
		return ModuleResult{Module: "subdomain", Target: target, Success: false, Error: err.Error()}
	}
	return ModuleResult{Module: "subdomain", Target: target, Success: true, Data: data}
}

func doSQLi(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestSQLi(baseURL, params, 15)
	return ModuleResult{Module: "sqli", Target: target, Success: true, Data: data}
}

func doXSS(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestXSS(baseURL, params)
	return ModuleResult{Module: "xss", Target: target, Success: true, Data: data}
}

func doSSRF(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestSSRF(baseURL, params)
	return ModuleResult{Module: "ssrf", Target: target, Success: true, Data: data}
}

func doRedirect(target string) ModuleResult {
	baseURL := ensureScheme(target)
	params := parseParamsFromURL(baseURL)
	data := native.TestOpenRedirect(baseURL, params)
	return ModuleResult{Module: "redirect", Target: target, Success: true, Data: data}
}

func doBypass403(target string) ModuleResult {
	baseURL := ensureScheme(target)
	data := native.TestBypass403(baseURL)
	return ModuleResult{Module: "bypass403", Target: target, Success: true, Data: data}
}

func doTech(target string) ModuleResult {
	host := target
	port := 80
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	}
	data := native.MapTechnologies(host, port, "")
	return ModuleResult{Module: "tech", Target: target, Success: true, Data: data}
}

func doWAF(target string) ModuleResult {
	host := target
	port := 443
	isHTTPS := true
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
		if port == 80 {
			isHTTPS = false
		}
	}
	data := native.DetectWAF(host, port, isHTTPS)
	return ModuleResult{Module: "waf", Target: target, Success: true, Data: data}
}

func doTakeover(target string) ModuleResult {
	domains := strings.Split(target, ",")
	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}
	data := native.CheckSubdomainTakeover(domains, 15)
	return ModuleResult{Module: "takeover", Target: target, Success: true, Data: data}
}

func doSSL(target string) ModuleResult {
	host := target
	port := 443
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	}
	data := native.AuditSSL(host, port)
	return ModuleResult{Module: "ssl", Target: target, Success: true, Data: data}
}

func doHeaders(target string) ModuleResult {
	data := native.AuditHeaders(target)
	return ModuleResult{Module: "headers", Target: target, Success: true, Data: data}
}

func doFuzz(target string) ModuleResult {
	data := native.FuzzDirectories(target, 30)
	return ModuleResult{Module: "fuzz", Target: target, Success: true, Data: data}
}

func doJS(target string) ModuleResult {
	baseURL := ensureScheme(target)
	u, err := url.Parse(baseURL)
	if err != nil {
		return ModuleResult{Module: "js", Target: target, Success: false, Error: err.Error()}
	}

	resp, err := httpClient.Get(u.String())
	if err != nil {
		return ModuleResult{Module: "js", Target: target, Success: false, Error: fmt.Sprintf("Fetch failed: %v", err)}
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var html strings.Builder
	for scanner.Scan() {
		html.WriteString(scanner.Text())
		html.WriteByte('\n')
	}

	pageContent := html.String()

	scriptSrcs := extractScriptSrcs(pageContent)
	endpoints := extractEndpointsFromJS(pageContent)
	secrets := findSecrets(pageContent)

	type JSResult struct {
		Scripts   []string          `json:"scripts"`
		Endpoints []string          `json:"endpoints"`
		Secrets   []SecretFinding   `json:"secrets"`
		PageSize  int               `json:"page_size_bytes"`
	}

	jsResults := JSResult{
		Scripts:   scriptSrcs,
		Endpoints: endpoints,
		Secrets:   secrets,
		PageSize:  len(pageContent),
	}

	return ModuleResult{Module: "js", Target: target, Success: true, Data: jsResults}
}

type SecretFinding struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Context  string `json:"context"`
	Severity string `json:"severity"`
}

func extractScriptSrcs(html string) []string {
	scripts := make([]string, 0)
	seen := make(map[string]bool)
	// Match <script src="...">
	idx := 0
	for idx < len(html) {
		si := strings.Index(strings.ToLower(html[idx:]), "<script")
		if si == -1 {
			break
		}
		si += idx
		ei := strings.Index(html[si:], ">")
		if ei == -1 {
			break
		}
		tag := html[si : si+ei+1]
		idx = si + ei + 1

		srcStart := strings.Index(tag, "src=")
		if srcStart == -1 {
			continue
		}
		srcStart += 4
		if srcStart >= len(tag) {
			continue
		}
		quote := tag[srcStart]
		if quote != '"' && quote != '\'' {
			continue
		}
		srcStart++
		srcEnd := strings.Index(tag[srcStart:], string(quote))
		if srcEnd == -1 {
			continue
		}
		src := tag[srcStart : srcStart+srcEnd]
		if !seen[src] {
			seen[src] = true
			scripts = append(scripts, src)
		}
	}
	return scripts
}

func extractEndpointsFromJS(html string) []string {
	endpoints := make([]string, 0)
	seen := make(map[string]bool)

	patterns := []string{
		`"/api/`, `'/api/`, `"/v1/`, `'/v1/`, `"/v2/`, `'/v2/`,
		`"/v3/`, `'/v3/`, `"/graphql`, `'/graphql`,
		`"/rest/`, `'/rest/`, `"/oauth`, `'/oauth`,
		`".php`, `'.php`, `".asp`, `'.asp`,
		`"/ws/`, `'/ws/`, `"/socket`, `'/socket`,
	}

	for _, p := range patterns {
		idx := 0
		for idx < len(html) {
			si := strings.Index(html[idx:], p)
			if si == -1 {
				break
			}
			si += idx

			quote := html[si]
			start := si + 1
			end := strings.Index(html[start:], string(quote))
			if end == -1 {
				idx = si + 1
				continue
			}
			endpoint := html[start : start+end]
			if len(endpoint) > 0 && len(endpoint) < 200 && !seen[endpoint] {
				seen[endpoint] = true
				endpoints = append(endpoints, endpoint)
			}
			idx = start + end + 1
		}
	}

	return endpoints
}

func findSecrets(content string) []SecretFinding {
	findings := make([]SecretFinding, 0)
	lines := strings.Split(content, "\n")

	secretPatterns := []struct {
		pattern  string
		typ      string
		severity string
	}{
		{"apiKey", "API Key", "high"},
		{"api_key", "API Key", "high"},
		{"apikey", "API Key", "high"},
		{"secret", "Secret", "high"},
		{"password", "Password", "critical"},
		{"token", "Token", "high"},
		{"auth", "Auth Token", "high"},
		{"jwt", "JWT Token", "high"},
		{"bearer", "Bearer Token", "high"},
		{"aws_access", "AWS Key", "critical"},
		{"aws_secret", "AWS Secret", "critical"},
		{"s3_key", "S3 Key", "high"},
		{"private_key", "Private Key", "critical"},
		{"-----BEGIN", "Private Key", "critical"},
		{"ghp_", "GitHub Token", "critical"},
		{"gho_", "GitHub Token", "critical"},
		{"sk_live", "Stripe Key", "critical"},
		{"sk_test", "Stripe Key", "high"},
		{"xoxb-", "Slack Token", "critical"},
		{"xoxp-", "Slack Token", "critical"},
	}

	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, sp := range secretPatterns {
			if strings.Contains(lower, sp.pattern) {
				truncated := line
				if len(truncated) > 150 {
					truncated = truncated[:150] + "..."
				}
				findings = append(findings, SecretFinding{
					Type:     sp.typ,
					Value:    strings.TrimSpace(truncated),
					Context:  sp.pattern,
					Severity: sp.severity,
				})
				break
			}
		}
	}

	return findings
}

func doParam(target string) ModuleResult {
	baseURL := ensureScheme(target)
	u, err := url.Parse(baseURL)
	if err != nil {
		return ModuleResult{Module: "param", Target: target, Success: false, Error: err.Error()}
	}

	type ParamResult struct {
		URLParams      []ParamInfo `json:"url_params"`
		ExtractedFromJS []ParamInfo `json:"extracted_from_js"`
		Total          int         `json:"total"`
	}

	var result ParamResult

	for k, v := range u.Query() {
		result.URLParams = append(result.URLParams, ParamInfo{
			Name:     k,
			Value:    strings.Join(v, ","),
			Source:   "url",
			Location: u.Path,
		})
	}

	if len(u.Query()) == 0 {
		commonParams := []string{
			"id", "page", "q", "s", "search", "query", "filter",
			"sort", "order", "limit", "offset", "page_size",
			"callback", "redirect", "url", "next", "return",
			"token", "api_key", "key", "file", "path",
			"action", "mode", "type", "format", "view",
			"lang", "locale", "debug", "test", "env",
		}
		for _, p := range commonParams {
			result.URLParams = append(result.URLParams, ParamInfo{
				Name:   p,
				Source: "common",
			})
		}
	}

	resp, err := httpClient.Get(u.String())
	if err == nil {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 512*1024), 512*1024)
		var body strings.Builder
		for scanner.Scan() {
			body.WriteString(scanner.Text())
			body.WriteByte('\n')
		}
		pageContent := body.String()

		formInputs := extractFormInputs(pageContent)
		for _, f := range formInputs {
			result.ExtractedFromJS = append(result.ExtractedFromJS, ParamInfo{
				Name:     f,
				Source:   "form_input",
				Location: u.Path,
			})
		}

		jsParams := findJSParams(pageContent)
		for _, p := range jsParams {
			found := false
			for _, e := range result.ExtractedFromJS {
				if e.Name == p {
					found = true
					break
				}
			}
			if !found {
				result.ExtractedFromJS = append(result.ExtractedFromJS, ParamInfo{
					Name:   p,
					Source: "js_variable",
				})
			}
		}
	}

	result.Total = len(result.URLParams) + len(result.ExtractedFromJS)
	return ModuleResult{Module: "param", Target: target, Success: true, Data: result}
}

type ParamInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Source   string `json:"source"`
	Location string `json:"location,omitempty"`
}

func extractFormInputs(html string) []string {
	inputs := make([]string, 0)
	seen := make(map[string]bool)

	idx := 0
	for idx < len(html) {
		si := strings.Index(strings.ToLower(html[idx:]), "<input")
		if si == -1 {
			break
		}
		si += idx
		ei := strings.Index(html[si:], ">")
		if ei == -1 {
			break
		}
		tag := html[si : si+ei+1]
		idx = si + ei + 1

		nameStart := strings.Index(tag, "name=")
		if nameStart == -1 {
			continue
		}
		nameStart += 5
		if nameStart >= len(tag) {
			continue
		}
		quote := tag[nameStart]
		if quote != '"' && quote != '\'' {
			continue
		}
		nameStart++
		nameEnd := strings.Index(tag[nameStart:], string(quote))
		if nameEnd == -1 {
			continue
		}
		name := tag[nameStart : nameStart+nameEnd]
		if name != "" && !seen[name] {
			seen[name] = true
			inputs = append(inputs, name)
		}
	}
	return inputs
}

func findJSParams(content string) []string {
	params := make([]string, 0)
	seen := make(map[string]bool)

	patterns := []string{
		`getElementById(`, `querySelector(`, `querySelectorAll(`,
		`getParameter(`, `getQueryParam(`, `urlParams.get(`,
		`searchParams.get(`, `param(`,
	}

	for _, p := range patterns {
		idx := 0
		for idx < len(content) {
			si := strings.Index(content[idx:], p)
			if si == -1 {
				break
			}
			si += idx
			start := si + len(p) + 1
			if start >= len(content) {
				break
			}
			quote := content[start]
			if quote != '"' && quote != '\'' {
				idx = si + 1
				continue
			}
			start++
			end := strings.Index(content[start:], string(quote))
			if end == -1 || end > 50 {
				idx = si + 1
				continue
			}
			name := content[start : start+end]
			if name != "" && !seen[name] {
				seen[name] = true
				params = append(params, name)
			}
			idx = si + 1
		}
	}

	// Also find URL params from fetch/ajax calls
	fetchPatterns := []string{`fetch(`, `axios.`, `$.ajax(`, `$.get(`, `$.post(`, `XMLHttpRequest`}
	for _, p := range fetchPatterns {
		idx := 0
		for idx < len(content) {
			si := strings.Index(content[idx:], p)
			if si == -1 {
				break
			}
			si += idx
			end := si + 500
			if end > len(content) {
				end = len(content)
			}
			snippet := content[si:end]
			// Find quoted strings that look like endpoints/params
			quoteIdx := 0
			for quoteIdx < len(snippet) {
				qStart := strings.IndexAny(snippet[quoteIdx:], "'\"")
				if qStart == -1 {
					break
				}
				qStart += quoteIdx
				q := snippet[qStart]
				qEnd := strings.Index(snippet[qStart+1:], string(q))
				if qEnd == -1 {
					idx = si + 1
					break
				}
				val := snippet[qStart+1 : qStart+1+qEnd]
				if strings.Contains(val, "/api/") || strings.Contains(val, "?") {
					if strings.Contains(val, "=") {
						pairs := strings.Split(val, "&")
						for _, pair := range pairs {
							kv := strings.SplitN(pair, "=", 2)
							if len(kv) == 2 && kv[0] != "" && !seen[kv[0]] {
								seen[kv[0]] = true
								params = append(params, kv[0])
							}
						}
					}
				}
				quoteIdx = qStart + 1 + qEnd + 1
			}
			idx = si + 1
		}
	}

	return params
}
