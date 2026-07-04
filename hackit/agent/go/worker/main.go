package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"hackit_ai_engine/native"
)

type WorkerResult struct {
	Module  string      `json:"module"`
	Target  string      `json:"target"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   string      `json:"error,omitempty"`
}

func main() {
	portScan := flag.String("portscan", "", "Run port scan on target")
	subdomain := flag.String("subdomain", "", "Run subdomain enumeration")
	sqli := flag.String("sqli", "", "Run SQLi test on URL")
	xss := flag.String("xss", "", "Run XSS test on URL")
	ssrf := flag.String("ssrf", "", "Run SSRF test on URL")
	redirect := flag.String("redirect", "", "Run open redirect test on URL")
	bypass403 := flag.String("bypass403", "", "Run 403 bypass on URL")
	tech := flag.String("tech", "", "Run tech fingerprinting on host:port")
	waf := flag.String("waf", "", "Run WAF detection on host:port")
	takeover := flag.String("takeover", "", "Run subdomain takeover check (comma-sep domains)")
	ssl := flag.String("ssl", "", "Run SSL audit on host:port")
	headers := flag.String("headers", "", "Run header audit on URL")
	fuzz := flag.String("fuzz", "", "Run directory fuzzing on base URL")
	all := flag.String("all", "", "Run all applicable modules on URL")
	flag.Parse()

	results := make([]WorkerResult, 0)

	if *portScan != "" {
		r := doPortScan(*portScan)
		results = append(results, r)
	}
	if *subdomain != "" {
		r := doSubdomain(*subdomain)
		results = append(results, r)
	}
	if *sqli != "" {
		r := doSQLi(*sqli)
		results = append(results, r)
	}
	if *xss != "" {
		r := doXSS(*xss)
		results = append(results, r)
	}
	if *ssrf != "" {
		r := doSSRF(*ssrf)
		results = append(results, r)
	}
	if *redirect != "" {
		r := doRedirect(*redirect)
		results = append(results, r)
	}
	if *bypass403 != "" {
		r := doBypass403(*bypass403)
		results = append(results, r)
	}
	if *tech != "" {
		r := doTechnology(*tech)
		results = append(results, r)
	}
	if *waf != "" {
		r := doWAF(*waf)
		results = append(results, r)
	}
	if *takeover != "" {
		r := doTakeover(*takeover)
		results = append(results, r)
	}
	if *ssl != "" {
		r := doSSL(*ssl)
		results = append(results, r)
	}
	if *headers != "" {
		r := doHeaders(*headers)
		results = append(results, r)
	}
	if *fuzz != "" {
		r := doFuzz(*fuzz)
		results = append(results, r)
	}
	if *all != "" {
		results = doAll(*all)
	}

	if len(results) == 0 {
		fmt.Println(`{"error": "no module specified"}`)
		os.Exit(1)
	}

	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}

func doPortScan(target string) WorkerResult {
	host := target
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	ports := native.TopPorts
	if len(ports) > 100 {
		ports = ports[:100]
	}
	data := native.ScanPorts(host, ports, 50, 2*time.Second)
	return WorkerResult{Module: "portscan", Target: target, Success: true, Data: data}
}

func doSubdomain(target string) WorkerResult {
	data, err := native.EnumerateSubdomains(target)
	if err != nil {
		return WorkerResult{Module: "subdomain", Target: target, Success: false, Error: err.Error()}
	}
	return WorkerResult{Module: "subdomain", Target: target, Success: true, Data: data}
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

func doSQLi(target string) WorkerResult {
	params := parseParamsFromURL(target)
	data := native.TestSQLi(target, params, 10)
	return WorkerResult{Module: "sqli", Target: target, Success: true, Data: data}
}

func doXSS(target string) WorkerResult {
	params := parseParamsFromURL(target)
	data := native.TestXSS(target, params)
	return WorkerResult{Module: "xss", Target: target, Success: true, Data: data}
}

func doSSRF(target string) WorkerResult {
	params := parseParamsFromURL(target)
	data := native.TestSSRF(target, params)
	return WorkerResult{Module: "ssrf", Target: target, Success: true, Data: data}
}

func doRedirect(target string) WorkerResult {
	params := parseParamsFromURL(target)
	data := native.TestOpenRedirect(target, params)
	return WorkerResult{Module: "redirect", Target: target, Success: true, Data: data}
}

func doBypass403(target string) WorkerResult {
	data := native.TestBypass403(target)
	return WorkerResult{Module: "bypass403", Target: target, Success: true, Data: data}
}

func doTechnology(target string) WorkerResult {
	host := target
	port := 80
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	}
	data := native.MapTechnologies(host, port, "")
	return WorkerResult{Module: "tech", Target: target, Success: true, Data: data}
}

func doWAF(target string) WorkerResult {
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
	return WorkerResult{Module: "waf", Target: target, Success: true, Data: data}
}

func doTakeover(target string) WorkerResult {
	domains := strings.Split(target, ",")
	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}
	data := native.CheckSubdomainTakeover(domains, 10)
	return WorkerResult{Module: "takeover", Target: target, Success: true, Data: data}
}

func doSSL(target string) WorkerResult {
	host := target
	port := 443
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	}
	data := native.AuditSSL(host, port)
	return WorkerResult{Module: "ssl", Target: target, Success: true, Data: data}
}

func doHeaders(target string) WorkerResult {
	data := native.AuditHeaders(target)
	return WorkerResult{Module: "headers", Target: target, Success: true, Data: data}
}

func doFuzz(target string) WorkerResult {
	data := native.FuzzDirectories(target, 10)
	return WorkerResult{Module: "fuzz", Target: target, Success: true, Data: data}
}

func doAll(target string) []WorkerResult {
	results := make([]WorkerResult, 0)
	results = append(results, doPortScan(target))
	results = append(results, doSubdomain(extractDomain(target)))
	results = append(results, doHeaders(target))
	results = append(results, doFuzz(target))
	return results
}

func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}
