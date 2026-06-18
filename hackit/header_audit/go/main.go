package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	urlFlag := flag.String("u", "", "Target URL")
	outputFlag := flag.String("o", "", "Output file (JSON)")
	useNDJSON := flag.Bool("ndjson", false, "Output NDJSON lines for real-time display")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -u <target_url> [-o output.json] [-ndjson]\n", os.Args[0])
		os.Exit(1)
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(*urlFlag)

	if result.Error != "" {
		if *useNDJSON {
			errLine, _ := json.Marshal(map[string]string{"type": "error", "message": result.Error})
			fmt.Println(string(errLine))
		} else {
			jsonOut, _ := json.Marshal(map[string]string{"error": result.Error})
			fmt.Println(string(jsonOut))
		}
		os.Exit(0)
	}

	if *useNDJSON {
		emitNDJSON(result)
	} else {
		jsonOut, _ := json.Marshal(result)
		fmt.Println(string(jsonOut))
	}

	if *outputFlag != "" {
		jsonOut, _ := json.Marshal(result)
		os.WriteFile(*outputFlag, jsonOut, 0644)
	}
}

func emitNDJSON(result Result) {
	writeJSONLine("summary", map[string]interface{}{
		"target":       result.Target,
		"ip":          result.ResolvedIP,
		"grade":       result.Grade,
		"score":       result.Score,
		"elapsed_ms":  result.ResponseTimeMs,
		"server":      result.ServerInfo,
		"powered_by":  result.PoweredBy,
		"total_headers": len(result.AllHeaders),
		"missing":     len(result.Missing),
		"dangerous":   len(result.Dangerous),
		"cookies":     len(result.CookieAudit),
		"cors_issues": len(result.CorsAudit),
		"technologies": len(result.Technologies),
		"subdomains":  len(result.SubdomainResults),
	})

	for _, h := range result.AllHeaders {
		writeJSONLine("header", map[string]interface{}{
			"key": h.Key, "value": h.Value, "category": h.Category,
			"is_security": h.IsSecurity, "description": h.Description,
		})
	}

	for _, m := range result.Missing {
		writeJSONLine("finding", map[string]interface{}{
			"finding_type": "missing", "header": m.Header, "description": m.Description,
			"recommendation": m.Recommendation, "severity": m.Severity, "category": m.Category,
		})
	}

	for _, d := range result.Dangerous {
		writeJSONLine("finding", map[string]interface{}{
			"finding_type": "dangerous", "header": d.Header, "value": d.Value,
			"description": d.Description, "severity": d.Severity,
		})
	}

	for _, c := range result.CookieAudit {
		writeJSONLine("cookie", map[string]interface{}{
			"name": c.Name, "value": c.Value, "domain": c.Domain, "path": c.Path,
			"issues": c.Issues, "severity": c.Severity,
		})
	}

	for _, c := range result.CorsAudit {
		writeJSONLine("cors", map[string]interface{}{
			"header": c.Header, "value": c.Value, "description": c.Description,
			"recommendation": c.Recommendation, "severity": c.Severity,
		})
	}

	if result.TLSInfo != nil {
		writeJSONLine("tls", map[string]interface{}{
			"version": result.TLSInfo.Version,
			"cipher": result.TLSInfo.CipherSuite,
			"subject": result.TLSInfo.CertificateSubject,
			"issuer": result.TLSInfo.CertificateIssuer,
			"expiry": result.TLSInfo.CertificateExpiry,
			"days_left": result.TLSInfo.CertificateDaysLeft,
			"self_signed": result.TLSInfo.SelfSigned,
			"wildcard": result.TLSInfo.WildcardCert,
		})
	}

	for _, t := range result.Technologies {
		writeJSONLine("tech", map[string]interface{}{
			"name": t.Name, "version": t.Version, "certainty": t.Certainty, "source": t.Source,
		})
	}

	for _, r := range result.SubdomainResults {
		writeJSONLine("subdomain", map[string]interface{}{
			"url": r.Subdomain, "status": r.Status, "grade": r.Grade,
			"score": r.Score, "server": r.Server, "findings": r.Findings,
		})
	}

	writeJSONLine("done", map[string]interface{}{"total_findings": len(result.Missing) + len(result.Dangerous) + len(result.CookieAudit) + len(result.CorsAudit)})
}

func writeJSONLine(eventType string, data map[string]interface{}) {
	data["type"] = eventType
	line, _ := json.Marshal(data)
	fmt.Println(string(line))
}
