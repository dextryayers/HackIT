package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// SubdomainReport is the structured findings for one extra host.
type SubdomainReport struct {
	Subdomain   string         `json:"subdomain"`
	Reachable   bool           `json:"reachable"`
	URL         string         `json:"url"`
	Technologies []string      `json:"technologies"`
	CVEs        []ExportResult `json:"cves"`
	Error       string         `json:"error,omitempty"`
	ScannedAt   string         `json:"scanned_at"`
}

// CVEReport is the machine-readable deliverable for one run.
type CVEReport struct {
	Target     string            `json:"target"`
	Mode       string            `json:"mode"`
	Started    string            `json:"started_at"`
	Elapsed    string            `json:"elapsed"`
	MainURL    string            `json:"main_url"`
	Techs      []string          `json:"techs"`
	Subdomains []SubdomainReport `json:"subdomains"`
	TotalCVEs  int               `json:"total_cves"`
	Severity   map[string]int    `json:"severity_counts"`
	RiskScore  float64           `json:"risk_score"`
	Summary    string            `json:"summary"`
	Findings   []ExportResult    `json:"findings"`
}

// ExportReport writes the run as JSON. Called when --output is supplied.
func ExportReport(target string, mode string, start time.Time, techs []DetectedTech,
	deduped []ExportResult, subBlocks []SubdomainReport) {
	sevCount := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	risk := 0.0
	techsAndSubs := make([]string, 0, len(techs)+len(subBlocks)*2)
	for _, t := range techs {
		techsAndSubs = append(techsAndSubs, fmt.Sprintf("%s %s (header/body match)", t.Software, t.Version))
	}
	for _, s := range subBlocks {
		if !s.Reachable {
			continue
		}
		host := s.Subdomain
		if len(s.Technologies) > 0 {
			techsAndSubs = append(techsAndSubs, fmt.Sprintf("%s: %s", host, strings.Join(s.Technologies, ", ")))
		} else {
			techsAndSubs = append(techsAndSubs, fmt.Sprintf("%s: reachable", host))
		}
	}
	for _, r := range deduped {
		sevCount[r.Severity]++
		if r.EPSS > risk {
			risk = r.EPSS
		}
	}
	summary := fmt.Sprintf(
		"%d unique CVEs identified. severity=%v. Target: %s (%s). Duration: %s",
		len(deduped), sevCount, target, mode, time.Since(start).Round(time.Millisecond))
	rep := CVEReport{
		Target:     target,
		Mode:       mode,
		Started:    start.UTC().Format(time.RFC3339),
		Elapsed:    time.Since(start).Round(time.Millisecond).String(),
		MainURL:    target,
		Techs:      techsAndSubs,
		Subdomains: subBlocks,
		TotalCVEs:  len(deduped),
		Severity:   sevCount,
		RiskScore:  risk,
		Summary:    summary,
		Findings:   deduped,
	}
	if *outputPtr == "" {
		return
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] JSON marshal error: %v\n", err)
		return
	}
	if err := os.WriteFile(*outputPtr, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Writing %s failed: %v\n", *outputPtr, err)
		return
	}
	fmt.Printf("\n%s▸ Structured report written to %s%s\n", Green, *outputPtr, Reset)
}

// ScanSubdomains probes baseHost + each candidate from wordlist or file, and
// returns full SubdomainReport entries. Never fails; any unreachable host
// is skipped silently.
func ScanSubdomains(baseHost string, activeWordlist bool, wordlist []string, extraHosts []string) []SubdomainReport {
	host := strings.TrimPrefix(strings.TrimPrefix(baseHost, "https://"), "http://")
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	if host == "" {
		return nil
	}

	labels := []string{}
	if activeWordlist {
		labels = append(labels, wordlist...)
	}
	labels = append(labels, extraHosts...)

	candidates := []string{}
	seen := map[string]bool{}
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		fqdn := label + "." + host
		if seen[fqdn] {
			continue
		}
		seen[fqdn] = true
		candidates = append(candidates, fqdn)
	}

	out := make([]SubdomainReport, 0, len(candidates))
	for _, fqdn := range candidates {
		if !HostReachable(fqdn) {
			continue
		}
		startCandidate := time.Now()
		techs := ProbeTarget("https://" + fqdn + "/")
		if len(techs) == 0 {
			techs = ProbeTarget("http://" + fqdn + "/")
		}
		subCVEs := []ExportResult{}
		techList := []string{}
		for _, t := range techs {
			techList = append(techList, t.Software+" "+t.Version)
			// Cap the NVD contamination: if version unknown, skip NVD for that tech.
			if t.Version == "" || t.Version == "unknown" {
				continue
			}
			cves := QueryNVD(t.Software, t.Version)
			if len(cves) == 0 {
				continue
			}
			for i := range cves {
				cves[i].Software = t.Software + " " + t.Version
				cves[i].MatchType = "version_match"
				if cves[i].Confidence == "" {
					cves[i].Confidence = "medium"
				}
			}
			subCVEs = append(subCVEs, cves...)
		}
		// De-duplicate within the subdomain.
		subCVEs = deduplicateResults(subCVEs)
		_ = startCandidate

		out = append(out, SubdomainReport{
			Subdomain:    fqdn,
			Reachable:    true,
			URL:          "https://" + fqdn + "/",
			Technologies: techList,
			CVEs:         subCVEs,
			ScannedAt:    time.Now().UTC().Format(time.RFC3339),
		})
		fmt.Printf("%s[+] Subdomain %s — tech: %s — CVEs: %d%s\n",
			Green, fqdn, strings.Join(techList, ", "), len(subCVEs), Reset)
	}
	return out
}
