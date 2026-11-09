package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
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

// ScanSubdomains probes reachable subdomains concurrently and returns their
// SubdomainReport entries. A global phase deadline prevents the pipeline from
// ever exceeding a fixed budget, even for large wildcard-heavy enumeration sets.
func ScanSubdomains(baseHost string, passive bool, wordlist []string, extraHosts []string) []SubdomainReport {
	_ = wordlist // kept for back-compatible signature; passive API enumerates

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

	if isPrivateHost(host) {
		fmt.Fprintf(os.Stderr, "[Phase 4] private/loopback host %s — skipping OSINT subdomain feeds\n", host)
		return []SubdomainReport{}
	}

	candidates := []string{}
	seen := map[string]bool{}

	// Cap candidate count to keep wildcard-heavy domains usable.
	const maxCandidates = 40
	// Primary source: the dedicated subdomain engine with many passive providers
	// (crt.sh, hackertarget, waybackmachine, rapiddns, commoncrawl, ...).
	// Wordlist is never the discovery mechanism for this worker.
	osint := []string{}
	if passive {
		osint = enumeratePassiveSubdomains(host, 45*time.Second)
	}
	for _, sub := range osint {
		if len(candidates) >= maxCandidates {
			break
		}
		sub = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(sub, ".")))
		if sub == "" || seen[sub] {
			continue
		}
		seen[sub] = true
		candidates = append(candidates, sub)
	}

	for _, raw := range extraHosts {
		if len(candidates) >= maxCandidates {
			break
		}
		fqdn := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
		if fqdn == "" {
			continue
		}
		if !strings.HasSuffix(fqdn, "."+host) && fqdn != host {
			fqdn = fqdn + "." + host
		}
		if seen[fqdn] {
			continue
		}
		seen[fqdn] = true
		candidates = append(candidates, fqdn)
	}
	if len(candidates) > maxCandidates {
		fmt.Fprintf(os.Stderr, "[*] subdomain candidate cap hit at %d — using first %d OSINT hits\n", len(candidates), maxCandidates)
		candidates = candidates[:maxCandidates]
	}

	out := make([]SubdomainReport, 0, len(candidates))
	if len(candidates) == 0 {
		return out
	}

	const phaseDeadline = 60 * time.Second
	deadline := time.Now().Add(phaseDeadline)
	sem := make(chan struct{}, 12)        // 12 concurrent HTTP probes — enough to saturate but keeps DNS/CDN friendly
	results := make(chan SubdomainReport, 128)
	var wg sync.WaitGroup

	for _, raw := range candidates {
		fqdn := strings.TrimSpace(raw)
		if fqdn == "" {
			continue
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "[Phase 4] global deadline reached; keeping %d results\n", len(out))
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(fqdn string) {
			defer wg.Done()
			defer func() { <-sem }()

			techs := ProbeTarget("https://" + fqdn + "/")
			if len(techs) == 0 {
				techs = ProbeTarget("http://" + fqdn + "/")
			}
			if len(techs) == 0 && !HostReachable(fqdn) {
				return // skip silently — candidate did not respond with HTTPS or HTTP
			}

			subCVEs := []ExportResult{}
			techList := []string{}
			for _, t := range techs {
				techList = append(techList, t.Software+" "+t.Version)
				if t.Version == "" || t.Version == "unknown" {
					continue // no version => no CVE query needed
				}
				cves := QueryNVD(t.Software, t.Version)
				for i := range cves {
					cves[i].Software = t.Software + " " + t.Version
					cves[i].MatchType = "version_match"
					if cves[i].Confidence == "" {
						cves[i].Confidence = "medium"
					}
				}
				subCVEs = append(subCVEs, cves...)
			}
			subCVEs = deduplicateResults(subCVEs)
			results <- SubdomainReport{
				Subdomain:    fqdn,
				Reachable:    true,
				URL:          "https://" + fqdn + "/",
				Technologies: techList,
				CVEs:         subCVEs,
				ScannedAt:    time.Now().UTC().Format(time.RFC3339),
			}
		}(fqdn)
	}

	wg.Wait()
	close(results)

	for r := range results {
		out = append(out, r)
		fmt.Printf("%s[+] Subdomain %s — tech: %s — CVEs: %d%s\n",
			Green, r.Subdomain, strings.Join(r.Technologies, ", "), len(r.CVEs), Reset)
	}
	return out
}


func isPrivateHost(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	p := net.ParseIP(strings.TrimSpace(host))
	if p == nil {
		return strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".lan")
	}
	iv4 := p.To4()
	if iv4 == nil {
		return p.IsLoopback()
	}
	return iv4[0] == 10 || iv4[0] == 127 ||
		(iv4[0] == 172 && iv4[1] >= 16 && iv4[1] <= 31) ||
		(iv4[0] == 192 && iv4[1] == 168)
}
