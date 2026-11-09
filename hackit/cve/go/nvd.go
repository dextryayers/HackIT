package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type NVDResponse struct {
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
	TotalResults    int                 `json:"totalResults"`
}

type VulnerabilityItem struct {
	CVE CVEInfo `json:"cve"`
}

type CVEInfo struct {
	ID             string         `json:"id"`
	SourceIdentifier string       `json:"sourceIdentifier"`
	Published      string         `json:"published"`
	LastModified   string         `json:"lastModified"`
	Descriptions   []LangString   `json:"descriptions"`
	Metrics        Metrics        `json:"metrics"`
	Weaknesses     []Weakness     `json:"weaknesses"`
	Configurations []interface{}  `json:"configurations"`
	References     []Reference    `json:"references"`
}

type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Weakness struct {
	Description []WeaknessDesc `json:"description"`
}

type WeaknessDesc struct {
	Value string `json:"value"`
}

type Metrics struct {
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetric `json:"cvssMetricV2"`
}

type CVSSMetric struct {
	CVSSData       CVSSData `json:"cvssData"`
	Exploitability float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore    float64  `json:"impactScore,omitempty"`
}

type CVSSData struct {
	BaseScore       float64 `json:"baseScore"`
	BaseSeverity    string  `json:"baseSeverity"`
	VectorString    string  `json:"vectorString"`
	AttackVector    string  `json:"attackVector,omitempty"`
	AttackComplexity string `json:"attackComplexity,omitempty"`
	PrivilegesReq   string  `json:"privilegesRequired,omitempty"`
	UserInteraction string  `json:"userInteraction,omitempty"`
	Scope           string  `json:"scope,omitempty"`
	Confidentiality string  `json:"confidentialityImpact,omitempty"`
	Integrity       string  `json:"integrityImpact,omitempty"`
	Availability    string  `json:"availabilityImpact,omitempty"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type ExportResult struct {
	CVEID       string   `json:"cve_id"`
	Score       float64  `json:"score"`
	Severity    string   `json:"severity"`
	Vector      string   `json:"vector"`
	Software    string   `json:"software"`
	Version     string   `json:"version,omitempty"`
	CWE         string   `json:"cwe"`
	Description string   `json:"description,omitempty"`
	EPSS        float64  `json:"epss,omitempty"`
	Published   string   `json:"published,omitempty"`
	AttackType  string   `json:"attack_type,omitempty"`
	Source      string   `json:"source,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	MatchType   string   `json:"match_type,omitempty"`
	References  []string `json:"references,omitempty"`
}

var (
	nvdSema     = make(chan struct{}, 4) // max concurrency for NVD requests
	nvdAPIKey   string
	nvdReqCount int

	nvdReqMu     sync.Mutex
	nvdLastReq   time.Time
	nvdCacheMu   sync.Mutex
)

func SetNVDAPIKey(key string) {
	nvdAPIKey = key
	if key == "" {
		// No key: honour NVD public-tier rate limit (1 request / second).
		nvdSema = make(chan struct{}, 2)
	}
}

func nvdRateLimit() {
	nvdReqMu.Lock()
	elapsed := time.Since(nvdLastReq)
	defer nvdReqMu.Unlock()
	if nvdAPIKey != "" {
		if elapsed < 600*time.Millisecond {
			time.Sleep(600*time.Millisecond - elapsed)
		}
	} else if elapsed < time.Second {
		time.Sleep(time.Second - elapsed)
	}
	nvdLastReq = time.Now()
	nvdReqCount++
}

func nvdCachePath() string {
	exe, err := os.Executable()
	if err == nil {
		if info, err := os.Stat(filepath.Dir(exe)); err == nil && info.IsDir() {
			return filepath.Join(filepath.Dir(exe), "nvd_cache.json")
		}
	}
	cacheRoot := os.Getenv("XDG_CACHE_HOME")
	if cacheRoot == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cacheRoot = filepath.Join(home, ".cache")
		} else {
			cacheRoot = os.TempDir()
		}
	}
	dir := filepath.Join(cacheRoot, "hackit")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "nvd_cache.json")
}

func readNVDCache() map[string]json.RawMessage {
	nvdCacheMu.Lock()
	defer nvdCacheMu.Unlock()
	data, err := os.ReadFile(nvdCachePath())
	if err != nil {
		return nil
	}
	cache := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}
	return cache
}

func writeNVDCacheEntry(key string, payload json.RawMessage) {
	nvdCacheMu.Lock()
	defer nvdCacheMu.Unlock()
	cache := readNVDCache()
	if len(cache) > 800 {
		trimmed := map[string]json.RawMessage{}
		count := 0
		for k, v := range cache {
			if count >= 400 {
				break
			}
			trimmed[k] = v
			count++
		}
		cache = trimmed
	}
	cache[key] = payload
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	tmp := nvdCachePath() + ".tmp"
	_ = os.WriteFile(tmp, data, 0o600)
	_ = os.Rename(tmp, nvdCachePath())
}

func cachedQueryNVDCPE(cpe string) []ExportResult {
	cacheKey := "cpe:" + cpe
	if cache := readNVDCache(); cache != nil {
		if raw, ok := cache[cacheKey]; ok {
			var items []ExportResult
			if err := json.Unmarshal(raw, &items); err == nil {
				return items
			}
		}
	}

	currentSema := nvdSema
	currentSema <- struct{}{}
	defer func() { <-currentSema }()
	nvdRateLimit()

	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=50",
		url.QueryEscape(cpe))
	debugCVE("NVD CPE query: %s", apiURL)

	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "HackIt-CVE/2.0 (authorised assessment)")
	req.Header.Set("Accept", "application/json")
	if nvdAPIKey != "" {
		req.Header.Set("apiKey", nvdAPIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		debugCVE("NVD CPE error: %v", err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		debugCVE("NVD CPE parse error: %v", err)
		return nil
	}

	results := extractResults(&nvdResp, "", "")
	if payload, err := json.Marshal(results); err == nil {
		writeNVDCacheEntry(cacheKey, payload)
	}
	return results
}

func cachedQueryNVDKeyword(software, version string) []ExportResult {
	cacheKey := "keyword:" + strings.ToLower(software) + ":" + strings.ToLower(version)
	if cache := readNVDCache(); cache != nil {
		if raw, ok := cache[cacheKey]; ok {
			var items []ExportResult
			if err := json.Unmarshal(raw, &items); err == nil {
				return items
			}
		}
	}

	currentSema := nvdSema
	currentSema <- struct{}{}
	defer func() { <-currentSema }()
	nvdRateLimit()

	query := url.QueryEscape(fmt.Sprintf("%s %s", software, version))
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=40", query)
	debugCVE("NVD keyword query: %s %s", software, version)

	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "HackIt-CVE/2.0 (authorised assessment)")
	req.Header.Set("Accept", "application/json")
	if nvdAPIKey != "" {
		req.Header.Set("apiKey", nvdAPIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		debugCVE("NVD keyword error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		debugCVE("NVD keyword parse error: %v", err)
		return nil
	}

	matches := extractResults(&nvdResp, software, version)
	filtered := make([]ExportResult, 0, len(matches))
	for _, r := range matches {
		if keywordMatchReasonable(software, r.Description) {
			filtered = append(filtered, r)
		}
	}
	if payload, err := json.Marshal(filtered); err == nil {
		writeNVDCacheEntry(cacheKey, payload)
	}
	return filtered
}

func QueryNVD(software, version string) []ExportResult {
	cpe := generateCPE(software, version)
	if cpe != "" {
		if results := QueryNVDCPE(cpe); len(results) > 0 {
			return results
		}
	}
	return cachedQueryNVDKeyword(software, version)
}

func getCVEInfo(cveID string) *CVEInfo {
	cached := nvdSema
	cached <- struct{}{}
	defer func() { <-cached }()
	nvdRateLimit()

	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", url.QueryEscape(cveID))
	debugCVE("Fetching CVE detail: %s", cveID)

	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (CVE Scanner)")
	req.Header.Set("Accept", "application/json")
	if nvdAPIKey != "" {
		req.Header.Set("apiKey", nvdAPIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		debugCVE("NVD error for %s: %v", cveID, err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil
	}
	if len(nvdResp.Vulnerabilities) == 0 {
		return nil
	}
	return &nvdResp.Vulnerabilities[0].CVE
}

func QueryNVDCPE(cpe string) []ExportResult {
	return cachedQueryNVDCPE(cpe)
}


func extractResults(nvdResp *NVDResponse, software, version string) []ExportResult {
	var results []ExportResult
	seen := make(map[string]bool)

	for _, vItem := range nvdResp.Vulnerabilities {
		cve := vItem.CVE
		if seen[cve.ID] {
			continue
		}
		seen[cve.ID] = true

		var score float64
		severity := ""   // resolved below from CVSS, and normalized
		vector := "N/A"
		attackType := ""

		if len(cve.Metrics.CVSSMetricV31) > 0 {
			m := cve.Metrics.CVSSMetricV31[0]
			score = m.CVSSData.BaseScore
			severity = m.CVSSData.BaseSeverity
			vector = m.CVSSData.VectorString
			attackType = summarizeAttackVector(m.CVSSData)
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			m := cve.Metrics.CVSSMetricV30[0]
			score = m.CVSSData.BaseScore
			severity = m.CVSSData.BaseSeverity
			vector = m.CVSSData.VectorString
			attackType = summarizeAttackVector(m.CVSSData)
		} else if len(cve.Metrics.CVSSMetricV2) > 0 {
			m := cve.Metrics.CVSSMetricV2[0]
			score = m.CVSSData.BaseScore
			severity = m.CVSSData.BaseSeverity
			vector = m.CVSSData.VectorString
			attackType = summarizeAttackVector(m.CVSSData)
		}

		// Normalize CVSS severity: prefer NVD value, fall back to score band.
		severityUpper := strings.ToUpper(strings.TrimSpace(severity))
		if severityUpper == "" || severityUpper == "UNKNOWN" || severityUpper == "NONE" {
			severity = severityFromScore(score)
		} else {
			switch severityUpper {
			case "CRITICAL":
				severity = "CRITICAL"
			case "HIGH":
				severity = "HIGH"
			case "MEDIUM":
				severity = "MEDIUM"
			case "LOW":
				severity = "LOW"
			default:
				severity = severityFromScore(score)
			}
		}

		// Extract description (English)
		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		if len(desc) > 200 {
			desc = desc[:200] + "..."
		}

		// Extract CWE
		cwe := "N/A"
		if len(cve.Weaknesses) > 0 && len(cve.Weaknesses[0].Description) > 0 {
			cwe = cve.Weaknesses[0].Description[0].Value
		}

		// Collect useful references (advisories, patches, vendor notes).
		refs := make([]string, 0, 12)
		for _, ref := range cve.References {
			if ref.URL == "" {
				continue
			}
			refs = append(refs, ref.URL)
			if len(refs) >= 12 {
				break
			}
		}

		// Determine displayed software name
		sw := software
		if sw == "" {
			sw = cve.ID
		}
		if version != "" {
			sw = fmt.Sprintf("%s %s", software, version)
		}

		runtimeSw := software
		if runtimeSw == "" {
			runtimeSw = cve.ID
		}
		matchType := ""
		if version != "" {
			matchType = "version_match"
		} else {
			matchType = "keyword"
		}
		results = append(results, ExportResult{
			CVEID:       cve.ID,
			Score:       score,
			Severity:    severity,
			Vector:      vector,
			Software:    sw,
			Version:     version,
			CWE:         cwe,
			Description: desc,
			Published:   cve.Published,
			AttackType:  attackType,
			Source:      cve.SourceIdentifier,
			Confidence:  "medium",
			MatchType:   matchType,
			References:  refs,
		})
	}
	return results
}

func summarizeAttackVector(d CVSSData) string {
	parts := []string{}
	if d.AttackVector == "NETWORK" {
		parts = append(parts, "Remote")
	} else if d.AttackVector != "" {
		parts = append(parts, d.AttackVector)
	}
	if d.AttackComplexity == "LOW" {
		parts = append(parts, "Low Complexity")
	}
	if d.PrivilegesReq == "NONE" {
		parts = append(parts, "No Auth")
	}
	impact := 0
	if d.Confidentiality == "HIGH" {
		impact++
	}
	if d.Integrity == "HIGH" {
		impact++
	}
	if d.Availability == "HIGH" {
		impact++
	}
	if impact >= 2 {
		parts = append(parts, "High Impact")
	}
	return strings.Join(parts, " | ")
}

func generateCPE(software, version string) string {
	sw := strings.ToLower(software)
	ver := strings.ToLower(version)
	if ver == "" || ver == "unknown" {
		return ""
	}
	// Map common software names to CPE vendor/product
	vendorMap := map[string]string{
		"apache":                "apache",
		"nginx":                 "nginx",
		"iis":                   "microsoft",
		"openssh":               "openbsd",
		"mysql":                 "oracle",
		"mariadb":               "mariadb",
		"postgresql":            "postgresql",
		"redis":                 "redis",
		"mongodb":               "mongodb",
		"node.js":               "nodejs",
		"python":                "python",
		"php":                   "php",
		"ruby":                  "ruby",
		"java":                  "oracle",
		"tomcat":                "apache",
		"jetty":                 "eclipse",
		"docker":                "docker",
		"kubernetes":            "kubernetes",
		"elasticsearch":         "elastic",
		"kibana":                "elastic",
		"logstash":              "elastic",
		"wordpress":             "wordpress",
		"drupal":                "drupal",
		"joomla":                "joomla",
		"magento":               "magento",
	}
	productMap := map[string]string{
		"apache":      "http_server",
		"nginx":       "nginx",
		"iis":         "iis",
		"openssh":     "openssh",
		"mysql":       "mysql",
		"mariadb":     "mariadb",
		"postgresql":  "postgresql",
		"redis":       "redis",
		"mongodb":     "mongodb",
		"node.js":     "node.js",
		"python":      "python",
		"php":         "php",
		"ruby":        "ruby",
		"java":        "java",
		"tomcat":      "tomcat",
		"jetty":       "jetty",
		"docker":      "docker",
		"kubernetes":  "kubernetes",
		"elasticsearch": "elasticsearch",
		"kibana":      "kibana",
		"logstash":    "logstash",
		"wordpress":   "wordpress",
		"drupal":      "drupal",
		"joomla":      "joomla",
		"magento":     "magento",
	}

	vendor, hasVendor := vendorMap[sw]
	prod, hasProd := productMap[sw]

	if hasVendor && hasProd {
		return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, prod, ver)
	}
	// Generic: use software name as both vendor and product
	sw = strings.ReplaceAll(sw, " ", "_")
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", sw, sw, ver)
}

// Deduplicate CVEs across all results
func deduplicateResults(results []ExportResult) []ExportResult {
	seen := make(map[string]ExportResult)
	for _, r := range results {
		if existing, ok := seen[r.CVEID]; ok {
			// Keep the one with the higher CVSS score
			if r.Score > existing.Score {
				seen[r.CVEID] = r
			}
		} else {
			seen[r.CVEID] = r
		}
	}
	deduped := make([]ExportResult, 0, len(seen))
	for _, r := range seen {
		deduped = append(deduped, r)
	}
	return deduped
}


func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "INFO"
	}
}

// keywordMatchReasonable drops NVD keyword hits in which the queried software
// name is absent from the summary; these are almost always mis-scoped.
func keywordMatchReasonable(sw, desc string) bool {
	sw = strings.ToLower(strings.TrimSpace(sw))
	if sw == "" {
		return true
	}
	desc = strings.ToLower(desc)
	if strings.Contains(desc, sw) {
		return true
	}
	// A few tolerant fallbacks (word-boundary-ish substring match).
	base := strings.TrimSuffix(sw, ".js")
	if base != sw && strings.Contains(desc, base) {
		return true
	}
	return false
}
