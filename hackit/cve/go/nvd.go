package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	CVEID       string  `json:"cve_id"`
	Score       float64 `json:"score"`
	Severity    string  `json:"severity"`
	Vector      string  `json:"vector"`
	Software    string  `json:"software"`
	CWE         string  `json:"cwe"`
	Description string  `json:"description,omitempty"`
	EPSS        float64 `json:"epss,omitempty"`
	Published   string  `json:"published,omitempty"`
	AttackType  string  `json:"attack_type,omitempty"`
	Source      string  `json:"source,omitempty"`
}

var (
	nvdSem       = make(chan struct{}, 3) // max 3 concurrent NVD requests
	nvdAPIKey    string
	nvdReqCount  int
	nvdReqMu     sync.Mutex
	nvdLastReq   time.Time
)

func SetNVDAPIKey(key string) {
	nvdAPIKey = key
}

func nvdRateLimit() {
	nvdReqMu.Lock()
	elapsed := time.Since(nvdLastReq)
	if elapsed < time.Second {
		nvdReqMu.Unlock()
		time.Sleep(time.Second - elapsed)
		return
	}
	nvdLastReq = time.Now()
	nvdReqCount++
	nvdReqMu.Unlock()
}

func getCVEInfo(cveID string) *CVEInfo {
	nvdSem <- struct{}{}
	defer func() { <-nvdSem }()
	nvdRateLimit()

	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", url.QueryEscape(cveID))
	debugCVE("Fetching CVE detail: %s", cveID)

	client := &http.Client{Timeout: 15 * time.Second}
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
	nvdSem <- struct{}{}
	defer func() { <-nvdSem }()
	nvdRateLimit()

	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=20",
		url.QueryEscape(cpe))
	debugCVE("NVD CPE query: %s", apiURL)

	client := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (CVE Scanner)")
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

	return extractResults(&nvdResp, "", "")
}

func QueryNVD(software, version string) []ExportResult {
	nvdSem <- struct{}{}
	defer func() { <-nvdSem }()
	nvdRateLimit()

	// First try CPE-based search
	cpe := generateCPE(software, version)
	if cpe != "" {
		results := QueryNVDCPE(cpe)
		if len(results) > 0 {
			return results
		}
	}

	// Fallback to keyword search
	query := url.QueryEscape(fmt.Sprintf("%s %s", software, version))
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20", query)
	debugCVE("NVD keyword query: %s %s", software, version)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (CVE Scanner)")
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
		return nil
	}

	return extractResults(&nvdResp, software, version)
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
		severity := "INFO"
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
			if severity == "" {
				severity = "UNKNOWN"
			}
			vector = m.CVSSData.VectorString
			attackType = summarizeAttackVector(m.CVSSData)
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

		// Determine displayed software name
		sw := software
		if sw == "" {
			sw = cve.ID
		}
		if version != "" {
			sw = fmt.Sprintf("%s %s", software, version)
		}

		results = append(results, ExportResult{
			CVEID:       cve.ID,
			Score:       score,
			Severity:    severity,
			Vector:      vector,
			Software:    sw,
			CWE:         cwe,
			Description: desc,
			Published:   cve.Published,
			AttackType:  attackType,
			Source:      cve.SourceIdentifier,
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
