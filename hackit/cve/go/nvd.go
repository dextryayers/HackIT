package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type NVDResponse struct {
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type VulnerabilityItem struct {
	CVE CVEInfo `json:"cve"`
}

type CVEInfo struct {
	ID      string  `json:"id"`
	Metrics Metrics `json:"metrics"`
	Weaknesses []Weakness `json:"weaknesses"`
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
	CVSSData CVSSData `json:"cvssData"`
}

type CVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type ExportResult struct {
	CVEID    string  `json:"cve_id"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector"`
	Software string  `json:"software"`
	CWE      string  `json:"cwe"`
}

func QueryNVD(software, version string) []ExportResult {
	var results []ExportResult
	query := url.QueryEscape(fmt.Sprintf("%s %s", software, version))
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s", query)

	client := http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return results
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var nvdResp NVDResponse
	json.Unmarshal(body, &nvdResp)

	for _, vItem := range nvdResp.Vulnerabilities {
		cve := vItem.CVE
		var score float64 = 0.0
		severity := "INFO"
		vector := "N/A"
		cwe := "N/A"

		if len(cve.Weaknesses) > 0 && len(cve.Weaknesses[0].Description) > 0 {
			cwe = cve.Weaknesses[0].Description[0].Value
		}

		if len(cve.Metrics.CVSSMetricV31) > 0 {
			score = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			severity = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
			vector = cve.Metrics.CVSSMetricV31[0].CVSSData.VectorString
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			score = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			severity = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
			vector = cve.Metrics.CVSSMetricV30[0].CVSSData.VectorString
		} else if len(cve.Metrics.CVSSMetricV2) > 0 {
			score = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
			severity = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseSeverity
			if severity == "" { severity = "UNKNOWN" }
			vector = cve.Metrics.CVSSMetricV2[0].CVSSData.VectorString
		}

		results = append(results, ExportResult{
			CVEID:    cve.ID,
			Score:    score,
			Severity: severity,
			Vector:   vector,
			Software: software,
			CWE:      cwe,
		})
	}
	return results
}
