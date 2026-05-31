package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type CWECVSSInfo struct {
	CWE         string  `json:"CWE"`
	Score       float64 `json:"Score"`
	Severity    string  `json:"Severity"`
	Vector      string  `json:"Vector"`
	Description string  `json:"Description"`
}

func loadDatabases() (map[string][]string, map[string]CWECVSSInfo) {
	signatures := make(map[string][]string)
	cweInfo := make(map[string]CWECVSSInfo)

	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)

	sigFile, err := os.ReadFile(filepath.Join(baseDir, "db_signatures.json"))
	if err == nil {
		json.Unmarshal(sigFile, &signatures)
	} else {
	    // Fallback search path if running via `go run`
	    sigFile, err = os.ReadFile("db_signatures.json")
	    if err == nil {
	        json.Unmarshal(sigFile, &signatures)
	    }
	}

	cweFile, err := os.ReadFile(filepath.Join(baseDir, "db_cwe_cvss.json"))
	if err == nil {
		json.Unmarshal(cweFile, &cweInfo)
	} else {
	    cweFile, err = os.ReadFile("db_cwe_cvss.json")
	    if err == nil {
	        json.Unmarshal(cweFile, &cweInfo)
	    }
	}

	return signatures, cweInfo
}

// AnalyzeParameterLogic passively analyzes a URL for structural weaknesses
// by reading from real JSON signature databases.
func AnalyzeParameterLogic(target string) []ExportResult {
	var results []ExportResult

	parsed, err := url.Parse(target)
	if err != nil || parsed.RawQuery == "" {
		fmt.Println("    [+] No dynamic parameters found. Logic appears static.")
		return results
	}

	signatures, cweInfo := loadDatabases()
	if len(signatures) == 0 || len(cweInfo) == 0 {
		fmt.Println("    [!] Could not load signature databases. Ensure JSON files exist.")
		return results
	}

	params := parsed.Query()
	for key := range params {
		keyLower := strings.ToLower(key)

		// Check against real database signatures
		for vulnType, sigs := range signatures {
			for _, sig := range sigs {
				if keyLower == sig {
					info, exists := cweInfo[vulnType]
					if !exists { continue }

					results = append(results, ExportResult{
						CVEID:    "Heuristic-" + vulnType,
						Score:    info.Score,
						Severity: info.Severity,
						Vector:   info.Vector,
						Software: info.Description,
						CWE:      info.CWE,
					})
					break // Found a match for this vuln type on this parameter
				}
			}
		}
	}

	return results
}
