package main

import "strings"

// Maps a CVE ID to a GitHub Advisory if known (Mocked for speed in defensive tool)
func CheckGitHubAdvisory(cveID string) string {
	// Simulated OSV mapping
	if strings.Contains(cveID, "2024") {
		return "GHSA-xxxx-xxxx-xxxx (Mapped by Year)"
	}
	return "No Advisory Found"
}

// Maps CWE to OWASP Top 10
func MapCWEtoOWASP(cweID string) string {
	if cweID == "N/A" {
		return "Unknown"
	}
	// Simplified Mapping
	switch cweID {
	case "CWE-89", "CWE-78", "CWE-79":
		return "A03:2021 - Injection"
	case "CWE-20", "CWE-22":
		return "A01:2021 - Broken Access Control"
	case "CWE-352":
		return "A01:2021 - Broken Access Control"
	case "CWE-319", "CWE-200":
		return "A02:2021 - Cryptographic Failures"
	case "CWE-400", "CWE-770":
		return "A05:2021 - Security Misconfiguration"
	default:
		return "Unmapped / Various"
	}
}

// Checks if it's likely in Exploit-DB based on severity (Simulated)
func CheckExploitDB(severity string, score float64) string {
	if score >= 8.5 || severity == "CRITICAL" {
		return "Likely Available (Check Exploit-DB)"
	}
	return "Not Publicly weaponized (Likely)"
}
