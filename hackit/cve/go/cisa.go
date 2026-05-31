package main

// Simulated CISA KEV (Known Exploited Vulnerabilities) Mapping
// In a full environment, this would fetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

func CheckCISA(cveID string) string {
	// A small mock of famous ones, otherwise "Not Listed"
	kev := map[string]string{
		"CVE-2021-44228": "Log4Shell - Remote Code Execution",
		"CVE-2021-34527": "PrintNightmare - Remote Code Execution",
		"CVE-2017-0144":  "EternalBlue - SMB Remote Code Execution",
		"CVE-2014-0160":  "Heartbleed - Information Disclosure",
	}

	if desc, found := kev[cveID]; found {
		return "YES - " + desc
	}
	return "No"
}
