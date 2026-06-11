package main

import (
	"strings"
)

// AITactics maps services/ports to specific bug hunting strategies.
type AITactic struct {
	ServiceName string
	Description string
	Action      string // Type of action: "fuzz", "enum", "exploit_check"
	Tools       []string
}

// KnowledgeBase holds the AI's internal logic for what to do when it finds something.
var KnowledgeBase = []AITactic{
	{
		ServiceName: "http",
		Description: "Web Server Found. Start directory busting and XSS/SQLi fuzzing.",
		Action:      "fuzz",
		Tools:       []string{"dir_finder", "sqli", "xss", "lfi", "header_audit"},
	},
	{
		ServiceName: "https",
		Description: "Secure Web Server Found. Start SSL analysis, directory busting, and web fuzzing.",
		Action:      "fuzz",
		Tools:       []string{"ssl_tool", "dir_finder", "sqli", "xss", "lfi"},
	},
	{
		ServiceName: "ssh",
		Description: "SSH Service Found. Enumerate users and check for known vulnerabilities (e.g., regreSSHion).",
		Action:      "enum",
		Tools:       []string{"cve_search", "ssh_enum"},
	},
	{
		ServiceName: "ftp",
		Description: "FTP Service Found. Check for anonymous login and known exploits.",
		Action:      "exploit_check",
		Tools:       []string{"ftp_anon_check", "cve_search"},
	},
	{
		ServiceName: "mysql",
		Description: "MySQL Database Found. Attempt default credential checks and enumeration.",
		Action:      "enum",
		Tools:       []string{"db_enum", "default_creds"},
	},
	{
		ServiceName: "smb",
		Description: "SMB Service Found. Check for EternalBlue and enumerate shares.",
		Action:      "exploit_check",
		Tools:       []string{"smb_enum", "cve_search"},
	},
	{
		ServiceName: "api",
		Description: "API Endpoint Discovered. Fuzz parameters, test for Broken Object Level Authorization (BOLA).",
		Action:      "fuzz",
		Tools:       []string{"api_fuzzer", "postman_recon"},
	},
	{
		ServiceName: "graphql",
		Description: "GraphQL Endpoint Found. Attempt Introspection query and batch attacks.",
		Action:      "exploit_check",
		Tools:       []string{"graphql_dumper", "query_brute"},
	},
}

// LookupTactic finds the best tactics for a given service.
func LookupTactic(service string) []AITactic {
	var results []AITactic
	svc := strings.ToLower(service)

	// Direct match
	for _, tactic := range KnowledgeBase {
		if strings.Contains(svc, tactic.ServiceName) {
			results = append(results, tactic)
		}
	}

	return results
}

// GenerateAttackPlan creates a strategic plan based on discovered open ports.
func GenerateAttackPlan(openServices []string) string {
	plan := "🎯 **AI Autonomous Attack Plan Generated**\n\n"

	for _, svc := range openServices {
		tactics := LookupTactic(svc)
		for _, t := range tactics {
			plan += "🔥 **Target Service**: `" + t.ServiceName + "`\n"
			plan += "   - **Strategy**: " + t.Description + "\n"
			plan += "   - **Action Phase**: " + t.Action + "\n"
			plan += "   - **Tooling**: " + strings.Join(t.Tools, ", ") + "\n\n"
		}
	}

	if plan == "🎯 **AI Autonomous Attack Plan Generated**\n\n" {
		plan += "No known strategic vectors found for the listed services. Will default to deep probing.\n"
	}

	return plan
}
