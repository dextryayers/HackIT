package main

import "fmt"

// CommandMap stores the intelligence directives for each slash command in Go
var CommandMap = map[string]string{
	// [ CORE ]
	"halo":     "Activate full intelligence mode. Perform a comprehensive analysis and provide general assistance as a Senior Pentester.",
	"summary":  "Provide a concise summary of all discovered artifacts, open ports, subdomains, and vulnerabilities found so far.",
	"explain":  "Translate complex technical findings into clear, human-readable explanations suitable for executive stakeholders.",
	"report":   "Generate a structured, professional-grade pentesting report including executive summary, technical details, and remediation.",

	// [ ANALYSIS ]
	"insight":  "Identify the most critical insights and core vulnerabilities. Focus on high-impact findings that affect the entire infrastructure.",
	"risk":     "Perform a detailed risk assessment. Calculate CVSS scores, business impact, exploitability, and overall technical severity.",
	"score":    "Assign a numerical security score (0-100). 100 is perfectly secure, 0 is fully compromised. Justify your scoring.",
	"priority": "Identify high-value targets (databases, admin panels, CI/CD) that must be prioritized for immediate testing.",
	"anomaly":  "Detect unusual patterns, non-standard headers, or unexpected system responses that deviate from typical web behavior.",
	"pattern":  "Identify recurring misconfigurations, auth weaknesses, or API design flaws across multiple endpoints/services.",
	"logic":    "Analyze application business logic for bypasses, race conditions, IDORs, or state-machine flaws in workflows.",
	"behavior": "Analyze system behavior under stress or malformed inputs. Look for time-based differentials or leaked debug info.",
	"context":  "Evaluate findings within the business context (e.g., e-commerce vs. internal tool) to determine actual threat levels.",

	// [ CORRELATION ]
	"correlate":  "Correlate multiple data points (e.g., open port + old service version + sensitive file) to find complex attack chains.",
	"graph":      "Map relationships between nodes, services, subdomains, and endpoints in a logical, hierarchical graph structure.",
	"flow":       "Analyze end-to-end data flow. Identify where sensitive data is processed and potential exfiltration points.",
	"boundary":   "Identify trust boundaries (e.g., frontend vs. backend, internal vs. public) and evaluate data crossing security.",
	"zone":       "Classify assets into Public (DMZ), Internal, or Restricted zones based on exposure and connectivity data.",
	"dependency": "Identify service dependencies, third-party libraries, and potential supply chain risks from integrated services.",

	// [ ATTACK INTEL ]
	"attack":   "Generate detailed, step-by-step attack paths to achieve specific objectives (e.g., gaining Root, DB access).",
	"chain":    "Build a vulnerability chain where one minor finding (e.g., info leak) leads to a major compromise (e.g., RCE).",
	"vector":   "Identify and rank the primary attack vectors currently exposed on the target surface.",
	"entry":    "Pinpoint the weakest entry points into the infrastructure based on current reconnaissance data.",
	"surface":  "Define the total attack surface area. Identify shadow IT, forgotten staging servers, and exposed sub-services.",
	"scenario": "Simulate complex attack scenarios (e.g., APT, Ransomware, Insider Threat) based on discovered gaps.",

	// [ API & AUTH ]
	"remaining": "Check and report on AI token/API usage and remaining quota based on current session activity.",
	"session":   "Analyze session management mechanisms (cookies, JWT, entropy) for potential hijacking or fixation issues.",

	// [ CLOUD & INFRA ]
	"cloud":  "Specialize in Cloud-native vulnerabilities. Audit S3 buckets, IAM roles, Metadata services, and Lambda functions.",
	"origin": "Analyze CDN/WAF headers and SSL certificates to predict the real Origin IP address and bypass protection.",
	"waf":    "Analyze WAF/IPS protection mechanisms. Identify potential bypass heuristics, rate-limit thresholds, and rule gaps.",

	// [ OSINT ]
	"osint":    "Correlate external OSINT data (DNS, WHOIS, Breach data) with internal scan results for a full threat profile.",
	"employee": "Identify employee patterns, common email structures, and potential social engineering targets within the org.",
	"leak":     "Search for potential data leaks, exposed secrets (API keys), or credential dumps related to the target domain.",

	// [ STRATEGY ]
	"strategy": "Recommend a comprehensive testing strategy (Black-box vs Grey-box) based on the reconnaissance dossier.",
	"next":     "Recommend the immediate next tactical steps the analyst should take for maximum discovery impact.",
	"focus":    "Identify the single most critical area where the analyst should focus all attention right now.",
	"plan":     "Generate a detailed exploitation plan for confirmed vulnerabilities, including recommended tools and payloads.",

	// [ OUTPUT ]
	"json":   "Format all output strictly as a valid JSON object for integration with automated parsing tools.",
	"clean":  "Provide a clean, minimal response with only the core findings and zero conversational fluff.",
	"detail": "Provide a comprehensive, high-fidelity response with all technical evidence and artifacts included.",
	"dev":    "Output technical details specifically for developers. Include code snippets, RFC references, and patch advice.",
	"human":  "Ensure the output is easy to read, professionally formatted with clear headings and bullet points.",

	// [ ADVANCED ]
	"deep":     "Perform a deep-dive analysis. Spend more tokens to simulate multiple layers of reasoning and edge cases.",
	"auto":     "Enter autonomous analysis mode. Correlate all available data and report findings without analyst input.",
	"adaptive": "Enable adaptive learning. Adjust analysis style and detail level based on previous analyst interactions.",
	"learn":    "Identify and save recurring patterns, bypasses, or successful payloads for future recognition.",
}

func GetCommandInstruction(cmd string) string {
	if desc, ok := CommandMap[cmd]; ok {
		return fmt.Sprintf("\n[ MODE: %s ]\nInstruction: %s\nFocus strictly on this task.", cmd, desc)
	}
	return ""
}
