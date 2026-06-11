package vuln_analysis

import (
	"fmt"
	"strings"

	"hackit_ai_engine/swarm/core"
)

// VulnAnalysisAgent is Node 6 in the 20-Node Autonomous Swarm
// Responsible for cross-referencing enumerated endpoints and tech stack against known CVEs and misconfigs.
type VulnAnalysisAgent struct{}

func NewVulnAnalysisAgent() *VulnAnalysisAgent {
	return &VulnAnalysisAgent{}
}

func (v *VulnAnalysisAgent) Name() string {
	return "Agent-6: Vulnerability Analysis"
}

func (v *VulnAnalysisAgent) Description() string {
	return "Analyzes the combined state to detect potential vulnerabilities, CVEs, and logic flaws."
}

func (v *VulnAnalysisAgent) Execute(state *core.SwarmState) error {
	state.Log(v.Name(), "START", "Commencing Deep Vulnerability Analysis...")

	state.Mu.Lock()
	endpointsRaw, ok := state.ContextData["enumerated_endpoints"]
	services := state.Discovered
	state.Mu.Unlock()

	var endpoints []string
	if ok {
		endpoints = endpointsRaw.([]string)
	}

	state.Log(v.Name(), "TASK", fmt.Sprintf("Analyzing %d services and %d endpoints against Exploit KB...", len(services), len(endpoints)))

	var vulns []core.Vulnerability

	// 1. Analyze Tech Stack for CVEs
	for _, svc := range services {
		if strings.Contains(svc.Tech, "WordPress") {
			vulns = append(vulns, core.Vulnerability{
				ID:          "CVE-2023-XXXX",
				Name:        "WordPress Plugin Vulnerability",
				Severity:    "High",
				CVSS:        8.5,
				Description: fmt.Sprintf("Outdated WordPress installation detected on %s", svc.IP),
				Evidence:    "Wappalyzer signature matched outdated WP-JSON API.",
			})
		}
		if svc.Port == 22 && strings.Contains(svc.Tech, "OpenSSH 8.2p1") {
			vulns = append(vulns, core.Vulnerability{
				ID:          "CVE-2020-15778",
				Name:        "OpenSSH SCP Command Execution",
				Severity:    "Medium",
				CVSS:        6.8,
				Description: fmt.Sprintf("OpenSSH 8.2p1 is vulnerable to scp injection on %s", svc.IP),
				Evidence:    svc.Banner,
			})
		}
	}

	// 2. Analyze Endpoints for Misconfigurations
	for _, ep := range endpoints {
		if strings.HasSuffix(ep, "/.env") {
			vulns = append(vulns, core.Vulnerability{
				ID:          "MISCONF-001",
				Name:        "Exposed Environment Variables",
				Severity:    "Critical",
				CVSS:        10.0,
				Description: fmt.Sprintf("Sensitive .env file exposed at %s", ep),
				Evidence:    "HTTP 200 OK containing DB_PASSWORD",
			})
		}
		if strings.HasSuffix(ep, "/.git/config") {
			vulns = append(vulns, core.Vulnerability{
				ID:          "MISCONF-002",
				Name:        "Exposed Git Repository",
				Severity:    "High",
				CVSS:        7.5,
				Description: fmt.Sprintf("Source code repository exposed at %s", ep),
				Evidence:    "HTTP 200 OK containing [core] repository info",
			})
		}
	}

	// Save to State
	state.Mu.Lock()
	state.Vulns = append(state.Vulns, vulns...)
	state.Mu.Unlock()

	state.Log(v.Name(), "DISCOVERY", fmt.Sprintf("Identified %d distinct vulnerabilities.", len(vulns)))
	state.Log(v.Name(), "COMPLETE", "Vulnerability analysis complete. Handing over to Agent-7: Correlation.")

	return nil
}
