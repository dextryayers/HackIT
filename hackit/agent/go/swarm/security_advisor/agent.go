package security_advisor

import (
	"fmt"
	"hackit_ai_engine/swarm/core"
)

// SecurityAdvisorAgent is Node 15 in the 20-Node Autonomous Swarm
// Responsible for producing precise, actionable technical mitigations.
type SecurityAdvisorAgent struct{}

func NewSecurityAdvisorAgent() *SecurityAdvisorAgent {
	return &SecurityAdvisorAgent{}
}

func (s *SecurityAdvisorAgent) Name() string {
	return "Agent-15: Security Advisor"
}

func (s *SecurityAdvisorAgent) Description() string {
	return "Provides technical explanations, risk levels, and mitigation best practices based on findings."
}

func (s *SecurityAdvisorAgent) Execute(state *core.SwarmState) error {
	state.Log(s.Name(), "START", "Starting Security Advisory & Mitigation Matrix...")

	vulns := state.Vulns
	if len(vulns) == 0 {
		state.Log(s.Name(), "INFO", "No vulnerabilities detected. Generating standard hardening advice.")
		return nil
	}

	state.Log(s.Name(), "TASK", fmt.Sprintf("Generating Mitigation Strategies for %d vulnerabilities...", len(vulns)))

	var mitigations []string

	for i, v := range vulns {
		mitigation := ""
		if v.ID == "MISCONF-001" {
			mitigation = "MITIGATION: Immediately rotate all database credentials and API keys. Restrict web server access to `.env` files using `location ~ /\\.env { deny all; }` in Nginx or `.htaccess` in Apache."
		} else if v.ID == "CVE-2023-XXXX" {
			mitigation = "MITIGATION: Update WordPress to the latest stable version. Implement a strict WAF rule to block unauthorized access to wp-json endpoints."
		} else if v.ID == "CVE-2020-15778" {
			mitigation = "MITIGATION: Upgrade OpenSSH to version 8.3p1 or newer. Alternatively, disable SCP entirely and enforce SFTP subsystem in `sshd_config`."
		} else {
			mitigation = "MITIGATION: Apply vendor patches immediately and restrict network access to the affected service."
		}

		// Inject mitigation back into the vulnerability object's description
		state.Mu.Lock()
		state.Vulns[i].Description += "\n\n" + mitigation
		state.Mu.Unlock()
		mitigations = append(mitigations, mitigation)
	}

	state.Log(s.Name(), "COMPLETE", "Mitigation strategies injected into the state. Handing over to Agent-16: Monitoring.")

	return nil
}
