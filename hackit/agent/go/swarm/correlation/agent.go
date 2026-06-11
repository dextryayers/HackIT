package correlation

import (
	"fmt"
	"hackit_ai_engine/swarm/core"
)

// CorrelationAgent is Node 7 in the 20-Node Autonomous Swarm
// Responsible for connecting isolated findings into contextual attack chains.
type CorrelationAgent struct{}

func NewCorrelationAgent() *CorrelationAgent {
	return &CorrelationAgent{}
}

func (c *CorrelationAgent) Name() string {
	return "Agent-7: Correlation"
}

func (c *CorrelationAgent) Description() string {
	return "Connects isolated vulnerabilities into larger risk contexts and attack chains."
}

func (c *CorrelationAgent) Execute(state *core.SwarmState) error {
	state.Log(c.Name(), "START", "Starting Threat Correlation Matrix...")

	state.Mu.Lock()
	vulns := state.Vulns
	state.Mu.Unlock()

	if len(vulns) == 0 {
		state.Log(c.Name(), "INFO", "No vulnerabilities to correlate. Attack surface appears sterile.")
		return nil
	}

	state.Log(c.Name(), "TASK", fmt.Sprintf("Analyzing %d isolated findings for attack chains...", len(vulns)))

	var attackChains []string

	// Detect if a .env leak can lead to RCE or DB compromise
	hasEnvLeak := false
	hasWordPress := false

	for _, v := range vulns {
		if v.ID == "MISCONF-001" {
			hasEnvLeak = true
		}
		if v.ID == "CVE-2023-XXXX" { // Our mock WP vuln
			hasWordPress = true
		}
	}

	if hasEnvLeak && hasWordPress {
		chain := "ATTACK CHAIN DETECTED: [Exposed .env] -> DB Credentials -> [WordPress DB Compromise] -> [Admin Account Takeover] -> [Remote Code Execution]"
		attackChains = append(attackChains, chain)
		state.Log(c.Name(), "ALERT", chain)

		// Elevate the severity of the original vulns because they chain
		state.Mu.Lock()
		for i := range state.Vulns {
			if state.Vulns[i].ID == "MISCONF-001" {
				state.Vulns[i].Description += " (CRITICAL: Confirmed chained with WordPress DB exposure)"
			}
		}
		state.Mu.Unlock()
	}

	state.Mu.Lock()
	if len(attackChains) > 0 {
		state.ContextData["attack_chains"] = attackChains
	}
	state.Mu.Unlock()

	state.Log(c.Name(), "COMPLETE", "Correlation complete. Handing over to Agent-8: Evidence Collection.")

	return nil
}
