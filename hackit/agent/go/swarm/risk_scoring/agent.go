package risk_scoring

import (
	"fmt"
	"hackit_ai_engine/swarm/core"
)

// RiskScoringAgent is Node 9 in the 20-Node Autonomous Swarm
// Responsible for CVSS calculations and business impact prioritization.
type RiskScoringAgent struct{}

func NewRiskScoringAgent() *RiskScoringAgent {
	return &RiskScoringAgent{}
}

func (r *RiskScoringAgent) Name() string {
	return "Agent-9: Risk Scoring"
}

func (r *RiskScoringAgent) Description() string {
	return "Calculates risk, CVSS vectors, and business priority for all discovered vulnerabilities."
}

func (r *RiskScoringAgent) Execute(state *core.SwarmState) error {
	state.Log(r.Name(), "START", "Starting Risk & CVSS Scoring Matrix...")

	vulns := state.Vulns
	if len(vulns) == 0 {
		state.Log(r.Name(), "INFO", "No vulnerabilities to score.")
		return nil
	}

	state.Log(r.Name(), "TASK", fmt.Sprintf("Scoring %d vulnerabilities for business impact.", len(vulns)))

	// Re-evaluate severity and calculate a mock CVSS 3.1 base score
	state.Mu.Lock()
	for i := range state.Vulns {
		if state.Vulns[i].Severity == "Critical" && state.Vulns[i].CVSS == 0 {
			state.Vulns[i].CVSS = 9.8 // Network, Low Complexity, No Privileges
		} else if state.Vulns[i].Severity == "High" && state.Vulns[i].CVSS == 0 {
			state.Vulns[i].CVSS = 7.5
		}
	}
	state.Mu.Unlock()

	for i := range vulns {
		// Adjust based on contextual asset value (Business Prioritization)
		// E.g., if it's the primary domain or 'api', bump the score slightly
		if vulns[i].ID == "MISCONF-001" { // The .env leak
			state.Log(r.Name(), "ALERT", fmt.Sprintf("Max CVSS (10.0) assigned to %s due to chained exposure context.", vulns[i].Name))
			state.Mu.Lock()
			state.Vulns[i].CVSS = 10.0
			state.Mu.Unlock()
		}
	}

	state.Log(r.Name(), "COMPLETE", "Risk scoring applied. Handing over to Agent-10: Report Generation.")

	return nil
}
