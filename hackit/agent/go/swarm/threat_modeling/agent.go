package threat_modeling

import (
	"fmt"
	"hackit_ai_engine/swarm/core"
)

// ThreatModelingAgent is Node 14 in the 20-Node Autonomous Swarm
// Responsible for calculating the structural threat pathways using STRIDE or MITRE ATT&CK concepts.
type ThreatModelingAgent struct{}

func NewThreatModelingAgent() *ThreatModelingAgent {
	return &ThreatModelingAgent{}
}

func (t *ThreatModelingAgent) Name() string {
	return "Agent-14: Threat Modeling"
}

func (t *ThreatModelingAgent) Description() string {
	return "Builds attack trees and evaluates structural exposure using Threat Modeling methodologies."
}

func (t *ThreatModelingAgent) Execute(state *core.SwarmState) error {
	state.Log(t.Name(), "START", "Initiating Threat Modeling Protocol (MITRE ATT&CK Mapping)...")

	state.Mu.RLock()
	vulns := state.Vulns
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.Log(t.Name(), "INFO", "No vulnerabilities detected. Attack Surface is minimal.")
		return nil
	}

	state.Log(t.Name(), "TASK", "Mapping discovered attack vectors to MITRE ATT&CK Tactics...")

	var attackPaths []string

	for _, v := range vulns {
		if v.ID == "MISCONF-001" {
			attackPaths = append(attackPaths, "[T1552.001 - Credentials In Files] -> [T1078 - Valid Accounts] -> [TA0004 - Privilege Escalation]")
		}
		if v.ID == "CVE-2023-XXXX" {
			attackPaths = append(attackPaths, "[T1190 - Exploit Public-Facing Application] -> [TA0002 - Execution]")
		}
		if v.ID == "CVE-2020-15778" {
			attackPaths = append(attackPaths, "[T1059.004 - Command and Scripting Interpreter: Unix Shell] -> [TA0008 - Lateral Movement]")
		}
	}

	state.Log(t.Name(), "ANALYSIS", fmt.Sprintf("Calculated %d distinct structural threat paths.", len(attackPaths)))

	// Saving Threat Model paths into ContextData
	state.Mu.Lock()
	state.ContextData["threat_models"] = attackPaths
	state.Mu.Unlock()

	state.Log(t.Name(), "COMPLETE", "Threat models synthesized. Handing over to Agent-15: Security Advisor.")

	return nil
}
