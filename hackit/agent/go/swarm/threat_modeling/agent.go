package threat_modeling

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type ThreatModelingAgent struct {
	name string
	desc string
}

func NewThreatModelingAgent() *ThreatModelingAgent {
	return &ThreatModelingAgent{
		name: "Agent-14: Threat Modeling",
		desc: "Builds attack trees and evaluates structural exposure using Threat Modeling methodologies.",
	}
}

func (t *ThreatModelingAgent) Name() string        { return t.name }
func (t *ThreatModelingAgent) Description() string  { return t.desc }

func (t *ThreatModelingAgent) Execute(state *core.SwarmState) error {
	state.Section("THREAT MODELING PHASE")
	state.Log(t.Name(), "START", "Initiating Threat Modeling Protocol (MITRE ATT&CK Mapping)...")

	state.Mu.RLock()
	vulns := state.Vulns
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.LogWarn(t.Name(), "WARN", "No vulnerabilities detected.")
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sMapping %d vulns to MITRE ATT&CK%s", core.Yellow, len(vulns), core.Reset))

	type mitreMapping struct {
		vulnID  string
		tactic  string
		technique string
	}

	mappings := []mitreMapping{
		{"MISCONF-001", "TA0006 Credential Access", "T1552.001 Unsecured Credentials"},
		{"MISCONF-002", "TA0007 Discovery", "T1083 File and Directory Discovery"},
		{"MISCONF-WP-ADMIN", "TA0001 Initial Access", "T1190 Exploit Public-Facing Application"},
		{"MISCONF-PHPINFO", "TA0007 Discovery", "T1083 File and Directory Discovery"},
		{"MISCONF-ACTUATOR", "TA0007 Discovery", "T1083 File and Directory Discovery"},
		{"MISCONF-SWAGGER", "TA0007 Discovery", "T1083 File and Directory Discovery"},
		{"MISCONF-MYSQL", "TA0008 Lateral Movement", "T1021 Remote Services"},
		{"MISCONF-MONGO", "TA0008 Lateral Movement", "T1021 Remote Services"},
		{"CVE-2023-XXXX", "TA0002 Execution", "T1190 Exploit Public-Facing Application"},
		{"CVE-2020-15778", "TA0008 Lateral Movement", "T1059.004 Unix Shell"},
		{"CVE-2021-41773", "TA0007 Discovery", "T1190 Exploit Public-Facing Application"},
		{"CVE-2021-23017", "TA0002 Execution", "T1498 Network DoS"},
		{"CVE-2021-31166", "TA0040 Impact", "T1499 Endpoint DoS"},
		{"CVE-2022-0543", "TA0002 Execution", "T1059.006 Python/Lua Shell"},
		{"TECH-VULN", "TA0002 Execution", "T1190 Exploit Public-Facing Application"},
	}

	mitreMap := map[string][]string{}
	for _, v := range vulns {
		for _, m := range mappings {
			if v.ID == m.vulnID || strings.HasPrefix(v.ID, m.vulnID) {
				mitreMap[m.tactic] = append(mitreMap[m.tactic], m.technique)
			}
		}
	}

	var attackPaths []string
	for tactic, techs := range mitreMap {
		unique := map[string]bool{}
		for _, t := range techs {
			if !unique[t] {
				unique[t] = true
				attackPaths = append(attackPaths, fmt.Sprintf("[%s] -> [%s]", tactic, t))
			}
		}
	}

	state.StopSpinner()

	state.Mu.Lock()
	state.ContextData["threat_models"] = attackPaths
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(t.Name(), "RESULT", fmt.Sprintf("Mapped %d vulns to %d MITRE ATT&CK paths in %s", len(vulns), len(attackPaths), elapsed))
	return nil
}
