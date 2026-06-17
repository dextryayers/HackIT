package correlation

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type CorrelationAgent struct {
	name string
	desc string
}

func NewCorrelationAgent() *CorrelationAgent {
	return &CorrelationAgent{
		name: "Agent-7: Correlation",
		desc: "Connects isolated vulnerabilities into larger risk contexts and attack chains.",
	}
}

func (c *CorrelationAgent) Name() string        { return c.name }
func (c *CorrelationAgent) Description() string  { return c.desc }

func (c *CorrelationAgent) Execute(state *core.SwarmState) error {
	state.Section("CORRELATION PHASE")
	state.Log(c.Name(), "START", "Starting Threat Correlation Matrix...")

	state.Mu.Lock()
	vulns := state.Vulns
	state.Mu.Unlock()

	if len(vulns) == 0 {
		state.LogWarn(c.Name(), "WARN", "No vulnerabilities to correlate.")
		return nil
	}

	start := time.Now()
	var attackChains []string
	severityMap := map[string]bool{}

	for _, v := range vulns {
		if v.ID == "MISCONF-001" {
			severityMap["env_leak"] = true
		}
		if v.ID == "MISCONF-002" {
			severityMap["git_leak"] = true
		}
		if strings.Contains(v.ID, "CVE-2023") || strings.Contains(v.ID, "MISCONF-WP") {
			severityMap["cms"] = true
		}
		if v.Port == 3306 || v.Port == 6379 || v.Port == 27017 {
			severityMap["db_exposed"] = true
		}
	}

	if severityMap["env_leak"] && severityMap["cms"] {
		chain := "ATTACK CHAIN: [Exposed .env] -> DB Credentials -> [CMS Compromise] -> [RCE]"
		attackChains = append(attackChains, chain)
		state.LogWarn(c.Name(), "CHAIN", chain)
		state.Mu.Lock()
		for i := range state.Vulns {
			if state.Vulns[i].ID == "MISCONF-001" {
				state.Vulns[i].Description += " (CRITICAL: Chained with CMS exposure)"
			}
		}
		state.Mu.Unlock()
	}
	if severityMap["git_leak"] && severityMap["db_exposed"] {
		chain := "ATTACK CHAIN: [Exposed .git] -> Source Code -> [DB Credentials] -> [Data Exfil]"
		attackChains = append(attackChains, chain)
		state.LogWarn(c.Name(), "CHAIN", chain)
	}
	if severityMap["cms"] && severityMap["db_exposed"] {
		chain := "ATTACK CHAIN: [CMS Vuln] -> [DB Exposed] -> [Direct Data Access]"
		attackChains = append(attackChains, chain)
		state.LogWarn(c.Name(), "CHAIN", chain)
	}

	state.Mu.Lock()
	if len(attackChains) > 0 {
		state.ContextData["attack_chains"] = attackChains
	}
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(c.Name(), "RESULT", fmt.Sprintf("Correlated %d vulns into %d attack chains in %s", len(vulns), len(attackChains), elapsed))
	return nil
}
