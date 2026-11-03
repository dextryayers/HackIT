package correlation

import (
	"fmt"
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
func (c *CorrelationAgent) Description() string { return c.desc }

// Execute builds chains only from verified finding IDs.  It never mutates a
// finding: the previous version appended "(CRITICAL: Chained with CMS
// exposure)" to descriptions, rewriting evidence that a probe had produced.
func (c *CorrelationAgent) Execute(state *core.SwarmState) error {
	state.Section("CORRELATION PHASE")
	state.Log(c.Name(), "START", "Starting Threat Correlation Matrix...")

	state.Mu.RLock()
	vulns := state.Vulns
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.LogWarn(c.Name(), "WARN", "No vulnerabilities to correlate.")
		return nil
	}

	start := time.Now()
	var attackChains []string
	envLeak, gitLeak, dbExposed := false, false, false

	for _, v := range vulns {
		switch {
		case v.ID == "MISCONF-001":
			envLeak = true
		case v.ID == "MISCONF-002":
			gitLeak = true
		}
		if v.Port == 3306 || v.Port == 6379 || v.Port == 27017 {
			dbExposed = true
		}
	}

	if envLeak && dbExposed {
		chain := "ATTACK CHAIN: [Exposed .env] -> DB Credentials -> [Database Exposed] -> [Data Exfil]"
		attackChains = append(attackChains, chain)
		state.LogWarn(c.Name(), "CHAIN", chain)
	}
	if gitLeak && dbExposed {
		chain := "ATTACK CHAIN: [Exposed .git] -> Source Code -> [DB Credentials] -> [Data Exfil]"
		attackChains = append(attackChains, chain)
		state.LogWarn(c.Name(), "CHAIN", chain)
	}

	state.Mu.Lock()
	if len(attackChains) > 0 {
		state.ContextData["attack_chains"] = attackChains
	}
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(c.Name(), "RESULT", fmt.Sprintf("Correlated %d verified vulns into %d attack chains in %s", len(vulns), len(attackChains), elapsed))
	return nil
}
