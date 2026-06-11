package planning

import (
	"errors"
	"fmt"
	"strings"

	"hackit_ai_engine/swarm/core"
)

// PlanningAgent is Node 1 in the 20-Node Autonomous Swarm
// It is responsible for understanding scope, goals, and rules of engagement.
type PlanningAgent struct{}

func NewPlanningAgent() *PlanningAgent {
	return &PlanningAgent{}
}

func (p *PlanningAgent) Name() string {
	return "Agent-1: Planning"
}

func (p *PlanningAgent) Description() string {
	return "Understands target scope, assessment goals, rules of engagement, and creates an automated testing plan."
}

func (p *PlanningAgent) Execute(state *core.SwarmState) error {
	state.Log(p.Name(), "INIT", "Initializing Planning Phase...")

	if state.Target.PrimaryDomain == "" {
		err := errors.New("fatal: no primary domain specified in target scope")
		state.Log(p.Name(), "ERROR", err.Error())
		return err
	}

	// Analyze Scope Type
	scopeMode := strings.ToLower(state.Target.ScopeType)
	state.Log(p.Name(), "ANALYSIS", fmt.Sprintf("Analyzing target '%s' with mode '%s'", state.Target.PrimaryDomain, scopeMode))

	// Define Rules of Engagement (RoE) based on scope
	switch scopeMode {
	case "passive":
		state.Target.Rules = []string{
			"NO_ACTIVE_EXPLOITS",
			"NO_BRUTEFORCE",
			"OSINT_ONLY",
			"NO_PACKET_INJECTION",
		}
		state.Log(p.Name(), "RULE_SET", "Applied strict passive OSINT rules. No active touching of the target.")
	case "active_stealth":
		state.Target.Rules = []string{
			"SLOW_RATE_LIMITING",
			"USER_AGENT_RANDOMIZATION",
			"WAF_EVASION_MODE_ON",
			"NO_DENIAL_OF_SERVICE",
		}
		state.Log(p.Name(), "RULE_SET", "Applied active stealth rules. Traffic will be heavily jittered and masked.")
	case "aggressive":
		state.Target.Rules = []string{
			"FULL_BRUTEFORCE_ALLOWED",
			"HIGH_THREAD_CONCURRENCY",
			"EXPLOITATION_ALLOWED",
			"NO_DENIAL_OF_SERVICE", // DoS is usually still off-limits unless specified
		}
		state.Log(p.Name(), "RULE_SET", "Applied aggressive rules. Proceeding with maximum thread concurrency and active exploitation.")
	default:
		// Default to a safe balanced mode
		state.Target.Rules = []string{
			"STANDARD_PORT_SCAN",
			"SAFE_VULN_CHECKS",
			"NO_EXPLOITATION_WITHOUT_PROMPT",
		}
		state.Log(p.Name(), "RULE_SET", "Applied standard balanced rules.")
	}

	// Python Logic Support Hook
	// If the scope is complex (e.g. natural language), we dump state here
	// and invoke the Python NLP orchestrator to append to rules.
	// For now, the Golang native logic handles standard ROE efficiently.

	state.Log(p.Name(), "COMPLETE", "Test plan finalized. Proceeding to Agent-2: Reconnaissance.")
	return nil
}
