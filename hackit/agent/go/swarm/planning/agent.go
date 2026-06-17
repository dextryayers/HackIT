package planning

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type PlanningAgent struct {
	name string
	desc string
}

func NewPlanningAgent() *PlanningAgent {
	return &PlanningAgent{
		name: "Agent-1: Planning",
		desc: "Understands target scope, assessment goals, rules of engagement, and creates an automated testing plan.",
	}
}

func (p *PlanningAgent) Name() string        { return p.name }
func (p *PlanningAgent) Description() string  { return p.desc }

func (p *PlanningAgent) Execute(state *core.SwarmState) error {
	state.Section("PLANNING PHASE")
	state.Log(p.Name(), "INIT", "Initializing Planning Phase...")

	if state.Target.PrimaryDomain == "" {
		return errors.New("fatal: no primary domain specified in target scope")
	}

	state.StartSpinner(fmt.Sprintf("%sResolving target%s", core.Yellow, core.Reset))
	ips, err := net.LookupHost(state.Target.PrimaryDomain)
	state.StopSpinner()
	if err == nil && len(ips) > 0 {
		state.Target.IPRange = ips[0]
		state.LogOk(p.Name(), "RESOLVED", fmt.Sprintf("%s -> %s (%d addresses)", state.Target.PrimaryDomain, ips[0], len(ips)))
	}

	scopeMode := strings.ToLower(state.Target.ScopeType)
	state.Log(p.Name(), "ANALYSIS", fmt.Sprintf("Analyzing target '%s' with mode '%s'", state.Target.PrimaryDomain, scopeMode))

	switch scopeMode {
	case "passive":
		state.Target.Rules = []string{
			"NO_ACTIVE_EXPLOITS", "NO_BRUTEFORCE", "OSINT_ONLY", "NO_PACKET_INJECTION",
			"SLOW_RATE_LIMITING", "MAX_CONCURRENCY_10",
		}
		state.LogOk(p.Name(), "RULE_SET", "Passive OSINT only. No active touching of the target.")
	case "active_stealth":
		state.Target.Rules = []string{
			"SLOW_RATE_LIMITING", "USER_AGENT_RANDOMIZATION", "WAF_EVASION_MODE_ON",
			"NO_DENIAL_OF_SERVICE", "MAX_CONCURRENCY_50", "BANNER_GRAB_ONLY",
		}
		state.LogOk(p.Name(), "RULE_SET", "Active stealth mode. Traffic jittered and masked.")
	case "aggressive":
		state.Target.Rules = []string{
			"FULL_BRUTEFORCE_ALLOWED", "HIGH_THREAD_CONCURRENCY", "EXPLOITATION_ALLOWED",
			"NO_DENIAL_OF_SERVICE", "MAX_CONCURRENCY_1000", "FULL_PORT_SCAN",
		}
		state.LogOk(p.Name(), "RULE_SET", "Aggressive mode. Maximum concurrency and exploitation.")
	default:
		state.Target.Rules = []string{
			"STANDARD_PORT_SCAN", "SAFE_VULN_CHECKS", "NO_EXPLOITATION_WITHOUT_PROMPT",
			"MAX_CONCURRENCY_100",
		}
		state.LogOk(p.Name(), "RULE_SET", "Standard balanced rules.")
	}

	state.LogOk(p.Name(), "PLAN", fmt.Sprintf("Attack plan ready for %s [%s]", state.Target.PrimaryDomain, scopeMode))
	elapsed := time.Since(state.StartTime).Round(time.Millisecond)
	state.Log(p.Name(), "COMPLETE", fmt.Sprintf("Planning finalized in %s. Proceeding to Agent-2: Reconnaissance.", elapsed))
	return nil
}
