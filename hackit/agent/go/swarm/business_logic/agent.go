package business_logic

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type BusinessLogicAgent struct {
	name string
	desc string
}

func NewBusinessLogicAgent() *BusinessLogicAgent {
	return &BusinessLogicAgent{
		name: "Agent-25: Business Logic Scenario Engine",
		desc: "Maps business-logic attack surface into hypotheses. Never reports a flaw without authenticated multi-step proof.",
	}
}

func (a *BusinessLogicAgent) Name() string        { return a.name }
func (a *BusinessLogicAgent) Description() string { return a.desc }

// Execute records business-logic hypotheses as leads only.  Proving a logic
// flaw needs authenticated multi-step state that passive enumeration cannot
// supply, so nothing here may reach state.Vulns: the previous version emitted
// seven canned scenarios with fixed CVSS for any site with a handful of
// endpoints, which filled reports with findings no probe ever tested.
func (a *BusinessLogicAgent) Execute(state *core.SwarmState) error {
	state.Section("BUSINESS LOGIC PHASE")
	state.Log(a.Name(), "START", "Mapping business-logic surface (leads only, no unproven findings)...")

	state.Mu.RLock()
	endpointsRaw := state.ContextData["enumerated_endpoints"]
	state.Mu.RUnlock()

	var endpoints []string
	// Guard: ContextData values cross agent boundaries untyped.
	switch v := endpointsRaw.(type) {
	case []string:
		endpoints = v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				endpoints = append(endpoints, s)
			}
		}
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sMapping %d routes to logic hypotheses%s", core.Yellow, len(endpoints), core.Reset))

	seen := map[string]bool{}
	var leads []string
	for _, ep := range endpoints {
		lower := strings.ToLower(ep)
		var lead string
		switch {
		case strings.Contains(lower, "cart") || strings.Contains(lower, "checkout") ||
			strings.Contains(lower, "payment") || strings.Contains(lower, "coupon"):
			lead = "price/quantity manipulation candidate: " + ep
		case strings.Contains(lower, "login") || strings.Contains(lower, "oauth") ||
			strings.Contains(lower, "2fa") || strings.Contains(lower, "verify"):
			lead = "auth-flow bypass candidate: " + ep
		case strings.Contains(lower, "order") || strings.Contains(lower, "invoice") ||
			strings.Contains(lower, "profile") || strings.Contains(lower, "account"):
			lead = "object-ownership (IDOR) candidate: " + ep
		}
		if lead == "" || seen[lead] {
			continue
		}
		seen[lead] = true
		leads = append(leads, lead)
		if len(leads) >= 25 {
			break
		}
	}

	state.StopSpinner()

	state.Mu.Lock()
	if len(leads) > 0 {
		state.ContextData["business_logic_leads"] = leads
	}
	state.Mu.Unlock()

	for i, lead := range leads {
		if i >= 5 {
			break
		}
		state.Log(a.Name(), "LEAD", lead)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("%d business-logic leads recorded in %s (hypotheses, not verified — require authenticated multi-step testing)",
		len(leads), elapsed))
	return nil
}
