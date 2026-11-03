package reasoning

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type ReasoningAgent struct {
	name string
	desc string
}

func NewReasoningAgent() *ReasoningAgent {
	return &ReasoningAgent{
		name: "Agent-24: Web App Reasoning",
		desc: "Maps route names to RBAC and IDOR hypotheses for later live authorization probes.",
	}
}

func (a *ReasoningAgent) Name() string        { return a.name }
func (a *ReasoningAgent) Description() string { return a.desc }

// Execute maps routes to RBAC/IDOR hypotheses.  Path names alone never prove
// an authorization gap: the previous version reported "Endpoint returned 200
// OK" without sending a request.  Confirmed findings come only from the live
// probes in vuln_analysis and exploitation; this agent records leads.
func (a *ReasoningAgent) Execute(state *core.SwarmState) error {
	state.Section("REASONING PHASE")
	state.Log(a.Name(), "START", "Mapping RBAC and IDOR hypotheses from route names...")

	state.Mu.RLock()
	services := state.Discovered
	endpointsRaw := state.ContextData["enumerated_endpoints"]
	state.Mu.RUnlock()

	var endpoints []string
	// Guard: never trust the concrete type inside ContextData.
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
	state.StartSpinner(fmt.Sprintf("%sAnalyzing %d routes for RBAC and IDOR patterns%s", core.Yellow, len(endpoints), core.Reset))

	adminPaths := []string{"/admin", "/wp-admin", "/dashboard", "/api/admin", "/administrator", "/backend", "/manager", "/console", "/panel", "/cpanel"}
	idorCandidates := []string{"/api/user/", "/api/order/", "/api/profile/", "/api/document/", "/api/invoice/", "/download/", "/file/", "/api/account/"}

	idors := 0
	adminEndpoints := 0
	seen := map[string]bool{}
	var leads []string

	for _, ep := range endpoints {
		lower := strings.ToLower(ep)
		for _, admin := range adminPaths {
			if strings.Contains(lower, admin) {
				adminEndpoints++
				if key := "admin:" + ep; !seen[key] {
					seen[key] = true
					leads = append(leads, "admin-adjacent route (verify authorization): "+ep)
				}
				break
			}
		}
		for _, idor := range idorCandidates {
			if strings.Contains(lower, idor) {
				idors++
				if key := "idor:" + ep; !seen[key] {
					seen[key] = true
					leads = append(leads, "object-reference route (verify ownership checks): "+ep)
				}
				break
			}
		}
	}

	state.StopSpinner()

	state.Mu.Lock()
	if len(leads) > 0 {
		state.ContextData["reasoning_leads"] = leads
	}
	state.Mu.Unlock()

	webCount := 0
	for _, svc := range services {
		if svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 {
			webCount++
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Analyzed %d web apps (%d endpoints): %d admin routes, %d object-reference routes recorded as leads in %s (unverified)",
		webCount, len(endpoints), adminEndpoints, idors, elapsed))
	return nil
}
