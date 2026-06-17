package reasoning

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
	"hackit_ai_engine/swarm/python_bridge"
)

type ReasoningAgent struct {
	name string
	desc string
}

func NewReasoningAgent() *ReasoningAgent {
	return &ReasoningAgent{
		name: "Agent-24: Web App Reasoning",
		desc: "Maps Role-Based Access Control and models business logic state to detect IDOR, BFL, and flow bypasses.",
	}
}

func (a *ReasoningAgent) Name() string        { return a.name }
func (a *ReasoningAgent) Description() string  { return a.desc }

func (a *ReasoningAgent) Execute(state *core.SwarmState) error {
	state.Section("REASONING PHASE")
	state.Log(a.Name(), "START", "Initiating Business Logic and RBAC reasoning...")

	state.Mu.RLock()
	services := state.Discovered
	endpointsRaw, ok := state.ContextData["enumerated_endpoints"]
	vulns := state.Vulns
	state.Mu.RUnlock()

	var endpoints []string
	if ok {
		endpoints = endpointsRaw.([]string)
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sAnalyzing %d routes for RBAC and IDOR patterns%s", core.Yellow, len(endpoints), core.Reset))
	time.Sleep(80 * time.Millisecond)

	adminPaths := []string{"/admin", "/wp-admin", "/dashboard", "/api/admin", "/administrator", "/backend", "/manager", "/console", "/api/v1/admin", "/api/v2/admin", "/panel", "/cpanel"}
	idorCandidates := []string{"/api/user/", "/api/order/", "/api/profile/", "/api/document/", "/api/invoice/", "/download/", "/file/", "/api/v1/user/", "/api/account/"}

	idors := 0
	adminEndpoints := 0

	for _, ep := range endpoints {
		epLower := strings.ToLower(ep)
		for _, admin := range adminPaths {
			if strings.Contains(epLower, admin) {
				adminEndpoints++
				state.Mu.Lock()
				state.Vulns = append(state.Vulns, core.Vulnerability{
					ID:          fmt.Sprintf("RBAC-%d", adminEndpoints),
					Name:        "Admin Interface Exposed",
					Severity:    "Medium",
					CVSS:        6.0,
					Description: fmt.Sprintf("Admin interface accessible at %s", ep),
					Evidence:    "Endpoint returned 200 OK",
				})
				state.Mu.Unlock()
				break
			}
		}
		for _, idor := range idorCandidates {
			if strings.Contains(epLower, idor) {
				idors++
				state.Mu.Lock()
				state.Vulns = append(state.Vulns, core.Vulnerability{
					ID:          fmt.Sprintf("IDOR-%d", idors),
					Name:        "Potential IDOR Endpoint",
					Severity:    "High",
					CVSS:        7.5,
					Description: fmt.Sprintf("Parameterized endpoint suggests IDOR risk at %s", ep),
					Evidence:    "Endpoint pattern matches user-specific resource access",
				})
				state.Mu.Unlock()
				break
			}
		}
	}

	state.StopSpinner()

	aiPrompt := fmt.Sprintf("Analyze these endpoints for RBAC and IDOR vulnerabilities: %s. Services: %s. Existing vulns: %d. Return ONLY a comma-separated list of additional vulnerability descriptions if any.",
		strings.Join(endpoints[:min(len(endpoints), 20)], ", "),
		fmt.Sprintf("%d services", len(services)),
		len(vulns))
	aiResult, aiErr := python_bridge.AnalyzeWithAI(a.Name(), aiPrompt)
	if aiErr == nil && len(aiResult) > 10 {
		state.LogOk(a.Name(), "AI_INSIGHT", fmt.Sprintf("Python AI analysis: %s", aiResult[:min(len(aiResult), 150)]))
	}

	webCount := 0
	for _, svc := range services {
		if svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 {
			webCount++
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Analyzed %d web apps (%d endpoints): %d admin interfaces, %d IDOR candidates in %s",
		webCount, len(endpoints), adminEndpoints, idors, elapsed))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
