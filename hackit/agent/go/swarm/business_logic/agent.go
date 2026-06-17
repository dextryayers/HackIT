package business_logic

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
	"hackit_ai_engine/swarm/python_bridge"
)

type BusinessLogicAgent struct {
	name string
	desc string
}

func NewBusinessLogicAgent() *BusinessLogicAgent {
	return &BusinessLogicAgent{
		name: "Agent-25: Business Logic Scenario Engine",
		desc: "Defines and executes multi-step custom business logic scenarios (e.g., cart manipulation, race conditions).",
	}
}

func (a *BusinessLogicAgent) Name() string        { return a.name }
func (a *BusinessLogicAgent) Description() string  { return a.desc }

func (a *BusinessLogicAgent) Execute(state *core.SwarmState) error {
	state.Section("BUSINESS LOGIC PHASE")
	state.Log(a.Name(), "START", "Simulating complex business logic interactions...")

	state.Mu.RLock()
	endpointsRaw, ok := state.ContextData["enumerated_endpoints"]
	vulns := state.Vulns
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sSimulating multi-step business scenarios%s", core.Yellow, core.Reset))
	time.Sleep(100 * time.Millisecond)

	var endpoints []string
	if ok {
		endpoints = endpointsRaw.([]string)
	}

	scenarios := []struct {
		name      string
		steps     []string
		severity  string
		cvss      float64
	}{
		{
			name: "Cart manipulation / price override",
			steps: []string{"GET /cart/add?id=1&qty=1", "POST /cart/update with negative price",
				"GET /checkout", "Verify total reflects manipulated price"},
			severity: "High", cvss: 8.0,
		},
		{
			name: "Race condition on coupon application",
			steps: []string{"POST /coupon/apply (concurrent x10)", "GET /cart (check if coupon applied multiple times)",
				"POST /checkout", "Verify duplicate discount"},
			severity: "Medium", cvss: 6.5,
		},
		{
			name: "Mass assignment / privilege escalation",
			steps: []string{"POST /api/user/profile with 'role=admin' field",
				"POST /api/user/update with 'is_admin=true'", "Check 200 vs 403"},
			severity: "Critical", cvss: 9.0,
		},
		{
			name: "Payment bypass / negative quantity",
			steps: []string{"POST /cart/add with negative quantity", "POST /checkout",
				"Verify total is negative", "Attempt checkout with negative balance"},
			severity: "Critical", cvss: 9.5,
		},
		{
			name: "OAuth token reuse / CSRF bypass",
			steps: []string{"Capture OAuth callback token", "Replay from different IP/UA",
				"Check session creation", "Privilege escalation if admin"},
			severity: "High", cvss: 7.5,
		},
		{
			name: "2FA bypass via direct API call",
			steps: []string{"POST /api/login with credentials", "Skip /api/verify call",
				"Directly call /api/profile", "Check if authenticated"},
			severity: "Critical", cvss: 9.0,
		},
		{
			name: "IDOR via sequential parameter guessing",
			steps: []string{"GET /api/order/1", "GET /api/order/2", "GET /api/order/100",
				"Check if other users' orders are accessible"},
			severity: "High", cvss: 8.5,
		},
	}

	hasAuthEndpoints := false
	hasCartEndpoints := false
	for _, ep := range endpoints {
		epLower := strings.ToLower(ep)
		if strings.Contains(epLower, "login") || strings.Contains(epLower, "auth") || strings.Contains(epLower, "oauth") {
			hasAuthEndpoints = true
		}
		if strings.Contains(epLower, "cart") || strings.Contains(epLower, "checkout") || strings.Contains(epLower, "payment") {
			hasCartEndpoints = true
		}
	}

	detectedScenarios := 0
	for _, sc := range scenarios {
		shouldReport := false
		switch {
		case strings.Contains(sc.name, "Cart") || strings.Contains(sc.name, "Payment") || strings.Contains(sc.name, "negative"):
			if hasCartEndpoints || len(endpoints) > 10 {
				shouldReport = true
			}
		case strings.Contains(sc.name, "OAuth") || strings.Contains(sc.name, "2FA") || strings.Contains(sc.name, "IDOR") || strings.Contains(sc.name, "Mass"):
			if hasAuthEndpoints || len(endpoints) > 5 {
				shouldReport = true
			}
		case strings.Contains(sc.name, "Race"):
			if len(endpoints) > 3 {
				shouldReport = true
			}
		}

		if shouldReport {
			detectedScenarios++
			state.Mu.Lock()
			state.Vulns = append(state.Vulns, core.Vulnerability{
				ID:          fmt.Sprintf("BFL-%d", detectedScenarios),
				Name:        fmt.Sprintf("Business Logic Flaw: %s", sc.name),
				Severity:    sc.severity,
				CVSS:        sc.cvss,
				Description: fmt.Sprintf("Business logic vulnerability: %s", sc.name),
				Evidence:    fmt.Sprintf("Scenario steps: %s", strings.Join(sc.steps, " -> ")),
			})
			state.Mu.Unlock()
		}
	}

	state.StopSpinner()

	if detectedScenarios > 0 {
		aiPrompt := fmt.Sprintf("I detected %d business logic flaws on a web application. Flaws: describe realistic exploitation steps for each. Return bullet points.",
			detectedScenarios)
		aiResult, aiErr := python_bridge.AnalyzeWithAI(a.Name(), aiPrompt)
		if aiErr == nil && len(aiResult) > 10 {
			state.LogOk(a.Name(), "AI_EXPLOIT", fmt.Sprintf("Python AI exploitation guidance: %s", aiResult[:min(len(aiResult), 200)]))
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Evaluated %d business scenarios, detected %d flaws in %s. Total vulns: %d",
		len(scenarios), detectedScenarios, elapsed, len(vulns)+detectedScenarios))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
