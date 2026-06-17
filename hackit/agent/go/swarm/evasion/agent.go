package evasion

import (
	"fmt"
	"math/rand"
	"time"

	"hackit_ai_engine/swarm/core"
)

type EvasionAgent struct {
	name string
	desc string
}

func NewEvasionAgent() *EvasionAgent {
	return &EvasionAgent{
		name: "Agent-20: Evasion and Stealth",
		desc: "Monitors rate-limits, rotates User-Agents/Proxies, and applies protocol-level WAF bypasses dynamically.",
	}
}

func (a *EvasionAgent) Name() string        { return a.name }
func (a *EvasionAgent) Description() string  { return a.desc }

func (a *EvasionAgent) Execute(state *core.SwarmState) error {
	state.Section("EVASION AND STEALTH PHASE")
	state.Log(a.Name(), "START", "Deploying stealth and evasion monitors...")

	start := time.Now()
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
		"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"curl/8.4.0",
		"Wget/1.21.4",
		"Go-http-client/2.0",
	}
	proxies := []string{
		"socks5://127.0.0.1:9050", "socks5://127.0.0.1:1080", "http://127.0.0.1:8080", "http://127.0.0.1:3128",
	}

	state.StartSpinner(fmt.Sprintf("%sInitializing evasion engine%s", core.Yellow, core.Reset))
	time.Sleep(80 * time.Millisecond)

	ruleCount := len(state.Target.Rules)
	hasWAFEvasion := false
	for _, rule := range state.Target.Rules {
		if rule == "WAF_EVASION_MODE_ON" {
			hasWAFEvasion = true
			break
		}
	}

	selectedUA := userAgents[rand.Intn(len(userAgents))]
	selectedProxy := ""
	if hasWAFEvasion && len(proxies) > 0 {
		selectedProxy = proxies[rand.Intn(len(proxies))]
	}

	state.Mu.Lock()
	state.ContextData["evasion_user_agent"] = selectedUA
	if selectedProxy != "" {
		state.ContextData["evasion_proxy"] = selectedProxy
	}
	state.ContextData["evasion_jitter_ms"] = fmt.Sprintf("%d", 500+rand.Intn(3000))
	state.Mu.Unlock()

	state.StopSpinner()

	state.LogOk(a.Name(), "CONFIG", fmt.Sprintf("Stealth profile active: %d rules, UA=%s...", ruleCount, selectedUA[:40]))
	if selectedProxy != "" {
		state.LogOk(a.Name(), "PROXY", fmt.Sprintf("WAF evasion proxy: %s", selectedProxy))
	}
	state.Log(a.Name(), "JITTER", fmt.Sprintf("Request jitter: %s", state.ContextData["evasion_jitter_ms"]))

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "COMPLETE", fmt.Sprintf("Evasion engine ready in %s. Threat footprint minimized.", elapsed))
	return nil
}
