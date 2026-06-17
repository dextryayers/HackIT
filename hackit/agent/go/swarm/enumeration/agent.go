package enumeration

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

type EnumerationAgent struct {
	name string
	desc string
}

func NewEnumerationAgent() *EnumerationAgent {
	return &EnumerationAgent{
		name: "Agent-5: Enumeration",
		desc: "Deeply enumerates web directories, API endpoints, and sensitive cloud assets.",
	}
}

func (e *EnumerationAgent) Name() string        { return e.name }
func (e *EnumerationAgent) Description() string  { return e.desc }

func (e *EnumerationAgent) Execute(state *core.SwarmState) error {
	state.Section("ENUMERATION PHASE")
	state.Log(e.Name(), "START", "Starting Deep Directory and API Enumeration...")

	state.Mu.Lock()
	services := state.Discovered
	state.Mu.Unlock()

	webPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true, 3000: true, 5000: true, 8000: true, 8888: true, 9000: true}
	var webTargets []string

	for _, svc := range services {
		if webPorts[svc.Port] || strings.Contains(strings.ToLower(svc.Tech), "http") {
			protocol := "http://"
			if svc.Port == 443 || svc.Port == 8443 {
				protocol = "https://"
			}
			webTargets = append(webTargets, fmt.Sprintf("%s%s:%d", protocol, svc.IP, svc.Port))
		}
	}

	if len(webTargets) == 0 {
		state.LogWarn(e.Name(), "WARN", "No HTTP/HTTPS services found. Skipping web enumeration.")
		return nil
	}

	concurrency := 10
	for _, rule := range state.Target.Rules {
		if rule == "FULL_BRUTEFORCE_ALLOWED" || rule == "HIGH_THREAD_CONCURRENCY" {
			concurrency = 100
			break
		}
	}

	start := time.Now()
	var enumeratedPaths []string
	statusCount := map[int]int{}

	state.StartSpinner(fmt.Sprintf("%sFuzzing %d web targets [%d threads]%s", core.Yellow, len(webTargets), concurrency, core.Reset))

	for _, target := range webTargets {
		fuzzResults := native.FuzzDirectories(target, concurrency)
		for _, res := range fuzzResults {
			fullPath := target + res.Path
			enumeratedPaths = append(enumeratedPaths, fullPath)
			statusCount[res.StatusCode]++
		}
	}

	state.StopSpinner()

	state.Mu.Lock()
	state.ContextData["enumerated_endpoints"] = enumeratedPaths
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	summary := fmt.Sprintf("Fuzzer found %d endpoints in %s", len(enumeratedPaths), elapsed)
	for code, count := range statusCount {
		summary += fmt.Sprintf(" | %d: %d", code, count)
	}
	state.LogOk(e.Name(), "RESULT", summary)

	return nil
}
