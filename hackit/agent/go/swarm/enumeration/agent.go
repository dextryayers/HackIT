package enumeration

import (
	"fmt"
	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

// EnumerationAgent is Node 5 in the 20-Node Autonomous Swarm
// Responsible for brute-forcing paths, APIs, admin panels, and finding sensitive files.
type EnumerationAgent struct{}

func NewEnumerationAgent() *EnumerationAgent {
	return &EnumerationAgent{}
}

func (e *EnumerationAgent) Name() string {
	return "Agent-5: Enumeration"
}

func (e *EnumerationAgent) Description() string {
	return "Deeply enumerates web directories, API endpoints, and sensitive cloud assets."
}

func (e *EnumerationAgent) Execute(state *core.SwarmState) error {
	state.Log(e.Name(), "START", "Starting Deep Directory & API Enumeration...")

	state.Mu.Lock()
	services := state.Discovered
	state.Mu.Unlock()

	var webTargets []string

	for _, svc := range services {
		if svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 {
			protocol := "http://"
			if svc.Port == 443 || svc.Port == 8443 {
				protocol = "https://"
			}
			webTargets = append(webTargets, fmt.Sprintf("%s%s:%d", protocol, svc.IP, svc.Port))
		}
	}

	if len(webTargets) == 0 {
		state.Log(e.Name(), "WARN", "No HTTP/HTTPS services found. Skipping web enumeration.")
		return nil
	}

	// Determine Fuzzing Aggressiveness
	concurrency := 10
	for _, rule := range state.Target.Rules {
		if rule == "FULL_BRUTEFORCE_ALLOWED" || rule == "HIGH_THREAD_CONCURRENCY" {
			concurrency = 100
			break
		}
	}

	state.Log(e.Name(), "TASK", fmt.Sprintf("Triggering Native Go HTTP Fuzzer on %d web targets (%d threads)", len(webTargets), concurrency))

	// Native Enumeration Logic
	var enumeratedPaths []string

	for _, target := range webTargets {
		state.Log(e.Name(), "SCAN", fmt.Sprintf("Fuzzing paths on %s...", target))
		fuzzResults := native.FuzzDirectories(target, concurrency)

		for _, res := range fuzzResults {
			fullPath := target + res.Path
			enumeratedPaths = append(enumeratedPaths, fullPath)
			state.Log(e.Name(), "DISCOVERY", fmt.Sprintf("Found [HTTP %d] %s", res.StatusCode, fullPath))
		}
	}

	state.Log(e.Name(), "DISCOVERY", fmt.Sprintf("Fuzzer mapped %d sensitive endpoints across the attack surface.", len(enumeratedPaths)))

	// Save to State Context Data (Since it's unstructured URLs)
	state.Mu.Lock()
	state.ContextData["enumerated_endpoints"] = enumeratedPaths
	state.Mu.Unlock()

	state.Log(e.Name(), "COMPLETE", "Enumeration complete. Handing over to Agent-6: Vulnerability Analysis.")

	return nil
}
