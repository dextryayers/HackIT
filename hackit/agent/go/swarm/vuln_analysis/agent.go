package vuln_analysis

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

type VulnAnalysisAgent struct {
	name string
	desc string
}

func NewVulnAnalysisAgent() *VulnAnalysisAgent {
	return &VulnAnalysisAgent{
		name: "Agent-6: Vulnerability Analysis",
		desc: "Confirms vulnerabilities with live probes: endpoint signature verification, banner CVE matching, anonymous-login checks.",
	}
}

func (v *VulnAnalysisAgent) Name() string        { return v.name }
func (v *VulnAnalysisAgent) Description() string { return v.desc }

func (v *VulnAnalysisAgent) Execute(state *core.SwarmState) error {
	state.Section("VULNERABILITY ANALYSIS PHASE")
	state.Log(v.Name(), "START", "Commencing verified vulnerability analysis (no claim without live evidence)...")

	state.Mu.RLock()
	endpointsRaw, ok := state.ContextData["enumerated_endpoints"]
	services := state.Discovered
	existing := len(state.Vulns)
	state.Mu.RUnlock()

	var endpoints []string
	if ok {
		// Guard: ContextData values cross agent boundaries untyped.
		switch t := endpointsRaw.(type) {
		case []string:
			endpoints = t
		case []any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					endpoints = append(endpoints, s)
				}
			}
		}
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sVerifying %d endpoints + %d services with live probes%s",
		core.Yellow, len(endpoints), len(services), core.Reset))

	var mu sync.Mutex
	var newVulns []core.Vulnerability
	add := func(f *native.VerifiedFinding, where string) {
		if f == nil {
			return
		}
		mu.Lock()
		newVulns = append(newVulns, core.Vulnerability{
			ID: f.ID, Name: f.Name, Severity: f.Severity, CVSS: f.CVSS,
			Port: f.Port, Description: f.Description, Evidence: f.Evidence,
			Remediation: f.Remediation, Category: f.Category,
		})
		mu.Unlock()
		state.LogOk(v.Name(), "CONFIRMED", fmt.Sprintf("[%s] %s @ %s — %s", f.Severity, f.Name, where, f.Reproduce))
	}

	// Phase 1: re-probe enumerated endpoints, confirm by body signature.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for _, ep := range endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			add(native.VerifyExposedEndpoint(endpoint), endpoint)
		}(ep)
	}
	wg.Wait()

	// Phase 2: banner-pinned CVE checks + anonymous FTP proof.
	for _, svc := range services {
		add(native.VerifyServiceBanner(svc.IP, svc.Port, svc.Banner, svc.Tech),
			fmt.Sprintf("%s:%d", svc.IP, svc.Port))
		tech := strings.ToLower(svc.Tech)
		if svc.Port == 21 || strings.Contains(tech, "ftp") {
			add(native.ProbeAnonymousFTP(svc.IP, svc.Port), fmt.Sprintf("%s:%d", svc.IP, svc.Port))
		}
	}

	state.Mu.Lock()
	state.Vulns = append(state.Vulns, newVulns...)
	total := len(state.Vulns)
	state.Mu.Unlock()
	state.StopSpinner()

	severe := 0
	for _, f := range newVulns {
		if f.Severity == "Critical" || f.Severity == "High" {
			severe++
		}
	}
	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(v.Name(), "RESULT", fmt.Sprintf("Live-verified %d vulns (%d critical/high) in %s. Total: %d (was %d). Unverified candidates are NOT reported.",
		len(newVulns), severe, elapsed, total, existing))
	return nil
}
