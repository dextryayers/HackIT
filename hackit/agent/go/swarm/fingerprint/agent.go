package fingerprint

import (
	"fmt"
	"strings"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

// FingerprintAgent is Node 4 in the 20-Node Autonomous Swarm
// Responsible for detecting OS, web server, framework, CMS, DB, and WAFs.
type FingerprintAgent struct{}

func NewFingerprintAgent() *FingerprintAgent {
	return &FingerprintAgent{}
}

func (f *FingerprintAgent) Name() string {
	return "Agent-4: Fingerprint"
}

func (f *FingerprintAgent) Description() string {
	return "Analyzes open services to detect underlying technologies, CMS, WAF, and frameworks."
}

func (f *FingerprintAgent) Execute(state *core.SwarmState) error {
	state.Log(f.Name(), "START", "Initiating profound tech-stack fingerprinting...")

	state.Mu.Lock()
	services := state.Discovered
	state.Mu.Unlock()

	if len(services) == 0 {
		state.Log(f.Name(), "WARN", "No services discovered to fingerprint.")
		return nil
	}

	state.Log(f.Name(), "TASK", fmt.Sprintf("Analyzing %d discovered endpoints for technology headers", len(services)))

	// Process each discovered service
	var updatedServices []core.Service

	for _, svc := range services {
		techDetected := svc.Tech // Start with Discovery's initial guess

		// If it's a web port, run deep native fingerprinting
		if svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 || strings.Contains(strings.ToLower(svc.Tech), "http") {
			isHTTPS := (svc.Port == 443 || svc.Port == 8443 || strings.Contains(strings.ToLower(svc.Tech), "ssl") || strings.Contains(strings.ToLower(svc.Tech), "https"))

			// 1. Detect WAF
			wafRes := native.DetectWAF(svc.IP, svc.Port, isHTTPS)
			if wafRes.Detected {
				techDetected += fmt.Sprintf(" | WAF: %s", wafRes.WAFName)
			}

			// 2. Map Technology Stack
			techRes := native.MapTechnologies(svc.IP, svc.Port, svc.Banner)
			if techRes.Server != "" {
				techDetected = techRes.Server
			}
			if len(techRes.Frameworks) > 0 {
				techDetected += " | " + strings.Join(techRes.Frameworks, ", ")
			}

			// If we found specific vulns from the tech map, add them directly to state
			if len(techRes.Vulnerabilities) > 0 {
				state.Mu.Lock()
				for _, v := range techRes.Vulnerabilities {
					state.Vulns = append(state.Vulns, core.Vulnerability{
						ID:          "TECH-VULN",
						Name:        "Framework Vulnerability Detected",
						Severity:    "High", // Default assumption for mapped framework vulns
						CVSS:        7.0,
						Description: fmt.Sprintf("Found %s on %s:%d", v, svc.IP, svc.Port),
						Evidence:    "Identified via Tech Mapping Regex",
					})
				}
				state.Mu.Unlock()
			}
		}

		// Update the service object
		svc.Tech = techDetected
		updatedServices = append(updatedServices, svc)
	}

	// Commit updated tech stack to global Swarm State
	state.Mu.Lock()
	state.Discovered = updatedServices
	state.Mu.Unlock()

	state.Log(f.Name(), "DISCOVERY", "Successfully fingerprinted the underlying technologies.")
	state.Log(f.Name(), "COMPLETE", "Fingerprinting complete. Handing over to Agent-5: Enumeration.")

	return nil
}
