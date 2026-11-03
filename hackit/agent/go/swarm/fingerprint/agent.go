package fingerprint

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

type FingerprintAgent struct {
	name string
	desc string
}

func NewFingerprintAgent() *FingerprintAgent {
	return &FingerprintAgent{
		name: "Agent-4: Fingerprint",
		desc: "Analyzes open services to detect underlying technologies, CMS, WAF, and frameworks.",
	}
}

func (f *FingerprintAgent) Name() string        { return f.name }
func (f *FingerprintAgent) Description() string { return f.desc }

func (f *FingerprintAgent) Execute(state *core.SwarmState) error {
	state.Section("FINGERPRINT PHASE")
	state.Log(f.Name(), "START", "Initiating tech-stack fingerprinting...")

	state.Mu.Lock()
	services := state.Discovered
	state.Mu.Unlock()

	if len(services) == 0 {
		state.LogWarn(f.Name(), "WARN", "No services discovered to fingerprint.")
		return nil
	}

	start := time.Now()
	var updatedServices []core.Service
	wafCount, cmsCount := 0, 0
	var advisories []string

	state.StartSpinner(fmt.Sprintf("%sFingerprinting %d services%s", core.Yellow, len(services), core.Reset))

	for _, svc := range services {
		techDetected := svc.Tech
		isWeb := svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 || svc.Port == 3000 || svc.Port == 5000 || strings.Contains(strings.ToLower(svc.Tech), "http")

		if isWeb {
			isHTTPS := svc.Port == 443 || svc.Port == 8443 || strings.Contains(strings.ToLower(svc.Tech), "https")

			wafRes := native.DetectWAF(svc.IP, svc.Port, isHTTPS)
			if wafRes.Detected {
				techDetected += fmt.Sprintf(" | WAF: %s", wafRes.WAFName)
				wafCount++
			}

			techRes := native.MapTechnologies(svc.IP, svc.Port, svc.Banner)
			if techRes.Server != "" {
				techDetected = techRes.Server
			}
			if len(techRes.Frameworks) > 0 {
				techDetected += " | " + strings.Join(techRes.Frameworks, ", ")
				cmsCount++
			}

			// MapTechnologies returns advisory strings ("Check for CVE-..."),
			// not confirmed bugs.  Keep them as review leads: the previous
			// version turned every advisory into a TECH-VULN High 7.0 finding
			// with fabricated evidence ("Identified via Tech Mapping Regex").
			for _, v := range techRes.Vulnerabilities {
				advisories = append(advisories, fmt.Sprintf("%s:%d — %s", svc.IP, svc.Port, v))
			}
		}

		svc.Tech = techDetected
		updatedServices = append(updatedServices, svc)
	}

	state.StopSpinner()

	state.Mu.Lock()
	state.Discovered = updatedServices
	if len(advisories) > 0 {
		state.ContextData["tech_advisories"] = advisories
	}
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(f.Name(), "RESULT", fmt.Sprintf("Fingerprinted %d services in %s | %d WAFs, %d CMS, %d version advisories recorded as leads",
		len(services), elapsed, wafCount, cmsCount, len(advisories)))
	return nil
}
