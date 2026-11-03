package vuln_analysis

import (
	"fmt"
	"net/url"
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
	parsed := state.Target.Parsed
	rules := append([]string(nil), state.Target.Rules...)
	subdomains := append([]string(nil), state.ReconData.Subdomains...)
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
			Remediation: f.Remediation, Category: f.Category, Reproduce: f.Reproduce,
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

	// Phase 3: injection and misconfiguration detectors (SQLi/SSTI/LFI/cmd,
	// CORS/CSRF/headers, takeover, TLS). Skipped in passive scope, where the
	// rules of engagement forbid active payloads.
	activeAllowed := true
	for _, r := range rules {
		if r == "NO_ACTIVE_EXPLOITS" {
			activeAllowed = false
			break
		}
	}

	if activeAllowed {
		var targets []native.ScanTarget
		seenBase := map[string]bool{}
		addBase := func(u string) {
			if u == "" || seenBase[u] {
				return
			}
			seenBase[u] = true
			targets = append(targets, native.ScanTarget{URL: u})
		}
		addBase(parsed.BaseURL)
		// The operator's own URL path is a real route: scan it too.
		if u, err := url.Parse(parsed.Raw); err == nil && u.Path != "" && u.Path != "/" {
			path := strings.TrimSuffix(parsed.BaseURL, "/") + u.Path
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
			addBase(path)
		}
		for _, svc := range services {
			if svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 {
				scheme := "http"
				if svc.Port == 443 || svc.Port == 8443 {
					scheme = "https"
				}
				addBase(fmt.Sprintf("%s://%s:%d", scheme, svc.IP, svc.Port))
			}
		}
		// Enumerated endpoints are the highest-signal injection targets: pass the
		// path through so parameter fuzzing hits a real route.
		for _, ep := range endpoints {
			path := ep
			if i := strings.IndexAny(path, "?#"); i > 0 {
				path = path[:i]
			}
			if seenBase[path] {
				continue
			}
			seenBase[path] = true
			targets = append(targets, native.ScanTarget{URL: path})
		}
		if len(targets) > 10 {
			targets = targets[:10]
		}

		var tlsTargets []native.HostPort
		for _, svc := range services {
			if svc.Port == 443 || svc.Port == 8443 {
				tlsTargets = append(tlsTargets, native.HostPort{IP: svc.IP, Port: svc.Port})
			}
		}

		state.StartSpinner(fmt.Sprintf("%sActive detectors on %d web targets%s", core.Yellow, len(targets), core.Reset))
		for _, f := range native.ActiveScanTargets(targets, subdomains, tlsTargets) {
			add(f, f.Name)
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
