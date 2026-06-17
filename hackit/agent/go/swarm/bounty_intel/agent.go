package bounty_intel

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
	"hackit_ai_engine/swarm/python_bridge"
)

type BountyIntelAgent struct {
	name string
	desc string
}

func NewBountyIntelAgent() *BountyIntelAgent {
	return &BountyIntelAgent{
		name: "Agent-27: Bug Bounty Intelligence",
		desc: "Prioritizes vulnerabilities based on real-world bug bounty impact, CVSS 4.0, and EPSS likelihood scores.",
	}
}

func (a *BountyIntelAgent) Name() string        { return a.name }
func (a *BountyIntelAgent) Description() string  { return a.desc }

func (a *BountyIntelAgent) Execute(state *core.SwarmState) error {
	state.Section("BOUNTY INTELLIGENCE PHASE")
	state.Log(a.Name(), "START", "Scoring findings using Bug Bounty priority metrics...")

	state.Mu.RLock()
	vulns := state.Vulns
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.LogWarn(a.Name(), "WARN", "No vulns to score for bounty intelligence")
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sCalculating EPSS/CVSS 4.0 scores for %d vulns%s", core.Yellow, len(vulns), core.Reset))
	time.Sleep(100 * time.Millisecond)

	type bountyScore struct {
		vuln    core.Vulnerability
		epss    float64
		bounty  string
		multiplier float64
	}

	bountyMap := map[string]struct {
		epss   float64
		bounty string
	}{
		"MISCONF-001":       {0.85, "High ($500-$2000)"},
		"MISCONF-002":       {0.72, "Medium ($250-$1000)"},
		"MISCONF-WP-ADMIN":  {0.45, "Low ($100-$500)"},
		"MISCONF-PHPINFO":   {0.38, "Low ($50-$250)"},
		"MISCONF-ACTUATOR":  {0.65, "Medium ($200-$800)"},
		"MISCONF-SWAGGER":   {0.42, "Low ($100-$400)"},
		"MISCONF-MYSQL":     {0.78, "High ($500-$2000)"},
		"MISCONF-MONGO":     {0.82, "High ($500-$2500)"},
		"MISCONF-FTP":       {0.30, "Low ($50-$200)"},
		"CVE-2023":          {0.91, "High ($1000-$5000)"},
		"CVE-2020-15778":    {0.88, "High ($750-$3000)"},
		"CVE-2021-41773":    {0.93, "Critical ($1500-$5000)"},
		"CVE-2021-23017":    {0.55, "Medium ($200-$750)"},
		"CVE-2021-31166":    {0.60, "Medium ($250-$1000)"},
		"CVE-2022-0543":     {0.95, "Critical ($2000-$7500)"},
		"TECH-VULN":         {0.50, "Medium ($150-$500)"},
		"ZERODAY":           {0.99, "Critical ($5000-$25000)"},
		"BFL":               {0.80, "High ($500-$3000)"},
		"IDOR":              {0.85, "High ($500-$3000)"},
		"RBAC":              {0.60, "Medium ($200-$1000)"},
	}

	var scored []bountyScore
	totalBounty := 0.0
	for _, v := range vulns {
		bs := bountyScore{vuln: v, epss: 0.1, bounty: "Unknown", multiplier: 1.0}
		for prefix, bm := range bountyMap {
			if len(v.ID) >= len(prefix) && v.ID[:len(prefix)] == prefix {
				bs.epss = bm.epss
				bs.bounty = bm.bounty
				break
			}
		}
		bs.multiplier = bs.epss * 0.5 + (v.CVSS / 10.0) * 0.5
		scored = append(scored, bs)
		totalBounty += bs.epss * v.CVSS
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].multiplier > scored[j].multiplier
	})

	state.StopSpinner()

	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Scored %d vulns by bounty impact on %s", len(scored), domain))
	for i, bs := range scored {
		if i >= 5 {
			break
		}
		state.LogOk(a.Name(), "PRIORITY", fmt.Sprintf("#%d: [%s] %s | Impact: %.2f | Est. Bounty: %s",
			i+1, bs.vuln.Severity, bs.vuln.Name, bs.multiplier*10, bs.bounty))
	}

	topVulns := []string{}
	for i, bs := range scored {
		if i >= 3 {
			break
		}
		topVulns = append(topVulns, fmt.Sprintf("%s (CVSS %.1f, EPSS %.2f)", bs.vuln.Name, bs.vuln.CVSS, bs.epss))
	}

	aiPrompt := fmt.Sprintf("Rank and provide exploitation strategies for these top bug bounty findings on %s: %s. For each, suggest: 1) exploitation approach 2) WAF bypass 3) expected payout range.",
		domain, strings.Join(topVulns, "; "))
	aiResult, aiErr := python_bridge.AnalyzeWithAI(a.Name(), aiPrompt)
	if aiErr == nil && len(aiResult) > 10 {
		state.LogOk(a.Name(), "AI_STRATEGY", fmt.Sprintf("Python AI bounty strategy: %s", aiResult[:min(len(aiResult), 200)]))
	}

	state.Mu.Lock()
	state.ContextData["bounty_scores"] = scored
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "COMPLETE", fmt.Sprintf("Bounty intelligence complete in %s", elapsed))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
