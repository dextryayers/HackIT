package bounty_intel

import (
	"fmt"
	"sort"
	"time"

	"hackit_ai_engine/swarm/core"
)

type BountyIntelAgent struct {
	name string
	desc string
}

func NewBountyIntelAgent() *BountyIntelAgent {
	return &BountyIntelAgent{
		name: "Agent-27: Bug Bounty Intelligence",
		desc: "Ranks verified findings by CVSS for bounty triage.",
	}
}

func (a *BountyIntelAgent) Name() string        { return a.name }
func (a *BountyIntelAgent) Description() string { return a.desc }

// Execute ranks the verified findings by CVSS.  The previous version attached
// fixed EPSS values and dollar payout ranges from a lookup table keyed on
// finding-ID prefixes — including prefixes ("ZERODAY", "BFL", "IDOR", "RBAC")
// for findings that were themselves fabricated.  No EPSS or payout is claimed
// here: real EPSS is per-CVE and comes from FIRST.org, not a local table.
func (a *BountyIntelAgent) Execute(state *core.SwarmState) error {
	state.Section("BOUNTY INTELLIGENCE PHASE")
	state.Log(a.Name(), "START", "Ranking verified findings by CVSS for bounty triage...")

	state.Mu.RLock()
	vulns := state.Vulns
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.LogWarn(a.Name(), "WARN", "No vulns to score for bounty intelligence")
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sRanking %d findings%s", core.Yellow, len(vulns), core.Reset))

	type bountyScore struct {
		vuln       core.Vulnerability
		multiplier float64
	}

	scored := make([]bountyScore, 0, len(vulns))
	for _, v := range vulns {
		scored = append(scored, bountyScore{vuln: v, multiplier: v.CVSS})
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].multiplier > scored[j].multiplier
	})

	state.StopSpinner()

	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Ranked %d verified findings by CVSS on %s", len(scored), domain))
	for i, bs := range scored {
		if i >= 5 {
			break
		}
		state.LogOk(a.Name(), "PRIORITY", fmt.Sprintf("#%d: [%s] %s | CVSS %.1f",
			i+1, bs.vuln.Severity, bs.vuln.Name, bs.multiplier))
	}

	state.Mu.Lock()
	state.ContextData["bounty_scores"] = scored
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "COMPLETE", fmt.Sprintf("Bounty triage complete in %s", elapsed))
	return nil
}
