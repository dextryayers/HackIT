package risk_scoring

import (
	"fmt"
	"time"

	"hackit_ai_engine/swarm/core"
)

type RiskScoringAgent struct {
	name string
	desc string
}

func NewRiskScoringAgent() *RiskScoringAgent {
	return &RiskScoringAgent{
		name: "Agent-9: Risk Scoring",
		desc: "Calculates aggregate risk from the CVSS scores attached to verified findings.",
	}
}

func (r *RiskScoringAgent) Name() string        { return r.name }
func (r *RiskScoringAgent) Description() string { return r.desc }

// Execute aggregates the CVSS scores already assigned by the verifier.  It no
// longer force-upgrades specific IDs: the previous version pushed MISCONF-002
// from the verifier's High 7.5 to Critical 9.0 here, so a report contradicted
// the probe that produced the evidence.
func (r *RiskScoringAgent) Execute(state *core.SwarmState) error {
	state.Section("RISK SCORING PHASE")
	state.Log(r.Name(), "START", "Starting Risk Scoring Matrix...")

	state.Mu.Lock()
	vulns := state.Vulns
	state.Mu.Unlock()

	if len(vulns) == 0 {
		state.LogWarn(r.Name(), "WARN", "No vulnerabilities to score.")
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sScoring %d vulnerabilities%s", core.Yellow, len(vulns), core.Reset))

	riskScore := 0.0
	unscored := 0
	for _, v := range vulns {
		if v.CVSS == 0 {
			// Verified findings always carry a score; anything unscored is a
			// lead that leaked in, so exclude it from the aggregate.
			unscored++
			continue
		}
		riskScore += v.CVSS
	}

	scoredCount := len(vulns) - unscored
	avgRisk := 0.0
	if scoredCount > 0 {
		avgRisk = riskScore / float64(scoredCount)
	}
	riskLevel := "Low"
	if avgRisk >= 7.0 {
		riskLevel = "High"
	} else if avgRisk >= 4.0 {
		riskLevel = "Medium"
	}
	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(r.Name(), "RESULT", fmt.Sprintf("Scored %d vulns | Avg CVSS: %.1f | Risk: %s | Total: %.1f | Duration: %s",
		scoredCount, avgRisk, riskLevel, riskScore, elapsed))
	return nil
}
