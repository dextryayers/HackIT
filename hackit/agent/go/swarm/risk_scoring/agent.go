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
		desc: "Calculates risk, CVSS vectors, and business priority for all discovered vulnerabilities.",
	}
}

func (r *RiskScoringAgent) Name() string        { return r.name }
func (r *RiskScoringAgent) Description() string  { return r.desc }

func (r *RiskScoringAgent) Execute(state *core.SwarmState) error {
	state.Section("RISK SCORING PHASE")
	state.Log(r.Name(), "START", "Starting Risk and CVSS Scoring Matrix...")

	state.Mu.Lock()
	vulns := state.Vulns
	state.Mu.Unlock()

	if len(vulns) == 0 {
		state.LogWarn(r.Name(), "WARN", "No vulnerabilities to score.")
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sScoring %d vulnerabilities%s", core.Yellow, len(vulns), core.Reset))

	type score struct {
		severity  string
		min, max  float64
	}

	scores := map[string]score{
		"Critical": {"Critical", 9.0, 10.0},
		"High":     {"High", 7.0, 8.9},
		"Medium":   {"Medium", 4.0, 6.9},
		"Low":      {"Low", 0.1, 3.9},
		"Info":     {"Info", 0.0, 0.0},
	}

	state.Mu.Lock()
	riskScore := 0.0
	for i := range state.Vulns {
		v := &state.Vulns[i]
		s, ok := scores[v.Severity]
		if !ok {
			s = scores["Medium"]
		}
		if v.CVSS == 0 {
			v.CVSS = s.min + (s.max-s.min)*0.5
		}
		if v.ID == "MISCONF-001" || v.ID == "MISCONF-002" {
			if v.CVSS < 9.0 {
				v.CVSS = 9.0
				v.Severity = "Critical"
			}
		}
		riskScore += v.CVSS
	}
	state.Mu.Unlock()

	avgRisk := riskScore / float64(len(vulns))
	riskLevel := "Low"
	if avgRisk >= 7.0 {
		riskLevel = "High"
	} else if avgRisk >= 4.0 {
		riskLevel = "Medium"
	}
	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(r.Name(), "RESULT", fmt.Sprintf("Scored %d vulns | Avg CVSS: %.1f | Risk: %s | Total: %.1f | Duration: %s",
		len(vulns), avgRisk, riskLevel, riskScore, elapsed))
	return nil
}
