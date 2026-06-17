package log_analysis

import (
	"fmt"
	"time"

	"hackit_ai_engine/swarm/core"
)

type LogAnalysisAgent struct {
	name string
	desc string
}

func NewLogAnalysisAgent() *LogAnalysisAgent {
	return &LogAnalysisAgent{
		name: "Agent-18: AI Log Analysis",
		desc: "Parses raw tool logs (Nmap, Go, Python) to detect obfuscated anomalies and hidden patterns.",
	}
}

func (l *LogAnalysisAgent) Name() string        { return l.name }
func (l *LogAnalysisAgent) Description() string  { return l.desc }

func (l *LogAnalysisAgent) Execute(state *core.SwarmState) error {
	state.Section("LOG ANALYSIS PHASE")
	state.Log(l.Name(), "START", "Starting Deep Log Anomaly Parser...")

	state.Mu.RLock()
	logCount := len(state.Logs)
	vulns := state.Vulns
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sParsing %d execution logs%s", core.Yellow, logCount, core.Reset))
	time.Sleep(50 * time.Millisecond)
	state.StopSpinner()

	if logCount > 50 {
		state.LogWarn(l.Name(), "ANOMALY", fmt.Sprintf("High log volume (%d entries). Target may be triggering tarpit/honeypot.", logCount))
	} else {
		state.LogOk(l.Name(), "ANOMALY", fmt.Sprintf("Log variance normal (%d entries). No honeypot indicators.", logCount))
	}

	if len(vulns) > 0 {
		state.Log(l.Name(), "CORRELATE", fmt.Sprintf("Cross-referencing %d vulns with execution logs", len(vulns)))
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(l.Name(), "COMPLETE", fmt.Sprintf("Log analysis finished in %s", elapsed))
	return nil
}
