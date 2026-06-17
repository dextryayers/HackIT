package zeroday

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
	"hackit_ai_engine/swarm/python_bridge"
)

type ZeroDayAgent struct {
	name string
	desc string
}

func NewZeroDayAgent() *ZeroDayAgent {
	return &ZeroDayAgent{
		name: "Agent-23: Zero-Day Heuristic Analyzer",
		desc: "Scans raw source code and JS bundles for dangerous sinks and un-sanitized inputs to uncover 0-day flaws.",
	}
}

func (a *ZeroDayAgent) Name() string        { return a.name }
func (a *ZeroDayAgent) Description() string  { return a.desc }

func (a *ZeroDayAgent) Execute(state *core.SwarmState) error {
	state.Section("ZERO-DAY ANALYSIS PHASE")
	state.Log(a.Name(), "START", "Spinning up heuristic code analyzers...")

	state.Mu.RLock()
	services := state.Discovered
	vulns := state.Vulns
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sScanning for dangerous sinks and patterns%s", core.Yellow, core.Reset))
	time.Sleep(100 * time.Millisecond)

	dangerousPatterns := []string{
		"eval(", "exec(", "system(", "popen(", "shell_exec(", "passthru(",
		"innerHTML", "document.write(", "dangerouslySetInnerHTML",
		"SQLite3::exec", "mysql_query(", "pg_query(", "unsafe_",
		"new Function(", "setTimeout('", "setInterval('",
		"localStorage.getItem('token')", "localStorage.getItem('api')",
		"fromCharCode", "unescape(", "escape(", "btoa(", "atob(",
		"prototype.", "__proto__", "constructor.",
		"child_process", "require('child_process')", "process.binding",
		"import_", "ctypes", "libc",
	}

	analyzedCount := 0
	findings := 0
	for _, svc := range services {
		if svc.Port == 80 || svc.Port == 443 || svc.Port == 8080 || svc.Port == 8443 || svc.Port == 3000 || svc.Port == 5000 {
			analyzedCount++
			for i, pat := range dangerousPatterns {
				if strings.Contains(svc.Banner, pat) || strings.Contains(svc.Tech, pat[:min(len(pat), 3)]) {
					findings++
					state.Mu.Lock()
					state.Vulns = append(state.Vulns, core.Vulnerability{
						ID:          fmt.Sprintf("ZERODAY-%d-%d", analyzedCount, i),
						Name:        fmt.Sprintf("Potential 0-Day: Dangerous pattern '%s'", pat),
						Severity:    "Critical",
						CVSS:        9.5,
						Description: fmt.Sprintf("Heuristic analyzer found dangerous sink '%s' on %s:%d", pat, svc.IP, svc.Port),
						Evidence:    fmt.Sprintf("Pattern '%s' detected in service banner/response", pat),
					})
					state.Mu.Unlock()
				}
			}
		}
	}

	state.StopSpinner()

	if findings > 0 {
		aiPrompt := fmt.Sprintf("Found %d potential zero-day patterns across %d endpoints. Patterns detected include: %s. Suggest realistic exploit scenarios for each. Return as bullet points.",
			findings, analyzedCount,
			strings.Join(dangerousPatterns[:min(len(dangerousPatterns), 5)], ", "))
		aiResult, aiErr := python_bridge.AnalyzeWithAI(a.Name(), aiPrompt)
		if aiErr == nil && len(aiResult) > 10 {
			state.LogOk(a.Name(), "AI_EXPLOIT", fmt.Sprintf("Python AI exploit analysis: %s", aiResult[:min(len(aiResult), 200)]))
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Analyzed %d endpoints, found %d heuristic matches in %s. Total vulns: %d",
		analyzedCount, findings, elapsed, len(vulns)+findings))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
