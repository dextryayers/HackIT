package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hackit_ai_engine/swarm/core"
)

// ReportGenerationAgent is Node 10 in the 20-Node Autonomous Swarm
// Responsible for compiling the final JSON and Markdown report.
type ReportGenerationAgent struct{}

func NewReportGenerationAgent() *ReportGenerationAgent {
	return &ReportGenerationAgent{}
}

func (r *ReportGenerationAgent) Name() string {
	return "Agent-10: Report Generation"
}

func (r *ReportGenerationAgent) Description() string {
	return "Compiles the executive summary, technical findings, and mitigation strategies into a final report."
}

func (r *ReportGenerationAgent) Execute(state *core.SwarmState) error {
	state.Log(r.Name(), "START", "Starting Final Report Compilation...")

	reportDir := filepath.Join("reports", "final", state.SessionID)
	err := os.MkdirAll(reportDir, 0755)
	if err != nil {
		state.Log(r.Name(), "ERROR", fmt.Sprintf("Failed to create report directory: %v", err))
		return err
	}

	state.Log(r.Name(), "TASK", fmt.Sprintf("Generating Markdown Report to %s", reportDir))

	state.Mu.RLock()
	mdContent := fmt.Sprintf("# HackIT AI Autonomous Swarm Report\n\n")
	mdContent += fmt.Sprintf("## Executive Summary\n")
	mdContent += fmt.Sprintf("- **Target:** %s\n", state.Target.PrimaryDomain)
	mdContent += fmt.Sprintf("- **Session ID:** %s\n", state.SessionID)
	mdContent += fmt.Sprintf("- **Start Time:** %s\n", state.StartTime.Format(time.RFC1123))
	mdContent += fmt.Sprintf("- **Total Vulnerabilities:** %d\n\n", len(state.Vulns))

	mdContent += fmt.Sprintf("## Technical Findings\n\n")
	for i, v := range state.Vulns {
		mdContent += fmt.Sprintf("### %d. [%s] %s (CVSS: %.1f)\n", i+1, v.Severity, v.Name, v.CVSS)
		mdContent += fmt.Sprintf("**Description:** %s\n\n", v.Description)
	}
	state.Mu.RUnlock() // Unlock after reading, no defer

	// Write Markdown
	mdPath := filepath.Join(reportDir, "report.md")
	err = os.WriteFile(mdPath, []byte(mdContent), 0644)
	if err != nil {
		return err
	}

	// Write JSON State Dump
	jsonPath := filepath.Join(reportDir, "state.json")
	state.Dump(jsonPath)

	state.Log(r.Name(), "COMPLETE", "Final report generated successfully. Handing over to Agent-11: Memory.")

	return nil
}
