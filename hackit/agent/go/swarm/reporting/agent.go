package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hackit_ai_engine/swarm/core"
)

type ReportGenerationAgent struct {
	name string
	desc string
}

func NewReportGenerationAgent() *ReportGenerationAgent {
	return &ReportGenerationAgent{
		name: "Agent-10: Report Generation",
		desc: "Compiles the executive summary, technical findings, and mitigation strategies into a final report.",
	}
}

func (r *ReportGenerationAgent) Name() string        { return r.name }
func (r *ReportGenerationAgent) Description() string  { return r.desc }

func (r *ReportGenerationAgent) Execute(state *core.SwarmState) error {
	state.Section("REPORT GENERATION PHASE")
	state.Log(r.Name(), "START", "Starting Final Report Compilation...")

	reportDir := filepath.Join("reports", "final", state.SessionID)
	err := os.MkdirAll(reportDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create report dir: %w", err)
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sGenerating Markdown report%s", core.Yellow, core.Reset))

	state.Mu.RLock()
	summary := state.Summary()
	vulns := state.Vulns
	domain := state.Target.PrimaryDomain
	sessionID := state.SessionID
	startTime := state.StartTime
	discovered := state.Discovered
	subdomains := state.ReconData.Subdomains
	asn := state.ReconData.ASN
	cloudInfra := state.ReconData.CloudInfra
	state.Mu.RUnlock()

	elapsed := time.Since(startTime).Round(time.Second)

	critical, high, medium, low, info := 0, 0, 0, 0, 0
	for _, v := range vulns {
		switch v.Severity {
		case "Critical": critical++
		case "High": high++
		case "Medium": medium++
		case "Low": low++
		default: info++
		}
	}

	md := fmt.Sprintf("# HackIT AI Autonomous Swarm Report\n\n")
	md += fmt.Sprintf("## Executive Summary\n")
	md += fmt.Sprintf("- Target: %s\n", domain)
	md += fmt.Sprintf("- Session ID: %s\n", sessionID)
	md += fmt.Sprintf("- Duration: %s\n", elapsed)
	md += fmt.Sprintf("- Scan Mode: %s\n", state.Target.ScopeType)
	md += fmt.Sprintf("- Total Vulnerabilities: %d\n\n", len(vulns))

	md += fmt.Sprintf("### Score Summary\n")
	md += fmt.Sprintf("| Severity | Count |\n|----------|-------|\n")
	md += fmt.Sprintf("| Critical | %d |\n", critical)
	md += fmt.Sprintf("| High     | %d |\n", high)
	md += fmt.Sprintf("| Medium   | %d |\n", medium)
	md += fmt.Sprintf("| Low      | %d |\n", low)
	md += fmt.Sprintf("| Info     | %d |\n\n", info)

	md += fmt.Sprintf("### Attack Surface\n")
	md += fmt.Sprintf("- Subdomains: %d\n", len(subdomains))
	md += fmt.Sprintf("- Services: %d\n", len(discovered))
	md += fmt.Sprintf("- ASN: %s\n", asn)
	md += fmt.Sprintf("- Cloud Infrastructure: %s\n\n", cloudInfra)

	if chains, ok := state.ContextData["attack_chains"]; ok {
		md += fmt.Sprintf("### Attack Chains\n\n")
		for _, chain := range chains.([]string) {
			md += fmt.Sprintf("- %s\n", chain)
		}
		md += "\n"
	}

	md += fmt.Sprintf("## Technical Findings\n\n")
	for i, v := range vulns {
		md += fmt.Sprintf("### %d. [%s] %s\n", i+1, v.Severity, v.Name)
		md += fmt.Sprintf("- ID: %s\n", v.ID)
		md += fmt.Sprintf("- CVSS: %.1f\n", v.CVSS)
		md += fmt.Sprintf("- Description: %s\n", v.Description)
		md += fmt.Sprintf("- Evidence: %s\n", v.Evidence)
		md += "\n"
	}

	md += fmt.Sprintf("## Summary\n\n")
	md += fmt.Sprintf("%s\n", summary)

	mdPath := filepath.Join(reportDir, "report.md")
	err = os.WriteFile(mdPath, []byte(md), 0644)
	if err != nil {
		state.LogWarn(r.Name(), "ERROR", fmt.Sprintf("Failed to write markdown: %v", err))
	}

	jsonPath := filepath.Join(reportDir, "state.json")
	state.Dump(jsonPath)
	state.StopSpinner()

	compileElapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(r.Name(), "RESULT", fmt.Sprintf("Report generated at %s in %s", reportDir, compileElapsed))
	return nil
}
