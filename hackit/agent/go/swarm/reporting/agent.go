package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
func (r *ReportGenerationAgent) Description() string { return r.desc }

// leadsSection renders untested hypotheses.  They are deliberately outside
// the findings list and carry no severity: an unprobed hypothesis is not a
// vulnerability, but the operator still needs to see what the swarm noticed.
func leadsSection(state *core.SwarmState) string {
	keys := []string{"reasoning_leads", "business_logic_leads", "zeroday_leads", "tech_advisories"}
	total := 0
	var b strings.Builder
	for _, key := range keys {
		items, ok := state.ContextData[key]
		if !ok {
			continue
		}
		var list []string
		switch v := items.(type) {
		case []string:
			list = v
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					list = append(list, s)
				}
			}
		}
		if len(list) == 0 {
			continue
		}
		if total == 0 {
			b.WriteString("## Untested Leads (not vulnerabilities)\n\n")
			b.WriteString("Hypotheses that no live probe confirmed. Treat as review pointers, not findings.\n\n")
		}
		for _, lead := range list {
			b.WriteString(fmt.Sprintf("- %s\n", lead))
			total++
		}
	}
	if total > 0 {
		b.WriteString("\n")
	}
	return b.String()
}

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
		case "Critical":
			critical++
		case "High":
			high++
		case "Medium":
			medium++
		case "Low":
			low++
		default:
			info++
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
		// Guard: ContextData values cross agent boundaries untyped.
		switch v := chains.(type) {
		case []string:
			for _, chain := range v {
				md += fmt.Sprintf("- %s\n", chain)
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					md += fmt.Sprintf("- %s\n", s)
				}
			}
		}
		md += "\n"
	}

	md += fmt.Sprintf("## Technical Findings\n\n")
	if len(vulns) == 0 {
		md += "No finding passed live verification. Leads that were not proven are listed below.\n\n"
	}
	for i, v := range vulns {
		md += fmt.Sprintf("### %d. [%s] %s\n", i+1, v.Severity, v.Name)
		md += fmt.Sprintf("- ID: %s\n", v.ID)
		md += fmt.Sprintf("- CVSS: %.1f\n", v.CVSS)
		md += fmt.Sprintf("- Description: %s\n", v.Description)
		md += fmt.Sprintf("- Evidence: %s\n", v.Evidence)
		if v.Reproduce != "" {
			md += fmt.Sprintf("- Reproduce: `%s`\n", v.Reproduce)
		}
		if v.Remediation != "" {
			md += fmt.Sprintf("- Remediation: %s\n", v.Remediation)
		}
		md += "\n"
	}

	md += leadsSection(state)

	// Plain-text summary: state.Summary() carries ANSI codes for the TTY.
	md += fmt.Sprintf("## Summary\n\n")
	md += fmt.Sprintf("- Session: %s\n", sessionID)
	md += fmt.Sprintf("- Target: %s\n", domain)
	md += fmt.Sprintf("- Scope: %s\n", state.Target.ScopeType)
	md += fmt.Sprintf("- Duration: %s\n", elapsed)
	md += fmt.Sprintf("- Verified findings: %d\n", len(vulns))
	md += fmt.Sprintf("- Log events: %d\n", len(state.Logs))

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
