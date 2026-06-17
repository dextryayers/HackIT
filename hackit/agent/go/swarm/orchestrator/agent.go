package orchestrator

import (
	"fmt"

	"hackit_ai_engine/swarm/asset_intel"
	"hackit_ai_engine/swarm/attack_chain"
	"hackit_ai_engine/swarm/bounty_intel"
	"hackit_ai_engine/swarm/business_logic"
	"hackit_ai_engine/swarm/core"
	"hackit_ai_engine/swarm/correlation"
	"hackit_ai_engine/swarm/dashboard"
	"hackit_ai_engine/swarm/discovery"
	"hackit_ai_engine/swarm/enumeration"
	"hackit_ai_engine/swarm/evasion"
	"hackit_ai_engine/swarm/evidence"
	"hackit_ai_engine/swarm/exploitation"
	"hackit_ai_engine/swarm/fingerprint"
	"hackit_ai_engine/swarm/knowledge_graph"
	"hackit_ai_engine/swarm/learning"
	"hackit_ai_engine/swarm/log_analysis"
	"hackit_ai_engine/swarm/mcp_integration"
	"hackit_ai_engine/swarm/memory"
	"hackit_ai_engine/swarm/monitoring"
	"hackit_ai_engine/swarm/planning"
	"hackit_ai_engine/swarm/poc_generator"
	"hackit_ai_engine/swarm/reasoning"
	"hackit_ai_engine/swarm/recon"
	"hackit_ai_engine/swarm/reporting"
	"hackit_ai_engine/swarm/risk_scoring"
	"hackit_ai_engine/swarm/security_advisor"
	"hackit_ai_engine/swarm/threat_modeling"
	"hackit_ai_engine/swarm/vuln_analysis"
	"hackit_ai_engine/swarm/zeroday"
)

type OrchestratorAgent struct {
	Agents    []core.Agent
	name      string
	desc      string
}

func NewOrchestratorAgent() *OrchestratorAgent {
	return &OrchestratorAgent{
		name: "Agent-0: Autonomous Security Orchestrator",
		desc: "The absolute master node. Controls the DAG workflow and coordinates the entire 28-node swarm lifecycle.",
		Agents: []core.Agent{
			mcp_integration.NewMCPIntegrationAgent(),
			evasion.NewEvasionAgent(),
			planning.NewPlanningAgent(),
			recon.NewReconAgent(),
			discovery.NewDiscoveryAgent(),
			fingerprint.NewFingerprintAgent(),
			enumeration.NewEnumerationAgent(),
			vuln_analysis.NewVulnAnalysisAgent(),
			zeroday.NewZeroDayAgent(),
			reasoning.NewReasoningAgent(),
			business_logic.NewBusinessLogicAgent(),
			exploitation.NewExploitationAgent(),
			correlation.NewCorrelationAgent(),
			attack_chain.NewAttackChainAgent(),
			evidence.NewEvidenceAgent(),
			risk_scoring.NewRiskScoringAgent(),
			bounty_intel.NewBountyIntelAgent(),
			reporting.NewReportGenerationAgent(),
			poc_generator.NewPoCGeneratorAgent(),
			memory.NewMemoryAgent(),
			learning.NewLearningAgent(),
			knowledge_graph.NewKnowledgeGraphAgent(),
			threat_modeling.NewThreatModelingAgent(),
			security_advisor.NewSecurityAdvisorAgent(),
			monitoring.NewMonitoringAgent(),
			dashboard.NewDashboardAgent(),
			log_analysis.NewLogAnalysisAgent(),
			asset_intel.NewAssetIntelligenceAgent(),
		},
	}
}

func (o *OrchestratorAgent) Name() string  { return o.name }
func (o *OrchestratorAgent) Description() string { return o.desc }

func (o *OrchestratorAgent) Execute(domain, scope string) error {
	state := core.InitSwarm(domain, scope)

	fmt.Printf("\n%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", core.Bold+core.Magenta, core.Reset, core.Reset)
	fmt.Printf("%s%s        HACKIT V3 SWARM ORCHESTRATOR       %s\n", core.Bold+core.BgPurple, core.White, core.Reset)
	fmt.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", core.Bold+core.Magenta, core.Reset, core.Reset)
	fmt.Printf("  %sSession:%s %s\n", core.Bold, core.Reset, state.SessionID)
	fmt.Printf("  %sTarget:%s  %s [%s]\n", core.Bold, core.Reset, domain, scope)
	fmt.Printf("  %sAgents:%s  %d\n\n", core.Bold, core.Reset, len(o.Agents))

	state.Log(o.Name(), "BOOT", "Swarm initialized. Beginning DAG execution pipeline.")
	total := len(o.Agents)

	for idx, agent := range o.Agents {
		current := idx + 1
		pct := float64(current) * 100 / float64(total)
		bar := ""
		for i := 0; i < 30; i++ {
			if i < int(pct*30/100) {
				bar += "▓"
			} else {
				bar += "░"
			}
		}
		fmt.Printf("\r%s%s [%s] %sAgent %d/%d%s %s %s", core.SavePos, core.Cyan, bar, core.Bold, current, total, core.Reset, agent.Name(), core.ClearLine)

		state.Log(o.Name(), "INVOKE", fmt.Sprintf("Waking up %s...", agent.Name()))

		err := agent.Execute(state)
		if err != nil {
			state.LogErr(o.Name(), "FATAL", fmt.Sprintf("Agent %s failed: %v", agent.Name(), err))
			fmt.Print(core.ShowCur)
			return err
		}

		state.LogOk(o.Name(), "DONE", fmt.Sprintf("%s completed successfully", agent.Name()))

		dumpPath := fmt.Sprintf("reports/dashboard/%s.json", state.SessionID)
		state.Dump(dumpPath)
	}

	state.Section("SWARM LIFECYCLE COMPLETE")
	fmt.Printf("%s", state.Summary())

	dumpPath := fmt.Sprintf("reports/final/%s/state.json", state.SessionID)
	if err := state.Dump(dumpPath); err != nil {
		state.LogErr(o.Name(), "DUMP", fmt.Sprintf("Failed to dump state: %v", err))
	}

	fmt.Printf("\n%s%s Report: %s %s\n", core.Bold, core.Green, dumpPath, core.Reset)
	fmt.Print(core.ShowCur)
	return nil
}
