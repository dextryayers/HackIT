package orchestrator

import (
	"fmt"
	"time"

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

// OrchestratorAgent is Node 0 - The Master Conductor of the Swarm.
type OrchestratorAgent struct {
	Agents []core.Agent
}

func NewOrchestratorAgent() *OrchestratorAgent {
	// Build the Directed Acyclic Graph (DAG) Execution Pipeline
	return &OrchestratorAgent{
		Agents: []core.Agent{
			mcp_integration.NewMCPIntegrationAgent(), // Initialize MCP first
			evasion.NewEvasionAgent(),                // Start Stealth/Evasion
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

func (o *OrchestratorAgent) Name() string {
	return "Agent-0: Autonomous Security Orchestrator"
}

func (o *OrchestratorAgent) Description() string {
	return "The absolute master node. Controls the DAG workflow and coordinates the entire 28-node swarm lifecycle."
}

// Execute kicks off the massive 20-node ecosystem
func (o *OrchestratorAgent) Execute(domain, scope string) error {
	fmt.Println("=========================================================")
	fmt.Println(" [X] HACKIT V3 AUTONOMOUS SWARM ORCHESTRATOR INITIALIZED")
	fmt.Println("=========================================================")

	state := core.InitSwarm(domain, scope)
	state.Log(o.Name(), "BOOT", fmt.Sprintf("Swarm Session ID: %s", state.SessionID))
	state.Log(o.Name(), "BOOT", fmt.Sprintf("Target Locked: %s", domain))

	// Execute sequentially based on the DAG
	for _, agent := range o.Agents {
		state.Log(o.Name(), "INVOKE", fmt.Sprintf("Waking up %s...", agent.Name()))

		time.Sleep(200 * time.Millisecond) // Slight jitter for visual effect
		err := agent.Execute(state)

		if err != nil {
			state.Log(o.Name(), "FATAL", fmt.Sprintf("Agent %s encountered a critical failure: %v", agent.Name(), err))
			state.Log(o.Name(), "ABORT", "Swarm execution halted.")
			return err
		}
	}

	state.Log(o.Name(), "HALT", "All 28 Sub-Agents completed successfully. Swarm entering hibernation.")
	fmt.Println("=========================================================")
	fmt.Println(" [X] AUTONOMOUS LIFECYCLE COMPLETE. REPORT GENERATED.")
	fmt.Println("=========================================================")
	return nil
}
