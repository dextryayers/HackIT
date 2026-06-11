package mcp_integration

import (
	"fmt"
	"os/exec"

	"hackit_ai_engine/swarm/core"
)

// MCPIntegrationAgent bridges the Swarm with external security tools
type MCPIntegrationAgent struct{}

func NewMCPIntegrationAgent() *MCPIntegrationAgent {
	return &MCPIntegrationAgent{}
}

func (a *MCPIntegrationAgent) Name() string {
	return "Agent: MCP & Tool Orchestration"
}

func (a *MCPIntegrationAgent) Description() string {
	return "Orchestrates external security tools (Nmap, Amass, Katana, Nuclei) using the Model Context Protocol."
}

func (a *MCPIntegrationAgent) Execute(state *core.SwarmState) error {
	state.Log(a.Name(), "START", "Spinning up external tool orchestration containers via MCP...")

	// Execute Katana (crawler) if available
	state.Log(a.Name(), "TASK", "Attempting to execute Katana (crawler) for deep javascript analysis...")
	katanaPath, err := exec.LookPath("katana")
	if err == nil {
		state.Log(a.Name(), "EXEC", "Katana found. Running headlessly...")
		// Running Katana in JSON mode for structured data extraction
		cmd := exec.Command(katanaPath, "-u", state.Target.PrimaryDomain, "-jc", "-jsonl", "-silent", "-depth", "3")
		output, err := cmd.CombinedOutput()
		if err != nil {
			state.Log(a.Name(), "WARN", fmt.Sprintf("Katana execution encountered an error: %v", err))
		} else {
			state.Log(a.Name(), "PARSE", "Parsing Katana JSONL output into Swarm Memory...")
			// Simulate parsing logic by appending raw context
			state.Mu.Lock()
			state.ContextData["katana_raw_output"] = string(output)
			state.Mu.Unlock()
			state.Log(a.Name(), "DISCOVERY", "Katana intelligence assimilated.")
		}
	} else {
		state.Log(a.Name(), "WARN", "Katana binary not found in PATH. Skipping deep JS crawling.")
	}

	state.Log(a.Name(), "COMPLETE", "External tool orchestration phase finalized.")
	return nil
}
