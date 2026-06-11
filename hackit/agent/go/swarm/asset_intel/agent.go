package asset_intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"hackit_ai_engine/swarm/core"
)

// AssetIntelligenceAgent is Node 19 in the 20-Node Autonomous Swarm
// Responsible for producing a living inventory of all known corporate assets.
type AssetIntelligenceAgent struct{}

func NewAssetIntelligenceAgent() *AssetIntelligenceAgent {
	return &AssetIntelligenceAgent{}
}

func (a *AssetIntelligenceAgent) Name() string {
	return "Agent-19: Asset Intelligence"
}

func (a *AssetIntelligenceAgent) Description() string {
	return "Compiles a strictly structured, queryable living inventory of all discovered digital assets."
}

func (a *AssetIntelligenceAgent) Execute(state *core.SwarmState) error {
	state.Log(a.Name(), "START", "Compiling Living Asset Inventory...")

	state.Mu.RLock()
	services := state.Discovered
	subdomains := state.ReconData.Subdomains
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	// Build the Asset Inventory Structure
	inventory := map[string]interface{}{
		"corporate_domain": domain,
		"total_subdomains": len(subdomains),
		"active_services":  len(services),
		"asset_map":        services,
	}

	state.Log(a.Name(), "TASK", fmt.Sprintf("Compiled %d active assets into the global registry.", len(services)))

	invDir := filepath.Join("data", "inventory")
	os.MkdirAll(invDir, 0755)
	invPath := filepath.Join(invDir, fmt.Sprintf("%s_inventory.json", domain))

	data, err := json.MarshalIndent(inventory, "", "  ")
	if err == nil {
		os.WriteFile(invPath, data, 0644)
	}

	state.Log(a.Name(), "COMPLETE", "Asset Inventory persisted. Handing over to the absolute Master: Agent-20.")

	return nil
}
