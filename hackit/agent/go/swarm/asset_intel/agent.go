package asset_intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hackit_ai_engine/swarm/core"
)

type AssetIntelligenceAgent struct {
	name string
	desc string
}

func NewAssetIntelligenceAgent() *AssetIntelligenceAgent {
	return &AssetIntelligenceAgent{
		name: "Agent-19: Asset Intelligence",
		desc: "Compiles a strictly structured, queryable living inventory of all discovered digital assets.",
	}
}

func (a *AssetIntelligenceAgent) Name() string        { return a.name }
func (a *AssetIntelligenceAgent) Description() string  { return a.desc }

func (a *AssetIntelligenceAgent) Execute(state *core.SwarmState) error {
	state.Section("ASSET INTELLIGENCE PHASE")
	state.Log(a.Name(), "START", "Compiling Living Asset Inventory...")

	state.Mu.RLock()
	services := state.Discovered
	subdomains := state.ReconData.Subdomains
	vulns := state.Vulns
	domain := state.Target.PrimaryDomain
	asn := state.ReconData.ASN
	cloudInfra := state.ReconData.CloudInfra
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sCompiling inventory for %d assets%s", core.Yellow, len(services)+len(subdomains), core.Reset))

	type assetEntry struct {
		Domain     string `json:"domain"`
		Type       string `json:"type"`
		Value      string `json:"value"`
		Tech       string `json:"tech,omitempty"`
		Port       int    `json:"port,omitempty"`
		Severity   string `json:"severity,omitempty"`
		CVSS       float64 `json:"cvss,omitempty"`
	}

	inventory := map[string]interface{}{
		"corporate_domain": domain,
		"asn":              asn,
		"cloud_infrastructure": cloudInfra,
		"total_subdomains": len(subdomains),
		"active_services":  len(services),
		"total_vulnerabilities": len(vulns),
		"generated_at":     time.Now().UTC().Format(time.RFC3339),
	}

	for i, sub := range subdomains {
		subdomains[i] = sub
	}

	var assetList []assetEntry
	for _, sub := range subdomains {
		assetList = append(assetList, assetEntry{Domain: domain, Type: "subdomain", Value: sub})
	}
	for _, svc := range services {
		assetList = append(assetList, assetEntry{Domain: domain, Type: "service", Value: fmt.Sprintf("%s:%d", svc.IP, svc.Port), Tech: svc.Tech, Port: svc.Port})
	}
	for _, v := range vulns {
		assetList = append(assetList, assetEntry{Domain: domain, Type: "vulnerability", Value: v.ID, Severity: v.Severity, CVSS: v.CVSS})
	}
	inventory["assets"] = assetList

	invDir := filepath.Join("data", "inventory")
	os.MkdirAll(invDir, 0755)
	invPath := filepath.Join(invDir, fmt.Sprintf("%s_inventory.json", domain))
	data, _ := json.MarshalIndent(inventory, "", "  ")
	os.WriteFile(invPath, data, 0644)
	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Inventory with %d assets written to %s in %s", len(assetList), invPath, elapsed))
	return nil
}
