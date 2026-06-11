package knowledge_graph

import (
	"fmt"
	"os"
	"path/filepath"

	"hackit_ai_engine/swarm/core"
)

// KnowledgeGraphAgent is Node 13 in the 20-Node Autonomous Swarm
// Responsible for mapping the relational web of assets and vulnerabilities.
type KnowledgeGraphAgent struct{}

func NewKnowledgeGraphAgent() *KnowledgeGraphAgent {
	return &KnowledgeGraphAgent{}
}

func (k *KnowledgeGraphAgent) Name() string {
	return "Agent-13: Knowledge Graph"
}

func (k *KnowledgeGraphAgent) Description() string {
	return "Builds a relational graph linking Domains -> IPs -> Services -> Vulnerabilities."
}

func (k *KnowledgeGraphAgent) Execute(state *core.SwarmState) error {
	state.Log(k.Name(), "START", "Constructing the Relational Knowledge Graph...")

	state.Mu.RLock()
	domain := state.Target.PrimaryDomain
	subdomains := state.ReconData.Subdomains
	services := state.Discovered
	vulns := state.Vulns
	state.Mu.RUnlock()

	// Mock Graph Construction (Nodes and Edges)
	// Example format: Source -> Relationship -> Target
	var graph []string

	// Domain -> Subdomains
	for _, sub := range subdomains {
		graph = append(graph, fmt.Sprintf("[%s] -HAS_SUBDOMAIN-> [%s]", domain, sub))
	}

	// Subdomains -> IPs/Services
	for _, svc := range services {
		graph = append(graph, fmt.Sprintf("[%s] -HOSTS_SERVICE-> [%s:%d]", svc.IP, svc.IP, svc.Port))
		graph = append(graph, fmt.Sprintf("[%s:%d] -RUNS_TECH-> [%s]", svc.IP, svc.Port, svc.Tech))
	}

	// Services -> Vulnerabilities
	for _, v := range vulns {
		graph = append(graph, fmt.Sprintf("[VULN:%s] -AFFECTS-> [%s]", v.ID, domain)) // simplified link
	}

	state.Log(k.Name(), "TASK", fmt.Sprintf("Graph constructed with %d relational edges.", len(graph)))

	// Save the mock graph to a DOT file or CSV for Python to ingest via NetworkX
	graphDir := filepath.Join("data", "graphs")
	os.MkdirAll(graphDir, 0755)

	graphPath := filepath.Join(graphDir, fmt.Sprintf("%s.txt", state.SessionID))
	graphContent := "SOURCE|RELATIONSHIP|TARGET\n"
	for _, edge := range graph {
		graphContent += edge + "\n"
	}

	err := os.WriteFile(graphPath, []byte(graphContent), 0644)
	if err != nil {
		state.Log(k.Name(), "ERROR", "Failed to save knowledge graph data.")
	}

	state.Log(k.Name(), "COMPLETE", "Knowledge graph compiled. Handing over to Agent-14: Threat Modeling.")

	return nil
}
