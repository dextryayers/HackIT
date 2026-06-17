package knowledge_graph

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hackit_ai_engine/swarm/core"
)

type KnowledgeGraphAgent struct {
	name string
	desc string
}

func NewKnowledgeGraphAgent() *KnowledgeGraphAgent {
	return &KnowledgeGraphAgent{
		name: "Agent-13: Knowledge Graph",
		desc: "Builds a relational graph linking Domains -> IPs -> Services -> Vulnerabilities.",
	}
}

func (k *KnowledgeGraphAgent) Name() string        { return k.name }
func (k *KnowledgeGraphAgent) Description() string  { return k.desc }

func (k *KnowledgeGraphAgent) Execute(state *core.SwarmState) error {
	state.Section("KNOWLEDGE GRAPH PHASE")
	state.Log(k.Name(), "START", "Constructing the Relational Knowledge Graph...")

	state.Mu.RLock()
	domain := state.Target.PrimaryDomain
	subdomains := state.ReconData.Subdomains
	services := state.Discovered
	vulns := state.Vulns
	state.Mu.RUnlock()

	start := time.Now()
	var graph []string

	for _, sub := range subdomains {
		graph = append(graph, fmt.Sprintf("\"%s\" -> \"%s\" [label=\"HAS_SUBDOMAIN\"]", domain, sub))
	}
	for _, svc := range services {
		graph = append(graph, fmt.Sprintf("\"%s\" -> \"%s:%d\" [label=\"HOSTS\"]", svc.IP, svc.IP, svc.Port))
		graph = append(graph, fmt.Sprintf("\"%s:%d\" -> \"%s\" [label=\"RUNS\"]", svc.IP, svc.Port, svc.Tech))
	}
	for _, v := range vulns {
		graph = append(graph, fmt.Sprintf("\"%s\" -> \"VULN:%s\" [label=\"AFFECTS\" color=\"red\"]", domain, v.ID))
	}

	state.StartSpinner(fmt.Sprintf("%sBuilding DOT graph with %d edges%s", core.Yellow, len(graph), core.Reset))
	time.Sleep(50 * time.Millisecond)

	dotContent := "digraph G {\n  rankdir=LR;\n  node [shape=box style=rounded];\n"
	for _, edge := range graph {
		dotContent += "  " + edge + ";\n"
	}
	dotContent += "}\n"

	graphDir := filepath.Join("data", "graphs")
	os.MkdirAll(graphDir, 0755)
	dotPath := filepath.Join(graphDir, fmt.Sprintf("%s.dot", state.SessionID))
	os.WriteFile(dotPath, []byte(dotContent), 0644)

	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(k.Name(), "RESULT", fmt.Sprintf("Graph written to %s with %d edges in %s", dotPath, len(graph), elapsed))
	return nil
}
