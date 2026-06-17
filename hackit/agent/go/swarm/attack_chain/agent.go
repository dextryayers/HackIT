package attack_chain

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type AttackChainAgent struct {
	name string
	desc string
}

func NewAttackChainAgent() *AttackChainAgent {
	return &AttackChainAgent{
		name: "Agent-26: Attack Chain Builder",
		desc: "Analyzes relationship graphs between disjoint vulnerabilities to model multi-stage attack scenarios.",
	}
}

func (a *AttackChainAgent) Name() string        { return a.name }
func (a *AttackChainAgent) Description() string  { return a.desc }

func (a *AttackChainAgent) Execute(state *core.SwarmState) error {
	state.Section("ATTACK CHAIN BUILDING PHASE")
	state.Log(a.Name(), "START", "Building vulnerability attack graphs...")

	state.Mu.RLock()
	vulns := state.Vulns
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	if len(vulns) < 2 {
		state.LogWarn(a.Name(), "WARN", fmt.Sprintf("Need 2+ vulns to build attack chains (have %d)", len(vulns)))
		return nil
	}

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sCorrelating %d vulns into attack chains%s", core.Yellow, len(vulns), core.Reset))
	time.Sleep(80 * time.Millisecond)

	type node struct {
		id     string
		name   string
		port   int
	}
	type edge struct {
		from   string
		to     string
		label  string
	}

	nodes := map[string]node{}
	var edges []edge

	for _, v := range vulns {
		nodes[v.ID] = node{id: v.ID, name: v.Name, port: v.Port}
	}
	for i, v1 := range vulns {
		for j, v2 := range vulns {
			if i >= j {
				continue
			}
			if v1.ID == "MISCONF-001" && (strings.Contains(v2.ID, "CVE-2023") || strings.Contains(v2.Name, "CMS")) {
				edges = append(edges, edge{from: v1.ID, to: v2.ID, label: "credential access -> app compromise"})
			}
			if v1.ID == "MISCONF-002" && v2.Port == 3306 {
				edges = append(edges, edge{from: v1.ID, to: v2.ID, label: "source leak -> db access"})
			}
			if v1.Port == 6379 && (strings.Contains(v2.ID, "CVE-2022")) {
				edges = append(edges, edge{from: v1.ID, to: v2.ID, label: "redis exposed -> rce"})
			}
			if (v1.Port == 22 || v1.Port == 21) && v2.ID == "MISCONF-001" {
				edges = append(edges, edge{from: v1.ID, to: v2.ID, label: "ssh/ftp + .env = full compromise"})
			}
		}
	}

	var chains []string
	seen := map[string]bool{}
	for _, e := range edges {
		chain := fmt.Sprintf("[%s] %s -> [%s] %s (%s)", e.from, nodes[e.from].name, e.to, nodes[e.to].name, e.label)
		if !seen[chain] {
			seen[chain] = true
			chains = append(chains, chain)
		}
	}

	state.StopSpinner()

	state.Mu.Lock()
	if len(chains) > 0 {
		existing, ok := state.ContextData["attack_chains"]
		var allChains []string
		if ok {
			allChains = existing.([]string)
		}
		allChains = append(allChains, chains...)
		state.ContextData["attack_chains"] = allChains
	}
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Built %d attack chains from %d vulns on %s in %s",
		len(chains), len(vulns), domain, elapsed))
	return nil
}
