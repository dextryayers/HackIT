package attack_chain

import (
	"fmt"
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

	portName := map[int]string{
		21: "FTP", 22: "SSH", 1433: "MSSQL", 3306: "MySQL",
		5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
	}
	isAppSurface := func(v core.Vulnerability) bool {
		return v.ID == "MISCONF-PHPINFO" || v.ID == "MISCONF-SWAGGER" || v.ID == "MISCONF-GRAPHQL" || v.ID == "EOL-PHP"
	}
	// Chains are hypotheses over verified findings only; each label states the
	// concrete pivot, never a generic "could lead to compromise".
	chainLabel := func(a, b core.Vulnerability) (string, bool) {
		remotePort := func(v core.Vulnerability) bool { return v.Port == 21 || v.Port == 22 }
		switch {
		case a.ID == "MISCONF-001" && portName[b.Port] != "":
			return fmt.Sprintf("leaked secrets -> exposed %s service", portName[b.Port]), true
		case b.ID == "MISCONF-001" && remotePort(a):
			return fmt.Sprintf("exposed %s + leaked secrets = direct account access", portName[a.Port]), true
		case a.ID == "MISCONF-FTP-ANON" && b.ID == "MISCONF-001" ||
			b.ID == "MISCONF-FTP-ANON" && a.ID == "MISCONF-001":
			return "anonymous ftp -> app secrets downloadable", true
		case a.ID == "MISCONF-002" && isAppSurface(b) || b.ID == "MISCONF-002" && isAppSurface(a):
			return "source disclosure -> documented attack surface targets it directly", true
		}
		return "", false
	}

	for _, v := range vulns {
		nodes[v.ID] = node{id: v.ID, name: v.Name, port: v.Port}
	}
	for i, v1 := range vulns {
		for j, v2 := range vulns {
			if i >= j {
				continue
			}
			if label, ok := chainLabel(v1, v2); ok {
				edges = append(edges, edge{from: v1.ID, to: v2.ID, label: label})
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
			// Guard: ContextData values cross agent boundaries untyped.
			switch v := existing.(type) {
			case []string:
				allChains = v
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						allChains = append(allChains, s)
					}
				}
			}
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
