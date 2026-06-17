package discovery

import (
	"fmt"
	"time"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

type DiscoveryAgent struct {
	name string
	desc string
}

func NewDiscoveryAgent() *DiscoveryAgent {
	return &DiscoveryAgent{
		name: "Agent-3: Discovery",
		desc: "Identifies active hosts, running services, and open ports across the reconnaissance surface.",
	}
}

func (d *DiscoveryAgent) Name() string        { return d.name }
func (d *DiscoveryAgent) Description() string  { return d.desc }

func (d *DiscoveryAgent) Execute(state *core.SwarmState) error {
	state.Section("DISCOVERY PHASE")
	state.Log(d.Name(), "START", "Commencing active surface discovery...")

	targets := state.ReconData.Subdomains
	if len(targets) == 0 {
		targets = append(targets, state.Target.PrimaryDomain)
		state.LogWarn(d.Name(), "FALLBACK", "No subdomains in state. Falling back to primary domain.")
	}

	aggressive := false
	for _, rule := range state.Target.Rules {
		if rule == "FULL_BRUTEFORCE_ALLOWED" || rule == "HIGH_THREAD_CONCURRENCY" || rule == "FULL_PORT_SCAN" {
			aggressive = true
			break
		}
	}

	var concurrency int
	var timeout time.Duration
	var targetPorts []int

	if aggressive {
		state.LogWarn(d.Name(), "MODE", "Full port scan 1-65535, 1000 threads")
		concurrency = 1000
		timeout = 500 * time.Millisecond
		for i := 1; i <= 65535; i++ {
			targetPorts = append(targetPorts, i)
		}
	} else {
		state.Log(d.Name(), "MODE", "Top-1000 ports, 50 threads, 2000ms timeout")
		concurrency = 50
		timeout = 2000 * time.Millisecond
		targetPorts = make([]int, len(native.TopPorts))
		copy(targetPorts, native.TopPorts)
	}

	start := time.Now()
	var discovered []core.Service

	state.StartSpinner(fmt.Sprintf("%sScanning %d targets [%d ports each]%s", core.Yellow, len(targets), len(targetPorts), core.Reset))

	for _, t := range targets {
		results := native.ScanPorts(t, targetPorts, concurrency, timeout)
		for _, res := range results {
			discovered = append(discovered, core.Service{
				IP:       t,
				Port:     res.Port,
				Protocol: "tcp",
				Tech:     res.Service,
				Banner:   res.Banner,
			})
		}
	}

	state.StopSpinner()

	state.Mu.Lock()
	state.Discovered = append(state.Discovered, discovered...)
	state.Mu.Unlock()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(d.Name(), "RESULT", fmt.Sprintf("Mapped %d open services across %d targets in %s", len(discovered), len(targets), elapsed))
	return nil
}
