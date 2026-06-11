package discovery

import (
	"fmt"
	"time"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

// DiscoveryAgent is Node 3 in the 20-Node Autonomous Swarm
// Responsible for probing the attack surface identified by Recon Agent.
type DiscoveryAgent struct{}

func NewDiscoveryAgent() *DiscoveryAgent {
	return &DiscoveryAgent{}
}

func (d *DiscoveryAgent) Name() string {
	return "Agent-3: Discovery"
}

func (d *DiscoveryAgent) Description() string {
	return "Identifies active hosts, running services, and open ports across the reconnaissance surface."
}

func (d *DiscoveryAgent) Execute(state *core.SwarmState) error {
	state.Log(d.Name(), "START", "Commencing active surface discovery...")

	targets := state.ReconData.Subdomains
	if len(targets) == 0 {
		targets = append(targets, state.Target.PrimaryDomain)
		state.Log(d.Name(), "WARN", "No subdomains in state. Falling back to primary domain only.")
	}

	state.Log(d.Name(), "TASK", fmt.Sprintf("Triggering High-Speed Port Scanner on %d targets", len(targets)))

	// Check Rules of Engagement for constraints
	aggressive := false
	for _, rule := range state.Target.Rules {
		if rule == "FULL_BRUTEFORCE_ALLOWED" || rule == "HIGH_THREAD_CONCURRENCY" {
			aggressive = true
			break
		}
	}

	var concurrency int
	var timeout time.Duration
	var targetPorts []int

	if aggressive {
		state.Log(d.Name(), "MODE", "Running in aggressive full-port mode (1-65535, 1000 threads)")
		concurrency = 1000
		timeout = 500 * time.Millisecond
		// Build 1-65535 slice
		for i := 1; i <= 65535; i++ {
			targetPorts = append(targetPorts, i)
		}
	} else {
		state.Log(d.Name(), "MODE", "Running in active_stealth top-1000 mode (50 threads, 2000ms delay)")
		concurrency = 50
		timeout = 2000 * time.Millisecond
		targetPorts = native.TopPorts
	}

	var discovered []core.Service

	// Scan sequentially across targets (native port scanner handles deep concurrency internally)
	for _, t := range targets {
		state.Log(d.Name(), "SCAN", fmt.Sprintf("Scanning %s...", t))

		results := native.ScanPorts(t, targetPorts, concurrency, timeout)

		for _, res := range results {
			discovered = append(discovered, core.Service{
				IP:       t,
				Port:     res.Port,
				Protocol: "tcp",
				Tech:     res.Service, // Initial guess
				Banner:   res.Banner,
			})
		}
	}

	// Commit discovered services to global Swarm State
	state.Mu.Lock()
	state.Discovered = append(state.Discovered, discovered...)
	state.Mu.Unlock()

	state.Log(d.Name(), "DISCOVERY", fmt.Sprintf("Successfully mapped %d open services across the surface", len(discovered)))
	state.Log(d.Name(), "COMPLETE", "Surface mapping complete. Handing over to Agent-4: Fingerprint.")

	return nil
}
