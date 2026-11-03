package discovery

import (
	"fmt"
	"sync"
	"time"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

// hostParallelism keeps total socket usage bounded: each host runs its own
// worker pool, so hosts x concurrency must stay within fd/ulimit limits.
func hostParallelism(hosts int) int {
	n := hosts
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

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
		// IP / CIDR / local targets carry concrete seeds; domain targets fall
		// back to the primary host.
		parsed := state.Target.Parsed
		if len(parsed.ScanSeeds) > 0 {
			targets = append(targets, parsed.ScanSeeds...)
		} else {
			targets = append(targets, state.Target.PrimaryDomain)
		}
		state.LogWarn(d.Name(), "FALLBACK", fmt.Sprintf("No recon seeds in state. Using %d direct target(s).", len(targets)))
	}

	aggressive, passive := false, false
	for _, rule := range state.Target.Rules {
		switch rule {
		case "FULL_BRUTEFORCE_ALLOWED", "HIGH_THREAD_CONCURRENCY", "FULL_PORT_SCAN":
			aggressive = true
		case "LIGHT_PORT_SCAN":
			passive = true
		}
	}

	var concurrency int
	var timeout time.Duration
	var targetPorts []int
	switch {
	case aggressive:
		state.LogWarn(d.Name(), "MODE", "Full port scan 1-65535, 1000 threads")
		concurrency = 1000
		timeout = 500 * time.Millisecond
		for i := 1; i <= 65535; i++ {
			targetPorts = append(targetPorts, i)
		}
	case passive:
		// Passive must stay low-rate: top-1000 x 29 hosts x 2s would run for many minutes.
		state.Log(d.Name(), "MODE", "Passive: top-100 ports, 20 threads, 1500ms timeout")
		concurrency = 20
		timeout = 1500 * time.Millisecond
		targetPorts = append([]int(nil), native.TopPorts...)
	default:
		state.Log(d.Name(), "MODE", "Top-1000 ports, 50 threads, 2000ms timeout")
		concurrency = 50
		timeout = 2000 * time.Millisecond
		targetPorts = make([]int, len(native.TopPorts))
		copy(targetPorts, native.TopPorts)
	}

	start := time.Now()
	var discovered []core.Service

	state.StartSpinner(fmt.Sprintf("%sScanning %d targets [%d ports each, %d hosts in parallel]%s",
		core.Yellow, len(targets), len(targetPorts), hostParallelism(len(targets)), core.Reset))

	// Scan hosts concurrently: a domain target resolves to dozens of subdomains
	// and scanning them one by one was the main source of multi-minute stalls.
	type scanResult struct {
		host string
		open []native.PortResult
	}
	workers := hostParallelism(len(targets))
	jobs := make(chan string)
	results := make(chan scanResult, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				results <- scanResult{host: host, open: native.ScanPorts(host, targetPorts, concurrency, timeout)}
			}
		}()
	}
	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		for _, r := range res.open {
			discovered = append(discovered, core.Service{
				IP:       res.host,
				Port:     r.Port,
				Protocol: "tcp",
				Tech:     r.Service,
				Banner:   r.Banner,
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
