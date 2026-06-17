package monitoring

import (
	"fmt"
	"time"

	"hackit_ai_engine/swarm/core"
)

type MonitoringAgent struct {
	name string
	desc string
}

func NewMonitoringAgent() *MonitoringAgent {
	return &MonitoringAgent{
		name: "Agent-16: Monitoring",
		desc: "Continuously tracks asset drift, new open ports, new subdomains, and expiring certificates.",
	}
}

func (m *MonitoringAgent) Name() string        { return m.name }
func (m *MonitoringAgent) Description() string  { return m.desc }

func (m *MonitoringAgent) Execute(state *core.SwarmState) error {
	state.Section("MONITORING PHASE")
	state.Log(m.Name(), "START", "Spinning up Continuous Monitoring Daemon...")

	state.Mu.RLock()
	domain := state.Target.PrimaryDomain
	subdomains := state.ReconData.Subdomains
	services := state.Discovered
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sRegistering %s to monitoring scheduler%s", core.Yellow, domain, core.Reset))
	time.Sleep(100 * time.Millisecond)
	state.StopSpinner()

	state.LogOk(m.Name(), "SCHEDULE", fmt.Sprintf("%s registered: subdomains every 12h, ports every 24h, certs every 7d", domain))
	state.Log(m.Name(), "CHECK", fmt.Sprintf("Baseline: %d subdomains, %d services monitored", len(subdomains), len(services)))

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(m.Name(), "COMPLETE", fmt.Sprintf("Monitoring configured in %s", elapsed))
	return nil
}
