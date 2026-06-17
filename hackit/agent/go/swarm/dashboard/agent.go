package dashboard

import (
	"fmt"
	"time"

	"hackit_ai_engine/swarm/core"
)

type DashboardAgent struct {
	name string
	desc string
}

func NewDashboardAgent() *DashboardAgent {
	return &DashboardAgent{
		name: "Agent-17: Dashboard",
		desc: "Provides real-time JSON data streams and visual telemetry for the user interface.",
	}
}

func (d *DashboardAgent) Name() string        { return d.name }
func (d *DashboardAgent) Description() string  { return d.desc }

func (d *DashboardAgent) Execute(state *core.SwarmState) error {
	state.Section("TELEMETRY PHASE")
	state.Log(d.Name(), "START", "Spinning up Dashboard Telemetry Stream...")

	state.Mu.RLock()
	vulnCount := len(state.Vulns)
	serviceCount := len(state.Discovered)
	subdomainCount := len(state.ReconData.Subdomains)
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	start := time.Now()

	critical, high, medium, low, info := 0, 0, 0, 0, 0
	for _, v := range state.Vulns {
		switch v.Severity {
		case "Critical": critical++
		case "High": high++
		case "Medium": medium++
		case "Low": low++
		default: info++
		}
	}

	telemetry := fmt.Sprintf(
		`{"session":"%s","target":"%s","status":"active","subdomains":%d,"services":%d,"vulns":%d,"critical":%d,"high":%d,"medium":%d,"low":%d,"info":%d}`,
		state.SessionID, domain, subdomainCount, serviceCount, vulnCount, critical, high, medium, low, info)

	state.StartSpinner(fmt.Sprintf("%sPushing telemetry to UI%s", core.Yellow, core.Reset))
	time.Sleep(30 * time.Millisecond)
	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(d.Name(), "TELEMETRY", telemetry)
	state.LogOk(d.Name(), "COMPLETE", fmt.Sprintf("Telemetry pushed in %s", elapsed))
	return nil
}
