package dashboard

import (
	"fmt"
	"hackit_ai_engine/swarm/core"
)

// DashboardAgent is Node 17 in the 20-Node Autonomous Swarm
// Responsible for bridging the backend Swarm data stream to the WebUI frontend.
type DashboardAgent struct{}

func NewDashboardAgent() *DashboardAgent {
	return &DashboardAgent{}
}

func (d *DashboardAgent) Name() string {
	return "Agent-17: Dashboard"
}

func (d *DashboardAgent) Description() string {
	return "Provides real-time JSON data streams and visual telemetry for the user interface."
}

func (d *DashboardAgent) Execute(state *core.SwarmState) error {
	state.Log(d.Name(), "START", "Spinning up Dashboard Telemetry Stream...")

	state.Mu.RLock()
	vulnCount := len(state.Vulns)
	serviceCount := len(state.Discovered)
	state.Mu.RUnlock()

	// Mocking WebSocket/JSON stream push to UI
	state.Log(d.Name(), "TASK", "Pushing real-time statistics to UI websocket buffer...")

	telemetryData := fmt.Sprintf("{ \"session\": \"%s\", \"status\": \"ACTIVE\", \"vulns\": %d, \"assets\": %d }", state.SessionID, vulnCount, serviceCount)
	state.Log(d.Name(), "TELEMETRY", telemetryData)

	state.Log(d.Name(), "COMPLETE", "Telemetry stream active. Handing over to Agent-18: Log Analysis.")

	return nil
}
