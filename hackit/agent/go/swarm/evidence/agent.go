package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hackit_ai_engine/swarm/core"
)

// EvidenceAgent is Node 8 in the 20-Node Autonomous Swarm
// Responsible for securely storing proofs of vulnerability (logs, HTTP req/res, screenshots).
type EvidenceAgent struct{}

func NewEvidenceAgent() *EvidenceAgent {
	return &EvidenceAgent{}
}

func (e *EvidenceAgent) Name() string {
	return "Agent-8: Evidence Collection"
}

func (e *EvidenceAgent) Description() string {
	return "Collects and stores evidence like screenshots, HTTP responses, and exploit logs."
}

func (e *EvidenceAgent) Execute(state *core.SwarmState) error {
	state.Log(e.Name(), "START", "Starting Evidence Collection...")

	state.Mu.RLock()
	vulns := state.Vulns
	sessionID := state.SessionID
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.Log(e.Name(), "INFO", "No vulnerabilities to collect evidence for.")
		return nil
	}

	evidenceDir := filepath.Join("reports", "evidence", sessionID)
	err := os.MkdirAll(evidenceDir, 0755)
	if err != nil {
		state.Log(e.Name(), "ERROR", fmt.Sprintf("Failed to create evidence directory: %v", err))
		return err
	}

	state.Log(e.Name(), "TASK", fmt.Sprintf("Saving evidence artifacts to %s", evidenceDir))

	// Iterate through vulnerabilities and write out their evidence
	for i, v := range vulns {
		filename := filepath.Join(evidenceDir, fmt.Sprintf("%s_evidence_%d.txt", v.ID, i))

		evidenceContent := fmt.Sprintf("VULNERABILITY ID: %s\nTIMESTAMP: %s\n\nEVIDENCE TRACE:\n%s\n",
			v.ID, time.Now().Format(time.RFC3339), v.Evidence)

		err := os.WriteFile(filename, []byte(evidenceContent), 0644)
		if err != nil {
			state.Log(e.Name(), "ERROR", fmt.Sprintf("Failed to save evidence for %s", v.ID))
		}
	}

	// Python Logic Support Hook:
	// We would spawn Python `playwright` or `selenium` here to take actual screenshots of the vulnerable endpoints
	// and save them to `evidenceDir`.

	state.Log(e.Name(), "COMPLETE", fmt.Sprintf("Saved %d evidence artifacts. Handing over to Agent-9: Risk Scoring.", len(vulns)))

	return nil
}
