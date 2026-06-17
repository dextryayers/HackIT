package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hackit_ai_engine/swarm/core"
)

type EvidenceAgent struct {
	name string
	desc string
}

func NewEvidenceAgent() *EvidenceAgent {
	return &EvidenceAgent{
		name: "Agent-8: Evidence Collection",
		desc: "Collects and stores evidence like screenshots, HTTP responses, and exploit logs.",
	}
}

func (e *EvidenceAgent) Name() string        { return e.name }
func (e *EvidenceAgent) Description() string  { return e.desc }

func (e *EvidenceAgent) Execute(state *core.SwarmState) error {
	state.Section("EVIDENCE COLLECTION PHASE")
	state.Log(e.Name(), "START", "Starting Evidence Collection...")

	state.Mu.RLock()
	vulns := state.Vulns
	sessionID := state.SessionID
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.LogWarn(e.Name(), "WARN", "No vulnerabilities to collect evidence for.")
		return nil
	}

	start := time.Now()
	evidenceDir := filepath.Join("reports", "evidence", sessionID)
	err := os.MkdirAll(evidenceDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create evidence dir: %w", err)
	}

	state.StartSpinner(fmt.Sprintf("%sSaving %d evidence artifacts%s", core.Yellow, len(vulns), core.Reset))

	for i, v := range vulns {
		filename := filepath.Join(evidenceDir, fmt.Sprintf("%s_evidence_%d.txt", v.ID, i))
		content := fmt.Sprintf("VULNERABILITY ID: %s\nNAME: %s\nSEVERITY: %s\nCVSS: %.1f\nTIMESTAMP: %s\nEVIDENCE:\n%s\n",
			v.ID, v.Name, v.Severity, v.CVSS, time.Now().Format(time.RFC3339), v.Evidence)
		os.WriteFile(filename, []byte(content), 0644)
	}

	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(e.Name(), "RESULT", fmt.Sprintf("Saved %d evidence artifacts to %s in %s", len(vulns), evidenceDir, elapsed))
	return nil
}
