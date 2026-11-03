package poc_generator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type PoCGeneratorAgent struct {
	name string
	desc string
}

func NewPoCGeneratorAgent() *PoCGeneratorAgent {
	return &PoCGeneratorAgent{
		name: "Agent-22: AI PoC Generator",
		desc: "Generates fully runnable Proof of Concept (PoC) scripts (Python/Bash/Curl) to verify and reproduce findings.",
	}
}

func (a *PoCGeneratorAgent) Name() string        { return a.name }
func (a *PoCGeneratorAgent) Description() string  { return a.desc }

func (a *PoCGeneratorAgent) Execute(state *core.SwarmState) error {
	state.Section("POC GENERATION PHASE")
	state.Log(a.Name(), "START", "Compiling actionable Proof of Concept scripts...")

	state.Mu.RLock()
	vulns := state.Vulns
	domain := state.Target.PrimaryDomain
	state.Mu.RUnlock()

	if len(vulns) == 0 {
		state.LogWarn(a.Name(), "WARN", "No vulns to generate PoCs for")
		return nil
	}

	start := time.Now()
	pocDir := filepath.Join("reports", "pocs", state.SessionID)
	os.MkdirAll(pocDir, 0755)

	state.StartSpinner(fmt.Sprintf("%sGenerating PoC scripts for %d vulnerabilities%s", core.Yellow, len(vulns), core.Reset))
	time.Sleep(80 * time.Millisecond)

	count := 0
	for _, v := range vulns {
		if v.Reproduce == "" {
			continue // only verified findings carry a real command
		}
		filename := fmt.Sprintf("poc_%s.sh", strings.ToLower(strings.ReplaceAll(v.ID, "/", "_")))
		poc := fmt.Sprintf(`#!/bin/bash
# PoC: %s (%s)  CVSS %.1f
# Target: %s
# Verified evidence: %s
# Remediation: %s
set -u
%s
`, v.Name, v.ID, v.CVSS, domain, v.Evidence, v.Remediation, v.Reproduce)
		pocPath := filepath.Join(pocDir, filename)
		os.WriteFile(pocPath, []byte(poc), 0755)
		count++
	}

	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Generated %d PoC scripts in %s in %s", count, pocDir, elapsed))
	return nil
}
