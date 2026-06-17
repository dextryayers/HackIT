package mcp_integration

import (
	"fmt"
	"os/exec"
	"time"

	"hackit_ai_engine/swarm/core"
)

type MCPIntegrationAgent struct {
	name string
	desc string
}

func NewMCPIntegrationAgent() *MCPIntegrationAgent {
	return &MCPIntegrationAgent{
		name: "Agent-28: MCP and Tool Orchestration",
		desc: "Orchestrates external security tools (Nmap, Amass, Katana, Nuclei, ffuf, gospider) using the Model Context Protocol.",
	}
}

func (a *MCPIntegrationAgent) Name() string        { return a.name }
func (a *MCPIntegrationAgent) Description() string  { return a.desc }

func (a *MCPIntegrationAgent) Execute(state *core.SwarmState) error {
	state.Section("MCP AND TOOL ORCHESTRATION PHASE")
	state.Log(a.Name(), "START", "Spinning up external tool orchestration via MCP...")

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sProbing for external security tools%s", core.Yellow, core.Reset))
	time.Sleep(80 * time.Millisecond)

	tools := []struct {
		name    string
		binary  string
		args    []string
		handler func(string, string)
	}{
		{"Katana", "katana", []string{"-u", state.Target.PrimaryDomain, "-jc", "-jsonl", "-silent", "-depth", "2"},
			func(out, name string) {
				state.Mu.Lock()
				state.ContextData[name+"_raw"] = out
				state.Mu.Unlock()
				state.LogOk(a.Name(), name, fmt.Sprintf("%s output captured (%d bytes)", name, len(out)))
			}},
		{"Nuclei", "nuclei", []string{"-u", state.Target.PrimaryDomain, "-silent", "-json", "-nc", "-t", "~/.nuclei-templates/cves/"},
			func(out, name string) {
				state.Mu.Lock()
				state.ContextData[name+"_raw"] = out
				state.Mu.Unlock()
				state.LogOk(a.Name(), name, fmt.Sprintf("%s scan complete (%d bytes)", name, len(out)))
			}},
		{"Amass", "amass", []string{"enum", "-passive", "-d", state.Target.PrimaryDomain, "-json", "/tmp/amass_" + state.SessionID + ".json"},
			func(out, name string) {
				state.Mu.Lock()
				state.ContextData[name+"_raw"] = out
				state.Mu.Unlock()
				state.LogOk(a.Name(), name, fmt.Sprintf("%s passive enum complete", name))
			}},
		{"ffuf", "ffuf", []string{"-u", fmt.Sprintf("https://%s/FUZZ", state.Target.PrimaryDomain), "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50", "-of", "json", "-o", fmt.Sprintf("/tmp/ffuf_%s.json", state.SessionID)},
			func(out, name string) {
				state.Mu.Lock()
				state.ContextData[name+"_raw"] = out
				state.Mu.Unlock()
				state.LogOk(a.Name(), name, fmt.Sprintf("%s directory fuzz complete", name))
			}},
		{"gospider", "gospider", []string{"-s", fmt.Sprintf("https://%s", state.Target.PrimaryDomain), "-o", fmt.Sprintf("/tmp/gospider_%s", state.SessionID), "-c", "10", "-d", "2"},
			func(out, name string) {
				state.Mu.Lock()
				state.ContextData[name+"_raw"] = out
				state.Mu.Unlock()
				state.LogOk(a.Name(), name, fmt.Sprintf("%s spider complete", name))
			}},
		{"Nmap", "nmap", []string{"-T4", "-sV", "-F", state.Target.PrimaryDomain, "-oX", fmt.Sprintf("/tmp/nmap_%s.xml", state.SessionID)},
			func(out, name string) {
				state.Mu.Lock()
				state.ContextData[name+"_raw"] = out
				state.Mu.Unlock()
				state.LogOk(a.Name(), name, fmt.Sprintf("%s fast scan complete", name))
			}},
	}

	running := 0
	foundCount := 0
	for _, tool := range tools {
		toolPath, err := exec.LookPath(tool.binary)
		if err == nil {
			foundCount++
			state.Log(a.Name(), "FOUND", fmt.Sprintf("%s at %s", tool.name, toolPath))
			cmd := exec.Command(toolPath, tool.args...)
			output, err := cmd.CombinedOutput()
			if err == nil {
				tool.handler(string(output), tool.name)
				running++
			} else {
				state.LogWarn(a.Name(), tool.name, fmt.Sprintf("execution error: %v", err))
			}
		} else {
			state.Log(a.Name(), "MISSING", fmt.Sprintf("%s not in PATH", tool.name))
		}
	}

	state.StopSpinner()

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Found %d/%d tools, executed %d successfully in %s",
		foundCount, len(tools), running, elapsed))
	return nil
}
