package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Tactical Ruby Engine: Complex Protocol Analysis
func RubyScanProtocol(host string, port int) string {
	cmd := exec.Command("ruby", "../ruby/protocol_analyzer.rb", host, fmt.Sprintf("%d", port))
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

// Lua Execution Hub: Orchestrates multiple specialized tactical modules
func LuaRunTactical(host string, port int, moduleType string) string {
	scriptPath := "../lua/tactical_vuln.lua"
	switch moduleType {
	case "audit":
		scriptPath = "../lua/realtime_audit.lua"
	case "probe":
		scriptPath = "../lua/precision_probe.lua"
	case "exploit":
		scriptPath = "../lua/tactical_exploit.lua"
	}

	cmd := exec.Command("lua", scriptPath, host, fmt.Sprintf("%d", port))
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return ""
	}
	output := out.String()
	if strings.Contains(output, "RESULT: ") {
		parts := strings.Split(output, "RESULT: ")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

// Tactical C Core: Stealth Evasion Logic
func CRunTacticalEvasion(host string, port int, ttl int, mtu int) bool {
	// This would typically call the compiled c_evasion binary
	// For now, we simulate the execution check
	return true
}
