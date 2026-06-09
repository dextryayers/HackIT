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

// LuaRunTactical is now defined in lua_engine.go — removed from here to avoid redeclaration.

// Tactical C Core: Stealth Evasion Logic
func CRunTacticalEvasion(host string, port int, ttl int, mtu int) bool {
	// This would typically call the compiled c_evasion binary
	return true
}
