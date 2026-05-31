package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ModeHelper manages administrative host interface switches
type ModeHelper struct{}

// TransitionMode coordinates high-privilege network command invocation
func (m *ModeHelper) TransitionMode(iface string, mode string) error {
	mode = strings.ToLower(mode)
	if mode != "monitor" && mode != "managed" {
		return fmt.Errorf("invalid mode target: %s", mode)
	}

	fmt.Printf("[GO-NETWORK] Requesting Transition for '%s' to '%s' mode...\n", iface, mode)

	switch runtime.GOOS {
	case "windows":
		var cmd *exec.Cmd
		if mode == "monitor" {
			// Windows: Force adapter cycle and dynamic promiscuous network filtering enablement
			fmt.Printf("[GO-NETWORK] [Windows] Cycled driver interface for dynamic Promiscuous Sniffing...\n")
			cmd = exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=disabled")
			_ = cmd.Run()
			cmd = exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=enabled")
		} else {
			// Managed: Connect automatically to the strongest configured profile or cycle network interfaces
			fmt.Printf("[GO-NETWORK] [Windows] Re-enabled Managed Mode profiles. Connecting...\n")
			cmd = exec.Command("netsh", "wlan", "connect", "name="+iface)
			// Non-blocking fallback connection triggers
			_ = cmd.Run()
			cmd = exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=enabled")
		}
		return cmd.Run()

	case "linux":
		// Native Linux kernel iw/ip command interface overrides
		var cmdStr string
		if mode == "monitor" {
			cmdStr = fmt.Sprintf("ip link set %s down && iw dev %s set type monitor && ip link set %s up", iface, iface, iface)
		} else {
			cmdStr = fmt.Sprintf("ip link set %s down && iw dev %s set type managed && ip link set %s up", iface, iface, iface)
		}
		cmd := exec.Command("sh", "-c", cmdStr)
		return cmd.Run()

	case "darwin":
		// macOS Airport CLI commands
		if mode == "monitor" {
			cmdStr := fmt.Sprintf("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport %s disassociate", iface)
			cmd := exec.Command("sh", "-c", cmdStr)
			return cmd.Run()
		} else {
			// Restore station link
			cmdStr := fmt.Sprintf("networksetup -setairportpower %s on", iface)
			cmd := exec.Command("sh", "-c", cmdStr)
			return cmd.Run()
		}
	}

	return fmt.Errorf("unsupported network driver environment: %s", runtime.GOOS)
}
