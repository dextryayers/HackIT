package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ModeHelper manages administrative host interface switches
type ModeHelper struct{}

func sudoPrefix() string {
	out, err := exec.Command("id", "-u").Output()
	if err != nil {
		return ""
	}
	if strings.TrimSpace(string(out)) != "0" {
		return "sudo "
	}
	return ""
}

// TransitionMode coordinates high-privilege network command invocation
func (m *ModeHelper) TransitionMode(iface string, mode string) error {
	mode = strings.ToLower(mode)
	if mode != "monitor" && mode != "managed" {
		return fmt.Errorf("invalid mode target: %s", mode)
	}

	fmt.Printf("[GO-NETWORK] Requesting Transition for '%s' to '%s' mode...\n", iface, mode)
	sudo := sudoPrefix()

	switch runtime.GOOS {
	case "linux":
		return modeSwitchLinux(iface, mode, sudo)
	case "darwin":
		return modeSwitchMacOS(iface, mode, sudo)
	case "windows":
		return modeSwitchWindows(iface, mode)
	}

	return fmt.Errorf("unsupported network driver environment: %s", runtime.GOOS)
}

func modeSwitchLinux(iface, mode, sudo string) error {
	var cmdStr string

	if mode == "monitor" {
		// Kill interfering processes
		fmt.Printf("[GO-NETWORK] [Linux] Killing interfering processes...\n")
		exec.Command("sh", "-c", sudo+"systemctl stop NetworkManager wpa_supplicant avahi-daemon 2>/dev/null").Run()
		exec.Command("sh", "-c", sudo+"airmon-ng check kill 2>/dev/null").Run()

		// Try airmon-ng first
		if exec.Command("sh", "-c", "which airmon-ng 2>/dev/null").Run() == nil {
			fmt.Printf("[GO-NETWORK] [Linux] Trying airmon-ng...\n")
			exec.Command("sh", "-c", sudo+"airmon-ng start "+iface+" 2>/dev/null").Run()
			time.Sleep(500 * time.Millisecond)
			monIface := iface + "mon"
			if exec.Command("sh", "-c", "iw dev "+monIface+" info 2>/dev/null | grep -q 'type monitor'").Run() == nil {
				fmt.Printf("[GO-NETWORK] [Linux] %s → %smon (airmon-ng)\n", iface, iface)
				return nil
			}
			fmt.Printf("[GO-NETWORK] [Linux] airmon-ng failed, falling back to iw...\n")
		}

		// iw fallback
		cmdStr = fmt.Sprintf("%sip link set %s down && %siw dev %s set type monitor && %sip link set %s up",
			sudo, iface, sudo, iface, sudo, iface)
	} else {
		// managed: stop airmon-ng, restore interface
		exec.Command("sh", "-c", sudo+"airmon-ng stop "+iface+" 2>/dev/null").Run()
		exec.Command("sh", "-c", sudo+"airmon-ng stop "+iface+"mon 2>/dev/null").Run()
		cmdStr = fmt.Sprintf("%sip link set %s down && %siw dev %s set type managed && %sip link set %s up",
			sudo, iface, sudo, iface, sudo, iface)
	}

	out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mode switch failed: %s - %s", err, string(out))
	}

	// Verify
	verifyCmd := exec.Command("sh", "-c", fmt.Sprintf("iw dev %s info 2>&1 | grep 'type %s'", iface, mode))
	if verifyOut, _ := verifyCmd.Output(); len(verifyOut) > 0 {
		fmt.Printf("[GO-NETWORK] [Linux] %s → %s (verified)\n", iface, mode)
	} else {
		fmt.Printf("[GO-NETWORK] [Linux] %s → %s (unverified)\n", iface, mode)
	}

	if mode == "managed" {
		exec.Command("sh", "-c", sudo+"systemctl restart NetworkManager wpa_supplicant 2>/dev/null").Run()
	}
	return nil
}

func modeSwitchMacOS(iface, mode, sudo string) error {
	if mode == "monitor" {
		fmt.Printf("[GO-NETWORK] [macOS] Switching %s to monitor mode...\n", iface)
		// Disassociate
		exec.Command("sh", "-c",
			"/System/Library/PrivateFrameworks/Apple80211.framework/"+
				"Versions/Current/Resources/airport -z 2>/dev/null").Run()
		// Reset interface
		exec.Command("sh", "-c", fmt.Sprintf("ifconfig %s down && ifconfig %s up", iface, iface)).Run()
		// Enable sniff/monitor via airport
		exec.Command("sh", "-c",
			fmt.Sprintf("/System/Library/PrivateFrameworks/Apple80211.framework/"+
				"Versions/Current/Resources/airport %s sniff 1 2>/dev/null &", iface)).Run()
		fmt.Printf("[GO-NETWORK] [macOS] %s → monitor mode\n", iface)
	} else {
		fmt.Printf("[GO-NETWORK] [macOS] Restoring managed mode for %s...\n", iface)
		exec.Command("sh", "-c", "pkill -f 'airport.*sniff' 2>/dev/null").Run()
		exec.Command("sh", "-c", fmt.Sprintf("networksetup -setairportpower %s on", iface)).Run()
		exec.Command("sh", "-c", fmt.Sprintf("ifconfig %s up", iface)).Run()
		fmt.Printf("[GO-NETWORK] [macOS] %s → managed\n", iface)
	}
	return nil
}

func modeSwitchWindows(iface, mode string) error {
	if mode == "monitor" {
		fmt.Printf("[GO-NETWORK] [Windows] Enabling promiscuous mode on %s...\n", iface)
		exec.Command("sh", "-c", fmt.Sprintf("netsh interface set interface name=\"%s\" admin=disabled", iface)).Run()
		time.Sleep(300 * time.Millisecond)
		exec.Command("sh", "-c",
			"reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\NDIS\\Parameters "+
				"/v AllowMonitorMode /t REG_DWORD /d 1 /f 2>nul").Run()
		exec.Command("sh", "-c", fmt.Sprintf("netsh interface set interface name=\"%s\" admin=enabled", iface)).Run()
		time.Sleep(300 * time.Millisecond)
		exec.Command("sh", "-c",
			fmt.Sprintf("netsh wlan set autoconfig enabled=no interface=\"%s\" 2>nul", iface)).Run()
		fmt.Printf("[GO-NETWORK] [Windows] %s → promiscuous mode\n", iface)
	} else {
		fmt.Printf("[GO-NETWORK] [Windows] Restoring managed mode for %s...\n", iface)
		exec.Command("sh", "-c",
			fmt.Sprintf("netsh wlan set autoconfig enabled=yes interface=\"%s\" 2>nul", iface)).Run()
		exec.Command("sh", "-c", "netsh wlan set allowexplicitcreds enabled 2>nul").Run()
		exec.Command("sh", "-c", fmt.Sprintf("netsh interface set interface name=\"%s\" admin=enabled", iface)).Run()
		fmt.Printf("[GO-NETWORK] [Windows] %s → managed\n", iface)
	}
	return nil
}
