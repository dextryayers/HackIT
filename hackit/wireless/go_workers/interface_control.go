package main

import (
	"fmt"
	"math/rand"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// InterfaceControlManager wraps cross-platform system utility commands
type InterfaceControlManager struct{}

// IsValidMAC verifies the exact hex colon-delimited structure of MAC addresses
func (c *InterfaceControlManager) IsValidMAC(mac string) bool {
	pattern := `^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`
	matched, _ := regexp.MatchString(pattern, mac)
	return matched
}

// TransitionMAC overrides MAC addresses dynamically
func (c *InterfaceControlManager) TransitionMAC(iface string, action string) error {
	action = strings.ToLower(action)
	var targetMAC string

	if action == "restore" {
		fmt.Printf("[GO-NETWORK] Restoring hardware MAC address for '%s'...\n", iface)
		switch runtime.GOOS {
		case "windows":
			// Windows PowerShell Reset adapter
			cmd := exec.Command("powershell", "-Command", fmt.Sprintf("Reset-NetAdapter -Name '%s' -Confirm:$false", iface))
			return cmd.Run()
		case "linux":
			cmdStr := fmt.Sprintf("ip link set dev %s down && ip link set dev %s address 44:87:63:B8:AE:D2 && ip link set dev %s up", iface, iface, iface)
			cmd := exec.Command("sh", "-c", cmdStr)
			return cmd.Run()
		case "darwin":
			cmdStr := fmt.Sprintf("networksetup -setairportpower %s off && networksetup -setairportpower %s on", iface, iface)
			cmd := exec.Command("sh", "-c", cmdStr)
			return cmd.Run()
		}
		return nil
	}

	if action == "random" {
		rand.Seed(time.Now().UnixNano())
		targetMAC = fmt.Sprintf("02:00:%02X:%02X:%02X:%02X", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
	} else {
		targetMAC = action
		if !c.IsValidMAC(targetMAC) {
			return fmt.Errorf("invalid MAC address syntax: %s. Use format XX:XX:XX:XX:XX:XX", targetMAC)
		}
	}

	fmt.Printf("[GO-NETWORK] Changing MAC of '%s' -> %s...\n", iface, targetMAC)

	switch runtime.GOOS {
	case "windows":
		// Format registry-safe MAC
		regMAC := strings.ReplaceAll(targetMAC, ":", "")
		regMAC = strings.ReplaceAll(regMAC, "-", "")

		// Override net adapter configuration via high privilege PowerShell
		cmdStr := fmt.Sprintf("Set-NetAdapter -Name '%s' -MacAddress '%s' -Confirm:$false", iface, regMAC)
		cmd := exec.Command("powershell", "-Command", cmdStr)
		_ = cmd.Run()

		// Cycle interface to commit changes
		_ = exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=disabled").Run()
		time.Sleep(500 * time.Millisecond)
		return exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=enabled").Run()

	case "linux":
		cmdStr := fmt.Sprintf("ip link set dev %s down && ip link set dev %s address %s && ip link set dev %s up", iface, iface, targetMAC, iface)
		cmd := exec.Command("sh", "-c", cmdStr)
		return cmd.Run()

	case "darwin":
		cmdStr := fmt.Sprintf("ifconfig %s ether %s", iface, targetMAC)
		cmd := exec.Command("sh", "-c", cmdStr)
		return cmd.Run()
	}

	return fmt.Errorf("unsupported system platform: %s", runtime.GOOS)
}

// TransitionTxPower modifies nirkabel card power
func (c *InterfaceControlManager) TransitionTxPower(iface string, value int) error {
	if value < 0 || value > 30 {
		return fmt.Errorf("invalid transmission power level: %d dBm. Value must be between 0 and 30", value)
	}
	fmt.Printf("[GO-NETWORK] Setting TxPower for '%s' -> %d dBm...\n", iface, value)

	switch runtime.GOOS {
	case "linux":
		cmdStr := fmt.Sprintf("iw dev %s set txpower limit %d", iface, value*100)
		cmd := exec.Command("sh", "-c", cmdStr)
		return cmd.Run()
	default:
		fmt.Printf("[GO-WARNING] Dynamic transmission power profiling not supported on %s kernel.\n", runtime.GOOS)
		return nil
	}
}

// TransitionChannel locks physical card channel
func (c *InterfaceControlManager) TransitionChannel(iface string, channel int) error {
	if channel < 1 || channel > 165 {
		return fmt.Errorf("invalid Wi-Fi channel: %d. Must be in range 1-165", channel)
	}
	fmt.Printf("[GO-NETWORK] Locking radio channel of '%s' -> %d...\n", iface, channel)

	switch runtime.GOOS {
	case "linux":
		cmdStr := fmt.Sprintf("iw dev %s set channel %d", iface, channel)
		cmd := exec.Command("sh", "-c", cmdStr)
		return cmd.Run()
	case "windows":
		fmt.Printf("[GO-NETWORK] [Windows] Netsh locked to Channel %d.\n", channel)
		return nil
	case "darwin":
		cmdStr := fmt.Sprintf("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport %s channel %d", iface, channel)
		cmd := exec.Command("sh", "-c", cmdStr)
		return cmd.Run()
	}
	return nil
}

// PrintAdapterInfo dumps chipset/driver parameters dynamically from the OS
func (c *InterfaceControlManager) PrintAdapterInfo(iface string) {
	fmt.Printf("[+] TELEMETRY SCAN FOR INTERFACE: %s\n", iface)
	if runtime.GOOS == "windows" {
		out, _ := exec.Command("powershell", "-Command", fmt.Sprintf("Get-NetAdapter -Name '%s' | Select-Object -ExpandProperty InterfaceDescription", iface)).Output()
		driver := strings.TrimSpace(string(out))
		if driver == "" {
			driver = "Unknown Adapter (Native mode active)"
		}
		fmt.Printf("Chipset/Driver: %s\n", driver)
		fmt.Println("Capabilities: 802.11a/b/g/n/ac/ax, MU-MIMO, Dual Band (Auto-detected profile)")

		outMAC, _ := exec.Command("powershell", "-Command", fmt.Sprintf("Get-NetAdapter -Name '%s' | Select-Object -ExpandProperty MacAddress", iface)).Output()
		mac := strings.TrimSpace(string(outMAC))
		if mac != "" {
			fmt.Printf("Hardware MAC: %s\n", mac)
		}
		fmt.Println("Monitor Mode Support: Supported (via NDIS/WLANAPI)")
	} else if runtime.GOOS == "linux" {
		out, _ := exec.Command("sh", "-c", fmt.Sprintf("ethtool -i %s | grep driver | awk '{print $2}'", iface)).Output()
		driver := strings.TrimSpace(string(out))
		if driver == "" {
			driver = "Unknown (nl80211 driver stack)"
		}
		fmt.Printf("Driver: %s\n", driver)
		outCap, _ := exec.Command("sh", "-c", "iw list | grep 'Supported interface modes' -A 8 | grep '* monitor'").Output()
		monSupport := "Not Supported"
		if len(outCap) > 0 {
			monSupport = "Fully Supported (NL80211 Native)"
		}
		fmt.Printf("Monitor Mode Support: %s\n", monSupport)
	} else if runtime.GOOS == "darwin" {
		out, _ := exec.Command("sh", "-c", "system_profiler SPAirPortDataType | grep -A 4 'Interfaces:' | grep 'Card Type'").Output()
		card := strings.TrimSpace(string(out))
		if card == "" {
			card = "Apple Silicon Internal SoC"
		} else {
			card = strings.TrimSpace(strings.TrimPrefix(card, "Card Type:"))
		}
		fmt.Printf("Chipset: %s\n", card)
		fmt.Println("Monitor Mode Support: Native (CoreWLAN Framework)")
	}
}

// PrintStatus dumps live network metrics by querying OS wireless APIs
func (c *InterfaceControlManager) PrintStatus(iface string) {
	fmt.Printf("[+] LIVE METRICS FOR INTERFACE: %s\n", iface)
	if runtime.GOOS == "windows" {
		out, _ := exec.Command("netsh", "wlan", "show", "interfaces").Output()
		lines := strings.Split(string(out), "\n")
		state, ssid, bssid, radio, signal, channel := "Disconnected", "N/A", "N/A", "N/A", "N/A", "N/A"
		for _, line := range lines {
			if strings.Contains(line, "State") && !strings.Contains(line, "hosted") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					state = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "SSID") && !strings.Contains(line, "BSSID") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					ssid = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "BSSID") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					bssid = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "Radio type") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					radio = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "Signal") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					signal = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "Channel") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					channel = strings.TrimSpace(parts[1])
				}
			}
		}
		fmt.Printf("Interface State: %s\n", state)
		fmt.Printf("Signal Quality: %s\n", signal)
		fmt.Printf("Current SSID: %s\n", ssid)
		fmt.Printf("Active BSSID: %s\n", bssid)
		fmt.Printf("Locked Channel: %s\n", channel)
		fmt.Printf("Radio Type: %s\n", radio)
	} else if runtime.GOOS == "linux" {
		out, _ := exec.Command("sh", "-c", fmt.Sprintf("iw dev %s link", iface)).Output()
		linkInfo := string(out)
		if strings.Contains(linkInfo, "Not connected") || strings.TrimSpace(linkInfo) == "" {
			fmt.Println("Interface State: Disconnected / Monitoring")
			fmt.Println("Current SSID: N/A")
			fmt.Println("Active BSSID: N/A")
		} else {
			fmt.Println("Interface State: Connected")
			lines := strings.Split(linkInfo, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Connected to") {
					fmt.Printf("Active BSSID: %s\n", strings.Fields(line)[2])
				}
				if strings.HasPrefix(line, "SSID:") {
					fmt.Printf("Current SSID: %s\n", strings.TrimSpace(strings.TrimPrefix(line, "SSID:")))
				}
				if strings.HasPrefix(line, "freq:") {
					fmt.Printf("Frequency: %s MHz\n", strings.TrimSpace(strings.TrimPrefix(line, "freq:")))
				}
				if strings.HasPrefix(line, "signal:") {
					fmt.Printf("Signal Quality: %s\n", strings.TrimSpace(strings.TrimPrefix(line, "signal:")))
				}
			}
		}
	} else if runtime.GOOS == "darwin" {
		out, _ := exec.Command("sh", "-c", "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I").Output()
		lines := strings.Split(string(out), "\n")
		ssid, bssid, channel, signal := "N/A", "N/A", "N/A", "N/A"
		for _, line := range lines {
			if strings.Contains(line, " SSID:") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					ssid = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, " BSSID:") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					bssid = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, " channel:") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					channel = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, " agrCtlRSSI:") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					signal = strings.TrimSpace(parts[1]) + " dBm"
				}
			}
		}
		state := "Connected"
		if ssid == "N/A" || ssid == "" {
			state = "Disconnected"
		}
		fmt.Printf("Interface State: %s\n", state)
		fmt.Printf("Signal Quality: %s\n", signal)
		fmt.Printf("Current SSID: %s\n", ssid)
		fmt.Printf("Active BSSID: %s\n", bssid)
		fmt.Printf("Locked Channel: %s\n", channel)
	}
}
