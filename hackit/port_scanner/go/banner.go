package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func PrintBanner(target string) {
	titleArt := `
┌─────────────────────────────────────────────────┐
│ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ │
│ │ P │ │ O │ │ R │ │ T │ │ S │ │ C │ │ A │ │ N │ │
│ └───┘ └───┘ └───┘ └───┘ └───┘ └───┘ └───┘ └───┘ │
├─────────────────────────────────────────────────┤`
	footer := `└─────────────────────────────────────────────────┘`

	iface, gw := getInterfaceInfo()
	status := "Active"
	if _, err := net.DialTimeout("tcp", "8.8.8.8:53", time.Second); err != nil {
		status = "No Internet"
	}
	uptime := getUptime()

	fmt.Print("\033[2J\033[H")
	fmt.Println(ColorCyan + titleArt + ColorReset)
	fmt.Printf("%s│  Interface : %-8s  Gateway : %-12s   │%s\n", ColorCyan, iface, gw, ColorReset)
	fmt.Printf("%s│  Status    : %-8s  Uptime  : %-12s   │%s\n", ColorCyan, status, uptime, ColorReset)
	fmt.Println(ColorCyan + footer + ColorReset)
	fmt.Println()
}

func getInterfaceInfo() (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "lo", "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipv4 := ipnet.IP.To4(); ipv4 != nil {
					gw := getGateway(ipv4.String())
					return iface.Name, gw
				}
			}
		}
	}
	return "eth0", "0.0.0.0"
}

func getGateway(ip string) string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "0.0.0.0"
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		if parts[1] == "00000000" && len(parts[2]) == 8 {
			gw := fmt.Sprintf("%d.%d.%d.%d",
				hexByte(parts[2][6:8]), hexByte(parts[2][4:6]),
				hexByte(parts[2][2:4]), hexByte(parts[2][0:2]))
			return gw
		}
	}
	return ip
}

func hexByte(s string) int {
	var v int
	fmt.Sscanf(s, "%02x", &v)
	return v
}

func getUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "0h 0m"
	}
	var secs float64
	fmt.Sscanf(string(data), "%f", &secs)
	d := time.Duration(secs) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", h, m)
}
