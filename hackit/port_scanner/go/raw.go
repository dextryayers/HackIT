package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PortResult is defined in main.go

// RunCTurboScan calls the C-based Turbo Engine for ultra-fast port scanning
func RunCppServiceScan(host string, port int, timeout int) PortResult {
	var res PortResult
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	if strings.Contains(exePath, "Temp") {
		baseDir = "d:/web/hacks/hackstools/hackit/port_scanner/cpp"
	} else {
		baseDir = filepath.Join(filepath.Dir(baseDir), "cpp")
	}
	binary := filepath.Join(baseDir, "service_scanner.exe")
	cmd := exec.Command(binary, host, fmt.Sprintf("%d", port), fmt.Sprintf("%d", timeout))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		json.Unmarshal(out.Bytes(), &res)
	}
	return res
}

func RunCTurboScan(host string, ports string, timeout int) []PortResult {
	results := make([]PortResult, 0)

	// Determine binary path (assumes c/scanner.exe exists)
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	// If running via go run, we need to find the actual project dir
	if strings.Contains(exePath, "Temp") {
		// Fallback for development
		baseDir = "d:/web/hacks/hackstools/hackit/port_scanner/c"
	} else {
		baseDir = filepath.Join(filepath.Dir(baseDir), "c")
	}

	binary := filepath.Join(baseDir, "scanner.exe")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		// Try relative to current working directory
		binary = "./c/scanner.exe"
	}

	// Call C binary with host, ports, timeout, and default timing level 4 (Aggressive)
	cmd := exec.Command(binary, host, ports, fmt.Sprintf("%d", timeout), "4")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return results
	}

	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "{") {
			var res PortResult
			if err := json.Unmarshal([]byte(line), &res); err == nil {
				results = append(results, res)
			}
		}
	}

	return results
}

func RunRubyScan(host string, ports string, timeout int) []PortResult {
	results := make([]PortResult, 0)
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	if strings.Contains(exePath, "Temp") {
		baseDir = "d:/web/hacks/hackstools/hackit/port_scanner/ruby"
	} else {
		baseDir = filepath.Join(filepath.Dir(baseDir), "ruby")
	}

	script := filepath.Join(baseDir, "engine.rb")
	cmd := exec.Command("ruby", script, host, ports, fmt.Sprintf("%d", timeout))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		json.Unmarshal(out.Bytes(), &results)
	}
	return results
}

func RunPythonScan(host string, ports string, timeout int) []PortResult {
	results := make([]PortResult, 0)
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	if strings.Contains(exePath, "Temp") {
		baseDir = "d:/web/hacks/hackstools/hackit/port_scanner"
	} else {
		baseDir = filepath.Dir(baseDir)
	}

	script := filepath.Join(baseDir, "core.py")
	cmd := exec.Command("python", script, host, ports, fmt.Sprintf("%d", timeout))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		json.Unmarshal(out.Bytes(), &results)
	}
	return results
}

// NOTE: Raw socket scanning (SYN, FIN, Xmas, etc.) requires root/admin privileges.
// This is a foundational implementation for advanced stealth modes.

func ScanRaw(host string, port int, scanType string, timeoutMs int) (PortResult, bool) {
	// 1. Resolve target IP
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return PortResult{}, false
	}
	dstIP := ips[0]

	// 2. Get local IP and source port
	srcIP, srcPort := getLocalIPAndPort(dstIP)

	// 3. Create TCP Layer
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(port),
		Seq:     rand.Uint32(),
		Window:  64240,
	}

	// Set flags based on scan type
	switch scanType {
	case "stealth": // SYN Scan
		tcpLayer.SYN = true
	case "fin":
		tcpLayer.FIN = true
	case "null":
		// No flags set
	case "xmas":
		tcpLayer.FIN = true
		tcpLayer.URG = true
		tcpLayer.PSH = true
	case "ack":
		tcpLayer.ACK = true
	case "window":
		tcpLayer.ACK = true // Window scan sends ACK and checks window size
	case "maimon":
		tcpLayer.FIN = true
		tcpLayer.ACK = true
	}

	// 4. Create IP Layer
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	// Set Checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// 5. Build packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, tcpLayer); err != nil {
		return PortResult{}, false
	}

	// 6. Send and Listen (Requires raw socket - simplified here for architecture)
	// For Windows, raw sockets have limitations. We'll use a best-effort approach.

	// Open a raw socket
	protocol := "ip4:tcp"
	if scanType == "icmp" {
		protocol = "ip4:icmp"
	}

	conn, err := net.ListenPacket(protocol, "0.0.0.0")
	if err != nil {
		// Fallback: If raw socket fails (permissions), we can't do stealth scan.
		svc, ver := IdentifyService(port, "", host)
		return PortResult{
			Port:    port,
			State:   "filtered (no-privilege)",
			Service: svc,
			Version: ver,
		}, false
	}
	defer conn.Close()

	// Send the packet
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP})
	if err != nil {
		return PortResult{}, false
	}

	// Wait for response
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	// Track seen packets to avoid duplicate processing in the loop
	for {
		respBuf := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(respBuf)
		if err != nil {
			svc, ver := IdentifyService(port, "", host)
			// Timeout -> likely filtered or open (for FIN/Null/Xmas/Maimon)
			if scanType == "stealth" || scanType == "window" || scanType == "ack" {
				return PortResult{Port: port, State: "filtered", Service: svc, Version: ver}, false
			}
			// FIN/Null/Xmas/Maimon are "open|filtered" on timeout
			return PortResult{Port: port, State: "open|filtered", Service: svc, Version: ver}, true
		}

		if addr.String() != dstIP.String() {
			continue
		}

		// Parse TCP response
		packet := gopacket.NewPacket(respBuf[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.DstPort != layers.TCPPort(srcPort) || tcp.SrcPort != layers.TCPPort(port) {
				continue
			}

			svc, ver := IdentifyService(port, "", host)
			if scanType == "stealth" {
				if tcp.SYN && tcp.ACK {
					// Extract TTL and Window Size for C-Engine OS Fingerprinting
					// We need to access the IP layer to get TTL
					ttl := 64 // Default
					if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
						ip, _ := ipLayer.(*layers.IPv4)
						ttl = int(ip.TTL)
					}
					return PortResult{Port: port, State: "open", Service: svc, Version: ver, TTL: ttl}, true
				}
				if tcp.RST {
					return PortResult{Port: port, State: "closed", Service: svc, Version: ver}, false
				}
			} else if scanType == "window" {
				if tcp.RST {
					if tcp.Window > 0 {
						return PortResult{Port: port, State: "open", Service: svc, Version: ver}, true
					}
					return PortResult{Port: port, State: "closed", Service: svc, Version: ver}, false
				}
			} else if scanType == "ack" {
				if tcp.RST {
					return PortResult{Port: port, State: "unfiltered", Service: svc, Version: ver}, true
				}
			} else {
				// For FIN/Null/Xmas/Maimon, any response (usually RST) means closed
				if tcp.RST {
					return PortResult{Port: port, State: "closed", Service: svc, Version: ver}, false
				}
			}
		}
	}
}

func getLocalIPAndPort(dstIP net.IP) (net.IP, int) {
	conn, _ := net.Dial("udp", dstIP.String()+":80")
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, localAddr.Port
}
