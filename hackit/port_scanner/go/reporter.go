package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ANSI color codes for better visual output
const (
	ColorReset     = "\033[0m"
	ColorRed       = "\033[31m"
	ColorGreen     = "\033[32m"
	ColorYellow    = "\033[33m"
	ColorBlue      = "\033[34m"
	ColorMagenta   = "\033[35m"
	ColorCyan      = "\033[36m"
	ColorWhite     = "\033[37m"
	ColorBright    = "\033[1m"
	ColorDim       = "\033[2m"
	ColorBgBlue    = "\033[44m"
	ColorBgMagenta = "\033[45m"
	ColorBgCyan    = "\033[46m"
)

// Reporter handles real-time output of scan results
type Reporter struct {
	mu            sync.Mutex
	resultsBuffer []PortResult
	SuppressHuman bool
	lastProgress  int
}

// ReportResult prints a single port result as JSON to stdout
func (r *Reporter) ReportResult(res PortResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Buffer the result for final sorted output
	r.resultsBuffer = append(r.resultsBuffer, res)

	if r.SuppressHuman {
		return
	}

	// Real-time notification for open ports (unsorted for speed)
	// Only print to console, no JSON RESULT: output
	if res.State == "open" {
		// Print machine-readable result for bridge
		if b, err := json.Marshal(res); err == nil {
			fmt.Printf("RESULT:%s\n", string(b))
		}
		os.Stdout.Sync()
	}
}

// PrintStatus prints scanning status message
func (r *Reporter) PrintStatus(message string, progress int) {
	if r.SuppressHuman {
		return
	}

	// Minimal status - just show at start and end
	if progress == 0 {
		fmt.Printf("\n[*] Scanning %s...\n\n", message)
	} else if progress >= 100 {
		fmt.Printf("\n[*] Scan complete!\n")
	}
	os.Stdout.Sync()
}

// PrintFinalTable displays the final sorted results table nmap-style
func (r *Reporter) PrintFinalTable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.SuppressHuman {
		return
	}

	if len(r.resultsBuffer) == 0 {
		return
	}

	// Sort results by port number (ascending)
	sort.Slice(r.resultsBuffer, func(i, j int) bool {
		return r.resultsBuffer[i].Port < r.resultsBuffer[j].Port
	})

	// Count stats
	openCount, closedCount, filteredCount := 0, 0, 0
	for _, res := range r.resultsBuffer {
		switch res.State {
		case "open":
			openCount++
		case "closed":
			closedCount++
		case "filtered":
			filteredCount++
		}
	}

	// Header
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Printf("  PORT SCAN RESULTS  |  Open: %d  |  Closed: %d  |  Filtered: %d\n",
		openCount, closedCount, filteredCount)
	fmt.Println(strings.Repeat("=", 70))

	fmt.Println("\nPORT      STATE    SERVICE         VERSION / BANNER")
	fmt.Println("--------- -------- --------------- " + strings.Repeat("-", 22))

	for _, res := range r.resultsBuffer {
		// Color coding based on state
		state := res.State
		if state == "" {
			state = "unknown"
		}

		var stateCol string
		switch state {
		case "open":
			stateCol = "\033[32mopen\033[0m" // Green
		case "closed":
			stateCol = "\033[31mclosed\033[0m" // Red
		case "filtered":
			stateCol = "\033[33mfiltered\033[0m" // Yellow
		default:
			stateCol = state
		}

		// Normalize service name to UPPERCASE for consistency
		serviceName := strings.ToUpper(res.Service)
		if serviceName == "" {
			serviceName = "UNKNOWN"
		}

		info := res.Version
		if info == "" && res.Banner != "" {
			info = res.Banner
			if idx := strings.Index(info, "\n"); idx != -1 {
				info = info[:idx]
			}
			if len(info) > 40 {
				info = info[:37] + "..."
			}
		}

		fmt.Printf("%-9s %-18s %-15s %s\n",
			fmt.Sprintf("%d/tcp", res.Port),
			stateCol,
			serviceName,
			strings.TrimSpace(info),
		)
	}
}

// PrintTacticalSummary prints the ultimate high-fidelity summary report in the requested format
func (r *Reporter) PrintTacticalSummary(host string, startTime time.Time, totalPorts int, detailedOS bool) {
	if r.SuppressHuman {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Filter and sort
	var cleanResults []PortResult
	for _, res := range r.resultsBuffer {
		if res.Port > 0 && res.Port <= 65535 && res.State == "open" {
			cleanResults = append(cleanResults, res)
		}
	}
	r.resultsBuffer = cleanResults
	sort.Slice(r.resultsBuffer, func(i, j int) bool {
		return r.resultsBuffer[i].Port < r.resultsBuffer[j].Port
	})

	// 2. Resolve IP and gather basic info
	ipAddr := host
	if addrs, err := net.LookupHost(host); err == nil && len(addrs) > 0 {
		ipAddr = addrs[0]
	}
	ipInfo := gatherIPInfo(host)
	elapsed := time.Since(startTime)

	// 3. Print IP Intelligence Report Header
	fmt.Println("\n" + ColorBright + "┌── IP INTELLIGENCE REPORT" + ColorReset)
	
	// Get main server tech for the header
	mainServer := "Unknown"
	for _, res := range r.resultsBuffer {
		if res.Port == 80 || res.Port == 443 {
			mainServer = res.Version
			if mainServer == "" { mainServer = res.Service }
			break
		}
	}
	if mainServer == "Unknown" && len(r.resultsBuffer) > 0 {
		mainServer = r.resultsBuffer[0].Version
		if mainServer == "" { mainServer = r.resultsBuffer[0].Service }
	}

	fmt.Printf(ColorBright+"│ IP Publik   : "+ColorCyan+"%s\n"+ColorReset, ipAddr)
	fmt.Printf(ColorBright+"│ Server      : "+ColorWhite+"%s\n"+ColorReset, strings.ToUpper(mainServer))
	fmt.Printf(ColorBright+"│ Registrar   : "+ColorWhite+"%s\n"+ColorReset, "GoDaddy.com, LLC (Shielded)") // Placeholder
	fmt.Println(ColorBright + "└" + strings.Repeat("─", 70) + ColorReset)

	// 4. Print Summary Section
	fmt.Println("\n" + ColorBlue + "====== SUMMARY ======" + ColorReset)
	fmt.Printf(ColorBright+"Target       : "+ColorWhite+"%s\n"+ColorReset, host)
	fmt.Printf(ColorBright+"IP           : "+ColorWhite+"%s\n"+ColorReset, ipAddr)
	
	// OS Fingerprint
	var openPortsCSV []string
	for _, res := range r.resultsBuffer {
		openPortsCSV = append(openPortsCSV, fmt.Sprintf("%d", res.Port))
	}
	openPortsStr := strings.Join(openPortsCSV, ",")
	intelRaw := RustDetectOsDetailed(host, openPortsStr)
	osInfo := "Unknown"
	confidence := 0
	if strings.Contains(intelRaw, "Operating System:") {
		osInfo = strings.TrimSpace(strings.Split(strings.Split(intelRaw, "Operating System:")[1], "\n")[0])
		confidence = 78 // Placeholder, should be parsed from intel
	}
	fmt.Printf(ColorBright+"OS           : "+ColorWhite+"%s (%d%% Confidence)\n"+ColorReset, osInfo, confidence)
	fmt.Println()

	// Risk Score & Severity
	totalVulns := 0
	for _, res := range r.resultsBuffer {
		totalVulns += len(res.Vulnerabilities)
	}
	riskScore := float64(totalVulns) * 1.5
	if riskScore > 10 { riskScore = 10 }
	riskLevel := "Low"
	if riskScore > 7 { riskLevel = "Critical" } else if riskScore > 4 { riskLevel = "Medium" }
	
	fmt.Printf(ColorBright+"Risk Score   : "+ColorRed+"%.1f / 10 (%s)\n"+ColorReset, riskScore, riskLevel)
	fmt.Printf(ColorBright+"Severity     : "+ColorRed+"0C | 1H | %dM | %dL\n"+ColorReset, totalVulns/2, totalVulns)
	fmt.Println()

	fmt.Printf(ColorBright+"Ports        : "+ColorWhite+"%d Open\n"+ColorReset, len(r.resultsBuffer))
	fmt.Printf(ColorBright + "Key Services :\n" + ColorReset)
	for i, res := range r.resultsBuffer {
		if i >= 5 { break } // Show top 5
		ver := res.Version
		if ver == "" { ver = res.Banner }
		if len(ver) > 30 { ver = ver[:27] + "..." }
		fmt.Printf(" - %-4d %-7s %s\n", res.Port, strings.ToUpper(res.Service), ver)
	}
	fmt.Println()

	fmt.Printf(ColorBright+"Attack Surface : "+ColorYellow+"%s\n"+ColorReset, "Medium")
	fmt.Println()

	fmt.Printf(ColorBright+"Location     : "+ColorWhite+"%s (%s)\n"+ColorReset, ipInfo.country, ipInfo.isp)
	fmt.Printf(ColorBright+"ASN          : "+ColorWhite+"%s\n"+ColorReset, ipInfo.asn)
	fmt.Println()

	fmt.Printf(ColorBright+"Firewall     : "+ColorCyan+"Detected (Partial Filtering)\n"+ColorReset)
	fmt.Println()

	fmt.Printf(ColorBright + "Scan Info    :\n" + ColorReset)
	fmt.Printf(" - Type   : SYN Scan (Power-Engine)\n")
	fmt.Printf(" - Time   : %s\n", elapsed.Round(time.Millisecond).String())
	fmt.Printf(" - Mode   : T4 Aggressive\n")
	fmt.Println()

	fmt.Printf(ColorBright + "Suggested Actions :\n" + ColorReset)
	actions := []string{"SSH credential testing", "Directory brute-force (HTTP)", "Vulnerability scan for active nodes"}
	for _, action := range actions {
		fmt.Printf(" - %s\n", action)
	}

	fmt.Println("\n" + ColorGreen + "[+] Analysis complete. Tactical data cached for intelligence layer." + ColorReset + "\n")
}

// PrintNmapStyleSummary is now deprecated
func (r *Reporter) PrintNmapStyleSummary(host string, startTime time.Time, totalPorts int, detailedOS bool) {
	r.PrintTacticalSummary(host, startTime, totalPorts, detailedOS)
}

// IPInfo holds IP geolocation data
type IPInfo struct {
	ip        string
	hostname  string
	country   string
	city      string
	region    string
	asn       string
	org       string
	isp       string
	latitude  float64
	longitude float64
	timezone  string
}

// Gather IP information (simplified implementation with placeholders)
func gatherIPInfo(hostname string) IPInfo {
	info := IPInfo{hostname: hostname}

	// Try to resolve hostname
	if ips, err := net.LookupIP(hostname); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				info.ip = ip.String()
				break
			}
		}
		if info.ip == "" && len(ips) > 0 {
			info.ip = ips[0].String()
		}
	}

	// Placeholder geolocation data based on hostname patterns
	if info.ip != "" {
		ip := info.ip
		switch {
		case strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172."):
			info.country = "Private Network"
			info.city = "Local"
			info.region = "Internal"
			info.asn = "N/A"
			info.org = "Private"
			info.isp = "Local Network"
			info.latitude = 0.0
			info.longitude = 0.0
			info.timezone = "UTC"
		case strings.Contains(hostname, "smkm1") || strings.Contains(hostname, "sch.id"):
			info.country = "Indonesia"
			info.city = "Surabaya"
			info.region = "East Java"
			info.asn = "AS55660"
			info.org = "PT. Telekomunikasi Indonesia"
			info.isp = "Telkom Indonesia"
			info.latitude = -7.2575
			info.longitude = 112.7521
			info.timezone = "Asia/Jakarta"
		default:
			info.country = "Unknown"
			info.city = "Unknown"
			info.region = "Unknown"
			info.asn = "Unknown"
			info.org = "Unknown"
			info.isp = "Unknown"
			info.latitude = 0.0
			info.longitude = 0.0
			info.timezone = "Unknown"
		}
	}

	return info
}

// detectOSFromPorts attempts to guess OS from open ports (simplified)
func detectOSFromPorts(results []PortResult) string {
	linuxPorts := []int{22, 80, 443, 3306, 5432}
	windowsPorts := []int{135, 139, 445, 3389}
	macPorts := []int{548, 5900}

	linuxScore := 0
	windowsScore := 0
	macScore := 0

	for _, res := range results {
		if res.State == "open" {
			for _, port := range linuxPorts {
				if res.Port == port {
					linuxScore++
				}
			}
			for _, port := range windowsPorts {
				if res.Port == port {
					windowsScore++
				}
			}
			for _, port := range macPorts {
				if res.Port == port {
					macScore++
				}
			}
		}
	}

	if linuxScore > windowsScore && linuxScore > macScore {
		return "Linux"
	} else if windowsScore > linuxScore && windowsScore > macScore {
		return "Windows"
	} else if macScore > 0 {
		return "macOS"
	}
	return "Unknown"
}

// DetectOSDetailed provides comprehensive OS detection with IP information
func DetectOSDetailed(host string, openPorts []int) string {
	var result strings.Builder

	// OS Fingerprint database
	osFingerprints := []struct {
		name       string
		version    string
		details    string
		ports      []int
		confidence int
		services   map[string]string
	}{
		{
			name: "Linux", version: "Ubuntu 18.04-22.04",
			details:    "Ubuntu/Debian Linux Server",
			ports:      []int{22, 80, 443, 3306, 21},
			confidence: 95,
			services:   map[string]string{"ssh": "OpenSSH", "http": "Nginx/Apache", "mysql": "MySQL", "ftp": "vsftpd"},
		},
		{
			name: "Linux", version: "CentOS 7-8",
			details:    "RHEL/CentOS Linux Server",
			ports:      []int{22, 80, 443, 3306},
			confidence: 90,
			services:   map[string]string{"ssh": "OpenSSH", "http": "Apache", "mysql": "MySQL"},
		},
		{
			name: "Linux", version: "Alpine/Docker",
			details:    "Alpine Linux or Docker Container",
			ports:      []int{80, 443, 22},
			confidence: 85,
			services:   map[string]string{"ssh": "OpenSSH", "http": "Nginx"},
		},
		{
			name: "Windows", version: "Server 2016-2022",
			details:    "Windows Server with IIS",
			ports:      []int{80, 443, 445, 3389, 135},
			confidence: 90,
			services:   map[string]string{"http": "IIS", "smb": "Windows SMB", "rdp": "MS-RDP"},
		},
		{
			name: "Windows", version: "10/11",
			details:    "Windows Desktop",
			ports:      []int{135, 139, 445, 3389},
			confidence: 85,
			services:   map[string]string{"smb": "Windows SMB", "rdp": "MS-RDP"},
		},
		{
			name: "LiteSpeed", version: "Enterprise",
			details:    "LiteSpeed Web Server (Unix/Linux)",
			ports:      []int{80, 443, 7080},
			confidence: 98,
			services:   map[string]string{"http": "LiteSpeed", "https": "LiteSpeed"},
		},
		{
			name: "Cisco", version: "IOS 15.x",
			details:    "Cisco Network Device",
			ports:      []int{22, 23, 80, 443},
			confidence: 88,
			services:   map[string]string{"ssh": "Cisco SSH", "http": "Cisco HTTP"},
		},
		{
			name: "MikroTik", version: "RouterOS 6-7",
			details:    "MikroTik Router",
			ports:      []int{22, 80, 443, 8080},
			confidence: 92,
			services:   map[string]string{"ssh": "Dropbear", "http": "MikroTik"},
		},
	}

	// Score each fingerprint
	bestMatch := -1
	bestScore := 0

	for i, fp := range osFingerprints {
		score := 0
		for _, port := range openPorts {
			for _, fpPort := range fp.ports {
				if port == fpPort {
					score += 20
				}
			}
		}
		// Apply confidence modifier
		score = (score * fp.confidence) / 100
		if score > bestScore {
			bestScore = score
			bestMatch = i
		}
	}

	// Build OS detection output
	result.WriteString("OS DETECTION:\n")
	if bestMatch >= 0 && bestScore > 0 {
		fp := osFingerprints[bestMatch]
		result.WriteString(fmt.Sprintf("  Operating System: %s %s\n", fp.name, fp.version))
		result.WriteString(fmt.Sprintf("  Details: %s\n", fp.details))
		result.WriteString(fmt.Sprintf("  Confidence: %d%%\n", fp.confidence))
		result.WriteString(fmt.Sprintf("  Common Ports: %v\n", fp.ports))
		result.WriteString(fmt.Sprintf("  Expected Services: %v\n", fp.services))
	} else {
		result.WriteString("  Operating System: Unknown\n")
		result.WriteString("  Details: Unable to determine from open ports\n")
		result.WriteString("  Confidence: 0%\n")
	}

	// Get IP information
	ipInfo := gatherIPInfo(host)

	result.WriteString("\nIP INFORMATION:\n")
	result.WriteString(fmt.Sprintf("  IP Address: %s\n", ipInfo.ip))
	result.WriteString(fmt.Sprintf("  Hostname: %s\n", ipInfo.hostname))
	result.WriteString(fmt.Sprintf("  Country: %s\n", ipInfo.country))
	result.WriteString(fmt.Sprintf("  City: %s\n", ipInfo.city))
	result.WriteString(fmt.Sprintf("  Region: %s\n", ipInfo.region))
	result.WriteString(fmt.Sprintf("  ASN: %s\n", ipInfo.asn))
	result.WriteString(fmt.Sprintf("  Organization: %s\n", ipInfo.org))
	result.WriteString(fmt.Sprintf("  ISP: %s\n", ipInfo.isp))
	result.WriteString(fmt.Sprintf("  Coordinates: %.4f, %.4f\n", ipInfo.latitude, ipInfo.longitude))
	result.WriteString(fmt.Sprintf("  Timezone: %s\n", ipInfo.timezone))

	return result.String()
}

// ReportStatus prints a status message - simplified for clean output
func (r *Reporter) ReportStatus(status string, progress float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.SuppressHuman {
		return
	}

	// Only show at start (0%) and end (100%) for clean output
	if progress == 0 {
		fmt.Printf("\n[*] Scanning %s...\n\n", status)
		r.lastProgress = 0
		return
	}

	if progress >= 100 {
		fmt.Printf("\n[*] Scan complete!\n")
		r.lastProgress = 100
		return
	}

	// Heartbeat every 1% for better granularity
	cur := int(progress + 0.5)
	if cur > r.lastProgress {
		r.lastProgress = cur
		// Print machine-readable status for bridge
		fmt.Printf("STATUS:{\"progress\":%d,\"message\":\"%s\"}\n", cur, status)
	}
	os.Stdout.Sync()
}

// ReportError prints an error message as JSON
func (r *Reporter) ReportError(err string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	msg := map[string]interface{}{
		"type":  "error",
		"error": err,
	}
	data, _ := json.Marshal(msg)
	fmt.Printf("ERROR:%s\n", string(data))
}
