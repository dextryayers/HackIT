package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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

	// Scan context, set by main so the summary reports what actually ran.
	ScanMode       string
	Profile        string
	PortsRequested int
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

	// Real-time notification:
	// 1. Always report OPEN ports.
	// 2. Report CLOSED/FILTERED only if they are "Common/Critical" ports to avoid noise.
	isCommon := IsCommonPort(res.Port)
	shouldReport := res.State == "open" || isCommon

	if shouldReport {
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

	// Header Grid
	fmt.Println("\n" + ColorBright + "┌" + strings.Repeat("─", 78) + "┐" + ColorReset)
	title := fmt.Sprintf("  HACKIT TACTICAL GRID  |  OPEN: %d  |  CLOSED: %d  |  FILTERED: %d",
		openCount, closedCount, filteredCount)
	fmt.Printf("%s│%s│%s\n", ColorBright, padRight(title, 78), ColorReset)
	fmt.Println(ColorBright + "├" + strings.Repeat("─", 12) + "┬" + strings.Repeat("─", 12) + "┬" + strings.Repeat("─", 14) + "┬" + strings.Repeat("─", 37) + "┤" + ColorReset)
	fmt.Printf("%s│ %-10s │ %-10s │ %-12s │ %-35s │%s\n", ColorBright, "PORT", "STATE", "SERVICE", "VERSION / INTELLIGENCE", ColorReset)
	fmt.Println(ColorBright + "├" + strings.Repeat("─", 12) + "┼" + strings.Repeat("─", 12) + "┼" + strings.Repeat("─", 14) + "┼" + strings.Repeat("─", 37) + "┤" + ColorReset)

	for _, res := range r.resultsBuffer {
		state := res.State
		if state == "" {
			state = "unknown"
		}

		var stateCol string
		switch state {
		case "open":
			stateCol = ColorGreen + "OPEN" + ColorReset
		case "closed":
			stateCol = ColorRed + "CLOSED" + ColorReset
		case "filtered":
			stateCol = ColorYellow + "FILTERED" + ColorReset
		default:
			stateCol = strings.ToUpper(state)
		}

		// Ensure service is populated — fallback to banner detection + commonPorts
		serviceName := res.Service
		if serviceName == "" || serviceName == "unknown" {
			if res.Banner != "" {
				svc, _ := DetectService(res.Port, res.Banner, "")
				if svc != "" {
					serviceName = svc
				}
			}
			if serviceName == "" || serviceName == "unknown" {
				serviceName = lookupServiceName(res.Port)
			}
		}
		serviceName = strings.ToUpper(serviceName)
		if serviceName == "" {
			serviceName = "UNKNOWN"
		}

		info := res.Version
		if info == "" && res.Banner != "" {
			info = res.Banner
			if idx := strings.Index(info, "\n"); idx != -1 {
				info = info[:idx]
			}
		}
		if len(info) > 35 {
			info = info[:32] + "..."
		}

		fmt.Printf("%s│%s %-10d %s│ %s %-15s %s│ %-12s │ %-35s │%s\n",
			ColorBright, ColorReset, res.Port, ColorBright, ColorReset, stateCol, ColorBright, serviceName, info, ColorReset)
	}
	fmt.Println(ColorBright + "└" + strings.Repeat("─", 12) + "┴" + strings.Repeat("─", 12) + "┴" + strings.Repeat("─", 14) + "┴" + strings.Repeat("─", 37) + "┘" + ColorReset)
}

func padRight(s string, length int) string {
	if len(s) >= length {
		return s
	}
	return s + strings.Repeat(" ", length-len(s))
}

// ─────────────────────────────────────────────────────────────────
// SEVERITY MODEL — derived from real findings, never assumed
// ─────────────────────────────────────────────────────────────────

type severity int

const (
	sevInfo severity = iota
	sevLow
	sevMedium
	sevHigh
	sevCritical
)

var severityLabels = [5]string{"Info", "Low", "Medium", "High", "Critical"}
var severityWeight = [5]float64{0, 1, 3, 6, 10}

// classifyVulnerability maps a finding string to a severity. Findings emitted
// by the engine carry an explicit prefix; CVE-tagged entries default to High.
func classifyVulnerability(v string) severity {
	u := strings.ToUpper(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(u, "CRITICAL"):
		return sevCritical
	case strings.HasPrefix(u, "HIGH"):
		return sevHigh
	case strings.HasPrefix(u, "WARN"):
		return sevMedium
	case strings.HasPrefix(u, "EOLSUPPORT"):
		return sevMedium
	case strings.HasPrefix(u, "INFO"):
		return sevInfo
	case strings.HasPrefix(u, "CVE-"):
		return sevHigh
	}
	return sevLow
}

// severityProfile returns per-severity counts and the weighted risk score.
func severityProfile(results []PortResult) ([5]int, float64) {
	var counts [5]int
	seen := make(map[string]bool)
	var score float64
	for _, res := range results {
		for _, v := range res.Vulnerabilities {
			if seen[v] {
				continue
			}
			seen[v] = true
			s := classifyVulnerability(v)
			counts[s]++
			score += severityWeight[s]
		}
	}
	if score > 10 {
		score = 10
	}
	return counts, score
}

func riskLevel(score float64) string {
	switch {
	case score <= 0:
		return "None"
	case score < 3:
		return "Low"
	case score < 6:
		return "Medium"
	case score < 8:
		return "High"
	default:
		return "Critical"
	}
}

// exposedServiceWeight rates how much an open port widens the attack surface.
func exposedServiceWeight(port int) int {
	switch port {
	case 23, 21, 445, 3389, 2375, 6379, 27017, 9200, 11211, 5900, 4444:
		return 3
	case 22, 25, 110, 143, 3306, 5432, 1433, 1521, 5985, 5986, 6443, 10250:
		return 1
	}
	return 0
}

func assessAttackSurface(results []PortResult, counts [5]int) (string, string) {
	open := 0
	exposure := 0
	var drivers []string
	for _, res := range results {
		if res.State != "open" {
			continue
		}
		open++
		w := exposedServiceWeight(res.Port)
		if w > 0 {
			exposure += w
			svc := strings.ToUpper(res.Service)
			if svc == "" || svc == "UNKNOWN" {
				svc = strings.ToUpper(lookupServiceName(res.Port))
			}
			drivers = append(drivers, fmt.Sprintf("%s/%d", svc, res.Port))
		}
	}
	exposure += counts[sevCritical]*3 + counts[sevHigh]*2 + counts[sevMedium]

	var label string
	switch {
	case exposure == 0:
		label = "Minimal"
	case exposure <= 3:
		label = "Low"
	case exposure <= 7:
		label = "Moderate"
	case exposure <= 12:
		label = "Elevated"
	default:
		label = "High"
	}

	reason := fmt.Sprintf("%d open port(s)", open)
	if len(drivers) > 0 {
		reason += ", sensitive: " + strings.Join(drivers, ", ")
	}
	return label, reason
}

// filterAssessment reports what the state mix actually proves about filtering.
func filterAssessment(results []PortResult) string {
	filtered, closed, open := 0, 0, 0
	for _, res := range results {
		switch res.State {
		case "filtered":
			filtered++
		case "closed":
			closed++
		case "open":
			open++
		}
	}
	total := filtered + closed + open
	switch {
	case total == 0:
		return "No probes completed"
	case filtered > 0 && closed > 0:
		return fmt.Sprintf("Partial filtering — %d/%d probes filtered", filtered, total)
	case filtered > 0:
		return fmt.Sprintf("Filtering observed — %d/%d probes filtered", filtered, total)
	case closed > 0:
		return "No filtering observed — closed ports answered with RST"
	default:
		return "Untested — scan recorded open ports only"
	}
}

// suggestedActions maps real open services to concrete next steps.
func suggestedActions(results []PortResult) []string {
	byPort := make(map[int]string)
	for _, res := range results {
		if res.State != "open" {
			continue
		}
		var action string
		switch res.Port {
		case 21:
			action = "FTP: test anonymous login and TLS enforcement"
		case 22:
			action = "SSH: verify auth methods, banner, and key policy"
		case 23:
			action = "Telnet: plaintext protocol exposed — replace with SSH"
		case 25, 465, 587:
			action = "SMTP: check open relay and STARTTLS enforcement"
		case 80, 443, 8000, 8080, 8443, 8888:
			action = "HTTP: content discovery and TLS configuration review"
		case 139, 445:
			action = "SMB: verify MS17-010 patch level and share permissions"
		case 3306:
			action = "MySQL: enumerate grants and bind address"
		case 5432:
			action = "PostgreSQL: review pg_hba.conf and role privileges"
		case 6379:
			action = "Redis: verify AUTH and protected-mode"
		case 27017:
			action = "MongoDB: verify authentication is enabled"
		case 3389:
			action = "RDP: verify NLA and patch level"
		case 5900:
			action = "VNC: verify authentication is configured"
		case 11211:
			action = "Memcached: verify exposure and SASL"
		case 9200:
			action = "Elasticsearch: verify auth and index exposure"
		case 2375:
			action = "Docker API: unauthenticated daemon — restrict immediately"
		case 10250:
			action = "Kubelet API: verify anonymous auth is disabled"
		}
		if action != "" {
			byPort[res.Port] = action
		}
	}
	ports := make([]int, 0, len(byPort))
	for p := range byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	// One line per distinct action, first (lowest) port wins.
	seen := make(map[string]bool)
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		action := byPort[p]
		if seen[action] {
			continue
		}
		seen[action] = true
		out = append(out, action)
		if len(out) >= 6 {
			break
		}
	}
	return out
}

// PrintTacticalSummary prints the final report using only measured data.
func (r *Reporter) PrintTacticalSummary(host string, startTime time.Time, totalPorts int, detailedOS bool) {
	if r.SuppressHuman {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Keep open ports only, sorted.
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

	// 2. Live resolution + intelligence.
	ipAddr, _ := resolveHost(host)
	ipInfo := gatherIPInfo(host)
	elapsed := time.Since(startTime)

	// 3. Header — only print fields that resolved.
	fmt.Println("\n" + ColorBright + "┌── IP INTELLIGENCE REPORT" + ColorReset)

	mainServer := "Unknown"
	for _, res := range r.resultsBuffer {
		if res.Port == 80 || res.Port == 443 {
			mainServer = strings.TrimSpace(strings.ToUpper(res.Service) + " " + res.Version)
			if strings.TrimSpace(mainServer) == "" || mainServer == "UNKNOWN" {
				mainServer = res.Service
			}
			break
		}
	}
	if mainServer == "Unknown" && len(r.resultsBuffer) > 0 {
		mainServer = strings.TrimSpace(strings.ToUpper(r.resultsBuffer[0].Service) + " " + r.resultsBuffer[0].Version)
		if mainServer == "" {
			mainServer = r.resultsBuffer[0].Service
		}
	}
	if mainServer == "" {
		mainServer = "Unknown"
	}

	fmt.Printf(ColorBright+"│ IP Address  : "+ColorCyan+"%s\n"+ColorReset, ipAddr)
	fmt.Printf(ColorBright+"│ Server      : "+ColorWhite+"%s\n"+ColorReset, mainServer)
	if ipInfo.registrar != "" {
		fmt.Printf(ColorBright+"│ Registrar   : "+ColorWhite+"%s\n"+ColorReset, ipInfo.registrar)
	}
	if ipInfo.network != "" {
		fmt.Printf(ColorBright+"│ Network     : "+ColorWhite+"%s\n"+ColorReset, ipInfo.network)
	}
	fmt.Println(ColorBright + "└" + strings.Repeat("─", 70) + ColorReset)

	// 4. Summary — every value computed from this scan.
	fmt.Println("\n" + ColorBlue + "====== SUMMARY ======" + ColorReset)
	fmt.Printf(ColorBright+"Target       : "+ColorWhite+"%s\n"+ColorReset, host)
	fmt.Printf(ColorBright+"IP           : "+ColorWhite+"%s\n"+ColorReset, ipAddr)

	osInfo := AnalyzeOSFromResults(host, r.resultsBuffer)
	osName := strings.TrimSpace(osInfo.Name)
	if osName == "" || osName == "Unknown" || osInfo.Confidence < 0.5 {
		fmt.Printf(ColorBright + "OS           : " + ColorWhite + "Unknown (insufficient evidence)\n" + ColorReset)
	} else {
		label := osName
		if osInfo.Version != "" {
			label += " " + osInfo.Version
		}
		fmt.Printf(ColorBright+"OS           : "+ColorWhite+"%s (%d%% confidence)\n"+ColorReset,
			label, int(osInfo.Confidence*100+0.5))
	}
	fmt.Println()

	counts, riskScore := severityProfile(r.resultsBuffer)
	fmt.Printf(ColorBright+"Risk Score   : "+ColorRed+"%.1f / 10 (%s)\n"+ColorReset, riskScore, riskLevel(riskScore))
	fmt.Printf(ColorBright+"Severity     : "+ColorRed+"%d Critical | %d High | %d Medium | %d Low | %d Info\n"+ColorReset,
		counts[sevCritical], counts[sevHigh], counts[sevMedium], counts[sevLow], counts[sevInfo])
	fmt.Println()

	scriptHits := 0
	for _, res := range r.resultsBuffer {
		scriptHits += len(res.Scripts)
	}
	fmt.Printf(ColorBright+"Ports        : "+ColorWhite+"%d Open"+ColorReset, len(r.resultsBuffer))
	if r.PortsRequested > 0 {
		fmt.Printf(ColorDim+" of %d probed"+ColorReset, r.PortsRequested)
	}
	fmt.Println()
	if scriptHits > 0 {
		fmt.Printf(ColorBright+"Scripts      : "+ColorWhite+"%d finding(s)\n"+ColorReset, scriptHits)
	}

	if len(r.resultsBuffer) > 0 {
		fmt.Printf(ColorBright + "Key Services :\n" + ColorReset)
		for i, res := range r.resultsBuffer {
			if i >= 5 {
				break
			}
			ver := res.Version
			if ver == "" {
				ver = res.Banner
			}
			if idx := strings.Index(ver, "\n"); idx != -1 {
				ver = ver[:idx]
			}
			if len(ver) > 30 {
				ver = ver[:27] + "..."
			}
			fmt.Printf(" - %-5d %-12s %s\n", res.Port, strings.ToUpper(res.Service), ver)
		}
	}
	fmt.Println()

	surfaceLabel, surfaceReason := assessAttackSurface(r.resultsBuffer, counts)
	fmt.Printf(ColorBright+"Attack Surface : "+ColorYellow+"%s"+ColorReset+" (%s)\n", surfaceLabel, surfaceReason)
	fmt.Println()

	if ipInfo.country != "" {
		fmt.Printf(ColorBright+"Location     : "+ColorWhite+"%s (%s)\n"+ColorReset, ipInfo.country, ipInfo.isp)
		fmt.Printf(ColorBright+"ASN          : "+ColorWhite+"%s\n"+ColorReset, ipInfo.asn)
		fmt.Println()
	}

	fmt.Printf(ColorBright+"Firewall     : "+ColorCyan+"%s\n"+ColorReset, filterAssessment(r.resultsBuffer))
	fmt.Println()

	mode := r.ScanMode
	if mode == "" {
		mode = "connect"
	}
	fmt.Printf(ColorBright + "Scan Info    :\n" + ColorReset)
	fmt.Printf(" - Type   : %s\n", scanModeLabel(mode))
	if r.Profile != "" && r.Profile != "default" {
		fmt.Printf(" - Profile: %s\n", r.Profile)
	}
	fmt.Printf(" - Ports  : %d\n", totalPorts)
	fmt.Printf(" - Time   : %s\n", elapsed.Round(time.Millisecond).String())
	fmt.Println()

	if actions := suggestedActions(r.resultsBuffer); len(actions) > 0 {
		fmt.Printf(ColorBright + "Suggested Actions :\n" + ColorReset)
		for _, action := range actions {
			fmt.Printf(" - %s\n", action)
		}
		fmt.Println()
	}

	fmt.Println(ColorGreen + "[+] Analysis complete. Tactical data cached for intelligence layer." + ColorReset)
}

func scanModeLabel(mode string) string {
	switch strings.ToLower(mode) {
	case "connect", "tcp", "tcp-connect":
		return "TCP connect"
	case "syn", "half-open":
		return "TCP SYN (half-open)"
	case "udp":
		return "UDP"
	case "ack":
		return "TCP ACK"
	default:
		return mode
	}
}

// PrintHackITStyleSummary is now deprecated
func (r *Reporter) PrintHackITStyleSummary(host string, startTime time.Time, totalPorts int, detailedOS bool) {
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
	registrar string
	network   string
	latitude  float64
	longitude float64
	timezone  string
}

const intelHTTPTimeout = 3 * time.Second

func httpGetJSON(url string, out interface{}) error {
	client := &http.Client{Timeout: intelHTTPTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

type geoIPResponse struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
	ISP        string `json:"isp"`
	Org        string `json:"org"`
	AS         string `json:"as"`
	Query      string `json:"query"`
}

type rdapEntity struct {
	Roles []string      `json:"roles"`
	VCard []interface{} `json:"vcardArray"`
}

type rdapResponse struct {
	Name         string       `json:"name"`
	Handle       string       `json:"handle"`
	Country      string       `json:"country"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Entities     []rdapEntity `json:"entities"`
}

func rdapEntityName(e rdapEntity) string {
	for _, raw := range e.VCard {
		item, ok := raw.([]interface{})
		if !ok || len(item) < 4 {
			continue
		}
		key, _ := item[0].(string)
		if key != "fn" {
			continue
		}
		if val, ok := item[3].(string); ok {
			return val
		}
	}
	return ""
}

// gatherIPInfo collects live geolocation, ASN, and registration data.
// Unreachable sources leave fields empty — nothing is invented.
func gatherIPInfo(hostname string) IPInfo {
	info := IPInfo{hostname: hostname}

	ipStr, err := resolveHost(hostname)
	if err != nil || ipStr == "" {
		return info
	}
	info.ip = ipStr

	ip := net.ParseIP(info.ip)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		info.country = "Private Network"
		info.city = "Local"
		info.region = "Internal"
		info.asn = "N/A"
		info.org = "Private"
		info.isp = "Local Network"
		info.timezone = "Local"
		return info
	}

	// Geolocation + ASN (ip-api.com, no key required).
	var geo geoIPResponse
	if err := httpGetJSON(fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,message,country,regionName,city,isp,org,as,query",
		info.ip), &geo); err == nil && geo.Status == "success" {
		info.country = geo.Country
		info.city = geo.City
		info.region = geo.RegionName
		info.isp = geo.ISP
		info.org = geo.Org
		if geo.AS != "" {
			parts := strings.SplitN(geo.AS, " ", 2)
			info.asn = parts[0]
			if info.org == "" && len(parts) == 2 {
				info.org = parts[1]
			}
		}
	}

	// Network allocation (RDAP).
	var ipRdap rdapResponse
	if err := httpGetJSON("https://rdap.org/ip/"+info.ip, &ipRdap); err == nil {
		network := ipRdap.Name
		if ipRdap.StartAddress != "" && ipRdap.EndAddress != "" {
			span := fmt.Sprintf("%s - %s", ipRdap.StartAddress, ipRdap.EndAddress)
			if network != "" {
				network = fmt.Sprintf("%s (%s)", network, span)
			} else {
				network = span
			}
		}
		info.network = network
		if info.country == "" && ipRdap.Country != "" {
			info.country = ipRdap.Country
		}
	}

	// Registrar, only when the target is a domain.
	if net.ParseIP(hostname) == nil && strings.Contains(hostname, ".") {
		var domRdap rdapResponse
		if err := httpGetJSON("https://rdap.org/domain/"+hostname, &domRdap); err == nil {
			for _, ent := range domRdap.Entities {
				for _, role := range ent.Roles {
					if role == "registrar" {
						if name := rdapEntityName(ent); name != "" {
							info.registrar = name
						}
						break
					}
				}
				if info.registrar != "" {
					break
				}
			}
		}
	}

	return info
}

// DetectOSDetailed provides OS detection from open ports plus live IP intel.
func DetectOSDetailed(host string, openPorts []int) string {
	var result strings.Builder

	results := make([]PortResult, 0, len(openPorts))
	for _, port := range openPorts {
		results = append(results, PortResult{
			Port:    port,
			State:   "open",
			Service: lookupServiceName(port),
		})
	}

	osInfo := AnalyzeOSFromResults(host, results)

	result.WriteString("OS DETECTION:\n")
	if osInfo.Name != "" && osInfo.Name != "Unknown" {
		result.WriteString(fmt.Sprintf("  Operating System: %s %s\n", osInfo.Name, osInfo.Version))
		if osInfo.Family != "" {
			result.WriteString(fmt.Sprintf("  Family: %s\n", osInfo.Family))
		}
		result.WriteString(fmt.Sprintf("  Confidence: %d%%\n", int(osInfo.Confidence*100+0.5)))
		if osInfo.Fingerprint != "" {
			result.WriteString(fmt.Sprintf("  Evidence: %s\n", osInfo.Fingerprint))
		}
	} else {
		result.WriteString("  Operating System: Unknown\n")
		result.WriteString("  Details: Unable to determine from open ports\n")
		result.WriteString("  Confidence: 0%\n")
	}

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
	result.WriteString(fmt.Sprintf("  Network: %s\n", ipInfo.network))
	if ipInfo.registrar != "" {
		result.WriteString(fmt.Sprintf("  Registrar: %s\n", ipInfo.registrar))
	}
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

	if progress >= 100 {
		fmt.Printf("\n[*] Scan complete!\n")
		r.lastProgress = 100
		return
	}

	// Heartbeat for better granularity
	cur := int(progress + 0.5)
	// Force report if it's a significant jump OR we are at the very end to avoid "stuck" feeling
	isNearEnd := progress > 90 && progress < 100

	if cur > r.lastProgress || isNearEnd {
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
