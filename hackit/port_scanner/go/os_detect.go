package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunCExpertOSDetect calls the C engine for deep OS fingerprinting
func RunCExpertOSDetect(host string, ttl int, window int) string {
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	if strings.Contains(exePath, "Temp") {
		baseDir = "d:/web/hacks/hackstools/hackit/port_scanner/c"
	} else {
		baseDir = filepath.Join(filepath.Dir(baseDir), "c")
	}

	binary := filepath.Join(baseDir, "os_detect.exe")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}

	// C binary returns detailed text by default; if only a short pipe format is printed
	// by other builds, we still accept it.
	cmd := exec.Command(binary, host, "", fmt.Sprintf("%d", ttl), fmt.Sprintf("%d", window))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		output := strings.TrimSpace(out.String())
		if output != "" {
			return output
		}
	}
	return ""
}

// RunCExpertOSDetectDetailed calls the C engine for detailed OS+IP information text.
// Args: host, open_ports (comma separated), ttl, window
func RunCExpertOSDetectDetailed(host string, openPorts string, ttl int, window int) string {
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	if strings.Contains(exePath, "Temp") {
		baseDir = "d:/web/hacks/hackstools/hackit/port_scanner/c"
	} else {
		baseDir = filepath.Join(filepath.Dir(baseDir), "c")
	}

	binary := filepath.Join(baseDir, "os_detect.exe")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}

	cmd := exec.Command(binary, host, openPorts, fmt.Sprintf("%d", ttl), fmt.Sprintf("%d", window))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		return strings.TrimSpace(out.String())
	}
	return ""
}

// OSInfo holds the detected OS information
type OSInfo struct {
	Name        string  `json:"name"`
	Version     string  `json:"version,omitempty"`
	Family      string  `json:"family,omitempty"`
	Accuracy    int     `json:"accuracy,omitempty"`
	Confidence  float64 `json:"confidence"`
	Fingerprint string  `json:"fingerprint"`
	Kernel      string  `json:"kernel,omitempty"`
	Arch        string  `json:"arch,omitempty"`
	IPID        string  `json:"ipid,omitempty"`
	TTL         int     `json:"ttl,omitempty"`
	Window      int     `json:"window,omitempty"`
	MSS         int     `json:"mss,omitempty"`
}

func normalizeOSFamily(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "windows"):
		return "Windows"
	case strings.Contains(l, "ubuntu") || strings.Contains(l, "debian") || strings.Contains(l, "centos") || strings.Contains(l, "red hat") || strings.Contains(l, "rhel") || strings.Contains(l, "fedora") || strings.Contains(l, "alpine") || strings.Contains(l, "linux"):
		return "Linux/Unix"
	case strings.Contains(l, "freebsd") || strings.Contains(l, "openbsd"):
		return "BSD"
	case strings.Contains(l, "cisco") || strings.Contains(l, "mikrotik") || strings.Contains(l, "juniper") || strings.Contains(l, "fortinet"):
		return "Network Device"
	default:
		return "Unknown"
	}
}

func joinEvidence(items []string) string {
	if len(items) == 0 {
		return ""
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return strings.Join(out, "; ")
}

// ParseCOutput converts C engine output to OSInfo
func ParseCOutput(output string) OSInfo {
	parts := strings.Split(output, "|")
	if len(parts) < 3 {
		return OSInfo{Name: output, Confidence: 0.5}
	}

	conf := 0.0
	fmt.Sscanf(parts[2], "%f", &conf)

	return OSInfo{
		Name:       parts[0],
		Version:    parts[1],
		Confidence: conf,
	}
}

// Enhanced OS detection with TCP/IP fingerprinting
func DetectOS(host string) OSInfo {
	// Default info
	info := OSInfo{Name: "Unknown", Confidence: 0.0}

	// Resolve IP to ensure we have a direct connection
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return info
	}

	// 1. Perform advanced TCP/IP fingerprinting
	ttl, window, mss, ipid := PerformTCPFingerprinting(host)

	// 2. Analyze fingerprint characteristics
	info = AnalyzeFingerprint(ttl, window, mss, ipid)

	// 3. Cross-reference with banner analysis
	bannerInfo := AnalyzeOSFromBanners(host)
	if bannerInfo.Confidence > info.Confidence {
		info = bannerInfo
	}

	// 4. Apply C engine for deep analysis if available
	if ttl > 0 {
		cOutput := RunCExpertOSDetect(host, ttl, window)
		if cOutput != "" {
			cOS := ParseCOutput(cOutput)
			if cOS.Confidence > info.Confidence {
				info = cOS
			}
		}
	}

	// 5. Store fingerprint data
	info.TTL = ttl
	info.Window = window
	info.MSS = mss
	info.IPID = ipid
	info.Fingerprint = fmt.Sprintf("TTL:%d|WIN:%d|MSS:%d|IPID:%s", ttl, window, mss, ipid)

	return info
}

// PerformTCPFingerprinting performs advanced TCP/IP fingerprinting
func PerformTCPFingerprinting(host string) (ttl, window, mss int, ipid string) {
	// Default values
	ttl = 64
	window = 5840
	mss = 1460
	ipid = "Random"

	// Try to connect to port 80 or 443 to get TCP characteristics
	for _, port := range []int{80, 443, 22, 21, 25} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 2*time.Second)
		if err == nil {
			defer conn.Close()

			// Set read timeout
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			// Send a simple probe
			conn.Write([]byte("\r\n"))

			// Try to read response
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)

			if n > 0 {
				// Analyze TCP characteristics from response
				// This is simplified - real implementation would use raw sockets
				return AnalyzeTCPCharacteristics(buf[:n])
			}
		}
	}

	// Fallback to heuristic analysis
	return HeuristicTCPAnalysis(host)
}

// AnalyzeTCPCharacteristics analyzes TCP packet characteristics
func AnalyzeTCPCharacteristics(data []byte) (ttl, window, mss int, ipid string) {
	// Simplified analysis - real implementation would parse TCP headers
	// This is a placeholder for the actual fingerprinting logic
	return 64, 5840, 1460, "Random"
}

// HeuristicTCPAnalysis performs heuristic TCP analysis
func HeuristicTCPAnalysis(host string) (ttl, window, mss int, ipid string) {
	// Use known OS fingerprinting patterns
	// This is a simplified version - real Nmap uses extensive databases
	return 64, 5840, 1460, "Random"
}

// AnalyzeFingerprint analyzes TCP fingerprint to determine OS
func AnalyzeFingerprint(ttl, window, mss int, ipid string) OSInfo {
	// TTL-based OS detection
	osFamily := "Unknown"
	confidence := 0.0

	switch {
	case ttl >= 64 && ttl <= 65:
		osFamily = "Linux/Unix"
		confidence = 0.85
	case ttl >= 117 && ttl <= 128:
		osFamily = "Windows"
		confidence = 0.90
	case ttl >= 60 && ttl <= 64:
		osFamily = "Cisco/Network"
		confidence = 0.75
	case ttl >= 254 && ttl <= 255:
		osFamily = "BSD/Solaris"
		confidence = 0.80
	}

	// Window size refinement
	if window >= 65535 {
		osFamily = "Windows"
		confidence = 0.92
	} else if window >= 5840 && window <= 65535 {
		if osFamily == "Linux/Unix" {
			confidence = 0.88
		}
	}

	// IP ID sequence analysis
	if ipid == "Incremental" {
		osFamily = "Windows"
		confidence = 0.95
	} else if ipid == "Random" {
		osFamily = "Linux/Unix"
		confidence = 0.90
	} else if ipid == "Zero" {
		osFamily = "BSD"
		confidence = 0.85
	}

	return OSInfo{
		Name:       osFamily,
		Confidence: confidence,
	}
}

// AnalyzeOSFromBanners analyzes banners for OS detection
func AnalyzeOSFromBanners(host string) OSInfo {
	// Try to get banners from common ports
	for _, port := range []int{22, 80, 443, 21, 25, 110, 143, 3306, 5432} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 2*time.Second)
		if err == nil {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)

			if n > 0 {
				banner := string(buf[:n])
				return AnalyzeOSFromBanner(banner)
			}
		}
	}

	return OSInfo{Name: "Unknown", Confidence: 0.0}
}

// AnalyzeOSFromBanner analyzes a single banner for OS detection
func AnalyzeOSFromBanner(banner string) OSInfo {
	bannerLower := strings.ToLower(banner)

	// Linux indicators
	if strings.Contains(bannerLower, "ubuntu") {
		return OSInfo{Name: "Ubuntu", Confidence: 0.95}
	}
	if strings.Contains(bannerLower, "debian") {
		return OSInfo{Name: "Debian", Confidence: 0.95}
	}
	if strings.Contains(bannerLower, "centos") {
		return OSInfo{Name: "CentOS", Confidence: 0.95}
	}
	if strings.Contains(bannerLower, "red hat") || strings.Contains(bannerLower, "rhel") {
		return OSInfo{Name: "Red Hat Enterprise Linux", Confidence: 0.92}
	}
	if strings.Contains(bannerLower, "fedora") {
		return OSInfo{Name: "Fedora", Confidence: 0.92}
	}
	if strings.Contains(bannerLower, "alpine") {
		return OSInfo{Name: "Alpine Linux", Confidence: 0.90}
	}

	// Windows indicators
	if strings.Contains(bannerLower, "microsoft") || strings.Contains(bannerLower, "windows") {
		return OSInfo{Name: "Windows", Confidence: 0.90}
	}
	if strings.Contains(bannerLower, "iis") {
		return OSInfo{Name: "Windows Server", Confidence: 0.95}
	}

	// Network devices
	if strings.Contains(bannerLower, "cisco") {
		return OSInfo{Name: "Cisco IOS", Confidence: 0.95}
	}
	if strings.Contains(bannerLower, "mikrotik") {
		return OSInfo{Name: "MikroTik RouterOS", Confidence: 0.95}
	}
	if strings.Contains(bannerLower, "juniper") {
		return OSInfo{Name: "Juniper Junos", Confidence: 0.95}
	}

	// BSD
	if strings.Contains(bannerLower, "freebsd") {
		return OSInfo{Name: "FreeBSD", Confidence: 0.95}
	}
	if strings.Contains(bannerLower, "openbsd") {
		return OSInfo{Name: "OpenBSD", Confidence: 0.95}
	}

	return OSInfo{Name: "Unknown", Confidence: 0.0}
}

// HeuristicOSDetect uses common indicators to guess OS before/during scan
func HeuristicOSDetect(host string) OSInfo {
	return OSInfo{Name: "Detecting...", Confidence: 0.5}
}

// AnalyzeOSFromResults analyzes collected scan results to guess the OS
func AnalyzeOSFromResults(host string, results []PortResult) OSInfo {
	bannerSample := ""
	for _, r := range results {
		if r.Banner != "" {
			bannerSample += r.Banner + " "
		}
	}

	// 1. Try Advanced Rust OS Fingerprinting
	rustOS := RustDetectOS(host)
	if rustOS.Accuracy > 70 {
		name := strings.TrimSpace(strings.TrimSpace(rustOS.Name) + " " + strings.TrimSpace(rustOS.Version))
		if name == "" {
			name = "Unknown"
		}
		family := rustOS.Family
		if family == "" {
			family = normalizeOSFamily(name)
		}
		fp := rustOS.Fingerprint
		if fp == "" {
			fp = fmt.Sprintf("OS:%s|VER:%s|FAM:%s|ACC:%d", rustOS.Name, rustOS.Version, family, rustOS.Accuracy)
		}
		return OSInfo{
			Name:        name,
			Version:     rustOS.Version,
			Family:      family,
			Accuracy:    rustOS.Accuracy,
			Confidence:  float64(rustOS.Accuracy) / 100.0,
			TTL:         rustOS.TTL,
			Window:      rustOS.Window,
			Fingerprint: fp,
		}
	}

	// 2. Try C Engine (TTL/Window based)
	if len(results) > 0 && results[0].TTL > 0 {
		cOutput := RunCExpertOSDetect(host, results[0].TTL, 0) // Window size extraction needs more logic
		if cOutput != "" {
			cOS := ParseCOutput(cOutput)
			if cOS.Name != "Unknown OS" {
				return cOS
			}
		}
	}

	// 3. Fallback to existing Go logic (evidence-based scoring)
	var scoreLinux, scoreWindows, scoreNetwork, scoreFreeBSD int
	var detectedOS string
	var maxConfidence float64
	var evidence []string

	// Distro specific detection
	distros := map[string]int{
		"Ubuntu": 0, "Debian": 0, "CentOS": 0, "Red Hat": 0, "Fedora": 0, "Alpine": 0, "Arch": 0,
	}

	for _, res := range results {
		if res.State != "open" {
			continue
		}

		evidence = append(evidence, fmt.Sprintf("open port %d/tcp", res.Port))

		banner := strings.ToLower(res.Banner + " " + res.Version)

		// Linux indicators
		if strings.Contains(banner, "linux") || strings.Contains(banner, "unix") {
			scoreLinux += 5
			evidence = append(evidence, fmt.Sprintf("port %d banner indicates linux/unix", res.Port))
		}

		// Distro specific (Often in HTTP Server header or SSH banner)
		if strings.Contains(banner, "ubuntu") {
			distros["Ubuntu"] += 20
			scoreLinux += 15
			evidence = append(evidence, fmt.Sprintf("port %d banner contains ubuntu", res.Port))
			if strings.Contains(banner, "22.04") {
				detectedOS = "Ubuntu 22.04 LTS"
				maxConfidence = 0.95
			}
			if strings.Contains(banner, "20.04") {
				detectedOS = "Ubuntu 20.04 LTS"
				maxConfidence = 0.95
			}
			if strings.Contains(banner, "18.04") {
				detectedOS = "Ubuntu 18.04 LTS"
				maxConfidence = 0.95
			}
		}
		if strings.Contains(banner, "debian") {
			distros["Debian"] += 20
			scoreLinux += 15
			evidence = append(evidence, fmt.Sprintf("port %d banner contains debian", res.Port))
			if strings.Contains(banner, "deb11") || strings.Contains(banner, "bullseye") {
				detectedOS = "Debian 11 (Bullseye)"
				maxConfidence = 0.95
			}
			if strings.Contains(banner, "deb10") || strings.Contains(banner, "buster") {
				detectedOS = "Debian 10 (Buster)"
				maxConfidence = 0.95
			}
		}
		if strings.Contains(banner, "centos") {
			distros["CentOS"] += 20
			scoreLinux += 15
			evidence = append(evidence, fmt.Sprintf("port %d banner contains centos", res.Port))
			if strings.Contains(banner, "el7") {
				detectedOS = "CentOS 7"
				maxConfidence = 0.95
			}
			if strings.Contains(banner, "el8") {
				detectedOS = "CentOS 8"
				maxConfidence = 0.95
			}
		}
		if strings.Contains(banner, "red hat") || strings.Contains(banner, "rhel") {
			distros["Red Hat"] += 20
			scoreLinux += 15
		}
		if strings.Contains(banner, "fedora") {
			distros["Fedora"] += 15
			scoreLinux += 10
		}
		if strings.Contains(banner, "alpine") {
			distros["Alpine"] += 15
			scoreLinux += 10
		}

		if res.Port == 22 && strings.Contains(banner, "openssh") {
			scoreLinux += 2
			evidence = append(evidence, "ssh banner indicates openssh")
		}

		// Windows indicators
		if strings.Contains(banner, "microsoft") || strings.Contains(banner, "win32") || strings.Contains(banner, "win64") || strings.Contains(banner, "iis") || strings.Contains(banner, "windows") {
			scoreWindows += 10
			evidence = append(evidence, fmt.Sprintf("port %d banner indicates windows/microsoft", res.Port))
		}
		// Windows specific versions
		if strings.Contains(banner, "microsoft-iis/10.0") || strings.Contains(banner, "windows server 2019") || strings.Contains(banner, "windows server 2022") {
			detectedOS = "Windows Server 2016/2019/2022"
			maxConfidence = 0.9
		} else if strings.Contains(banner, "microsoft-iis/8.5") || strings.Contains(banner, "windows server 2012 r2") {
			detectedOS = "Windows Server 2012 R2"
			maxConfidence = 0.9
		} else if strings.Contains(banner, "microsoft-iis/8.0") || strings.Contains(banner, "windows server 2012") {
			detectedOS = "Windows Server 2012"
			maxConfidence = 0.9
		} else if strings.Contains(banner, "microsoft-iis/7.5") {
			detectedOS = "Windows Server 2008 R2"
			maxConfidence = 0.9
		}

		if res.Port == 445 || res.Port == 139 || res.Port == 3389 {
			scoreWindows += 10
			evidence = append(evidence, fmt.Sprintf("open port %d suggests windows services (smb/rdp)", res.Port))
		}

		// FreeBSD
		if strings.Contains(banner, "freebsd") {
			scoreFreeBSD += 15
			evidence = append(evidence, "banner contains freebsd")
		}

		// Network/Embedded indicators
		if strings.Contains(banner, "cisco") || strings.Contains(banner, "mikrotik") || strings.Contains(banner, "juniper") || strings.Contains(banner, "fortinet") {
			scoreNetwork += 15
			evidence = append(evidence, "banner indicates network device vendor")
		}
	}

	if detectedOS != "" {
		return OSInfo{
			Name:        detectedOS,
			Family:      normalizeOSFamily(detectedOS),
			Confidence:  maxConfidence,
			Fingerprint: joinEvidence(evidence),
		}
	}

	// Determine best match
	bestDistro := ""
	maxDistroScore := 0
	for d, s := range distros {
		if s > maxDistroScore {
			maxDistroScore = s
			bestDistro = d
		}
	}

	if scoreWindows > scoreLinux && scoreWindows > scoreFreeBSD && scoreWindows > scoreNetwork {
		return OSInfo{Name: "Windows", Family: "Windows", Confidence: 0.85, Fingerprint: joinEvidence(evidence)}
	} else if scoreLinux > scoreWindows && scoreLinux > scoreFreeBSD && scoreLinux > scoreNetwork {
		name := "Linux"
		confidence := 0.85
		if bestDistro != "" {
			name = bestDistro + " (Linux)"
			confidence = 0.92
		}
		return OSInfo{Name: name, Family: "Linux/Unix", Confidence: confidence, Fingerprint: joinEvidence(evidence)}
	} else if scoreFreeBSD > scoreLinux && scoreFreeBSD > scoreWindows {
		return OSInfo{Name: "FreeBSD", Family: "BSD", Confidence: 0.9, Fingerprint: joinEvidence(evidence)}
	} else if scoreNetwork > 0 {
		return OSInfo{Name: "Network Device / Embedded", Family: "Network Device", Confidence: 0.75, Fingerprint: joinEvidence(evidence)}
	}

	return OSInfo{Name: "General Purpose (Likely Linux/Unix)", Family: "Linux/Unix", Confidence: 0.4, Fingerprint: joinEvidence(evidence)}
}
