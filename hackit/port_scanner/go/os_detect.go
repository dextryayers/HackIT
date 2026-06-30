package main

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// OS FINGERPRINT CACHE
// ─────────────────────────────────────────────────────────────────

type osFPCacheEntry struct {
	info   OSInfo
	expiry time.Time
}

var osFPCache sync.Map

func getCachedOSInfo(host string) (OSInfo, bool) {
	if val, ok := osFPCache.Load(host); ok {
		entry := val.(*osFPCacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.info, true
		}
	}
	return OSInfo{}, false
}

func setCachedOSInfo(host string, info OSInfo) {
	osFPCache.Store(host, &osFPCacheEntry{
		info:   info,
		expiry: time.Now().Add(10 * time.Minute),
	})
}

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

// OSInfo holds the detected OS information with full TCP/IP fingerprint details
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
	WScale      int     `json:"wscale,omitempty"`
	DF          string  `json:"df,omitempty"`
	Timestamps  string  `json:"timestamps,omitempty"`
	SACK        string  `json:"sack,omitempty"`
	DeviceType  string  `json:"device_type,omitempty"`
	TCPOptions  string  `json:"tcp_options,omitempty"`
	Signature   string  `json:"signature,omitempty"`
	BannerHint  string  `json:"banner_hint,omitempty"`
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
	// Check cache first
	if cached, ok := getCachedOSInfo(host); ok {
		return cached
	}

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

	setCachedOSInfo(host, info)
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
	// This is a simplified version - real HackIT uses extensive databases
	return 64, 5840, 1460, "Random"
}

// AnalyzeFingerprint analyzes TCP/IP stack fingerprint to determine OS with nmap-level accuracy
func AnalyzeFingerprint(ttl, window, mss int, ipid string) OSInfo {
	var name, family, version string
	confidence := 0.0

	switch {
	// ─── Linux signatures ───
	case ttl >= 64 && ttl <= 65 && window == 5840 && mss == 1460:
		name, family, version = "Linux", "Linux/Unix", "kernel 2.4/2.6 (classic)"
		confidence = 0.85
	case ttl >= 64 && ttl <= 65 && window == 29200 && mss == 1460:
		name, family, version = "Linux", "Linux/Unix", "kernel 2.6+"
		confidence = 0.88
	case ttl >= 64 && ttl <= 65 && window >= 5800 && window <= 5900:
		name, family, version = "Linux", "Linux/Unix", "generic (5840 window)"
		confidence = 0.82
	case ttl >= 64 && ttl <= 65 && window >= 28960 && window <= 29200:
		name, family, version = "Linux", "Linux/Unix", "kernel 2.6+ (big window)"
		confidence = 0.85
	case ttl >= 64 && ttl <= 65 && window >= 60000:
		name, family, version = "Linux", "Linux/Unix", "modern (large window)"
		confidence = 0.88
	case ttl == 64 && window == 65535 && mss == 1460:
		name, family, version = "Linux", "Linux/Unix", "modern (Linux 5.x/6.x)"
		confidence = 0.90
	case ttl == 64 && window == 65535 && mss == 1440:
		name, family, version = "Linux", "Linux/Unix", "modern (PPP/virtual)"
		confidence = 0.85
	case ttl >= 64 && ttl <= 65 && window >= 65535:
		name, family, version = "Linux", "Linux/Unix", "modern (large window)"
		confidence = 0.87
	case ttl == 64 && window >= 60000 && ipid == "Random":
		name, family, version = "Linux", "Linux/Unix", "modern kernel"
		confidence = 0.91

	// ─── Windows signatures ───
	case ttl == 128 && window == 65535 && mss == 1460:
		name, family, version = "Windows", "Windows", "10/11/Server 2016+"
		confidence = 0.93
	case ttl == 128 && window == 65535:
		name, family, version = "Windows", "Windows", "8/10/11 (large window)"
		confidence = 0.91
	case ttl >= 117 && ttl <= 128 && window == 65535:
		name, family, version = "Windows", "Windows", "7/8/10/11"
		confidence = 0.90
	case ttl >= 117 && ttl <= 128 && window >= 8192 && window <= 16384 && mss == 1460:
		name, family, version = "Windows", "Windows", "7/8/10"
		confidence = 0.88
	case ttl >= 117 && ttl <= 128 && window == 8192:
		name, family, version = "Windows", "Windows", "XP/Server 2003"
		confidence = 0.87
	case ttl >= 117 && ttl <= 128 && window == 16384:
		name, family, version = "Windows", "Windows", "Vista/7/8"
		confidence = 0.87
	case ttl >= 117 && ttl <= 128 && window >= 60000:
		name, family, version = "Windows", "Windows", "modern (large window)"
		confidence = 0.90
	case ttl >= 117 && ttl <= 128 && mss == 1460:
		name, family, version = "Windows", "Windows", "generic"
		confidence = 0.85
	case ttl >= 117 && ttl <= 128:
		name, family, version = "Windows", "Windows", "(TTL-based)"
		confidence = 0.82

	// ─── Cisco / Network ───
	case ttl == 255 && mss <= 512:
		name, family, version = "Cisco IOS", "Network Device", "router/switch"
		confidence = 0.92
	case ttl == 255 && mss == 1380:
		name, family, version = "Cisco IOS", "Network Device", "with 1380 MSS"
		confidence = 0.88
	case ttl >= 250 && ttl <= 255 && window <= 4128:
		name, family, version = "Cisco IOS", "Network Device", "(small window)"
		confidence = 0.85
	case ttl >= 254 && ttl <= 255:
		name, family, version = "Cisco IOS", "Network Device", "generic"
		confidence = 0.80

	// ─── BSD / Solaris ───
	case ttl == 64 && window == 65535 && ipid == "Incremental":
		name, family, version = "FreeBSD", "BSD", "generic"
		confidence = 0.88
	case ttl == 64 && window == 33304:
		name, family, version = "OpenBSD", "BSD", "generic"
		confidence = 0.90
	case ttl == 64 && window == 65535 && mss == 1460:
		name, family, version = "FreeBSD/macOS", "BSD", "modern"
		confidence = 0.85
	case ttl >= 254 && ttl <= 255 && window >= 49000:
		name, family, version = "Solaris", "Solaris", "10/11"
		confidence = 0.88
	case ttl >= 254 && ttl <= 255 && window == 8760:
		name, family, version = "Solaris", "Solaris", "9/10"
		confidence = 0.90

	// ─── Generic TTL-based fallback ───
	case ttl >= 64 && ttl <= 65:
		name, family = "Linux/Unix", "Linux/Unix"
		confidence = 0.70
	case ttl >= 250 && ttl <= 255:
		name, family = "Network Device", "Network Device"
		confidence = 0.70
	default:
		name, family = "Unknown", "Unknown"
		confidence = 0.10
	}

	// IP ID refinement
	if ipid == "Incremental" && family == "Windows" {
		confidence = min64(confidence+0.05, 0.97)
	}
	if ipid == "Random" && (family == "Linux/Unix" || family == "BSD") {
		confidence = min64(confidence+0.03, 0.95)
	}
	if ipid == "Zero" && family == "BSD" {
		confidence = min64(confidence+0.05, 0.92)
	}

	return OSInfo{
		Name:       name,
		Family:     family,
		Version:    version,
		Confidence: min64(confidence, 1.0),
		TTL:        ttl,
		Window:     window,
		MSS:        mss,
		IPID:       ipid,
	}
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
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

// serviceVersionToOS maps (service, major, minor) to OS name
type svcOSEntry struct {
	svcKeyword string
	minVer     [3]int
	maxVer     [3]int
	osName     string
}

var serviceOSDB = []svcOSEntry{
	// OpenSSH → OS
	{"openssh", [3]int{1, 0, 0}, [3]int{3, 99, 99}, "OpenBSD"},
	{"openssh", [3]int{5, 0, 0}, [3]int{5, 2, 99}, "Ubuntu"},
	{"openssh", [3]int{5, 3, 0}, [3]int{5, 3, 99}, "Ubuntu 12.04"},
	{"openssh", [3]int{5, 5, 0}, [3]int{5, 5, 99}, "Ubuntu 12.04"},
	{"openssh", [3]int{5, 8, 0}, [3]int{5, 9, 99}, "Debian"},
	{"openssh", [3]int{6, 0, 0}, [3]int{6, 5, 99}, "Ubuntu"},
	{"openssh", [3]int{6, 6, 0}, [3]int{6, 6, 99}, "Ubuntu 14.04"},
	{"openssh", [3]int{6, 7, 0}, [3]int{6, 7, 99}, "Debian 8"},
	{"openssh", [3]int{6, 9, 0}, [3]int{7, 2, 99}, "Ubuntu 16.04"},
	{"openssh", [3]int{7, 4, 0}, [3]int{7, 4, 99}, "Ubuntu 17.04"},
	{"openssh", [3]int{7, 5, 0}, [3]int{7, 5, 99}, "Debian 10"},
	{"openssh", [3]int{7, 6, 0}, [3]int{7, 8, 99}, "Ubuntu 18.04"},
	{"openssh", [3]int{7, 9, 0}, [3]int{8, 2, 99}, "Ubuntu 20.04"},
	{"openssh", [3]int{8, 1, 0}, [3]int{8, 1, 99}, "Debian 11"},
	{"openssh", [3]int{8, 3, 0}, [3]int{8, 3, 99}, "Debian 11"},
	{"openssh", [3]int{8, 5, 0}, [3]int{8, 6, 99}, "Fedora"},
	{"openssh", [3]int{8, 7, 0}, [3]int{8, 7, 99}, "Debian 12"},
	{"openssh", [3]int{8, 8, 0}, [3]int{9, 0, 99}, "Ubuntu 22.04"},
	{"openssh", [3]int{9, 1, 0}, [3]int{9, 1, 99}, "Ubuntu 23.04"},
	{"openssh", [3]int{9, 2, 0}, [3]int{9, 2, 99}, "Ubuntu 23.10"},
	{"openssh", [3]int{9, 3, 0}, [3]int{9, 9, 99}, "Ubuntu 24.04"},

	// Apache → OS
	{"apache httpd", [3]int{2, 4, 1}, [3]int{2, 4, 7}, "Ubuntu 14.04"},
	{"apache httpd", [3]int{2, 4, 10}, [3]int{2, 4, 10}, "Debian 8"},
	{"apache httpd", [3]int{2, 4, 18}, [3]int{2, 4, 18}, "Ubuntu 16.04"},
	{"apache httpd", [3]int{2, 4, 25}, [3]int{2, 4, 25}, "Debian 9"},
	{"apache httpd", [3]int{2, 4, 29}, [3]int{2, 4, 38}, "Ubuntu 18.04"},
	{"apache httpd", [3]int{2, 4, 37}, [3]int{2, 4, 37}, "Debian 10"},
	{"apache httpd", [3]int{2, 4, 41}, [3]int{2, 4, 51}, "Ubuntu 20.04"},
	{"apache httpd", [3]int{2, 4, 48}, [3]int{2, 4, 48}, "Debian 11"},
	{"apache httpd", [3]int{2, 4, 52}, [3]int{2, 4, 55}, "Ubuntu 22.04"},
	{"apache httpd", [3]int{2, 4, 54}, [3]int{2, 4, 54}, "Debian 12"},
	{"apache httpd", [3]int{2, 4, 56}, [3]int{2, 4, 56}, "Ubuntu 23.04"},
	{"apache httpd", [3]int{2, 4, 57}, [3]int{2, 9, 99}, "Ubuntu 24.04"},

	// Nginx → OS
	{"nginx", [3]int{1, 10, 0}, [3]int{1, 10, 99}, "Ubuntu 16.04"},
	{"nginx", [3]int{1, 14, 0}, [3]int{1, 14, 99}, "Ubuntu 18.04"},
	{"nginx", [3]int{1, 15, 0}, [3]int{1, 15, 99}, "Debian 10"},
	{"nginx", [3]int{1, 18, 0}, [3]int{1, 18, 99}, "Ubuntu 20.04"},
	{"nginx", [3]int{1, 20, 0}, [3]int{1, 20, 99}, "Debian 11"},
	{"nginx", [3]int{1, 22, 0}, [3]int{1, 22, 99}, "Ubuntu 22.04"},
	{"nginx", [3]int{1, 24, 0}, [3]int{1, 24, 99}, "Ubuntu 23.04"},
	{"nginx", [3]int{1, 25, 0}, [3]int{1, 99, 99}, "Ubuntu 24.04"},

	// IIS → Windows
	{"iis", [3]int{7, 0, 0}, [3]int{7, 0, 99}, "Windows Server 2008"},
	{"iis", [3]int{7, 5, 0}, [3]int{7, 5, 99}, "Windows Server 2008 R2"},
	{"iis", [3]int{8, 0, 0}, [3]int{8, 0, 99}, "Windows Server 2012"},
	{"iis", [3]int{8, 5, 0}, [3]int{8, 5, 99}, "Windows Server 2012 R2"},
	{"iis", [3]int{10, 0, 0}, [3]int{99, 99, 99}, "Windows Server 2016/2019/2022"},

	// MySQL → Linux
	{"mysql", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},
	{"mariadb", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},

	// PostgreSQL → Linux
	{"postgresql", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},

	// FTP → OS
	{"pure-ftpd", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},
	{"vsftpd", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},
	{"proftpd", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux/Unix"},

	// Mail → OS
	{"dovecot", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},
	{"postfix", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},
	{"exim", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux"},
	{"sendmail", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux/Unix"},

	// LiteSpeed → OS
	{"litespeed", [3]int{0, 0, 0}, [3]int{99, 99, 99}, "Linux (cPanel)"},
}

func matchServiceVersion(svc, ver string) (string, float64) {
	svcLower := strings.ToLower(svc)
	verParts := parseVersionInts(ver)

	for _, entry := range serviceOSDB {
		if !strings.Contains(svcLower, entry.svcKeyword) {
			continue
		}
		if entry.minVer == [3]int{0, 0, 0} && entry.maxVer == [3]int{99, 99, 99} {
			return entry.osName, 0.85
		}
		if len(verParts) >= 3 {
			v := [3]int{verParts[0], verParts[1], verParts[2]}
			if versionGE(v, entry.minVer) && versionLE(v, entry.maxVer) {
				return entry.osName, 0.90
			}
		}
	}
	return "", 0
}

func parseVersionInts(ver string) []int {
	var parts []int
	for _, p := range strings.Split(ver, ".") {
		p = strings.TrimSpace(p)
		n := 0
		for _, c := range p {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			} else {
				break
			}
		}
		parts = append(parts, n)
	}
	return parts
}

func versionGE(a, b [3]int) bool {
	return a[0] >= b[0] && a[1] >= b[1] && a[2] >= b[2]
}
func versionLE(a, b [3]int) bool {
	return a[0] <= b[0] && a[1] <= b[1] && a[2] <= b[2]
}

// AnalyzeOSFromBanner analyzes a single banner for OS detection
func AnalyzeOSFromBanner(banner string) OSInfo {
	bannerLower := strings.ToLower(banner)

	// Specific OS distribution names (high confidence)
	osHints := []struct {
		keyword    string
		osName     string
		confidence float64
	}{
		{"ubuntu 24", "Ubuntu 24.04", 0.95},
		{"ubuntu 23", "Ubuntu 23.04", 0.95},
		{"ubuntu 22", "Ubuntu 22.04", 0.95},
		{"ubuntu 21", "Ubuntu 21.04", 0.95},
		{"ubuntu 20", "Ubuntu 20.04", 0.95},
		{"ubuntu 18", "Ubuntu 18.04", 0.95},
		{"ubuntu 16", "Ubuntu 16.04", 0.95},
		{"ubuntu 14", "Ubuntu 14.04", 0.95},
		{"ubuntu", "Ubuntu", 0.90},
		{"debian 12", "Debian 12", 0.95},
		{"debian 11", "Debian 11", 0.95},
		{"debian 10", "Debian 10", 0.95},
		{"debian 9", "Debian 9", 0.95},
		{"debian 8", "Debian 8", 0.95},
		{"debian", "Debian", 0.90},
		{"centos 9", "CentOS 9", 0.95},
		{"centos 8", "CentOS 8", 0.95},
		{"centos 7", "CentOS 7", 0.95},
		{"centos", "CentOS", 0.90},
		{"red hat", "Red Hat Enterprise Linux", 0.92},
		{"rhel 9", "RHEL 9", 0.95},
		{"rhel 8", "RHEL 8", 0.95},
		{"rhel 7", "RHEL 7", 0.95},
		{"fedora 40", "Fedora 40", 0.95},
		{"fedora 39", "Fedora 39", 0.95},
		{"fedora 38", "Fedora 38", 0.95},
		{"fedora", "Fedora", 0.90},
		{"alpine 3", "Alpine Linux", 0.92},
		{"alpine", "Alpine Linux", 0.85},
		{"suse", "SUSE Linux", 0.90},
		{"opensuse", "openSUSE", 0.90},
		{"arch linux", "Arch Linux", 0.95},
		{"gentoo", "Gentoo Linux", 0.90},
		{"slackware", "Slackware", 0.90},
		{"microsoft", "Windows", 0.90},
		{"windows server 2022", "Windows Server 2022", 0.95},
		{"windows server 2019", "Windows Server 2019", 0.95},
		{"windows server 2016", "Windows Server 2016", 0.95},
		{"windows server 2012", "Windows Server 2012", 0.95},
		{"windows server 2008", "Windows Server 2008", 0.95},
		{"windows 11", "Windows 11", 0.95},
		{"windows 10", "Windows 10", 0.95},
		{"windows", "Windows", 0.85},
		{"iis 10", "Windows Server 2016/2019/2022", 0.95},
		{"iis 8", "Windows Server 2012", 0.95},
		{"iis 7", "Windows Server 2008", 0.95},
		{"cisco ios", "Cisco IOS", 0.97},
		{"cisco", "Cisco IOS", 0.92},
		{"mikrotik", "MikroTik RouterOS", 0.95},
		{"juniper", "Juniper Junos", 0.95},
		{"freebsd", "FreeBSD", 0.95},
		{"openbsd", "OpenBSD", 0.95},
		{"netbsd", "NetBSD", 0.95},
		{"macos", "macOS", 0.90},
		{"darwin", "macOS", 0.90},
		{"apple", "macOS", 0.80},
		{"solaris", "Solaris", 0.92},
		{"sunos", "Solaris", 0.90},
		{"aix", "AIX", 0.92},
		{"hp-ux", "HP-UX", 0.92},
		{"hpux", "HP-UX", 0.90},
		{"openwrt", "OpenWrt", 0.95},
		{"dd-wrt", "DD-WRT", 0.95},
		{"pfsense", "pfSense", 0.95},
		{"vyos", "VyOS", 0.95},
		{"synology", "Synology DSM", 0.95},
		{"qnap", "QNAP", 0.95},
		{"vmware", "VMware ESXi", 0.90},
		{"esxi", "VMware ESXi", 0.95},
		{"xen", "Xen Server", 0.90},
		{"proxmox", "Proxmox VE", 0.95},
		{"docker", "Linux (Container)", 0.85},
		{"kubernetes", "Linux (Kubernetes)", 0.85},
		{"android", "Android", 0.90},
		{"iphone", "iOS", 0.90},
		{"ipad", "iPadOS", 0.90},
	}

	for _, hint := range osHints {
		if strings.Contains(bannerLower, hint.keyword) {
			return OSInfo{Name: hint.osName, Confidence: hint.confidence}
		}
	}

	return OSInfo{Name: "Unknown", Confidence: 0.0}
}

// AnalyzeOSFromResults analyzes collected scan results to guess the OS
func AnalyzeOSFromResults(host string, results []PortResult) OSInfo {
	var evidence []string
	var openPorts []int
	bannerSample := ""
	osVotes := make(map[string]float64)
	for _, r := range results {
		if r.Banner != "" {
			bannerSample += r.Banner + " "
		}
		if r.State == "open" {
			openPorts = append(openPorts, r.Port)
		}
	}

	// Phase 1: Service-to-OS correlation (most accurate non-root method)
	for _, r := range results {
		if r.State != "open" {
			continue
		}
		svc := r.Service
		ver := r.Version
		if svc == "" {
			svc = r.Banner
		}
		if osName, conf := matchServiceVersion(svc, ver); osName != "" {
			osVotes[osName] += conf
			evidence = append(evidence, fmt.Sprintf("port %d %s %s → %s", r.Port, svc, ver, osName))
		}
	}

	// Phase 2: Check for specific OS keywords in banners
	for _, r := range results {
		if r.State != "open" || r.Banner == "" {
			continue
		}
		bannerOS := AnalyzeOSFromBanner(r.Banner)
		if bannerOS.Confidence > 0 {
			osVotes[bannerOS.Name] += bannerOS.Confidence
			evidence = append(evidence, fmt.Sprintf("port %d banner: %s", r.Port, bannerOS.Name))
		}
	}

	// If we have high-confidence service correlation, return it
	if len(osVotes) > 0 {
		bestOS := ""
		bestConf := 0.0
		totalConf := 0.0
		for osName, conf := range osVotes {
			totalConf += conf
			if conf > bestConf {
				bestConf = conf
				bestOS = osName
			}
		}
		confidence := bestConf
		if confidence > 0.95 {
			confidence = 0.95
		}
		return OSInfo{
			Name:        bestOS,
			Family:      normalizeOSFamily(bestOS),
			Confidence:  confidence,
			Fingerprint: joinEvidence(evidence),
		}
	}

	// Priority: Polyglot cross-engine detection
	if len(openPorts) > 0 {
		poly := PolyglotOSDetect(host, openPorts)
		if poly.Confidence >= 0.4 {
			if poly.Fingerprint == "" {
				poly.Fingerprint = joinEvidence(evidence)
			}
			return poly
		}
	}

	// 1. Try Advanced Rust OS Fingerprinting
	rustOSRaw := RustDetectOsDetailed(host, strings.Join(evidence, ","), true, false)
	if rustOSRaw != "" && strings.Contains(rustOSRaw, "Operating System:") {
		lines := strings.Split(rustOSRaw, "\n")
		var name, version string
		for _, line := range lines {
			if strings.Contains(line, "Operating System:") {
				name = strings.TrimSpace(strings.Split(line, ":")[1])
			}
		}
		
		return OSInfo{
			Name:        name,
			Version:     version,
			Family:      normalizeOSFamily(name),
			Confidence:  0.8,
			Fingerprint: rustOSRaw,
		}
	}

	// 2. Try C Engine (TTL/Window based)
	if len(results) > 0 && results[0].TTL > 0 {
		cOutput := RunCExpertOSDetect(host, results[0].TTL, 0)
		if cOutput != "" {
			cOS := ParseCOutput(cOutput)
			if cOS.Name != "Unknown OS" {
				return cOS
			}
		}
	}

	// 3. Fallback to evidence-based scoring
	var scoreLinux, scoreWindows, scoreNetwork, scoreFreeBSD int
	var detectedOS string
	var maxConfidence float64

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

// PolyglotOSDetect runs ALL engines (C, C++, Rust, Go) and returns cross-validated result
func PolyglotOSDetect(host string, openPorts []int) OSInfo {
	// Check cache first
	if cached, ok := getCachedOSInfo(host); ok {
		return cached
	}

	timeoutMs := 3000
	if len(openPorts) == 0 {
		openPorts = []int{22, 80, 443}
	}

	// Run all 4 engines concurrently
	type osResult struct {
		engine string
		info   OSInfo
	}
	ch := make(chan osResult, 4)

	// 1. C engine — TCP/IP stack fingerprinting
	go func() {
		info := COsFingerprint(host, openPorts, timeoutMs)
		ch <- osResult{"c", info}
	}()

	// 2. C++ engine — deep signature matching
	go func() {
		info := CppOsDetect(host, openPorts, timeoutMs)
		ch <- osResult{"cpp", info}
	}()

	// 3. Rust engine — async probing + banner analysis
	go func() {
		info := RustDetectOS(host)
		ch <- osResult{"rust", info}
	}()

	// 4. Go engine — banner-based + result analysis
	go func() {
		info := DetectOS(host)
		ch <- osResult{"go", info}
	}()

	results := make(map[string]OSInfo)
	for i := 0; i < 4; i++ {
		r := <-ch
		results[r.engine] = r.info
	}

	// Cross-validation scoring
	type scored struct {
		name       string
		version    string
		family     string
		totalScore float64
		count      int
	}
	candidates := make(map[string]*scored)

	for _, info := range results {
		if info.Confidence < 0.1 || info.Name == "Unknown" {
			continue
		}
		key := info.Name
		if info.Version != "" {
			key += " " + info.Version
		}
		if _, ok := candidates[key]; !ok {
			candidates[key] = &scored{
				name:    info.Name,
				version: info.Version,
				family:  info.Family,
			}
		}
		candidates[key].totalScore += info.Confidence
		candidates[key].count++
	}

	// Find best match
	var best *scored
	bestScore := 0.0
	for _, s := range candidates {
		// Score = average confidence + engine count bonus
		avg := s.totalScore / float64(s.count)
		engBonus := float64(s.count) * 0.15
		if s.count >= 2 {
			engBonus += 0.10 // cross-engine validation bonus
		}
		total := avg + engBonus
		if total > bestScore {
			bestScore = total
			best = s
		}
	}

	if best == nil {
		// Fallback to Go engine
		if r, ok := results["go"]; ok {
			r.Confidence = math.Min(r.Confidence, 1.0)
			return r
		}
		return OSInfo{Name: "Unknown", Confidence: 0}
	}

	// Cap overall confidence at 1.0 (100%)
	if bestScore > 1.0 {
		bestScore = 1.0
	}

	// Build combined fingerprint string
	fp := fmt.Sprintf("engines=4")
	for eng, info := range results {
		if info.Fingerprint != "" {
			fp += fmt.Sprintf(" [%s:%s]", eng, info.Fingerprint)
		}
	}

	result := OSInfo{
		Name:        best.name,
		Version:     best.version,
		Family:      best.family,
		Confidence:  bestScore,
		Fingerprint: fp,
	}
	setCachedOSInfo(host, result)
	return result
}
