package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	// The C binary returns OS|Details|Confidence
	cmd := exec.Command(binary, host, fmt.Sprintf("%d", ttl), fmt.Sprintf("%d", window))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		output := strings.TrimSpace(out.String())
		if output != "" && strings.Contains(output, "|") {
			return output
		}
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

// DetectOS performs OS detection based on TTL and TCP window size
func DetectOS(host string) OSInfo {
	// Default info
	info := OSInfo{Name: "Unknown", Confidence: 0.0}

	// Resolve IP to ensure we have a direct connection
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return info
	}
	ip := ips[0].String()

	// 1. TTL-based detection
	// We'll try to get TTL by sending a ping or a quick TCP connection
	// For simplicity and compatibility, we'll use a heuristic based on banners first
	// but we can add a TTL check here if we have a way to read IP headers.
	_ = ip // Future use for TTL probes

	// Since we are already doing port scanning, the engine will call AnalyzeOSFromResults.
	// We'll return a placeholder here that AnalyzeOSFromResults will refine.
	return HeuristicOSDetect(host)
}

// HeuristicOSDetect uses common indicators to guess OS before/during scan
func HeuristicOSDetect(host string) OSInfo {
	// Try to get TTL via a simple ping-like mechanism if possible,
	// or just return a base detection.
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
		return OSInfo{
			Name:       rustOS.Name + " " + rustOS.Version,
			Confidence: float64(rustOS.Accuracy) / 100.0,
			Fingerprint: fmt.Sprintf("OS:%s|VER:%s|FAM:%s|ACC:%d",
				rustOS.Name, rustOS.Version, rustOS.Family, rustOS.Accuracy),
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

	// 3. Fallback to existing Go logic
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

		banner := strings.ToLower(res.Banner + " " + res.Version)

		// Linux indicators
		if strings.Contains(banner, "linux") || strings.Contains(banner, "unix") {
			scoreLinux += 5
		}

		// Distro specific (Often in HTTP Server header or SSH banner)
		if strings.Contains(banner, "ubuntu") {
			distros["Ubuntu"] += 20
			scoreLinux += 15
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
		}

		// Windows indicators
		if strings.Contains(banner, "microsoft") || strings.Contains(banner, "win32") || strings.Contains(banner, "win64") || strings.Contains(banner, "iis") || strings.Contains(banner, "windows") {
			scoreWindows += 10
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
		}

		// FreeBSD
		if strings.Contains(banner, "freebsd") {
			scoreFreeBSD += 15
		}

		// Network/Embedded indicators
		if strings.Contains(banner, "cisco") || strings.Contains(banner, "mikrotik") || strings.Contains(banner, "juniper") || strings.Contains(banner, "fortinet") {
			scoreNetwork += 15
		}
	}

	if detectedOS != "" {
		return OSInfo{Name: detectedOS, Confidence: maxConfidence}
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
		return OSInfo{Name: "Windows", Confidence: 0.85}
	} else if scoreLinux > scoreWindows && scoreLinux > scoreFreeBSD && scoreLinux > scoreNetwork {
		name := "Linux"
		confidence := 0.85
		if bestDistro != "" {
			name = bestDistro + " (Linux)"
			confidence = 0.92
		}
		return OSInfo{Name: name, Confidence: confidence}
	} else if scoreFreeBSD > scoreLinux && scoreFreeBSD > scoreWindows {
		return OSInfo{Name: "FreeBSD", Confidence: 0.9}
	} else if scoreNetwork > 0 {
		return OSInfo{Name: "Network Device / Embedded", Confidence: 0.75}
	}

	return OSInfo{Name: "General Purpose (Likely Linux/Unix)", Confidence: 0.4}
}
