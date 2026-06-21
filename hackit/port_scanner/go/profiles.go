package main

import (
	"fmt"
	"strings"
	"sync"
)

type Profile struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Ports       []int    `json:"ports"`
	Workers     int      `json:"workers"`
	TimeoutMs   int      `json:"timeout_ms"`
	ScanMode    string   `json:"scan_mode"`
	Stealth     bool     `json:"stealth"`
	Stages      []string `json:"stages"`
	Deep        bool     `json:"deep"`
	OSDetect    bool     `json:"os_detect"`
	VulnScan    bool     `json:"vuln_scan"`
	Adaptive    bool     `json:"adaptive"`
	Quantum     bool     `json:"quantum"`
	UltraDeep   bool     `json:"ultra_deep"`
	MinRate     int      `json:"min_rate"`
	MaxRate     int      `json:"max_rate"`
	MaxRetries  int      `json:"max_retries"`
	HostTimeout int      `json:"host_timeout"`
	NoPing      bool     `json:"no_ping"`
	Script      string   `json:"script"`
}

var profileCache struct {
	once     sync.Once
	profiles map[string]Profile
}

func GetProfile(name string) Profile {
	profileCache.once.Do(initProfiles)

	name = strings.ToLower(strings.TrimSpace(name))

	if p, ok := profileCache.profiles[name]; ok {
		return p
	}

	return profileCache.profiles["quick"]
}

func initProfiles() {
	profileCache.profiles = map[string]Profile{
		"quick":        quickProfile(),
		"stealth":      stealthProfile(),
		"full":         fullProfile(),
		"web":          webProfile(),
		"lan":          lanProfile(),
		"comprehensive": comprehensiveProfile(),
	}
}

func quickProfile() Profile {
	return Profile{
		Name:        "Quick",
		Description: "Fast scan of top 100 common ports",
		Ports:       nil,
		Workers:     200,
		TimeoutMs:   500,
		ScanMode:    "syn",
		Stealth:     false,
		Stages:      []string{"tcp_scan", "service_detect"},
		Deep:        false,
		OSDetect:    false,
		VulnScan:    false,
		Adaptive:    true,
		Quantum:     true,
		UltraDeep:   false,
		MinRate:     5,
		MaxRate:     100,
		MaxRetries:  2,
		HostTimeout: 60,
		NoPing:      false,
		Script:      "",
	}
}

func stealthProfile() Profile {
	return Profile{
		Name:        "Stealth",
		Description: "Low-and-slow SYN scan with evasion techniques",
		Ports:       nil,
		Workers:     10,
		TimeoutMs:   3000,
		ScanMode:    "syn",
		Stealth:     true,
		Stages:      []string{"tcp_scan", "service_detect", "os_detect"},
		Deep:        false,
		OSDetect:    true,
		VulnScan:    false,
		Adaptive:    true,
		Quantum:     true,
		UltraDeep:   false,
		MinRate:     1,
		MaxRate:     10,
		MaxRetries:  5,
		HostTimeout: 600,
		NoPing:      true,
		Script:      "",
	}
}

func fullProfile() Profile {
	return Profile{
		Name:        "Full",
		Description: "Comprehensive scan of all 65535 ports with service detection",
		Ports:       nil,
		Workers:     150,
		TimeoutMs:   1500,
		ScanMode:    "syn",
		Stealth:     false,
		Stages:      []string{"discovery", "tcp_scan", "service_detect", "os_detect", "vuln_scan", "enrich"},
		Deep:        true,
		OSDetect:    true,
		VulnScan:    true,
		Adaptive:    true,
		Quantum:     true,
		UltraDeep:   false,
		MinRate:     3,
		MaxRate:     50,
		MaxRetries:  3,
		HostTimeout: 1800,
		NoPing:      false,
		Script:      "",
	}
}

func webProfile() Profile {
	return Profile{
		Name:        "Web",
		Description: "Web server focused scan (HTTP/HTTPS ports + common web services)",
		Ports:       []int{80, 443, 8080, 8443, 8000, 8888, 9443, 3000, 4000, 5000, 8008, 8069, 9000, 9090, 21, 22, 25, 53, 110, 143, 3306, 5432, 6379, 27017, 3389, 5900, 6443, 2375, 2376, 9200, 11211, 1433, 1521, 5672, 5984, 9042, 9092, 8200, 8500, 2181, 10250, 10255},
		Workers:     100,
		TimeoutMs:   1000,
		ScanMode:    "connect",
		Stealth:     false,
		Stages:      []string{"tcp_scan", "service_detect", "vuln_scan"},
		Deep:        true,
		OSDetect:    false,
		VulnScan:    true,
		Adaptive:    false,
		Quantum:     true,
		UltraDeep:   false,
		MinRate:     0,
		MaxRate:     0,
		MaxRetries:  2,
		HostTimeout: 300,
		NoPing:      true,
		Script:      "http-enum",
	}
}

func lanProfile() Profile {
	return Profile{
		Name:        "LAN",
		Description: "Optimized for local network scanning (low latency, high throughput)",
		Ports:       nil,
		Workers:     300,
		TimeoutMs:   300,
		ScanMode:    "syn",
		Stealth:     false,
		Stages:      []string{"discovery", "tcp_scan", "service_detect", "os_detect", "enrich"},
		Deep:        true,
		OSDetect:    true,
		VulnScan:    false,
		Adaptive:    true,
		Quantum:     true,
		UltraDeep:   false,
		MinRate:     10,
		MaxRate:     200,
		MaxRetries:  1,
		HostTimeout: 120,
		NoPing:      false,
		Script:      "",
	}
}

func comprehensiveProfile() Profile {
	return Profile{
		Name:        "Comprehensive",
		Description: "Maximum depth — all ports, all engines, full vulnerability analysis",
		Ports:       nil,
		Workers:     200,
		TimeoutMs:   2000,
		ScanMode:    "c-turbo",
		Stealth:     false,
		Stages:      []string{"discovery", "tcp_scan", "service_detect", "os_detect", "vuln_scan", "enrich"},
		Deep:        true,
		OSDetect:    true,
		VulnScan:    true,
		Adaptive:    true,
		Quantum:     true,
		UltraDeep:   true,
		MinRate:     0,
		MaxRate:     0,
		MaxRetries:  4,
		HostTimeout: 3600,
		NoPing:      false,
		Script:      "all",
	}
}

func ListProfiles() []Profile {
	profileCache.once.Do(initProfiles)
	profiles := make([]Profile, 0, len(profileCache.profiles))
	for _, p := range profileCache.profiles {
		profiles = append(profiles, p)
	}
	return profiles
}

func (p Profile) String() string {
	portStr := "default"
	if len(p.Ports) > 0 {
		ps := make([]string, 0, len(p.Ports))
		for _, port := range p.Ports {
			ps = append(ps, fmt.Sprintf("%d", port))
		}
		portStr = strings.Join(ps, ",")
	}
	return fmt.Sprintf("%s[%s] workers=%d timeout=%dms mode=%s ports=%s deep=%v os=%v vuln=%v",
		p.Name, p.Description, p.Workers, p.TimeoutMs, p.ScanMode, portStr, p.Deep, p.OSDetect, p.VulnScan)
}
