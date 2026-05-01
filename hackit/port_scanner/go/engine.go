package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type PortResult struct {
	Port            int      `json:"port"`
	State           string   `json:"status"`
	Service         string   `json:"service"`
	Banner          string   `json:"banner"`
	Version         string   `json:"version"`
	TTL             int      `json:"ttl"`
	Scripts         []string `json:"scripts,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	DeepAnalysis    string   `json:"deep_analysis,omitempty"`
	RiskScore       float64  `json:"risk_score,omitempty"`
}

type ScanEngine struct {
	Host                   string
	Ports                  []int
	Threads                int
	TimeoutMs              int
	Stealth                bool
	ScanMode               string
	Reporter               *Reporter
	Lua                    *LuaEngine
	LuaScript              string
	LuaArgs                string
	MTU                    int
	DataLength             int
	SourcePort             int
	IdentifyOS             bool
	DetectService          bool
	CustomTTL              int
	SpoofIP                string
	SpoofMAC               string
	PacketSplit            bool
	Traceroute             bool
	IncludeClosed          bool
	BadSum                 bool
	DNSInfo                bool
	ReverseLookup          bool
	SubEnum                bool
	WhoisInfo              bool
	GeoInfo                bool
	ASNInfo                bool
	HttpInspect            bool
	TechAnalyze            bool
	TlsAnalyze             bool
	CertView               bool
	ShowTitle              bool
	DetectHoneypot         bool
	SmartBypass            bool
	RandomOrder            bool
	DecoyIP                string
	UseProxy               string
	UseTor                 bool
	VersionIntensity       int
	OSScanLimit            bool
	OSScanGuess            bool
	HostTimeout            int
	ScanDelay              int
	MaxScanDelay           int
	DefeatRstRateLimit     bool
	DefeatIcmpRateLimit    bool
	NsockEngine            string
	UltraDeep              bool
	VulnScan               bool
}

func (e *ScanEngine) Run() []PortResult {
	if e.Reporter != nil {
		e.Reporter.ReportStatus("Initializing Tactical Discovery Engine", 0)
	}

	ports := e.Ports
	if len(ports) == 0 {
		return nil
	}

	results := make([]PortResult, 0)
	var mutex sync.Mutex
	var wg sync.WaitGroup
	portsChan := make(chan int, e.Threads)

	totalPorts := len(ports)
	processedPorts := 0
	var progressMu sync.Mutex

	workerCount := e.Threads
	if workerCount > totalPorts {
		workerCount = totalPorts
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if port <= 0 || port > 65535 {
					continue
				}
				if e.Stealth {
					jitterSleep(10, 50)
				}

				var res PortResult
				var open bool

				// Multi-Engine Selector logic
				switch e.ScanMode {
				case "udp":
					res, open = ScanUDP(e.Host, port, e.TimeoutMs)
				case "syn":
					// Call Rust for high-speed SYN scan
					res = RustFastScan(e.Host, port, e.TimeoutMs, e.Stealth)
					open = res.State == "open"
				case "c-turbo":
					// Placeholder for C engine call
					res, open = ScanPort(e.Host, port, e.TimeoutMs)
				default:
					res, open = ScanPort(e.Host, port, e.TimeoutMs)
				}

				if open || e.IncludeClosed {
					// 1. Service & Banner Recon (Nmap-Style)
					if e.DetectService && open {
						if res.Banner == "" {
							res.Banner = GrabBannerByHost(e.Host, port, e.TimeoutMs)
						}
						res.Service, res.Version = DetectService(port, res.Banner, e.Host)
					}

					// 2. Vulnerability Discovery (The "Powerfull" part)
					if open {
						// Call specialized vulnerability scanners
						vulns := e.AnalyzeVulnerabilities(res)
						if len(vulns) > 0 {
							res.Vulnerabilities = append(res.Vulnerabilities, vulns...)
						}
					}

					// 3. Lua/NSE Script Integration
					if e.Lua != nil && open {
						scriptOutput := e.Lua.RunScripts(e.Host, port, res.Service, res.Banner)
						if len(scriptOutput) > 0 {
							res.Scripts = append(res.Scripts, scriptOutput...)
						}
					}
					// DEEP RECON: Every open port gets a deep check if enabled (Rust Engine)
					if e.VulnScan {
						res.Vulnerabilities = RustCheckVulnerabilities(e.Host, port, res.Service, res.Banner)
					}
					
					// ULTRA-DEEP: Engaging C/CPP/Rust Deep Audit Engines if flag is set
					if e.UltraDeep {
						deepData := RustPerformDeepScan(e.Host, port, res.Banner)
						res.DeepAnalysis = deepData
						
						// Add more detailed info from C/CPP if needed (future integration)
						// For now, Rust orchestrates the Deep results.
					}

					mutex.Lock()
					results = append(results, res)
					mutex.Unlock()

					if e.Reporter != nil {
						e.Reporter.ReportResult(res)
					}
				}

				progressMu.Lock()
				processedPorts++
				if e.Reporter != nil {
					progress := float64(processedPorts) / float64(totalPorts) * 100
					e.Reporter.ReportStatus(fmt.Sprintf("RECON: %d/%d ports mapped", processedPorts, totalPorts), progress)
				}
				progressMu.Unlock()
			}
		}()
	}

	for _, p := range ports {
		portsChan <- p
	}
	close(portsChan)

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

// AnalyzeVulnerabilities performs multi-engine vulnerability fingerprinting
func (e *ScanEngine) AnalyzeVulnerabilities(res PortResult) []string {
	var vulns []string
	
	// 1. Simple Go-based signature matching
	if res.Port == 22 && strings.Contains(strings.ToLower(res.Banner), "openssh 8.7") {
		vulns = append(vulns, "POTENTIAL: CVE-2024-6387 (regreSSHion)")
	}

	// 2. Call Rust for advanced OS/Service-based vuln analysis
	// We'll implement this wrapper in rust_wrapper.go
	rustVulns := RustCheckVulnerabilities(e.Host, res.Port, res.Service, res.Banner)
	if len(rustVulns) > 0 {
		vulns = append(vulns, rustVulns...)
	}

	return vulns
}

func NewScanEngine(host string, ports []int, threads int, timeoutMs int, stealth bool, mode string, reporter *Reporter) *ScanEngine {
	return &ScanEngine{
		Host:      host,
		Ports:     ports,
		Threads:   threads,
		TimeoutMs: timeoutMs,
		Stealth:   stealth,
		ScanMode:  mode,
		Reporter:  reporter,
	}
}
