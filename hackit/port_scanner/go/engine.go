package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
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
	Hostname               string
	Ports                  []int
	Threads                int
	TimeoutMs              int
	Stealth                bool
	ScanMode               string
	Reporter               *Reporter
	Lua                    *LuaEngine
	
	// Core Config
	IncludeClosed          bool
	Format                 string
	OutputFile             string
	OpenOnly               bool

	// Evasion & Stealth
	GhostProtocol          bool
	Chaos                  bool
	Decoy                  string
	Zombie                 string
	SpoofIP                string
	SourcePort             int
	Frag                   bool
	FragSize               int
	MTU                    int
	TTL                    int

	// Detection & Intel
	Deep                   bool
	Passive                bool
	SmartProbe             bool
	FingerprintIntensity   int
	OSDetect               bool
	Script                 string
	ScriptArgs             string

	// Timing & Performance
	Adaptive               bool
	Quantum                bool
	MinRate                int
	MaxRate                int
	MaxRetries             int
	HostTimeout            int
	ScanDelay              int

	// Discovery & Resolution
	RandomizeTargets       bool
	RandomizePorts         bool
	NoPing                 bool
	PingMethod             string
	ResolvePolicy          string
	DNSServer              string

	// Internal Logic Flags (Legacy/Internal)
	UltraDeep              bool
	VulnScan               bool
	IdentifyOS             bool
	DetectService          bool
	CustomTTL              int
	SpoofMAC               string
	PacketSplit            bool
	Traceroute             bool
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
	UseProxy               string
	UseTor                 bool
	VersionIntensity       int
	OSScanLimit            bool
	OSScanGuess            bool
	MaxScanDelay           int
	DefeatRstRateLimit     bool
	DefeatIcmpRateLimit    bool
	NsockEngine            string
}

func (e *ScanEngine) Run() []PortResult {
	if e.Reporter != nil {
		e.Reporter.ReportStatus("Initializing Tactical Discovery Engine", 0)
	}

	ports := e.Ports
	results := make([]PortResult, 0)
	if len(ports) == 0 {
		return results
	}

	// 1. Quantum Port Ordering (Industrial Prioritization)
	if e.Quantum {
		common := make([]int, 0)
		rare := make([]int, 0)
		for _, p := range ports {
			if IsCommonPort(p) {
				common = append(common, p)
			} else {
				rare = append(rare, p)
			}
		}
		// Prioritize common ports for immediate intelligence
		ports = append(common, rare...)
	}

	// 0. Use Rust for Mass Scanning (Industrial Range) - Only if we only care about OPEN ports
	if !e.IncludeClosed && len(ports) > 1000 && (e.ScanMode == "syn" || e.ScanMode == "connect") {
		if e.Reporter != nil {
			e.Reporter.ReportStatus("Engaging Rust-Turbo Engine for Full Range Scan", 10)
		}
		
		// Find range
		min := ports[0]
		max := ports[0]
		for _, p := range ports {
			if p < min { min = p }
			if p > max { max = p }
		}
		
		// If it's a dense range, use RustBatchScan
		if (max - min) < len(ports) * 2 {
			openPortsStr := RustBatchScan(e.Host, min, max, e.TimeoutMs, e.Threads)
			if openPortsStr != "" {
				openPorts := strings.Split(openPortsStr, ",")
				// Convert back to PortResults for secondary processing
				for _, pStr := range openPorts {
					p := 0
					fmt.Sscanf(pStr, "%d", &p)
					if p > 0 {
						res := PortResult{Port: p, State: "open"}
						// Still perform secondary enrichment (banner, scripts, etc.)
						results = append(results, res)
					}
				}
				// If we got results, we might want to skip the main loop for THESE ports
				// For now, let's just proceed with secondary enrichment for these ports
				// This is a simplified integration.
			}
		}
	}
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

				// PHASE 1: Basic Discovery (Ultra Fast)
				switch e.ScanMode {
				case "udp":
					res, open = ScanUDP(e.Host, port, e.TimeoutMs)
				case "syn":
					res = e.MultiEngineOrchestrator(port)
					if res.State == "error" {
						res, open = ScanPort(e.Host, port, e.TimeoutMs)
					} else {
						open = res.State == "open"
					}
				case "c-turbo":
					res, open = ScanPort(e.Host, port, e.TimeoutMs)
					if open {
						c_os := CExpertDetectOs(e.Host, fmt.Sprintf("%d", port), 64, 29200)
						res.DeepAnalysis = c_os
					}
				default:
					res, open = ScanPort(e.Host, port, e.TimeoutMs)
				}

				// PROGRESS UPDATE: Increment immediately after basic discovery to prevent UI lag
				progressMu.Lock()
				processedPorts++
				if e.Reporter != nil {
					progress := float64(processedPorts) / float64(totalPorts) * 100
					e.Reporter.ReportStatus(fmt.Sprintf("RECON: %d/%d ports mapped", processedPorts, totalPorts), progress)
				}
				progressMu.Unlock()

				// PHASE 2: Deep Recon (Timeout Protected - Synchronous within Worker)
				if open || e.IncludeClosed {
					// Use a dedicated timer for tactical cutoff
					timer := time.NewTimer(3 * time.Second)
					reconDone := make(chan bool, 1)

					go func() {
						if e.DetectService && open {
							if res.Banner == "" {
								res.Banner = GrabBannerByHost(e.Host, port, e.TimeoutMs)
							}
							res.Service, res.Version = DetectService(port, res.Banner, e.Host)
							if res.Service == "" || strings.Contains(res.Service, "unassigned") {
								if name, ok := commonPorts[port]; ok { res.Service = name }
							}
						}

						if open && res.Banner != "" {
							// Rust/C++ Fast Audits
							rustService := RustFingerprintService(res.Banner)
							if rustService != "" && rustService != "unknown" { res.Service = rustService }
							cppRes := CppScanService(e.Host, port, 500)
							if cppRes.Service != "" && cppRes.Service != "UNKNOWN" { res.Service = cppRes.Service }

							// Vulnerabilities & Scripts
							vulns := e.AnalyzeVulnerabilities(res)
							if len(vulns) > 0 { res.Vulnerabilities = append(res.Vulnerabilities, vulns...) }

							audit := LuaRunTactical(e.Host, port, "audit")
							if audit != "" { res.Vulnerabilities = append(res.Vulnerabilities, "[LUA-AUDIT]: "+audit) }
							
							luaEngine := NewLuaEngine()
							luaResults := luaEngine.RunScripts(e.Host, port, res.Service, res.Banner)
							if len(luaResults) > 0 { res.Vulnerabilities = append(res.Vulnerabilities, luaResults...) }

							if res.Service == "http" || port == 80 || port == 443 {
								rubyRes := RubyScanPorts(e.Host, []int{port}, "http")
								if rubyRes != "" && !strings.Contains(rubyRes, "Error") { res.Vulnerabilities = append(res.Vulnerabilities, "[RUBY-RECON]: "+rubyRes) }
							}
						}

						if e.UltraDeep && open {
							rustDeep := RustPerformDeepScan(e.Host, port, res.Banner)
							if rustDeep != "" { res.DeepAnalysis += "\n[RUST-DEEP]: " + rustDeep }
							rubyAnalysis := RubyScanProtocol(e.Host, port)
							if rubyAnalysis != "" { res.DeepAnalysis += "\n" + rubyAnalysis }
						}
						reconDone <- true
					}()

					select {
					case <-reconDone:
						timer.Stop()
					case <-timer.C:
						// Hard Tactical Cutoff - Prevents single port stalling the entire worker
						if res.Service == "" {
							if name, ok := commonPorts[port]; ok { res.Service = name }
						}
					}

					mutex.Lock()
					results = append(results, res)
					mutex.Unlock()

					if e.Reporter != nil {
						e.Reporter.ReportResult(res)
					}
				}
			}
		}()
	}

	for _, p := range ports {
		portsChan <- p
	}
	close(portsChan)

	// --- MISSION WATCHDOG: Ensuring Zero-Lag Collation ---
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	select {
	case <-c:
		// Normal completion
	case <-time.After(15 * time.Second): // Hard Cutoff for stuck workers
		if e.Reporter != nil {
			e.Reporter.ReportStatus("TACTICAL: Watchdog triggered - Forcing result collation", 100)
		}
	}

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
