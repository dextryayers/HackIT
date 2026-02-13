package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type ScanEngine struct {
	Host          string
	TimeoutMs     int
	Threads       int
	IncludeClosed bool
	Stealth       bool
	ScanMode      string // "connect", "udp", "stealth", etc.
	Reporter      *Reporter
	Lua           *LuaEngine

	// Nmap parity flags
	LuaScript     string
	LuaArgs       string
	MTU           int
	DataLength    int
	SourcePort    int
	IdentifyOS    bool
	DetectService bool
	CustomTTL     int
	SpoofIP       string
	SpoofMAC      string
	PacketSplit   bool
	BadSum        bool
	Traceroute    bool

	// New Intel & Web flags
	DNSInfo       bool
	ReverseLookup bool
	SubEnum       bool
	WhoisInfo     bool
	GeoInfo       bool
	ASNInfo       bool
	HttpInspect   bool
	TechAnalyze   bool
	TlsAnalyze    bool
	CertView      bool
	ShowTitle     bool
}

func NewScanEngine(host string, timeoutMs int, threads int, includeClosed bool, stealth bool, scanMode string, reporter *Reporter) *ScanEngine {
	return &ScanEngine{
		Host:          host,
		TimeoutMs:     timeoutMs,
		Threads:       threads,
		IncludeClosed: includeClosed,
		Stealth:       stealth,
		ScanMode:      scanMode,
		Reporter:      reporter,
		Lua:           NewLuaEngine(),
	}
}

func (e *ScanEngine) Run(ports []int) []PortResult {
	// If scan mode is "c-turbo", use the ultra-fast C socket engine
	if e.ScanMode == "c-turbo" {
		fmt.Printf("[*] Starting Ultra-Fast C Turbo Engine for %s...\n", e.Host)
		// Convert ports to string for C engine
		var portsStr string
		if len(ports) > 0 {
			portsStr = fmt.Sprintf("%d-%d", ports[0], ports[len(ports)-1])
		} else {
			portsStr = "1-1024"
		}

		results := RunCTurboScan(e.Host, portsStr, e.TimeoutMs)

		// Enrich results with service identification
		for i := range results {
			if results[i].State == "open" {
				// 1. First, identify basic service with Go
				s, v := IdentifyService(results[i].Port, results[i].Banner, e.Host)
				results[i].Service = s
				results[i].Version = v

				// 2. Call C++ Expert Engine for Deep Banner & Version analysis
				cppRes := RunCppServiceScan(e.Host, results[i].Port, e.TimeoutMs)
				if cppRes.Version != "" && cppRes.Version != "unknown" {
					results[i].Version = cppRes.Version
					results[i].Banner = cppRes.Banner
				}

				// 3. Add OS info from C engine
				if results[i].OS != "" {
					results[i].Banner = fmt.Sprintf("%s [OS: %s]", results[i].Banner, results[i].OS)
				}
			}
		}

		// Sort results by port
		sort.Slice(results, func(i, j int) bool {
			return results[i].Port < results[j].Port
		})

		// Print real-time like output for consistency
		if e.Reporter != nil {
			for _, res := range results {
				// Run Lua Scripts (NSE-style)
				if e.Lua != nil {
					scriptResults := e.Lua.RunScripts(e.Host, res.Port, res.Service, res.Banner)
					for _, sr := range scriptResults {
						fmt.Printf(" |  \033[33m%s\033[0m\n", sr)
					}
				}
				e.Reporter.ReportResult(res)
			}
		}

		return results
	}

	// If scan mode is "syn" (default), use the Ultimate Rust Mass Scanner
	// This replaces the per-port loop with a single high-performance Rust call
	if e.ScanMode == "syn" {
		fmt.Printf("[*] Starting Ultimate Rust Core Engine for %s...\n", e.Host)
		results := RustMassScan(e.Host, ports, e.Threads, e.TimeoutMs, e.Stealth)

		// Enrich results with service identification
		for i := range results {
			if results[i].State == "open" {
				// 1. First, identify basic service with Go
				s, v := IdentifyService(results[i].Port, results[i].Banner, e.Host)
				results[i].Service = s
				results[i].Version = v

				// 2. Call C++ Expert Engine for Deep Banner & Version analysis
				cppRes := RunCppServiceScan(e.Host, results[i].Port, e.TimeoutMs)
				if cppRes.Version != "" && cppRes.Version != "unknown" {
					results[i].Version = cppRes.Version
					results[i].Banner = cppRes.Banner
				}

				// 3. Add OS info from C engine
				if results[i].OS != "" {
					results[i].Banner = fmt.Sprintf("%s [OS: %s]", results[i].Banner, results[i].OS)
				}
			}
		}

		// Sort results by port
		sort.Slice(results, func(i, j int) bool {
			return results[i].Port < results[j].Port
		})

		// Print real-time like output for consistency
		if e.Reporter != nil {
			for _, res := range results {
				// Run Lua Scripts (NSE-style)
				if e.Lua != nil {
					scriptResults := e.Lua.RunScripts(e.Host, res.Port, res.Service, res.Banner)
					for _, sr := range scriptResults {
						fmt.Printf(" |  \033[33m%s\033[0m\n", sr)
					}
				}
				e.Reporter.ReportResult(res)
			}
		}

		return results
	}

	// If scan mode is "ruby", use the Ruby-based engine
	if e.ScanMode == "ruby" {
		fmt.Printf("[*] Starting Ruby Engine for %s...\n", e.Host)
		var portsStr string
		if len(ports) > 0 {
			portsStr = fmt.Sprintf("%d-%d", ports[0], ports[len(ports)-1])
		} else {
			portsStr = "1-1024"
		}
		results := RunRubyScan(e.Host, portsStr, e.TimeoutMs)
		if e.Reporter != nil {
			for _, res := range results {
				e.Reporter.ReportResult(res)
			}
		}
		return results
	}

	// If scan mode is "python", use the Python-based engine
	if e.ScanMode == "python" {
		fmt.Printf("[*] Starting Python Engine for %s...\n", e.Host)
		var portsStr string
		if len(ports) > 0 {
			portsStr = fmt.Sprintf("%d-%d", ports[0], ports[len(ports)-1])
		} else {
			portsStr = "1-1024"
		}
		results := RunPythonScan(e.Host, portsStr, e.TimeoutMs)
		if e.Reporter != nil {
			for _, res := range results {
				e.Reporter.ReportResult(res)
			}
		}
		return results
	}

	results := make([]PortResult, 0)
	var mutex sync.Mutex
	var wg sync.WaitGroup
	portsChan := make(chan int, e.Threads)

	// Total ports for progress calculation
	totalPorts := len(ports)
	processedPorts := 0
	var progressMu sync.Mutex

	// Start workers
	for i := 0; i < e.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					if e.Reporter != nil {
						e.Reporter.ReportError(fmt.Sprintf("Worker panic: %v", r))
					}
				}
			}()
			currentTimeout := e.TimeoutMs
			for port := range portsChan {
				// Stealth: add jitter and randomize timing
				if e.Stealth {
					jitterSleep(10, 50)
				}

				// Adaptive timing: measure response time and adjust
				start := time.Now()

				var res PortResult
				var open bool

				// Select scanning logic based on mode
				if e.ScanMode == "udp" {
					res, open = ScanUDP(e.Host, port, currentTimeout)
				} else if e.ScanMode == "syn" {
					// Use the new Rust Fast Scanner for superior performance and accuracy
					res = RustFastScan(e.Host, port, currentTimeout, e.Stealth)
					open = res.State == "open"

					// If it's a web port, force firewall bypass check
					if port == 80 || port == 443 || port == 8443 {
						bypassMethod, confidence := RustFirewallBypass(e.Host, port)
						if confidence > 50 {
							res.Banner += fmt.Sprintf(" [WAF-Bypass: %s]", bypassMethod)
						}
					}
				} else if e.ScanMode != "connect" {
					res, open = ScanRaw(e.Host, port, e.ScanMode, currentTimeout)
				} else {
					res, open = ScanPort(e.Host, port, currentTimeout)
				}

				elapsed := time.Since(start)
				// Adaptive Timeout Logic:
				if open {
					// If response was fast, lower timeout slightly (confidence in network speed)
					if elapsed < time.Duration(currentTimeout/2)*time.Millisecond {
						currentTimeout = int(float64(currentTimeout) * 0.95)
					}
				} else {
					// If it timed out, increase timeout slightly for next ports (noise/latency detected)
					if elapsed >= time.Duration(currentTimeout)*time.Millisecond {
						currentTimeout = int(float64(currentTimeout) * 1.05)
					}
				}
				// Keep within sane bounds
				if currentTimeout < 200 {
					currentTimeout = 200
				}
				if currentTimeout > 5000 {
					currentTimeout = 5000
				}

				if open {
					// Double-check accuracy for open ports to avoid false positives
					// Especially useful in noisy networks. For raw scans, we might do a connect check.
					verified := false
					if e.ScanMode == "connect" {
						_, verified = ScanPort(e.Host, port, currentTimeout+500)
					} else if e.ScanMode == "stealth" {
						// For stealth, re-run raw check or just trust if response was clear
						_, verified = ScanRaw(e.Host, port, e.ScanMode, currentTimeout+500)
					} else {
						verified = true // Trust other specialized scans for now
					}

					if verified {
						// Run Lua Scripts (NSE-style)
						if e.Lua != nil {
							res.Scripts = e.Lua.RunScripts(e.Host, res.Port, res.Service, res.Banner)
						}

						mutex.Lock()
						results = append(results, res)
						mutex.Unlock()

						// Report real-time
						// Run Lua Scripts (NSE-style) for each open port
						if e.Lua != nil {
							scriptResults := e.Lua.RunScripts(e.Host, res.Port, res.Service, res.Banner)
							for _, sr := range scriptResults {
								fmt.Printf(" |  \033[33m%s\033[0m\n", sr)
							}
						}

						if e.Reporter != nil {
							e.Reporter.ReportResult(res)
						}
					}
				} else if e.IncludeClosed {
					state := QuickCheckPort(e.Host, port, currentTimeout)
					service, version := IdentifyService(port, "", e.Host)
					closedRes := PortResult{
						Port:    port,
						State:   state,
						Service: service,
						Version: version,
					}
					mutex.Lock()
					results = append(results, closedRes)
					mutex.Unlock()

					if e.Reporter != nil {
						e.Reporter.ReportResult(closedRes)
					}
				}

				// Update progress
				progressMu.Lock()
				processedPorts++
				if processedPorts%100 == 0 || processedPorts == totalPorts {
					progress := float64(processedPorts) / float64(totalPorts) * 100
					if e.Reporter != nil {
						e.Reporter.ReportStatus("Scanning", progress)
					}
				}
				progressMu.Unlock()
			}
		}()
	}

	// Feed ports to channel
	for _, port := range ports {
		portsChan <- port
	}
	close(portsChan)

	wg.Wait()
	return results
}
