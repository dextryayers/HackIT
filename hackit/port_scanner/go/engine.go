package main

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// PORTSTORM SCAN ENGINE v3.0 — Polyglot Orchestrator
// ─────────────────────────────────────────────────────────────────

var portResultPool = sync.Pool{
	New: func() interface{} { return &PortResult{} },
}

// resultChanPool provides buffered result channels with work stealing
var resultChanPool = sync.Pool{
	New: func() interface{} { return make(chan PortResult, 1) },
}

type PortResult struct {
	Port            int      `json:"port"`
	State           string   `json:"status"`
	Service         string   `json:"service"`
	Banner          string   `json:"banner"`
	Version         string   `json:"version"`
	TTL             int      `json:"ttl,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	Scripts         []string `json:"scripts,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	DeepAnalysis    string   `json:"deep_analysis,omitempty"`
	RiskScore       float64  `json:"risk_score,omitempty"`
	CPEList         []string `json:"cpe,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

type ScanEngine struct {
	Host     string
	Hostname string
	Ports    []int
	Threads  int
	TimeoutMs int
	Stealth  bool
	ScanMode string
	Reporter *Reporter
	Lua      *LuaEngine

	// Core Config
	IncludeClosed bool
	Format        string
	OutputFile    string
	OpenOnly      bool

	// Evasion & Stealth
	GhostProtocol bool
	Chaos         bool
	Decoy         string
	Zombie        string
	SpoofIP       string
	SourcePort    int
	Frag          bool
	FragSize      int
	MTU           int
	TTL           int

	// Detection & Intel
	Deep                 bool
	Passive              bool
	SmartProbe           bool
	FingerprintIntensity int
	OSDetect             bool
	Script               string
	ScriptArgs           string

	// Timing & Performance
	Adaptive         bool
	Quantum          bool
	MinRate          int
	MaxRate          int
	MaxRetries       int
	HostTimeout      int
	ScanDelay        int
	AdaptiveEngine   *AdaptiveTiming

	// Discovery & Resolution
	RandomizeTargets bool
	RandomizePorts   bool
	NoPing           bool
	PingMethod       string
	ResolvePolicy    string
	DNSServer        string

	// Internal / Legacy
	UltraDeep           bool
	VulnScan            bool
	IdentifyOS          bool
	DetectService       bool
	CustomTTL           int
	SpoofMAC            string
	PacketSplit         bool
	Traceroute          bool
	BadSum              bool
	DNSInfo             bool
	ReverseLookup       bool
	SubEnum             bool
	WhoisInfo           bool
	GeoInfo             bool
	ASNInfo             bool
	HttpInspect         bool
	TechAnalyze         bool
	TlsAnalyze          bool
	CertView            bool
	ShowTitle           bool
	DetectHoneypot      bool
	SmartBypass         bool
	RandomOrder         bool
	UseProxy            string
	UseTor              bool
	VersionIntensity    int
	OSScanLimit         bool
	OSScanGuess         bool
	MaxScanDelay        int
	DefeatRstRateLimit  bool
	DefeatIcmpRateLimit bool
	NsockEngine         string

	// Pipeline & Scheduler
	PipelineStages []string
	AllEngines     bool
	UseScheduler   bool
	Scheduler      *Scheduler

	// Orchestrator (lazy-init)
	orchestrator *Orchestrator

	// Counters (atomic for thread-safety)
	totalScanned  int64
	totalOpen     int64
	totalFiltered int64
	totalClosed   int64
}

// ─────────────────────────────────────────────────────────────────
// MAIN RUN ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────

func (e *ScanEngine) Run() []PortResult {
	if e.Reporter != nil {
		e.Reporter.ReportStatus("PortStorm v3.0 — Initializing Polyglot Engine", 0)
	}

	ports := e.Ports
	if len(ports) == 0 {
		return nil
	}

	// 1. Scheduler-based port ordering
	if e.UseScheduler && e.Scheduler != nil {
		jobs := e.Scheduler.Schedule(e.Host, ports, "normal")
		ports = make([]int, len(jobs))
		for i, j := range jobs {
			ports[i] = j.Port
		}
	} else if e.Quantum {
		ports = quantumSort(ports)
	}

	// 2. Randomize port order (stealth / chaos)
	if e.RandomizePorts || e.Chaos {
		rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	}

	// 3. Adaptive timing engine initialization
	if e.Adaptive {
		tmpl := GetTimingTemplate(3) // Start at Normal
		e.AdaptiveEngine = NewAdaptiveTiming(tmpl)
	}

	// 4. Determine which fast-path engine to use for initial discovery
	// Rust handles massive port ranges (>2000 ports, open-only mode)
	if !e.IncludeClosed && len(ports) > 2000 && (e.ScanMode == "syn" || e.ScanMode == "connect") {
		if e.Reporter != nil {
			e.Reporter.ReportStatus("Engaging Rust Turbo Engine for mass scan", 5)
		}
		min, max := ports[0], ports[0]
		for _, p := range ports {
			if p < min { min = p }
			if p > max { max = p }
		}
		// Dense range: use Rust batch scan as initial filter
		if (max-min) < len(ports)*3 {
			openStr := RustBatchScan(e.Host, min, max, e.TimeoutMs, e.Threads)
			if openStr != "" {
				return e.enrichRustResults(openStr, ports)
			}
		}
	}

	// 5. Concurrent scan pipeline
	var (
		mutex   sync.Mutex
		wg      sync.WaitGroup
		results = make([]PortResult, 0, len(ports)/4)
	)

	portsChan := make(chan int, min2(e.Threads*2, len(ports)))

	workerCount := e.Threads
	if workerCount > len(ports) {
		workerCount = len(ports)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	// 6. Rate limiter for max-rate control
	var rateLimiter *time.Ticker
	if e.MaxRate > 0 {
		interval := time.Second / time.Duration(e.MaxRate)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
	}

	// 7. Worker pool
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if port <= 0 || port > 65535 {
					continue
				}

				// Min-rate enforcement
				if e.MinRate > 0 {
					time.Sleep(time.Second / time.Duration(e.MinRate))
				}

				// Stealth jitter
				if e.Stealth || e.GhostProtocol {
					jitterSleep(5, 80)
				}

				// Adaptive timing delay
				if e.AdaptiveEngine != nil {
					time.Sleep(e.AdaptiveEngine.GetRecommendedDelay())
				}

				// Scan delay
				if e.ScanDelay > 0 {
					time.Sleep(time.Duration(e.ScanDelay) * time.Millisecond)
				}

				// Phase 1: Port discovery with multi-engine cross-check
				var res PortResult
				var isOpen bool

				switch e.ScanMode {
				case "udp":
					res, isOpen = ScanUDP(e.Host, port, e.TimeoutMs)
				case "syn":
					res = e.MultiEngineOrchestrator(port)
					if res.State == "error" {
						res, isOpen = ScanPort(e.Host, port, e.TimeoutMs)
					} else {
						isOpen = res.State == "open"
					}
				case "ack":
					res, isOpen = ScanACK(e.Host, port, e.TimeoutMs)
				case "fin":
					res, isOpen = ScanFIN(e.Host, port, e.TimeoutMs)
				case "xmas":
					res, isOpen = ScanXMAS(e.Host, port, e.TimeoutMs)
				case "null":
					res, isOpen = ScanNULL(e.Host, port, e.TimeoutMs)
				case "window":
					res, isOpen = ScanWindow(e.Host, port, e.TimeoutMs)
				case "maimon":
					res, isOpen = ScanMaimon(e.Host, port, e.TimeoutMs)
				case "idle":
					if e.Zombie != "" {
						res, isOpen = ScanIdle(e.Host, port, e.Zombie, e.TimeoutMs)
					} else {
						res, isOpen = ScanPort(e.Host, port, e.TimeoutMs)
					}
				case "protocol":
					res, isOpen = ScanProtocol(e.Host, port, e.TimeoutMs)
				case "c-turbo":
					res = e.CrossCheckOrchestrator(port)
					isOpen = res.State == "open"
					if isOpen {
						cOS := CExpertDetectOs(e.Host, fmt.Sprintf("%d", port), 64, 29200)
						res.DeepAnalysis = cOS
					}
				case "anon-self":
					res, isOpen = ScanPort(e.Host, port, e.TimeoutMs)
					if isOpen && e.GhostProtocol {
						res.State = "self-listening"
					}
				default: // "connect" — standard TCP connect scan
					res, isOpen = ScanPort(e.Host, port, e.TimeoutMs)
				}

				// Update adaptive engine
				if e.AdaptiveEngine != nil {
					e.AdaptiveEngine.AdjustTiming(isOpen, time.Duration(e.TimeoutMs)*time.Millisecond)
				}

				// Progress tracking
				n := atomic.AddInt64(&e.totalScanned, 1)
				if isOpen {
					atomic.AddInt64(&e.totalOpen, 1)
				}
				if e.Reporter != nil {
					progress := float64(n) / float64(len(ports)) * 100
					e.Reporter.ReportStatus(
						fmt.Sprintf("Probing %d/%d ports | Open: %d",
							n, len(ports), atomic.LoadInt64(&e.totalOpen)),
						progress,
					)
				}

				// Phase 2: Always include all scanned ports so Python CLI can display counts
				e.enrichPort(&res, port, isOpen)

				mutex.Lock()
				results = append(results, res)
				mutex.Unlock()

				if e.Reporter != nil {
					e.Reporter.ReportResult(res)
				}
			}
		}()
	}

	// Feed ports to workers
	go func() {
		for _, p := range ports {
			if rateLimiter != nil {
				<-rateLimiter.C
			}
			portsChan <- p
		}
		close(portsChan)
	}()

	// Wait with watchdog timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	hostTimeout := 300 * time.Second
	if e.HostTimeout > 0 {
		hostTimeout = time.Duration(e.HostTimeout) * time.Millisecond
	}
	select {
	case <-done:
	case <-time.After(hostTimeout):
		if e.Reporter != nil {
			e.Reporter.ReportStatus("Watchdog timeout — collating partial results", 100)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Deep mode: run full pipeline via Orchestrator for enrichment + cross-validation
	if e.Deep || e.AllEngines {
		orch := e.getOrchestrator()
		stages := e.PipelineStages
		if len(stages) == 0 {
			stages = []string{"service_detect", "os_detect", "vuln_scan", "enrich"}
		}
		pipelineResult := orch.RunPipeline(e.Hostname, ports, stages)
		if len(pipelineResult.Results) > 0 {
			if e.AllEngines {
				results = MergeResults(
					[]string{"go"},
					results, pipelineResult.Results,
				)
			} else {
				for i, r := range results {
					for _, pr := range pipelineResult.Results {
						if pr.Port == r.Port {
							if pr.Service != "" && pr.Service != "unknown" {
								results[i].Service = pr.Service
							}
							if pr.Version != "" {
								results[i].Version = pr.Version
							}
							if len(pr.Vulnerabilities) > 0 {
								results[i].Vulnerabilities = append(results[i].Vulnerabilities, pr.Vulnerabilities...)
							}
							if pr.RiskScore > results[i].RiskScore {
								results[i].RiskScore = pr.RiskScore
							}
							if len(pr.CPEList) > 0 {
								results[i].CPEList = append(results[i].CPEList, pr.CPEList...)
							}
							break
						}
					}
				}
			}
		}
	}

	return results
}

func (e *ScanEngine) getOrchestrator() *Orchestrator {
	if e.orchestrator == nil {
		e.orchestrator = NewOrchestrator(e)
	}
	return e.orchestrator
}

func (e *ScanEngine) RunWithOrchestrator() ScanResult {
	orch := e.getOrchestrator()
	return orch.RunPipeline(e.Hostname, e.Ports, e.PipelineStages)
}

// ─────────────────────────────────────────────────────────────────
// DEEP ENRICHMENT PIPELINE
// ─────────────────────────────────────────────────────────────────

func (e *ScanEngine) enrichPort(res *PortResult, port int, isOpen bool) {
	if !isOpen {
		return
	}

	timer := time.NewTimer(5 * time.Second)
	done := make(chan struct{}, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
			}
			done <- struct{}{}
		}()

		// 1. Banner grab if missing
		if res.Banner == "" && (e.SmartProbe || e.Deep) {
			res.Banner = GrabBannerByHost(e.Host, port, e.TimeoutMs)
		}

		// 2. Detection Chain: Go baseline → Rust → C++ override
		// Always run Go DetectService first to get baseline service
		goService, goVersion := DetectService(port, res.Banner, e.Host)

		// 2a. Rust Fingerprinting — override if confident
		if res.Banner != "" {
			rustSvc := RustFingerprintService(res.Banner)
			rus := strings.ToUpper(rustSvc)
			if rus != "" && rus != "UNKNOWN" {
				res.Service = rustSvc
				res.Version = RustExtractVersion(res.Banner, rustSvc)
			}
		}

		// 2b. C++ Deep Fingerprint — override if service still unknown
		if res.Service == "" || res.Service == "unknown" || res.Version == "" {
			cppRes := CppScanService(e.Host, port, 800)
			if cppRes.Banner != "" && res.Banner == "" {
				res.Banner = cppRes.Banner
			}
			if cppRes.Service != "" && cppRes.Service != "UNKNOWN" {
				res.Service = cppRes.Service
				if cppRes.Version != "" {
					res.Version = cppRes.Version
				}
			}
		}

		// 2c. Go baseline fallback — fill in if Rust/C++ returned nothing
		if res.Service == "" || res.Service == "unknown" {
			res.Service = goService
			res.Version = goVersion
		} else if res.Version == "" && goVersion != "" {
			res.Version = goVersion
		}

		// 3. Lua script engine
		if e.Lua == nil {
			e.Lua = NewLuaEngine()
		}
		luaResults := e.Lua.RunScripts(e.Host, port, res.Service, res.Banner)
		if len(luaResults) > 0 {
			res.Scripts = append(res.Scripts, luaResults...)
		}

		// 4. Vulnerability analysis
		if e.Deep || e.Script != "" || e.VulnScan {
			vulns := e.AnalyzeVulnerabilities(*res)
			if len(vulns) > 0 {
				res.Vulnerabilities = append(res.Vulnerabilities, vulns...)
			}
		}

		// 5. Deep analysis (UltraDeep)
		if e.UltraDeep && isOpen {
			deepResult := RustPerformDeepScan(e.Host, port, res.Banner)
			if deepResult != "" {
				res.DeepAnalysis += "[RUST-DEEP]: " + deepResult
			}
		}

		// 6. CPE generation
		if res.Service != "" && res.Version != "" {
			cpe := generateCPE(res.Service, res.Version)
			if cpe != "" {
				res.CPEList = []string{cpe}
			}
		}

		// 7. Risk scoring
		res.RiskScore = calculateRiskScore(port, res.Service, res.Banner, res.Vulnerabilities)

		// 8. Final safety net: ensure Service is never empty if banner exists
		if res.Service == "" && res.Banner != "" {
			res.Service, res.Version = DetectService(port, res.Banner, e.Host)
		}
		if res.Service == "" {
			if name, ok := commonPorts[port]; ok {
				res.Service = name
			}
		}
	}()

	select {
	case <-done:
		timer.Stop()
	case <-timer.C:
		if res.Service == "" && res.Banner != "" {
			res.Service, res.Version = DetectService(port, res.Banner, e.Host)
		}
		if res.Service == "" {
			if name, ok := commonPorts[port]; ok {
				res.Service = name
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// VULNERABILITY ANALYSIS ENGINE
// ─────────────────────────────────────────────────────────────────

func (e *ScanEngine) AnalyzeVulnerabilities(res PortResult) []string {
	var vulns []string

	bannerLow := toLower(res.Banner)

	// Known CVEs via banner matching
	cveMap := map[string][]string{
		"openssh 8.7":      {"CVE-2024-6387 (regreSSHion) — unauthenticated RCE"},
		"openssh 8.5":      {"CVE-2023-38408 — SSH Agent remote code exec"},
		"openssh 7.4":      {"CVE-2018-15473 — Username enumeration"},
		"openssh 7.2":      {"CVE-2016-10012 — Privilege separation bypass"},
		"vsftpd 2.3.4":     {"CVE-2011-2523 — Backdoor (smiley face :))", "CRITICAL: backdoor present"},
		"proftpd 1.3.3":    {"CVE-2010-4221 — Remote code execution"},
		"apache/2.2":       {"CVE-2017-7679 — mod_mime buffer overflow", "EOLSUPPORT: Apache 2.2 end-of-life"},
		"apache/2.4.49":    {"CVE-2021-41773 — Path traversal + RCE"},
		"apache/2.4.50":    {"CVE-2021-42013 — Path traversal bypass"},
		"nginx/1.0":        {"EOLSUPPORT: nginx 1.0 end-of-life"},
		"iis/6.0":          {"CVE-2017-7269 — Buffer overflow RCE (EternalBlue-linked)"},
		"iis/7.5":          {"CVE-2010-1256 — Information disclosure"},
		"php/5.":           {"EOLSUPPORT: PHP 5.x end-of-life (critical)", "Multiple known CVEs"},
		"php/7.0":          {"EOLSUPPORT: PHP 7.0 end-of-life"},
		"php/7.1":          {"EOLSUPPORT: PHP 7.1 end-of-life"},
		"openssl/1.0":      {"CVE-2014-0160 — Heartbleed", "EOLSUPPORT: OpenSSL 1.0.x EOL"},
		"openssl/1.1.0":    {"EOLSUPPORT: OpenSSL 1.1.0 EOL"},
		"redis_version:2":  {"CRITICAL: Redis 2.x unauthenticated — data exposure"},
		"redis_version:3":  {"WARN: Redis 3.x — no auth by default"},
		"redis_version:4":  {"INFO: Redis 4.x — verify ACL config"},
		"mongodb":          {"INFO: Check auth required — MongoDB defaults open"},
		"elastic":          {"CVE-2021-22145 — Elasticsearch info disclosure"},
		"jenkins":          {"CVE-2024-23897 — Arbitrary file read (Jenkins 2.441)"},
		"tomcat/7":         {"EOLSUPPORT: Tomcat 7 EOL", "CVE-2020-1938 — Ghostcat AJP"},
		"tomcat/8.0":       {"EOLSUPPORT: Tomcat 8.0 EOL"},
		"drupal":           {"CVE-2018-7600 — Drupalgeddon2 RCE"},
		"wordpress":        {"INFO: Check WP-Scan for plugin vulns"},
		"jboss":            {"CVE-2015-7501 — Java deserialization RCE"},
		"weblogic":         {"CVE-2023-21839 — Deserialization RCE"},
	}

	for pattern, cves := range cveMap {
		if contains(bannerLow, pattern) {
			vulns = append(vulns, cves...)
		}
	}

	// Port-based risk indicators
	portRisks := map[int]string{
		23:    "TELNET: Plaintext credentials — deprecated",
		21:    "FTP: Check for anonymous access",
		2375:  "CRITICAL: Docker daemon exposed — container escape possible",
		2376:  "Docker TLS daemon — verify cert requirements",
		6379:  "Redis: Verify auth — default is no auth",
		27017: "MongoDB: Verify auth — default is no auth",
		9200:  "Elasticsearch: Verify auth — default is open",
		5432:  "PostgreSQL: Verify pg_hba.conf restrictions",
		3306:  "MySQL: Verify bind-address and user grants",
		11211: "Memcached: No auth — data exposure risk",
		5900:  "VNC: Verify password strength",
		3389:  "RDP: BlueKeep-class vulns — ensure patched",
		445:   "SMB: EternalBlue-class — verify MS17-010 patch",
		4444:  "CRITICAL: Possible Meterpreter/reverse shell listener",
		10250: "K8s Kubelet: API may allow unauthenticated exec",
		6443:  "K8s API Server: Verify auth and RBAC",
		50000: "IBM DB2: Default port — verify auth",
	}

	if risk, ok := portRisks[res.Port]; ok {
		vulns = append(vulns, risk)
	}

	// Rust vulnerability check (signature DB)
	rustVulns := RustCheckVulnerabilities(e.Host, res.Port, res.Service, res.Banner)
	vulns = append(vulns, rustVulns...)

	// Deduplicate
	seen := map[string]bool{}
	unique := vulns[:0]
	for _, v := range vulns {
		if !seen[v] {
			seen[v] = true
			unique = append(unique, v)
		}
	}

	return unique
}

// ─────────────────────────────────────────────────────────────────
// SCANNING MODES (stubs that use best available method)
// ─────────────────────────────────────────────────────────────────

// ScanACK — ACK scan for firewall mapping via C raw engine
func ScanACK(host string, port int, timeoutMs int) (PortResult, bool) {
	if _, _, state := CRawScan(host, port, timeoutMs, 5, 0, 0, nil, false, 0); state != "no-result" && state != "error" {
		return PortResult{Port: port, State: state}, state == "unfiltered" || state == "open"
	}
	res := RustFastScan(host, port, timeoutMs, true)
	if res.State == "error" || res.State == "" {
		return ScanPort(host, port, timeoutMs)
	}
	return res, res.State == "open" || res.State == "unfiltered"
}

// ScanFIN — FIN scan (expects RST from closed, silence from open/filtered)
func ScanFIN(host string, port int, timeoutMs int) (PortResult, bool) {
	if _, _, state := CRawScan(host, port, timeoutMs, 2, 0, 0, nil, false, 0); state != "no-result" && state != "error" {
		return PortResult{Port: port, State: state}, state == "open"
	}
	res := RustFastScan(host, port, timeoutMs, true)
	if res.State == "error" {
		return ScanPort(host, port, timeoutMs)
	}
	return res, res.State == "open"
}

// ScanXMAS — Christmas tree scan (FIN+PSH+URG)
func ScanXMAS(host string, port int, timeoutMs int) (PortResult, bool) {
	if _, _, state := CRawScan(host, port, timeoutMs, 3, 0, 0, nil, false, 0); state != "no-result" && state != "error" {
		return PortResult{Port: port, State: state}, state == "open"
	}
	res := RustFastScan(host, port, timeoutMs, true)
	if res.State == "error" {
		return ScanPort(host, port, timeoutMs)
	}
	return res, res.State == "open"
}

// ScanNULL — Null scan (no flags)
func ScanNULL(host string, port int, timeoutMs int) (PortResult, bool) {
	if _, _, state := CRawScan(host, port, timeoutMs, 4, 0, 0, nil, false, 0); state != "no-result" && state != "error" {
		return PortResult{Port: port, State: state}, state == "open"
	}
	res := RustFastScan(host, port, timeoutMs, true)
	if res.State == "error" {
		return ScanPort(host, port, timeoutMs)
	}
	return res, res.State == "open"
}

// ScanWindow — Window scan (RST response, window size determines state)
func ScanWindow(host string, port int, timeoutMs int) (PortResult, bool) {
	if _, _, state := CRawScan(host, port, timeoutMs, 6, 0, 0, nil, false, 0); state != "no-result" && state != "error" {
		return PortResult{Port: port, State: state}, state == "open"
	}
	res := RustFastScan(host, port, timeoutMs, false)
	if res.State == "error" {
		return ScanPort(host, port, timeoutMs)
	}
	return res, res.State == "open"
}

// ScanMaimon — Maimon scan (FIN/ACK)
func ScanMaimon(host string, port int, timeoutMs int) (PortResult, bool) {
	if _, _, state := CRawScan(host, port, timeoutMs, 7, 0, 0, nil, false, 0); state != "no-result" && state != "error" {
		return PortResult{Port: port, State: state}, state == "open"
	}
	res := RustFastScan(host, port, timeoutMs, true)
	if res.State == "error" {
		return ScanPort(host, port, timeoutMs)
	}
	return res, res.State == "open"
}

// ScanIdle — Idle/IPID zombie scan via C raw engine
func ScanIdle(host string, port int, zombie string, timeoutMs int) (PortResult, bool) {
	decoys := []string{zombie}
	if _, _, state := CRawScan(host, port, timeoutMs, 9, 0, 0, decoys, false, 0); state != "no-result" && state != "error" {
		return PortResult{Port: port, State: state}, state == "open"
	}
	res := RustFastScan(host, port, timeoutMs, true)
	if res.State == "error" {
		return ScanPort(host, port, timeoutMs)
	}
	return res, res.State == "open"
}

// ScanProtocol — IP protocol sweep (ICMP, IGMP, TCP, UDP, etc.)
func ScanProtocol(host string, port int, timeoutMs int) (PortResult, bool) {
	// Protocol sweep: try common IP protocol numbers
	// For most practical use, we do TCP + UDP probe
	tcpRes, tcpOpen := ScanPort(host, port, timeoutMs)
	if tcpOpen {
		return tcpRes, true
	}
	udpRes, udpOpen := ScanUDP(host, port, timeoutMs)
	if udpOpen {
		return udpRes, true
	}
	return tcpRes, false
}

// ─────────────────────────────────────────────────────────────────
// MULTI-ENGINE ORCHESTRATOR (SYN mode)
// ─────────────────────────────────────────────────────────────────

func (e *ScanEngine) MultiEngineOrchestrator(port int) PortResult {
	// Phase 1: Try Rust fast-scan (zero-copy, epoll-based)
	res := RustFastScan(e.Host, port, e.TimeoutMs, e.Stealth)
	if res.State == "open" {
		// Cross-validate with Go
		goRes, goOpen := ScanPort(e.Host, port, e.TimeoutMs)
		if !goOpen {
			// Rust says open but Go says closed — mark as filtered
			res.State = "filtered"
		} else if goRes.Service != "" {
			res.Service = goRes.Service
			res.Banner = goRes.Banner
			res.Version = goRes.Version
		}
		return res
	}

	// Phase 2: Fallback: Go connect scan
	goRes, isOpen := ScanPort(e.Host, port, e.TimeoutMs)
	if isOpen {
		// Cross-validate with C scanner
		cRes := CScannerScan(e.Host, []int{port}, e.TimeoutMs, 1)
		if len(cRes) > 0 && cRes[0].State == "open" {
			if cRes[0].Service != "" {
				goRes.Service = cRes[0].Service
			}
			if cRes[0].Banner != "" {
				goRes.Banner = cRes[0].Banner
			}
			if cRes[0].Version != "" {
				goRes.Version = cRes[0].Version
			}
		}
	}
	return goRes
}

// CrossCheckOrchestrator runs ALL engines on a port and returns consensus
func (e *ScanEngine) CrossCheckOrchestrator(port int) PortResult {
	// Run all engines in parallel
	type engineResult struct {
		name string
		res  PortResult
	}
	ch := make(chan engineResult, 4)

	go func() {
		goRes, _ := ScanPort(e.Host, port, e.TimeoutMs)
		ch <- engineResult{"go", goRes}
	}()

	go func() {
		rustRes := RustFastScan(e.Host, port, e.TimeoutMs, e.Stealth)
		ch <- engineResult{"rust", rustRes}
	}()

	go func() {
		cRes := CScannerScan(e.Host, []int{port}, e.TimeoutMs, 1)
		if len(cRes) > 0 {
			ch <- engineResult{"c", cRes[0]}
		} else {
			ch <- engineResult{"c", PortResult{Port: port, State: "error"}}
		}
	}()

	go func() {
		cppRes := CppServiceScanner(e.Host, port, e.TimeoutMs)
		ch <- engineResult{"cpp", cppRes}
	}()

	results := make(map[string]PortResult)
	for i := 0; i < 4; i++ {
		r := <-ch
		results[r.name] = r.res
	}

	// Consensus: open count vs filtered count
	openCount := 0
	var best PortResult
	for _, r := range results {
		if r.State == "open" {
			openCount++
			if best.State == "" || best.State == "error" {
				best = r
			}
			if r.Service != "" && best.Service == "" {
				best.Service = r.Service
			}
			if r.Banner != "" && best.Banner == "" {
				best.Banner = r.Banner
			}
			if r.Version != "" && best.Version == "" {
				best.Version = r.Version
			}
		} else if best.State == "" || best.State == "error" {
			if r.State != "" {
				best = r
			}
		}
	}

	if best.State == "" || best.State == "error" {
		// Use Go result as default
		if r, ok := results["go"]; ok {
			best = r
		}
	}

	// If at least 2 engines agree it's open, mark as open
	if openCount >= 2 {
		best.State = "open"
	} else if best.State == "open" && openCount < 2 {
		// Only one engine says open — mark as filtered
		best.State = "filtered"
	}

	best.Port = port
	return best
}

// ─────────────────────────────────────────────────────────────────
// RUST RESULTS ENRICHER
// ─────────────────────────────────────────────────────────────────

func (e *ScanEngine) enrichRustResults(openPortsStr string, allPorts []int) []PortResult {
	var results []PortResult
	
	if openPortsStr == "" {
		return results
	}

	for _, pStr := range splitCSV(openPortsStr) {
		p := 0
		fmt.Sscanf(pStr, "%d", &p)
		if p <= 0 {
			continue
		}
		res := PortResult{Port: p, State: "open", Protocol: "tcp"}
		e.enrichPort(&res, p, true)
		results = append(results, res)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

// ─────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────

func quantumSort(ports []int) []int {
	// Quantum ordering: common ports → medium → rare
	// Uses statistical likelihood of being open (nmap top-ports ordering)
	topPriority := []int{
		80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
		8080, 1723, 111, 995, 993, 5900, 587, 8443, 6379, 27017, 5432,
		2375, 9200, 11211, 1433, 1521, 5672, 8000, 8888, 3000, 9090,
		6443, 10250, 2379, 2376, 5985, 5986,
	}
	topSet := map[int]bool{}
	for _, p := range topPriority {
		topSet[p] = true
	}

	var priority, rest []int
	for _, p := range ports {
		if topSet[p] {
			priority = append(priority, p)
		} else {
			rest = append(rest, p)
		}
	}
	return append(priority, rest...)
}

func generateCPE(service, version string) string {
	if service == "" {
		return ""
	}
	svc := toLower(service)
	cpeMap := map[string]string{
		"ssh": "a:openssh:openssh", "openssh": "a:openssh:openssh",
		"http": "a:apache:http_server", "nginx": "a:nginx:nginx",
		"ftp": "a:vsftpd:vsftpd", "mysql": "a:mysql:mysql",
		"redis": "a:redis:redis", "mongodb": "a:mongodb:mongodb",
		"postgresql": "a:postgresql:postgresql",
		"mssql": "a:microsoft:sql_server",
	}
	for k, v := range cpeMap {
		if contains(svc, k) {
			if version != "" {
				return "cpe:/"+v+":"+version
			}
			return "cpe:/" + v
		}
	}
	return ""
}

func calculateRiskScore(port int, service, banner string, vulns []string) float64 {
	score := 0.0
	
	highRisk := map[int]bool{
		21: true, 23: true, 445: true, 3389: true, 5900: true,
		2375: true, 6379: true, 27017: true, 9200: true, 11211: true,
		4444: true, 1080: true, 6667: true, 10250: true, 50000: true,
	}
	if highRisk[port] {
		score += 40
	}

	bannerL := toLower(banner)
	if contains(bannerL, "openssh 5") || contains(bannerL, "openssh 6") ||
		contains(bannerL, "apache/2.2") || contains(bannerL, "openssl/1.0") {
		score += 30
	}

	score += float64(len(vulns)) * 10

	if score > 100 {
		score = 100
	}
	return score
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	var parts []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				parts = append(parts, cur)
			}
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}

func min2(a, b int) int {
	if a < b { return a }
	return b
}

func jitterSleep(minMs, maxMs int) {
	d := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(d) * time.Millisecond)
}

func NewScanEngine(host string, ports []int, threads int, timeoutMs int, stealth bool, mode string, reporter *Reporter) *ScanEngine {
	return &ScanEngine{
		Host:        host,
		Ports:       ports,
		Threads:     threads,
		TimeoutMs:   timeoutMs,
		Stealth:     stealth,
		ScanMode:    mode,
		Reporter:    reporter,
		MaxRetries:  3,
	}
}
