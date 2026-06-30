package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PipelineStage int

const (
	StageDiscovery   PipelineStage = iota
	StageTCPScan
	StageServiceDetect
	StageOSDetect
	StageVulnScan
	StageEnrich
)

var stageNames = map[PipelineStage]string{
	StageDiscovery:   "discovery",
	StageTCPScan:     "tcp_scan",
	StageServiceDetect: "service_detect",
	StageOSDetect:    "os_detect",
	StageVulnScan:    "vuln_scan",
	StageEnrich:      "enrich",
}

type Orchestrator struct {
	mu         sync.Mutex
	scanEngine *ScanEngine
	reporter   *Reporter
	ctx        context.Context
	cancel     context.CancelFunc

	totalStages int64
	failedStages int64
}

func NewOrchestrator(engine *ScanEngine) *Orchestrator {
	ctx, cancel := context.WithCancel(context.Background())
	return &Orchestrator{
		scanEngine: engine,
		reporter:   engine.Reporter,
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (o *Orchestrator) RunPipeline(target string, ports []int, stages []string) ScanResult {
	if o.reporter != nil {
		o.reporter.ReportStatus("Orchestrator: initializing pipeline", 0)
	}

	host := target
	if ip, err := resolveHost(target); err == nil {
		host = ip
	}

	pipeline := o.resolveStages(stages)
	if len(pipeline) == 0 {
		pipeline = []PipelineStage{
			StageDiscovery, StageTCPScan, StageServiceDetect,
			StageOSDetect, StageVulnScan, StageEnrich,
		}
	}

	var portResults []PortResult
	var osInfo OSInfo
	var intelInfo IntelInfo

	for _, stage := range pipeline {
		select {
		case <-o.ctx.Done():
			return ScanResult{
				Host:    target,
				IP:      host,
				OS:      osInfo,
				Intel:   intelInfo,
				Results: portResults,
			}
		default:
		}

		stageName := stageNames[stage]
		if o.reporter != nil {
			o.reporter.ReportStatus(fmt.Sprintf("Pipeline stage: %s", stageName), o.progress(pipeline, stage))
		}

		switch stage {
		case StageDiscovery:
			discPorts := o.runDiscovery(host, ports)
			if len(discPorts) > 0 {
				ports = discPorts
			}

		case StageTCPScan:
			results := o.runTCPScan(host, ports)
			if len(results) > 0 {
				portResults = append(portResults, results...)
			} else {
				atomic.AddInt64(&o.failedStages, 1)
			}

		case StageServiceDetect:
			o.runServiceDetect(host, portResults)

		case StageOSDetect:
			osInfo = o.runOSDetect(host, portResults)

		case StageVulnScan:
			o.runVulnScan(host, portResults)

		case StageEnrich:
			intelInfo = o.runIntelEnrich(host)
			o.runDeepEnrich(host, portResults)
		}
	}

	sort.Slice(portResults, func(i, j int) bool {
		return portResults[i].Port < portResults[j].Port
	})

	return ScanResult{
		Host:    target,
		IP:      host,
		OS:      osInfo,
		Intel:   intelInfo,
		Results: portResults,
	}
}

func (o *Orchestrator) resolveStages(names []string) []PipelineStage {
	stageMap := map[string]PipelineStage{
		"discovery":      StageDiscovery,
		"tcp_scan":       StageTCPScan,
		"service_detect": StageServiceDetect,
		"os_detect":      StageOSDetect,
		"vuln_scan":      StageVulnScan,
		"enrich":         StageEnrich,
	}
	var stages []PipelineStage
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if s, ok := stageMap[n]; ok {
			stages = append(stages, s)
		}
	}
	return stages
}

func (o *Orchestrator) progress(stages []PipelineStage, current PipelineStage) float64 {
	for i, s := range stages {
		if s == current {
			return float64(i) / float64(len(stages)) * 100
		}
	}
	return 0
}

func (o *Orchestrator) runDiscovery(host string, ports []int) []int {
	if o.scanEngine.NoPing {
		return ports
	}

	var alive []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)
	work := make(chan int, 100)
	discoveryDialer := getDialer(500 * time.Millisecond)

	worker := func() {
		defer wg.Done()
		for port := range work {
			sem <- struct{}{}
			func(port int) {
				defer func() { <-sem }()
				select {
				case <-o.ctx.Done():
					return
				default:
				}
				address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
				conn, err := discoveryDialer.Dial("tcp", address)
				if err == nil {
					conn.Close()
					mu.Lock()
					alive = append(alive, port)
					mu.Unlock()
				}
			}(port)
		}
	}

	numWorkers := 20
	if len(ports) < numWorkers {
		numWorkers = len(ports)
	}
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}

	for _, p := range ports {
		select {
		case work <- p:
		case <-o.ctx.Done():
			close(work)
			wg.Wait()
			if len(alive) == 0 {
				return ports
			}
			return alive
		}
	}
	close(work)
	wg.Wait()

	if len(alive) == 0 {
		return ports
	}
	return alive
}

func (o *Orchestrator) runTCPScan(host string, ports []int) []PortResult {
	if o.scanEngine == nil {
		engine := NewScanEngine(host, ports, 100, 1000, false, "connect", o.reporter)
		o.scanEngine = engine
	}
	o.scanEngine.Host = host
	o.scanEngine.Ports = ports
	return o.scanEngine.Run()
}

func (o *Orchestrator) runServiceDetect(host string, results []PortResult) {
	engine := o.scanEngine
	for i := range results {
		if results[i].State != "open" {
			continue
		}
		if results[i].Service == "" || results[i].Service == "unknown" {
			banner := results[i].Banner
			if banner == "" {
				banner = GrabBannerByHost(host, results[i].Port, 2000)
				results[i].Banner = banner
			}
			svc, ver := DetectService(results[i].Port, banner, host)
			if svc != "" {
				results[i].Service = svc
				results[i].Version = ver
			}
		}
		if results[i].Service == "" {
			results[i].Service = lookupServiceName(results[i].Port)
		}
		if engine != nil && engine.Deep && results[i].Banner != "" {
			rustSvc := RustFingerprintService(results[i].Banner)
			rus := strings.ToUpper(rustSvc)
			if rus != "" && rus != "UNKNOWN" {
				results[i].Service = rustSvc
				results[i].Version = RustExtractVersion(results[i].Banner, rustSvc)
			}
		}
	}
}

func (o *Orchestrator) runOSDetect(host string, results []PortResult) OSInfo {
	if o.scanEngine == nil || !o.scanEngine.OSDetect {
		return OSInfo{Name: "Unknown", Accuracy: 0}
	}

	osInfo := RustDetectOS(host)
	if osInfo.Name != "" && osInfo.Name != "Unknown" {
		return osInfo
	}

	openPorts := make([]string, 0)
	for _, r := range results {
		if r.State == "open" {
			openPorts = append(openPorts, fmt.Sprintf("%d", r.Port))
		}
	}
	if len(openPorts) > 0 {
		portsStr := strings.Join(openPorts, ",")
		detailed := RustDetectOsDetailed(host, portsStr, true, false)
		if detailed != "" {
			return OSInfo{
				Name:        detailed,
				Accuracy:    70,
				Fingerprint: "rust_detailed",
			}
		}
	}

	return AnalyzeOSFromResults(host, results)
}

func (o *Orchestrator) runVulnScan(host string, results []PortResult) {
	if o.scanEngine == nil || (!o.scanEngine.Deep && !o.scanEngine.VulnScan) {
		return
	}

	var wg sync.WaitGroup
	work := make(chan int, 100)

	worker := func() {
		for idx := range work {
			select {
			case <-o.ctx.Done():
				return
			default:
			}
			vulns := o.scanEngine.AnalyzeVulnerabilities(results[idx])
			if len(vulns) > 0 {
				results[idx].Vulnerabilities = append(results[idx].Vulnerabilities, vulns...)
			}
			if results[idx].Service != "" && results[idx].Version != "" {
				cpe := generateCPE(results[idx].Service, results[idx].Version)
				if cpe != "" {
					results[idx].CPEList = []string{cpe}
				}
			}
			results[idx].RiskScore = calculateRiskScore(
				results[idx].Port,
				results[idx].Service,
				results[idx].Banner,
				results[idx].Vulnerabilities,
			)
		}
	}

	numWorkers := 10
	openCount := 0
	for i := range results {
		if results[i].State == "open" {
			openCount++
		}
	}
	if openCount < numWorkers {
		numWorkers = openCount
	}
	if numWorkers < 1 {
		return
	}

	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}

	for i := range results {
		if results[i].State != "open" {
			continue
		}
		work <- i
	}
	close(work)
	wg.Wait()
}

func (o *Orchestrator) runIntelEnrich(host string) IntelInfo {
	return GetNetworkIntel(host)
}

func (o *Orchestrator) runDeepEnrich(host string, results []PortResult) {
	if o.scanEngine == nil || !o.scanEngine.UltraDeep {
		return
	}
	for i := range results {
		if results[i].State != "open" {
			continue
		}
		deepResult := RustPerformDeepScan(host, results[i].Port, results[i].Banner)
		if deepResult != "" {
			results[i].DeepAnalysis += "[RUST-DEEP]: " + deepResult
		}
	}
}
