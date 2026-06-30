package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PipelineEngineResult struct {
	Engine string
	Result PortResult
}

type ParallelPipeline struct {
	ctx         context.Context
	cancel      context.CancelFunc
	host        string
	ports       []int
	engines     []string
	scanEngine  *ScanEngine
	reporter    *Reporter
	shmRing     *ShmRing

	engineResults chan PipelineEngineResult
	mergedResults []PortResult
	osInfo        OSInfo
	intelInfo     IntelInfo

	stageTimes map[string]time.Duration
	mu         sync.Mutex
}

func NewParallelPipeline(engine *ScanEngine, host string, ports []int) *ParallelPipeline {
	ctx, cancel := context.WithCancel(context.Background())
	engines := []string{"c", "cpp", "rust", "go", "lua"}
	if cgo := GetCgoEngine(); !cgo.IsCAvailable() {
		engines = []string{"rust", "go", "lua"}
	}

	p := &ParallelPipeline{
		ctx:           ctx,
		cancel:        cancel,
		host:          host,
		ports:         ports,
		engines:       engines,
		scanEngine:    engine,
		reporter:      engine.Reporter,
		engineResults: make(chan PipelineEngineResult, 65536),
		stageTimes:    make(map[string]time.Duration),
	}

	ring, err := NewShmRing("/portstorm-pipeline", 64*1024*1024)
	if err == nil {
		p.shmRing = ring
	}

	return p
}

func (p *ParallelPipeline) Run() ScanResult {
	if p.reporter != nil {
		p.reporter.ReportStatus("Parallel pipeline: starting all engines", 0)
	}

	hostIP := p.host
	if ip, err := resolveHostCached(p.host); err == nil {
		hostIP = ip
	}

	var wg sync.WaitGroup
	portCount := len(p.ports)

	openPorts := make(map[int]bool)
	var openMu sync.Mutex
	var scanned int64

	reporter := p.reporter
	progressFn := func(stage string) {
		n := atomic.AddInt64(&scanned, 1)
		if reporter != nil && n%100 == 0 {
			reporter.ReportStatus(
				fmt.Sprintf("Pipeline %s: %d/%d", stage, n, portCount),
				float64(n)/float64(portCount)*100,
			)
		}
	}

	startTotal := time.Now()

	allEngineResults := make([]PipelineEngineResult, 0, portCount)
	var resultsMu sync.Mutex

	scanPort := func(port int, engineName string) PortResult {
		progressFn(engineName)
		switch engineName {
		case "go":
			res, isOpen := ScanPort(p.host, port, p.scanEngine.TimeoutMs)
			if isOpen {
				openMu.Lock()
				openPorts[port] = true
				openMu.Unlock()
			}
			return res
		case "rust":
			res := RustFastScan(p.host, port, p.scanEngine.TimeoutMs, p.scanEngine.Stealth)
			if res.State == "open" {
				openMu.Lock()
				openPorts[port] = true
				openMu.Unlock()
			}
			return res
		case "c":
			cBridge := GetCBridge()
			res := cBridge.SYCScan(p.host, port, p.scanEngine.TimeoutMs)
			if res.State == "open" {
				openMu.Lock()
				openPorts[port] = true
				openMu.Unlock()
			}
			return res
		case "cpp":
			cppBridge := GetCppBridge()
			res := cppBridge.DeepAnalyze(p.host, port, "")
			if res != "" {
				return PortResult{Port: port, State: "open", DeepAnalysis: res}
			}
			cppRes := CppServiceScanner(p.host, port, p.scanEngine.TimeoutMs)
			if cppRes.State == "open" {
				openMu.Lock()
				openPorts[port] = true
				openMu.Unlock()
			}
			return cppRes
		case "lua":
			if p.scanEngine.Lua == nil {
				p.scanEngine.Lua = NewLuaEngine()
			}
			luaRes := p.scanEngine.Lua.RunScripts(p.host, port, "", "")
			if len(luaRes) > 0 {
				return PortResult{Port: port, State: "open", Scripts: luaRes}
			}
			return PortResult{Port: port, State: "filtered"}
		default:
			return PortResult{Port: port, State: "error"}
		}
	}

	engineChunks := make([][]int, len(p.engines))
	for i, port := range p.ports {
		engineIdx := i % len(p.engines)
		engineChunks[engineIdx] = append(engineChunks[engineIdx], port)
	}

	for ei, engineName := range p.engines {
		chunk := engineChunks[ei]
		if len(chunk) == 0 {
			continue
		}
		wg.Add(1)
		go func(name string, ports []int) {
			defer wg.Done()
			for _, port := range ports {
				select {
				case <-p.ctx.Done():
					return
				default:
				}
				res := scanPort(port, name)
				resultsMu.Lock()
				allEngineResults = append(allEngineResults, PipelineEngineResult{Engine: name, Result: res})
				resultsMu.Unlock()
			}
		}(engineName, chunk)
	}

	shmCollectorWg := sync.WaitGroup{}
	if p.shmRing != nil {
		shmCollectorWg.Add(1)
		go func() {
			defer shmCollectorWg.Done()
			for {
				port, _, isOpen, ok := p.shmRing.PopEntry()
				if !ok {
					select {
					case <-p.ctx.Done():
						return
					case <-time.After(10 * time.Millisecond):
						continue
					}
				}
				resultsMu.Lock()
				state := "filtered"
				if isOpen {
					state = "open"
				}
				allEngineResults = append(allEngineResults, PipelineEngineResult{
					Engine: "shm",
					Result: PortResult{Port: int(port), State: state, Reason: "shm_ring"},
				})
				resultsMu.Unlock()
			}
		}()
	}

	wg.Wait()

	if p.shmRing != nil {
		p.cancel()
		shmCollectorWg.Wait()
		p.ctx, p.cancel = context.WithCancel(context.Background())
	}

	p.stageTimes["scan"] = time.Since(startTotal)

	mergeStart := time.Now()

	goResults := extractEngineResults(allEngineResults, "go")
	rustResults := extractEngineResults(allEngineResults, "rust")
	cResults := extractEngineResults(allEngineResults, "c")
	cppResults := extractEngineResults(allEngineResults, "cpp")
	luaResults := extractEngineResults(allEngineResults, "lua")
	shmResults := extractEngineResults(allEngineResults, "shm")

	resultSets := [][]PortResult{goResults, rustResults, cResults, cppResults, luaResults, shmResults}
	var nonEmpty [][]PortResult
	engineNames := []string{}
	for i, rs := range resultSets {
		if len(rs) > 0 {
			nonEmpty = append(nonEmpty, rs)
			engineNames = append(engineNames, []string{"go", "rust", "c", "cpp", "lua", "shm"}[i])
		}
	}

	var merged []PortResult
	if len(nonEmpty) > 1 {
		merged = MergeResults(engineNames, nonEmpty...)
	} else if len(nonEmpty) == 1 {
		merged = nonEmpty[0]
	} else {
		merged = goResults
	}

	if len(merged) == 0 {
		merged = p.scanEngine.Run()
	}

	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Port < merged[j].Port
	})

	p.stageTimes["merge"] = time.Since(mergeStart)

	postStart := time.Now()
	p.postProcess(hostIP, merged)
	p.stageTimes["post_process"] = time.Since(postStart)

	osInfo := OSInfo{}
	intelInfo := IntelInfo{}

	if p.scanEngine.OSDetect {
		osInfo = p.runOSDetectParallel(hostIP, merged)
	}
	if p.scanEngine.Deep {
		intelInfo = p.runIntelParallel(hostIP)
	}

	p.mergedResults = merged
	p.osInfo = osInfo
	p.intelInfo = intelInfo

	result := ScanResult{
		Host:    p.host,
		IP:      hostIP,
		OS:      osInfo,
		Intel:   intelInfo,
		Results: merged,
	}

	if p.reporter != nil {
		p.reporter.ReportStatus(
			fmt.Sprintf("Pipeline complete: %d ports in %v", len(merged), time.Since(startTotal)),
			100,
		)
	}

	return result
}

func (p *ParallelPipeline) postProcess(host string, results []PortResult) {
	if !p.scanEngine.Deep && !p.scanEngine.DetectService {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for i := range results {
		if results[i].State != "open" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			r := &results[idx]

			if r.Service == "" || r.Service == "unknown" {
				if r.Banner == "" {
					r.Banner = GrabBannerByHost(host, r.Port, p.scanEngine.TimeoutMs)
				}
				svc, ver := DetectService(r.Port, r.Banner, host)
				if svc != "" {
					r.Service = svc
					r.Version = ver
				}
			}

			if r.Banner != "" {
				rustSvc := RustFingerprintService(r.Banner)
				if rustSvc != "" && rustSvc != "UNKNOWN" {
					r.Service = rustSvc
					r.Version = RustExtractVersion(r.Banner, rustSvc)
				}
			}

			if r.Service == "" || r.Service == "unknown" {
				r.Service = lookupServiceName(r.Port)
			}

			if p.scanEngine.Lua == nil {
				p.scanEngine.Lua = NewLuaEngine()
			}
			luaResults := p.scanEngine.Lua.RunScripts(host, r.Port, r.Service, r.Banner)
			if len(luaResults) > 0 {
				r.Scripts = append(r.Scripts, luaResults...)
			}

			if p.scanEngine.VulnScan || p.scanEngine.Deep {
				vulns := p.scanEngine.AnalyzeVulnerabilities(*r)
				if len(vulns) > 0 {
					r.Vulnerabilities = append(r.Vulnerabilities, vulns...)
				}
			}

			if r.Service != "" && r.Version != "" {
				cpe := generateCPE(r.Service, r.Version)
				if cpe != "" {
					r.CPEList = []string{cpe}
				}
			}

			if r.Service == "" && r.Banner != "" {
				r.Service, r.Version = DetectService(r.Port, r.Banner, host)
			}
			r.Service = lookupServiceName(r.Port)

			r.RiskScore = calculateRiskScore(r.Port, r.Service, r.Banner, r.Vulnerabilities)
		}(i)
	}
	wg.Wait()
}

func (p *ParallelPipeline) runOSDetectParallel(host string, results []PortResult) OSInfo {
	if !p.scanEngine.OSDetect {
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
			return OSInfo{Name: detailed, Accuracy: 70, Fingerprint: "rust_detailed"}
		}
	}

	return AnalyzeOSFromResults(host, results)
}

func (p *ParallelPipeline) runIntelParallel(host string) IntelInfo {
	return GetNetworkIntel(host)
}

func (p *ParallelPipeline) Close() {
	p.cancel()
	if p.shmRing != nil {
		p.shmRing.Close()
	}
}

func extractEngineResults(all []PipelineEngineResult, engine string) []PortResult {
	var out []PortResult
	seen := make(map[int]bool)
	for _, er := range all {
		if er.Engine == engine {
			if !seen[er.Result.Port] {
				seen[er.Result.Port] = true
				out = append(out, er.Result)
			}
		}
	}
	return out
}
