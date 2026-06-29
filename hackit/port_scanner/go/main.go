package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime/pprof"
	"sort"
	"strings"
	"time"
)

type ScanResult struct {
	Host         string       `json:"host"`
	IP           string       `json:"ip"`
	OS           OSInfo       `json:"os"`
	Intel        IntelInfo    `json:"intel"`
	Results      []PortResult `json:"results"`
	Intelligence interface{}  `json:"intelligence,omitempty"`
}

func init() {
	os.Setenv("GODEBUG", "netdns=cgo")
}

func main() {
	target := flag.String("target", "", "Target Host or CIDR")
	ports := flag.String("ports", "", "Ports (comma separated or range)")
	timeout := flag.Int("timeout", 1000, "Timeout in ms")
	concurrency := flag.Int("threads", 100, "Threads")
	includeClosed := flag.Bool("include-closed", true, "Include closed ports")
	stealth := flag.Bool("stealth", false, "Stealth mode")
	scanMode := flag.String("mode", "connect", "Scan mode")
	enrich := flag.Bool("enrich", false, "Enrich results")
	profile := flag.String("profile", "default", "Scan profile")
	format := flag.String("format", "text", "Output format")
	outputFile := flag.String("output", "", "Output filename")
	openOnly := flag.Bool("open-only", false, "Show only open ports")
	quietJSON := flag.Bool("quiet-json", false, "Suppress human output")
	// Stealth & Evasion flags
	ghostProtocol := flag.Bool("ghost-protocol", false, "Enable Ghost Protocol")
	chaos := flag.Bool("chaos", false, "Enable Chaos Mode")
	decoy := flag.String("decoy", "", "Decoy IPs")
	zombie := flag.String("zombie", "", "Zombie host")
	spoofIP := flag.String("spoof-ip", "", "Spoof IP")
	sourcePort := flag.Int("source-port", 0, "Source port")
	frag := flag.Bool("frag", false, "Fragment packets")
	fragSize := flag.Int("frag-size", 0, "Fragment size")
	mtu := flag.Int("mtu", 0, "MTU size")
	ttl := flag.Int("ttl", 0, "Custom TTL")

	// Intelligence & Detection flags
	deep := flag.Bool("deep", false, "Deep inspection")
	passive := flag.Bool("passive", false, "Passive intelligence")
	smartProbe := flag.Bool("smart-probe", false, "Smart service probe")
	fingerprintIntensity := flag.Int("fingerprint-intensity", 5, "Fingerprint intensity")
	osDetect := flag.Bool("os-detect", false, "Enable OS detection")
	script := flag.String("script", "", "Run script modules")
	scriptArgs := flag.String("script-args", "", "Arguments for scripts")

	// Pipeline & Multi-Engine flags
	pipeline := flag.String("pipeline", "", "Pipeline stages: tcp,service,os,vuln (comma-separated)")
	allEngines := flag.Bool("all-engines", false, "Run ALL engines and correlate results")

	// Timing & Performance flags
	adaptive := flag.Bool("adaptive", false, "Adaptive timing")
	quantum := flag.Bool("quantum", false, "Quantum port ordering")
	minRate := flag.Int("min-rate", 0, "Min packets/sec")
	maxRate := flag.Int("max-rate", 0, "Max packets/sec")
	maxRetries := flag.Int("max-retries", 3, "Max retries")
	hostTimeout := flag.Int("host-timeout", 0, "Host timeout")
	scanDelay := flag.Int("scan-delay", 0, "Scan delay")

	// Network & Discovery flags
	randomizeTargets := flag.Bool("randomize-targets", false, "Randomize targets")
	randomizePorts := flag.Bool("randomize-ports", false, "Randomize ports")
	noPing := flag.Bool("no-ping", false, "Skip host discovery")
	pingMethod := flag.String("ping-method", "icmp", "Ping method")
	resolvePolicy := flag.String("resolve", "all", "DNS resolution policy")
	dnsServer := flag.String("dns-server", "", "Custom DNS server")

	// Control socket
	controlSocket := flag.String("control-socket", "", "Unix socket path for GUI control commands")

	// Version / Profiling flags
	showVersion := flag.Bool("version", false, "Show version and exit")
	cpuProfile := flag.String("cpuprofile", "", "Write CPU profile to file")
	memProfile := flag.String("memprofile", "", "Write memory profile to file")

	flag.Parse()

	if *showVersion {
		fmt.Printf("HackIT PortStorm v3.0.0 (Go engine)\n")
		return
	}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating CPU profile: %v\n", err)
			return
		}
		pprof.StartCPUProfile(f)
		defer func() {
			pprof.StopCPUProfile()
			f.Close()
		}()
	}
	defer func() {
		if *memProfile != "" {
			f, err := os.Create(*memProfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating mem profile: %v\n", err)
				return
			}
			pprof.WriteHeapProfile(f)
			f.Close()
		}
	}()

	// Control socket listener for GUI commands
	if *controlSocket != "" {
		ctrlAddr := *controlSocket
		go func() {
			ln, err := net.Listen("unix", ctrlAddr)
			if err != nil {
				return
			}
			defer ln.Close()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					var cmd struct {
						Command string `json:"command"`
					}
					json.NewDecoder(c).Decode(&cmd)
					if cmd.Command == "stop" {
						os.Exit(0)
					}
				}(conn)
			}
		}()
	}

	if *target == "" {
		fmt.Println(`ERROR:{"type":"error","error":"Target is required"}`)
		return
	}

	// Apply Profile Settings using profiles.go
	p := GetProfile(*profile)
	if *profile != "default" {
		*timeout = p.TimeoutMs
		*concurrency = p.Workers
		*scanMode = p.ScanMode
		*stealth = p.Stealth
		*deep = p.Deep
		*osDetect = p.OSDetect
		*adaptive = p.Adaptive
		*quantum = p.Quantum
		*minRate = p.MinRate
		*maxRate = p.MaxRate
		*maxRetries = p.MaxRetries
		*hostTimeout = p.HostTimeout
		*noPing = p.NoPing
		if len(p.Ports) > 0 {
			ps := make([]string, len(p.Ports))
			for i, v := range p.Ports {
				ps[i] = fmt.Sprintf("%d", v)
			}
			*ports = strings.Join(ps, ",")
		} else if p.Name == "Full" && *ports == "" {
			*ports = "1-65535"
		}
	}

	// Parse Ports
	portList := parsePorts(*ports)

	// Targets processing
	targets, err := expandTargets(*target)
	if err != nil {
		fmt.Printf(`ERROR:{"type":"error","error":"Invalid target: %v"}`+"\n", err)
		return
	}

	reporter := &Reporter{}
	if *format == "json" && *quietJSON {
		reporter = &Reporter{SuppressHuman: true}
	}
	allResults := make([]ScanResult, 0)
	startTime := time.Now()

	// Print ASCII banner
	if !(reporter.SuppressHuman) {
		if len(targets) > 0 {
			PrintBanner(targets[0])
		} else {
			PrintBanner(*target)
		}
	}

	for _, host := range targets {
		targetIP, _ := resolveHost(host)

		engine := NewScanEngine(targetIP, portList, *concurrency, *timeout, *stealth, *scanMode, reporter)
		engine.Hostname = host // Keep original for reporting

		// Core Mapping
		engine.IncludeClosed = *includeClosed
		engine.ScanMode = *scanMode
		engine.Format = *format
		engine.OutputFile = *outputFile
		engine.OpenOnly = *openOnly

		// Stealth & Evasion Mapping
		engine.GhostProtocol = *ghostProtocol
		engine.Chaos = *chaos
		engine.Decoy = *decoy
		engine.Zombie = *zombie
		engine.SpoofIP = *spoofIP
		engine.SourcePort = *sourcePort
		engine.Frag = *frag
		engine.FragSize = *fragSize
		engine.MTU = *mtu
		engine.TTL = *ttl

		// Intelligence & Detection Mapping
		engine.Deep = *deep
		engine.Passive = *passive
		engine.SmartProbe = *smartProbe
		engine.FingerprintIntensity = *fingerprintIntensity
		engine.OSDetect = *osDetect
		engine.Script = *script
		engine.ScriptArgs = *scriptArgs

		// Timing & Performance Mapping
		engine.Adaptive = *adaptive
		engine.Quantum = *quantum
		engine.MinRate = *minRate
		engine.MaxRate = *maxRate
		engine.MaxRetries = *maxRetries
		engine.HostTimeout = *hostTimeout
		engine.ScanDelay = *scanDelay

		// Pipeline & Multi-Engine mapping
		if *pipeline != "" {
			engine.PipelineStages = strings.Split(*pipeline, ",")
		}
		engine.AllEngines = *allEngines

		// Network & Discovery Mapping
		engine.RandomizeTargets = *randomizeTargets
		engine.RandomizePorts = *randomizePorts
		engine.NoPing = *noPing
		engine.PingMethod = *pingMethod
		engine.ResolvePolicy = *resolvePolicy
		engine.DNSServer = *dnsServer

		results := engine.Run()

		ipAddr := targetIP

		// High-Accuracy IP & Infrastructure Mapping (only in deep/os-detect/passive mode)
		var intelInfo IntelInfo
		if *deep || *osDetect || *passive {
			intelInfo = GetNetworkIntel(targetIP)
		}

		// Passive intelligence (DNS SRV/MX, CT logs, cache snoop)
		if *passive || *deep {
			passiveInfo := RunPassiveScan(host)
			if len(passiveInfo.SRVRecords) > 0 || len(passiveInfo.MXRecords) > 0 {
				if reporter != nil && !reporter.SuppressHuman {
					fmt.Printf("\n  [PASSIVE] DNS SRV: %d records, MX: %d records, CT: %d entries\n",
						len(passiveInfo.SRVRecords), len(passiveInfo.MXRecords), len(passiveInfo.CTLogs))
					for _, srv := range passiveInfo.SRVRecords {
						fmt.Printf("    SRV _%s._%s → %s:%d\n", srv.Service, srv.Proto, srv.Target, srv.Port)
					}
					for _, mx := range passiveInfo.MXRecords {
						fmt.Printf("    MX %s (pref %d)\n", mx.Host, mx.Preference)
					}
					if len(passiveInfo.Subdomains) > 0 {
						fmt.Printf("    Subdomains found: %d\n", len(passiveInfo.Subdomains))
					}
				}
			}
		}

		var osInfo OSInfo
		if *osDetect || *deep {
			osInfo = AnalyzeOSFromResults(host, results)
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].Port < results[j].Port
		})

		allResults = append(allResults, ScanResult{
			Host:    host,
			IP:      ipAddr,
			OS:      osInfo,
			Intel:   intelInfo,
			Results: results,
		})
	}

	if *enrich {
		for i := range allResults {
			enriched := EnrichWithPython(allResults[i])
			allResults[i] = enriched
		}
	}

	// Run results through C++ correlator for cross-validation
	if *allEngines || *deep {
		for i := range allResults {
			corr := GetCppBridge().Correlate(allResults[i].Host, allResults[i].Results)
			if corr != "" {
				allResults[i].Intelligence = corr
			}
		}
	}

	// Print the final comprehensive HackIT-style summary
	if *format != "json" {
		reporter.PrintHackITStyleSummary(*target, startTime, len(portList), *osDetect)
	}

	// Collect engine metadata
	engineMeta := map[string]interface{}{
		"go":      true,
		"rust":    true,
		"c":       true,
		"cpp":     true,
		"python":  *enrich,
	}

	// Machine-readable final payload for Python bridge
	finalPayload := map[string]any{
		"schema_version":    "2",
		"os_schema_version": "1",
		"scanner":           "hackit-port-scanner",
		"format":            *format,
		"target":            *target,
		"started_at":        startTime.Format(time.RFC3339),
		"elapsed_ms":        int(time.Since(startTime).Milliseconds()),
		"notes":             "os.fingerprint may contain evidence details when available",
		"results":           allResults,
		"profile":           *profile,
		"pipeline":          *pipeline,
		"all_engines":       *allEngines,
		"engines":           engineMeta,
	}
	if b, err := json.Marshal(finalPayload); err == nil {
		fmt.Printf("FINAL:%s\n", string(b))
	} else {
		fmt.Printf("ERROR:%s\n", `{"type":"error","error":"failed to marshal final payload"}`)
	}
	os.Stdout.Sync()
}

func EnrichWithPython(data ScanResult) ScanResult {
	jsonData, _ := json.Marshal(data)
	// intelligence.py should be in the parent directory of go/
	cmd := exec.Command("python", "../intelligence.py")
	cmd.Stdin = bytes.NewReader(jsonData)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return data
	}

	var enriched ScanResult
	err = json.Unmarshal(out.Bytes(), &enriched)
	if err != nil {
		return data
	}
	return enriched
}

func expandTargets(target string) ([]string, error) {
	// Check if it's a CIDR
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		var ips []string
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
		// Remove network and broadcast addresses for typical scans
		if len(ips) > 2 {
			return ips[1 : len(ips)-1], nil
		}
		return ips, nil
	}

	// Just a single host/IP
	return []string{target}, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// runScan is now deprecated in favor of ScanEngine.Run
