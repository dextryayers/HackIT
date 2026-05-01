package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
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

func main() {
	target := flag.String("target", "", "Target Host or CIDR (e.g. 192.168.1.1 or 192.168.1.0/24)")
	ports := flag.String("ports", "", "Ports (comma separated or range 1-100)")
	timeout := flag.Int("timeout", 1000, "Timeout in ms")
	concurrency := flag.Int("threads", 100, "Threads")
	includeClosed := flag.Bool("include-closed", true, "Include closed ports in results")
	stealth := flag.Bool("stealth", false, "Stealth/Anonymous mode")
	scanMode := flag.String("mode", "connect", "Scan mode (connect, syn, udp, stealth, fin, xmas, etc.)")
	enrich := flag.Bool("enrich", false, "Enrich results with Python Intelligence Layer")
	profile := flag.String("profile", "default", "Scan profile (fast, stealth, full, web, lan)")
	format := flag.String("format", "text", "Output format: text or json")
	quietJSON := flag.Bool("quiet-json", false, "When format=json, suppress human-readable output")

	// Nmap parity flags
	script := flag.String("script", "", "Run specific Lua scripts (NSE-style)")
	scriptArgs := flag.String("script-args", "", "Arguments for Lua scripts")
	mtu := flag.Int("mtu", 0, "Set MTU size for fragmentation")
	dataLength := flag.Int("data-length", 0, "Append random data to packets")
	sourcePort := flag.Int("source-port", 0, "Set custom source port")
	identifyOS := flag.Bool("O", true, "Enable OS detection (Enabled by default for Deep Recon)")
	detailedOS := flag.Bool("detailed-os", true, "Enable detailed OS fingerprinting (Default: Deep)")
	ultraDeep := flag.Bool("ultra-deep", false, "Enable Extremely Deep Analysis (C/CPP/Rust Deep Audit)")
	detectService := flag.Bool("detect-service", false, "Enable service detection")
	osDetection := flag.Bool("os-detection", false, "Enable detailed OS detection and IP information")
	// Network Intel flags
	dnsInfo := flag.Bool("dns-info", false, "Enable DNS lookup")
	reverseLookup := flag.Bool("reverse-lookup", false, "Enable reverse DNS")
	subEnum := flag.Bool("sub-enum", false, "Enable subdomain enumeration")
	vulnScan := flag.Bool("vuln", true, "Enable vulnerability scanning (Default: Enabled)")
	whoisInfo := flag.Bool("whois-info", false, "Enable WHOIS lookup")
	geoInfo := flag.Bool("geo-info", false, "Enable GeoIP lookup")
	asnInfo := flag.Bool("asn-info", false, "Enable ASN lookup")

	// Web flags
	httpInspect := flag.Bool("http-inspect", false, "Enable HTTP inspection")
	techAnalyze := flag.Bool("tech-analyze", false, "Enable technology detection")
	tlsAnalyze := flag.Bool("tls-analyze", false, "Enable TLS analysis")
	certView := flag.Bool("cert-view", false, "Enable certificate info")
	showTitle := flag.Bool("show-title", false, "Extract page title")

	// Advanced flags
	customTTL := flag.Int("custom-ttl", 0, "Set custom TTL")
	spoofIP := flag.String("mask-ip", "", "Spoof source IP")
	spoofMAC := flag.String("spoof-mac", "", "Spoof MAC address")
	packetSplit := flag.Bool("packet-split", false, "Fragment packets")
	badSum := flag.Bool("badsum", false, "Send packets with bad checksum")
	traceroute := flag.Bool("traceroute", false, "Enable traceroute")

	// New advanced evasion and timing flags
	detectHoneypot := flag.Bool("detect-honeypot", false, "Check for potential honeypots")
	smartBypass := flag.Bool("smart-bypass", false, "Try automatic firewall bypass")
	randomOrder := flag.Bool("random-order", false, "Randomize target")
	decoyIP := flag.String("decoy-ip", "", "Gunakan IP decoy (comma separated)")
	useProxy := flag.String("use-proxy", "", "Gunakan proxy (http://ip:port)")
	useTor := flag.Bool("use-tor", false, "Route via TOR")
	versionIntensity := flag.Int("version-intensity", 7, "Intensity for version detection (0-9)")
	osScanLimit := flag.Bool("osscan-limit", false, "Limit OS detection to promising targets")
	osScanGuess := flag.Bool("osscan-guess", false, "Guess OS more aggressively")
	hostTimeout := flag.Int("host-timeout", 0, "Give up on target after X ms")
	scanDelay := flag.Int("scan-delay", 0, "Delay between probes (ms)")
	maxScanDelay := flag.Int("max-scan-delay", 0, "Max delay between probes (ms)")
	defeatRstRateLimit := flag.Bool("defeat-rst-ratelimit", false, "Bypass RST rate limits")
	defeatIcmpRateLimit := flag.Bool("defeat-icmp-ratelimit", false, "Bypass ICMP rate limits")
	nsockEngine := flag.String("nsock-engine", "poll", "Select nsock IO engine")

	flag.Parse()

	if *target == "" {
		fmt.Println(`ERROR:{"type":"error","error":"Target is required"}`)
		return
	}

	// Apply Profile Settings
	switch *profile {
	case "fast":
		*timeout = 500
		*concurrency = 200
		*scanMode = "syn"
	case "stealth":
		*timeout = 2000
		*concurrency = 20
		*stealth = true
		*scanMode = "syn"
	case "full":
		*timeout = 1500
		*concurrency = 150
		*scanMode = "syn"
		if *ports == "" {
			*ports = "1-65535"
		}
	case "web":
		*timeout = 1000
		*concurrency = 100
		if *ports == "" {
			*ports = "80,443,8080,8443,8000,8888,21,22,25,53,110,143,3306,5432,6379,27017,3389,5900"
		}
	case "lan":
		*timeout = 300
		*concurrency = 300
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

	for _, host := range targets {
		reporter.PrintStatus(host, 0)
		engine := NewScanEngine(host, portList, *concurrency, *timeout, *stealth, *scanMode, reporter)

		// Pass all flags to engine for full power
		engine.LuaScript = *script
		engine.LuaArgs = *scriptArgs
		engine.MTU = *mtu
		engine.DataLength = *dataLength
		engine.SourcePort = *sourcePort
		engine.IdentifyOS = *identifyOS
		engine.DetectService = *detectService
		engine.CustomTTL = *customTTL
		engine.DNSInfo = *dnsInfo
		engine.ReverseLookup = *reverseLookup
		engine.SubEnum = *subEnum
		engine.UltraDeep = *ultraDeep
		engine.IdentifyOS = *identifyOS
		engine.DetectService = *detailedOS
		engine.VulnScan = *vulnScan
		engine.WhoisInfo = *whoisInfo
		engine.GeoInfo = *geoInfo
		engine.ASNInfo = *asnInfo
		engine.HttpInspect = *httpInspect
		engine.TechAnalyze = *techAnalyze
		engine.TlsAnalyze = *tlsAnalyze
		engine.CertView = *certView
		engine.ShowTitle = *showTitle
		engine.IncludeClosed = *includeClosed
		engine.BadSum = *badSum
		engine.Traceroute = *traceroute
		engine.DetectHoneypot = *detectHoneypot
		engine.SmartBypass = *smartBypass
		engine.RandomOrder = *randomOrder
		engine.DecoyIP = *decoyIP
		engine.UseProxy = *useProxy
		engine.UseTor = *useTor
		engine.VersionIntensity = *versionIntensity
		engine.OSScanLimit = *osScanLimit
		engine.OSScanGuess = *osScanGuess
		engine.HostTimeout = *hostTimeout
		engine.ScanDelay = *scanDelay
		engine.MaxScanDelay = *maxScanDelay
		engine.DefeatRstRateLimit = *defeatRstRateLimit
		engine.DefeatIcmpRateLimit = *defeatIcmpRateLimit
		engine.NsockEngine = *nsockEngine
		engine.SpoofIP = *spoofIP
		engine.SpoofMAC = *spoofMAC
		engine.PacketSplit = *packetSplit
		engine.BadSum = *badSum
		engine.Traceroute = *traceroute

		results := engine.Run()

		// Resolve IP
		ipAddr := ""
		ips, _ := net.LookupIP(host)
		if len(ips) > 0 {
			ipAddr = ips[0].String()
		} else {
			ipAddr = host // If it's already an IP
		}

		osInfo := AnalyzeOSFromResults(host, results)
		intelInfo := RustGetNetworkIntelAdvanced(host)

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

	// Print the final comprehensive Nmap-style summary
	if *format != "json" {
		reporter.PrintNmapStyleSummary(*target, startTime, len(portList), *osDetection)
	}

	// Machine-readable final payload for Python bridge
	finalPayload := map[string]any{
		"schema_version":    "1",
		"os_schema_version": "1",
		"scanner":           "hackit-port-scanner",
		"format":            *format,
		"target":            *target,
		"started_at":        startTime.Format(time.RFC3339),
		"elapsed_ms":        int(time.Since(startTime).Milliseconds()),
		"notes":             "os.fingerprint may contain evidence details when available",
		"results":           allResults,
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
