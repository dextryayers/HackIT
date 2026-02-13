package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os/exec"
	"sort"
)

type PortResult struct {
	Port    int      `json:"port"`
	State   string   `json:"status"`
	Service string   `json:"service"`
	Banner  string   `json:"banner"`
	Version string   `json:"version"`
	TTL     int      `json:"ttl"`
	OS      string   `json:"os"`
	Scripts []string `json:"scripts,omitempty"`
}

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

	// Nmap parity flags
	script := flag.String("script", "", "Run specific Lua scripts (NSE-style)")
	scriptArgs := flag.String("script-args", "", "Arguments for Lua scripts")
	mtu := flag.Int("mtu", 0, "Set MTU size for fragmentation")
	dataLength := flag.Int("data-length", 0, "Append random data to packets")
	sourcePort := flag.Int("source-port", 0, "Set custom source port")
	identifyOS := flag.Bool("identify-os", false, "Enable OS detection")
	detectService := flag.Bool("detect-service", false, "Enable service detection")

	// Network Intel flags
	dnsInfo := flag.Bool("dns-info", false, "Enable DNS lookup")
	reverseLookup := flag.Bool("reverse-lookup", false, "Enable reverse DNS")
	subEnum := flag.Bool("sub-enum", false, "Enable subdomain discovery")
	whoisInfo := flag.Bool("whois-info", false, "Enable WHOIS lookup")
	geoInfo := flag.Bool("geo-info", false, "Enable GeoIP lookup")
	asnInfo := flag.Bool("asn-info", false, "Enable ASN lookup")

	// Web flags
	httpInspect := flag.Bool("http-inspect", false, "Enable HTTP inspection")
	techAnalyze := flag.Bool("tech-analyze", false, "Enable technology detection")
	tlsAnalyze := flag.Bool("tls-analyze", false, "Enable TLS analysis")
	certView := flag.Bool("cert-view", false, "Enable certificate info")
	showTitle := flag.Bool("show-title", false, "Extract page title")

	flag.Parse()

	customTTL := flag.Int("custom-ttl", 0, "Set custom TTL")
	spoofIP := flag.String("mask-ip", "", "Spoof source IP")
	spoofMAC := flag.String("spoof-mac", "", "Spoof MAC address")
	packetSplit := flag.Bool("packet-split", false, "Fragment packets")
	badSum := flag.Bool("badsum", false, "Send packets with bad checksum")
	traceroute := flag.Bool("traceroute", false, "Enable traceroute")

	flag.Parse()

	if *target == "" {
		fmt.Println(`{"error": "Target is required"}`)
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
			*ports = "80,443,8080,8443,8000,8888"
		}
	case "lan":
		*timeout = 300
		*concurrency = 300
	}

	targets, err := expandTargets(*target)
	if err != nil {
		fmt.Printf(`{"error": "Invalid target: %v"}`+"\n", err)
		return
	}

	portList := parsePorts(*ports)
	// If no ports specified, scan full range 1-65535 (User request)
	if len(portList) == 0 {
		for i := 1; i <= 65535; i++ {
			portList = append(portList, i)
		}
	}

	if *stealth {
		portList = shufflePorts(portList)
		if *concurrency > 200 {
			*concurrency = *concurrency / 2
		}
	}

	reporter := &Reporter{}
	allResults := make([]ScanResult, 0)

	for _, host := range targets {
		reporter.ReportStatus(fmt.Sprintf("Scanning %s", host), 0)
		engine := NewScanEngine(host, *timeout, *concurrency, *includeClosed, *stealth, *scanMode, reporter)

		// Pass new flags to engine
		engine.LuaScript = *script
		engine.LuaArgs = *scriptArgs
		engine.MTU = *mtu
		engine.DataLength = *dataLength
		engine.SourcePort = *sourcePort
		engine.IdentifyOS = *identifyOS
		engine.DetectService = *detectService
		engine.CustomTTL = *customTTL
		engine.SpoofIP = *spoofIP
		engine.SpoofMAC = *spoofMAC
		engine.PacketSplit = *packetSplit
		engine.BadSum = *badSum
		engine.Traceroute = *traceroute

		// New Intel & Web flags
		engine.DNSInfo = *dnsInfo
		engine.ReverseLookup = *reverseLookup
		engine.SubEnum = *subEnum
		engine.WhoisInfo = *whoisInfo
		engine.GeoInfo = *geoInfo
		engine.ASNInfo = *asnInfo
		engine.HttpInspect = *httpInspect
		engine.TechAnalyze = *techAnalyze
		engine.TlsAnalyze = *tlsAnalyze
		engine.CertView = *certView
		engine.ShowTitle = *showTitle

		results := engine.Run(portList)

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

	finalJSON, _ := json.Marshal(allResults)
	fmt.Printf("\nFINAL:%s\n", string(finalJSON))

	// Print the final Nmap-style sorted table
	reporter.PrintFinalTable()
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
