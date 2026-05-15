package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fatih/color"
)

// --- Full Intelligence Map Structs ---

type Result struct {
	URL             string              `json:"url"`
	Status          int                 `json:"status"`
	Title           string              `json:"title"`
	IP              string              `json:"ip"`
	Server          string              `json:"server"`
	Technologies    map[string]TechInfo `json:"technologies"`
	Headers         map[string]string   `json:"headers"`
	DNS             *DNSInfo            `json:"dns,omitempty"`
	Whois           *WhoisInfo          `json:"whois,omitempty"`
	Forensics       string              `json:"forensics,omitempty"`
	Industry        string              `json:"industry,omitempty"`
	Description     string              `json:"description,omitempty"`
	Aliases         []string            `json:"aliases,omitempty"`
	Network         []*NetworkInfo      `json:"network,omitempty"`
	DNSEnum         *DNSEnumResult      `json:"dns_enum,omitempty"`
	DNSHistory      *DNSHistoryResult   `json:"dns_history,omitempty"`
	SSLAnalysis     *SSLAnalysisResult  `json:"ssl_analysis,omitempty"`
	PassiveDNS      *PassiveDNSResult   `json:"passive_dns,omitempty"`
	PortScan        []PortResult        `json:"port_scan,omitempty"`
	WAF             *WAFResult          `json:"waf,omitempty"`
	WebAudit        *WebAudit           `json:"web_audit,omitempty"`
	OriginDiscovery *OriginResult       `json:"origin_discovery,omitempty"`
	Subsidiaries    *SubsidiaryResult   `json:"subsidiaries,omitempty"`
	InfraForensics  *InfraForensics     `json:"infra_forensics,omitempty"`
	TCPForensics    string              `json:"tcp_forensics,omitempty"`
	BypassStrategy  string              `json:"bypass_strategy,omitempty"`
	AppFingerprint  *AppFingerprint     `json:"app_fingerprint,omitempty"`
	CMSCloud        *CMSCloudResult     `json:"cms_cloud,omitempty"`
	TechStackAdvanced *TechStackAdvanced `json:"tech_stack_advanced,omitempty"`
	Endpoints       []string            `json:"endpoints,omitempty"`
	ThirdParty      string              `json:"third_party,omitempty"`
	ScrapedContacts *ContactResult      `json:"scraped_contacts,omitempty"`
}

type ContactResult struct {
	Emails []string `json:"emails"`
	Phones []string `json:"phones"`
}

type CMSCloudResult struct {
	CMS         string `json:"cms"`
	Framework   string `json:"framework"`
	CloudAssets struct {
		S3Buckets   []string `json:"s3_buckets"`
		GCPBuckets  []string `json:"gcp_buckets"`
		Firebase    []string `json:"firebase"`
		GithubOrg   string   `json:"github_org"`
	} `json:"cloud_assets"`
}

type TechStackAdvanced struct {
	Frontend      string   `json:"frontend"`
	Backend       string   `json:"backend"`
	JSLibs        []string `json:"js_libs"`
	CSSFrameworks []string `json:"css_frameworks"`
	BuildTools    string   `json:"build_tools"`
	Analytics     []string `json:"analytics"`
}

type SubsidiaryResult struct {
	Aliases      []string `json:"aliases"`
	Subsidiaries []string `json:"subsidiaries"`
}

type InfraForensics struct {
	Traceroute string `json:"traceroute"`
}

type AppFingerprint struct {
	Framework  string `json:"framework"`
	CMS        string `json:"cms"`
	Confidence int    `json:"confidence"`
}

type WAFResult struct {
	Provider string `json:"provider"`
	WAFType  string `json:"waf_type"`
	Detected bool   `json:"detected"`
}

type OriginResult struct {
	OriginIP string   `json:"origin_ip"`
	Methods  []string `json:"methods"`
}

type DNSHistoryResult struct {
	HistoricalA  []string `json:"historical_a"`
	HistoricalNS []string `json:"historical_ns"`
	HistoricalMX []string `json:"historical_mx"`
}

type SSLAnalysisResult struct {
	Certificate *SSLResult `json:"certificate"`
	Protocols   string     `json:"protocols"`
	Vulns       string     `json:"vulns"`
}

type PassiveDNSResult struct {
	PossibleInternalDomains []string `json:"possible_internal_domains"`
	LastSeenIPs             []string `json:"last_seen_ips"`
}

type WhoisInfo struct {
	Registrar      string `json:"registrar"`
	IanaID         string `json:"iana_id"`
	Org            string `json:"org"`
	Email          string `json:"email"`
	AdminEmail     string `json:"admin_email"`
	TechEmail      string `json:"tech_email"`
	Phone          string `json:"phone"`
	Address        string `json:"address"`
	Created        string `json:"created"`
	Updated        string `json:"updated"`
	Expires        string `json:"expires"`
	Abuse          string `json:"abuse"`
	PrivacyEnabled bool   `json:"privacy_enabled"`
}
type TechInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Confidence int    `json:"confidence"`
}

type DNSInfo struct {
	A   []string `json:"a"`
	MX  []string `json:"mx"`
	TXT []string `json:"txt"`
	NS  []string `json:"ns"`
}

type Options struct {
	Target  string
	Threads int
	Timeout int
	Full    bool
	DNS     bool
	Tech    bool
}

var (
	ffiMutex sync.Mutex
	exePath, _  = os.Executable()
	basePath    = filepath.Dir(filepath.Dir(exePath)) // Go up one from go dir to tech_hunter root
	rustPath    = filepath.Join(basePath, "rust_engine/target/release/tech_hunter_rust.dll")
	cppPath     = filepath.Join(basePath, "cpp")
	cPath       = filepath.Join(basePath, "c")

	rustDLL  = syscall.NewLazyDLL(rustPath)
	fetchUrl = rustDLL.NewProc("rust_fetch_url")
	freeStr  = rustDLL.NewProc("free_rust_string")

	cppDLL        = syscall.NewLazyDLL(filepath.Join(cppPath, "forensics.dll"))
	analyzeSec    = cppDLL.NewProc("analyze_security_forensics")
	freeForensics = cppDLL.NewProc("free_forensics_string")

	deepScannerDLL = syscall.NewLazyDLL(filepath.Join(cppPath, "deep_scanner.dll"))
	deepScanProc   = deepScannerDLL.NewProc("deep_payload_scan")

	lowLevelDLL = syscall.NewLazyDLL(filepath.Join(cPath, "low_level.dll"))
	checkAnom   = lowLevelDLL.NewProc("check_header_anomalies")

	entropyDLL  = syscall.NewLazyDLL(filepath.Join(cPath, "entropy.dll"))
	calcEntropy = entropyDLL.NewProc("calculate_payload_entropy")

	vulnMatchDLL = syscall.NewLazyDLL(filepath.Join(cppPath, "vulnerability_matcher.dll"))
	matchVuln    = vulnMatchDLL.NewProc("match_vulnerabilities")

	sslVulnDLL    = syscall.NewLazyDLL(filepath.Join(cppPath, "ssl_vulns.dll"))
	checkSSLVulns = sslVulnDLL.NewProc("check_ssl_vulnerabilities")
	freeSSLVulns  = sslVulnDLL.NewProc("free_ssl_vulns_string")

	protoCheckDLL  = syscall.NewLazyDLL(filepath.Join(cPath, "proto_check.dll"))
	auditProtocols = protoCheckDLL.NewProc("audit_tls_protocols")
	freeProtoStr   = protoCheckDLL.NewProc("free_proto_string")

	dnsHistoryDLL  = syscall.NewLazyDLL(rustPath)
	fetchDNSHist   = dnsHistoryDLL.NewProc("fetch_dns_history")
	freeDNSHistStr = dnsHistoryDLL.NewProc("free_dns_history_string")

	wafDLL        = syscall.NewLazyDLL(rustPath)
	detectWAFProc = wafDLL.NewProc("detect_waf")
	freeWAFStr    = wafDLL.NewProc("free_waf_string")

	infraDLL      = syscall.NewLazyDLL(filepath.Join(cppPath, "infra_forensics.dll"))
	runTraceroute = infraDLL.NewProc("run_traceroute")
	freeInfraStr  = infraDLL.NewProc("free_infra_string")

	tcpDLL        = syscall.NewLazyDLL(filepath.Join(cPath, "tcp_forensics.dll"))
	analyzeTCP    = tcpDLL.NewProc("analyze_tcp_sequence")
	freeTCPStr    = tcpDLL.NewProc("free_tcp_string")

	serviceDLL  = syscall.NewLazyDLL(filepath.Join(cppPath, "service_fingerprinter.dll"))
	identifySvc = serviceDLL.NewProc("identify_service")
	freeSvcStr  = serviceDLL.NewProc("free_service_string")

	fingerprintDLL  = syscall.NewLazyDLL(rustPath)
	fingerprintApp  = fingerprintDLL.NewProc("fingerprint_web_app")
	freeFingerStr   = fingerprintDLL.NewProc("free_fingerprint_string")
	scanTechStack   = fingerprintDLL.NewProc("scan_tech_stack")
	freeTechStr     = fingerprintDLL.NewProc("free_tech_string")

	endpointDLL     = syscall.NewLazyDLL(filepath.Join(cppPath, "endpoint_forensics.dll"))
	scanEndpoints   = endpointDLL.NewProc("scan_endpoints")
	freeEndStr      = endpointDLL.NewProc("free_endpoint_string")

	tpDLL           = syscall.NewLazyDLL(filepath.Join(cPath, "third_party_mapper.dll"))
	checkTPProc     = tpDLL.NewProc("check_third_party")
	freeTPStr       = tpDLL.NewProc("free_tp_string")
)

func main() {
	opts := &Options{}
	flag.StringVar(&opts.Target, "t", "", "Target URL")
	flag.IntVar(&opts.Threads, "threads", 10, "Threads")
	flag.IntVar(&opts.Timeout, "timeout", 10, "Timeout")
	flag.BoolVar(&opts.Full, "full", false, "Full reconnaissance")
	jsonMode := flag.Bool("json", false, "Output only JSON")

	// Tactical Compatibility Layer (Handles flags from flag.txt)
	flag.String("input", "", "Target list input")
	flag.String("format", "json", "Output format")
	flag.Bool("whois", true, "Enable WHOIS module")
	flag.Bool("whois-full", true, "Enable Full WHOIS module")
	flag.Bool("registrar", true, "Enable Registrar module")
	flag.Bool("org", true, "Enable Org module")
	flag.Bool("dns", true, "Enable DNS module")
	flag.Bool("dns-bruteforce", true, "Enable DNS Brute module")
	flag.Bool("dns-zone-transfer", true, "Enable AXFR module")
	flag.Bool("dns-history", true, "Enable DNS History module")
	flag.Bool("passive-dns", true, "Enable Passive DNS module")
	flag.Bool("port-scan", true, "Enable Port Scan module")
	flag.Bool("udp", true, "Enable UDP Scan module")
	flag.Bool("service-detect", true, "Enable Service Detection")
	flag.Bool("banner", true, "Enable Banner Grabbing")
	flag.Bool("os-detect", true, "Enable OS Detection")
	flag.Bool("traceroute", true, "Enable Traceroute")
	flag.Bool("http", true, "Enable HTTP Scan")
	flag.Bool("headers", true, "Enable Header Audit")
	flag.Bool("tls", true, "Enable TLS Audit")
	flag.Bool("tls-deep", true, "Enable Deep TLS Audit")
	flag.Bool("ciphers", true, "Enable Cipher Audit")
	flag.Bool("ssl-cert", true, "Enable Cert Audit")
	flag.Bool("cert-transparency", true, "Enable CT Log Audit")
	flag.Bool("tech", true, "Enable Tech Detection")
	flag.Bool("tech-deep", true, "Enable Deep Tech Audit")
	flag.Bool("cms-detect", true, "Enable CMS Detection")
	flag.Bool("framework-detect", true, "Enable Framework Detection")
	flag.Bool("js-libs", true, "Enable JS Lib Detection")
	flag.Bool("subdomains", true, "Enable Subdomain Enum")
	flag.Bool("sub-passive", true, "Enable Passive Subdomain")
	flag.Bool("sub-active", true, "Enable Active Subdomain")
	flag.Bool("sub-bruteforce", true, "Enable Subdomain Brute")
	flag.Bool("sub-takeover", true, "Enable Takeover Check")
	flag.Bool("asset-discovery", true, "Enable Asset Discovery")
	flag.Bool("fuzz", true, "Enable Fuzzing module")
	flag.Bool("dirscan", true, "Enable Directory Scan")
	flag.Bool("filescan", true, "Enable File Scan")
	flag.Bool("sensitive-files", true, "Enable Sensitive File Scan")
	flag.Bool("backup-files", true, "Enable Backup File Scan")
	flag.Bool("auth-detect", true, "Enable Auth Detection")
	flag.Bool("session-analysis", true, "Enable Session Audit")
	flag.Bool("jwt-analysis", true, "Enable JWT Audit")
	flag.Bool("oauth-check", true, "Enable OAuth Audit")
	flag.Bool("mfa-detect", true, "Enable MFA Detection")
	flag.Bool("api", true, "Enable API Detection")
	flag.Bool("api-discovery", true, "Enable API Discovery")
	flag.Bool("graphql", true, "Enable GraphQL Audit")
	flag.Bool("swagger", true, "Enable Swagger Check")
	flag.Bool("postman-leak", true, "Enable Postman Leak Check")
	flag.Bool("api-auth", true, "Enable API Auth Audit")
	flag.Bool("cloud", true, "Enable Cloud Detection")
	flag.Bool("s3-scan", true, "Enable S3 Audit")
	flag.Bool("firebase", true, "Enable Firebase Check")
	flag.Bool("azure", true, "Enable Azure Discovery")
	flag.Bool("gcp", true, "Enable GCP Discovery")
	flag.Bool("third-party", true, "Enable 3rd Party Integration Check")
	flag.Bool("cdn-detect", true, "Enable CDN Detection")
	flag.Bool("waf-detect", true, "Enable WAF Detection")
	flag.Bool("origin-ip", true, "Enable Origin IP Discovery")
	flag.Bool("js", true, "Enable JS Analysis")
	flag.Bool("js-endpoints", true, "Enable JS Endpoint Extraction")
	flag.Bool("js-secrets", true, "Enable JS Secret Detection")
	flag.Bool("js-map", true, "Enable JS Source Map Audit")
	flag.Bool("behavior", true, "Enable Behavior Analysis")
	flag.Bool("rate-limit-detect", true, "Enable Rate Limit Detection")
	flag.Bool("anomaly-detect", true, "Enable Anomaly Detection")
	flag.Bool("logic-analysis", true, "Enable Logic Analysis")
	flag.Bool("osint", true, "Enable OSINT module")
	flag.Bool("employees", true, "Enable Employee Discovery")
	flag.Bool("emails", true, "Enable Email Extraction")
	flag.Bool("github", true, "Enable GitHub Audit")
	flag.Bool("leaks", true, "Enable Leak Audit")
	flag.Bool("darkweb", true, "Enable Darkweb Audit")
	flag.Bool("quick", true, "Enable Quick Scan Mode")
	flag.Bool("recon", true, "Enable Recon Mode")
	flag.Bool("stealth", true, "Enable Stealth Mode")
	flag.Bool("aggressive", true, "Enable Aggressive Mode")

	flag.Parse()

	if opts.Target == "" {
		if !*jsonMode {
			fmt.Println("Usage: tech -t <url> [--full]")
		}
		os.Exit(1)
	}

	if !*jsonMode {
		printBanner()
	}

	runRecon(opts, *jsonMode)
}

func runRecon(opts *Options, jsonMode bool) {
	targets := strings.Split(opts.Target, ",")
	var results []Result
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			res := processTarget(target, opts)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
			if !jsonMode {
				displayResult(res)
			}
		}(t)
	}
	wg.Wait()

	// Final Step: Call Python Intelligence Brain
	callPythonBrain(results)
}

func processTarget(target string, opts *Options) Result {
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	res := Result{URL: target, Technologies: make(map[string]TechInfo)}

	// 1. Rust Core Fetching
	fetchResult := callRustFetcher(target, opts)
	res.Status = fetchResult.Status
	res.Headers = fetchResult.Headers
	res.Server = res.Headers["Server"]
	res.Industry = fetchResult.IndustryHint
	res.Description = fetchResult.Description
	if fetchResult.TLSIssuer != "" {
		res.Forensics += "TLS_Issuer:" + fetchResult.TLSIssuer + "|"
	}

	for k, v := range fetchResult.DetectedTechs {
		res.Technologies[k] = TechInfo{Name: v.Name, Version: v.Version, Category: v.Category, Confidence: v.Confidence}
	}

	// 2. C++ Native Forensics & Deep Scan
	res.Forensics = callCppForensics(fetchResult.BodySnippet, res.Headers)
	res.Forensics += callDeepScanner(fetchResult.BodySnippet)

	// 3. Low-Level C Header & Entropy Check
	res.Forensics += callLowLevelCheck(res.Headers)
	ent := callEntropy(fetchResult.BodySnippet)
	res.Forensics += fmt.Sprintf("entropy:%.2f|", ent)

	// 4. Vulnerability Matching (C++)
	for name, tech := range res.Technologies {
		vuln := callVulnMatcher(name, tech.Version)
		if vuln != "" {
			res.Forensics += vuln
		}
	}

	// 5. Ruby Extended Fingerprinting
	rubyTechs := callRubyFingerprinter(fetchResult.BodySnippet, res.Headers)
	for _, rt := range rubyTechs {
		res.Technologies[rt.Name] = rt
	}

	// 6. Subdomain Recon (Go Native)
	u, _ := url.Parse(target)
	res.AddSubdomains(u.Hostname())

	// 7. WHOIS Parser (Go Native)
	res.Whois = ParseWhois(u.Hostname())
	if res.Whois.Phone == "" {
		res.Whois.Phone = fetchResult.Phone
	}
	if res.Whois.Address == "" {
		res.Whois.Address = fetchResult.Address
	}

	// 8. Alias Discovery (Ruby OSINT)
	res.Aliases = callRubyOSINT(u.Hostname())

	// 8b. Real TLS Forensics (Go Native)
	tlsInfo := GetRealTLSInfo(u.Hostname())
	if tlsInfo.Issuer != "" {
		res.Forensics += "REAL_TLS_Issuer:" + tlsInfo.Issuer + "|"
	}

	// 9. DNS Passive Recon
	res.DNS = performDNSRecon(target)
	if res.DNS != nil && len(res.DNS.A) > 0 {
		res.IP = res.DNS.A[0]
	}

	// 9. Network & Infrastructure Recon (Go Native)
	if len(res.DNS.A) > 0 {
		res.Network = PerformNetworkRecon(res.DNS.A)
		for _, n := range res.Network {
			n.OS = fetchResult.OSInfo
		}
	} else if res.IP != "" {
		res.Network = PerformNetworkRecon([]string{res.IP})
		res.Network[0].OS = fetchResult.OSInfo
	}

	// 10. DNS Enumeration (Full)
	res.DNSEnum = PerformFullDNSEnum(u.Hostname())

	// 11. DNS History (Rust)
	res.DNSHistory = callRustDNSHistory(u.Hostname())

	// 12. SSL/TLS Analysis (Go + C++ + C)
	ssl, _ := AnalyzeSSL(target)
	vulns := callSSLVulnChecker(u.Hostname())
	protos := callProtoChecker(u.Hostname())
	res.SSLAnalysis = &SSLAnalysisResult{Certificate: ssl, Vulns: vulns, Protocols: protos}

	// 13. Passive DNS (Ruby)
	res.PassiveDNS = callRubyPassiveDNS(u.Hostname())

	// 14. Port & Service Inventory (Go + C++ + C + Lua)
	res.PortScan = ScanPorts(u.Hostname(), []int{21, 22, 80, 443, 3306, 8080}, 2*time.Second)
	for i, p := range res.PortScan {
		res.PortScan[i].Service = callCppServiceIdentifier(p.Port, p.Banner)
		if res.PortScan[i].Service == "Unknown" {
			res.PortScan[i].Service = callLuaServiceIdentifier(p.Port, p.Banner)
		}
	}

	// 15. CDN/WAF Detection (Rust)
	res.WAF = callRustWAFDetector(res.Headers)

	// 16. Origin Discovery (Ruby)
	if res.WAF.Detected && res.DNSHistory != nil {
		res.OriginDiscovery = callRubyOriginDiscovery(u.Hostname(), res.DNSHistory.HistoricalA)
	}

	// 17. Web Application Audit (Go)
	res.WebAudit = AuditWebApplication(res.Headers)

	// 18. Tier 3 Advanced Intelligence
	res.Subsidiaries = callRubySubsidiaryDiscovery(u.Hostname())
	res.InfraForensics = callCppInfraForensics(u.Hostname())
	res.TCPForensics = callCTCPForensics(res.IP)
	res.BypassStrategy = callLuaWAFBypass(res.WAF.WAFType)
	res.AppFingerprint = callRustAppFingerprinter(res.Headers)

	// 19. Tier 4 Advanced Intelligence (New Points)
	res.CMSCloud = callRubyCMSCloudMapper(u.Hostname(), fetchResult.BodySnippet, res.Headers)
	res.TechStackAdvanced = callRustTechScanner(res.Headers, fetchResult.BodySnippet)
	res.Endpoints = callCppEndpointForensics(u.Hostname())
	res.ThirdParty = callCThirdPartyMapper(fetchResult.BodySnippet)

	// 20. Contact Strengthening (Ruby)
	res.ScrapedContacts = callRubyContactScraper(fetchResult.BodySnippet, res.Headers)

	// Fallback logic for WHOIS (If redacted, use scraped)
	if res.Whois != nil && res.ScrapedContacts != nil {
		if strings.Contains(strings.ToLower(res.Whois.Email), "privacy") || res.Whois.Email == "" {
			if len(res.ScrapedContacts.Emails) > 0 {
				res.Whois.Email = res.ScrapedContacts.Emails[0] + " (Scraped)"
			}
		}
		if strings.Contains(strings.ToLower(res.Whois.AdminEmail), "redacted") || res.Whois.AdminEmail == "" {
			if len(res.ScrapedContacts.Emails) > 1 {
				res.Whois.AdminEmail = res.ScrapedContacts.Emails[1] + " (Scraped)"
			} else if len(res.ScrapedContacts.Emails) > 0 {
				res.Whois.AdminEmail = res.ScrapedContacts.Emails[0] + " (Scraped)"
			}
		}
		if res.Whois.Phone == "REDACTED" || res.Whois.Phone == "" {
			if len(res.ScrapedContacts.Phones) > 0 {
				res.Whois.Phone = res.ScrapedContacts.Phones[0] + " (Scraped)"
			}
		}
	}

	// User Request Logic: If WordPress, disable other CMS/Framework info
	if res.CMSCloud != nil && res.CMSCloud.CMS == "WordPress" {
		res.AppFingerprint.CMS = "WordPress"
		res.AppFingerprint.Framework = "None (WordPress Priority)"
	}

	return res
}

func callRubyCMSCloudMapper(domain, body string, headers map[string]string) *CMSCloudResult {
	hJson, _ := json.Marshal(headers)
	cmd := exec.Command("ruby", "../ruby/cms_cloud_mapper.rb", domain, body, string(hJson))
	out, err := cmd.Output()
	if err != nil { return nil }
	var res CMSCloudResult
	json.Unmarshal(out, &res)
	return &res
}

func callRustTechScanner(headers map[string]string, body string) *TechStackAdvanced {
	hJson, _ := json.Marshal(headers)
	cHeaders, _ := syscall.BytePtrFromString(string(hJson))
	cBody, _ := syscall.BytePtrFromString(body)
	retPtr, _, _ := scanTechStack.Call(uintptr(unsafe.Pointer(cHeaders)), uintptr(unsafe.Pointer(cBody)))
	if retPtr == 0 { return nil }
	jsonStr := goString(retPtr)
	freeTechStr.Call(retPtr)
	var res TechStackAdvanced
	json.Unmarshal([]byte(jsonStr), &res)
	return &res
}

func callCppEndpointForensics(domain string) []string {
	cDomain, _ := syscall.BytePtrFromString(domain)
	retPtr, _, _ := scanEndpoints.Call(uintptr(unsafe.Pointer(cDomain)))
	if retPtr == 0 { return nil }
	res := goString(retPtr)
	freeEndStr.Call(retPtr)
	return strings.Split(res, "\n")
}

func callCThirdPartyMapper(body string) string {
	cBody, _ := syscall.BytePtrFromString(body)
	retPtr, _, _ := checkTPProc.Call(uintptr(unsafe.Pointer(cBody)))
	if retPtr == 0 { return "" }
	res := goString(retPtr)
	freeTPStr.Call(retPtr)
	return res
}

func callRubyContactScraper(body string, headers map[string]string) *ContactResult {
	hJson, _ := json.Marshal(headers)
	cmd := exec.Command("ruby", "../ruby/contact_scraper.rb", body, string(hJson))
	out, err := cmd.Output()
	if err != nil { return nil }
	var temp struct {
		Emails []string `json:"scraped_emails"`
		Phones []string `json:"scraped_phones"`
	}
	json.Unmarshal(out, &temp)
	return &ContactResult{Emails: temp.Emails, Phones: temp.Phones}
}

func callRubySubsidiaryDiscovery(domain string) *SubsidiaryResult {
	cmd := exec.Command("ruby", "../ruby/subsidiary_discovery.rb", domain)
	out, err := cmd.Output()
	if err != nil { return nil }
	var res SubsidiaryResult
	json.Unmarshal(out, &res)
	return &res
}

func callCppInfraForensics(target string) *InfraForensics {
	cTarget, _ := syscall.BytePtrFromString(target)
	retPtr, _, _ := runTraceroute.Call(uintptr(unsafe.Pointer(cTarget)))
	if retPtr == 0 { return nil }
	trace := goString(retPtr)
	freeInfraStr.Call(retPtr)
	return &InfraForensics{Traceroute: trace}
}

func callCTCPForensics(ip string) string {
	cIP, _ := syscall.BytePtrFromString(ip)
	retPtr, _, _ := analyzeTCP.Call(uintptr(unsafe.Pointer(cIP)))
	if retPtr == 0 { return "" }
	res := goString(retPtr)
	freeTCPStr.Call(retPtr)
	return res
}

func callLuaWAFBypass(wafType string) string {
	cmd := exec.Command("lua", "../lua/waf_bypass.lua", wafType)
	out, err := cmd.Output()
	if err != nil { return "Standard bypass heuristics" }
	return strings.TrimSpace(string(out))
}

func callRustAppFingerprinter(headers map[string]string) *AppFingerprint {
	hJson, _ := json.Marshal(headers)
	cHeaders, _ := syscall.BytePtrFromString(string(hJson))
	retPtr, _, _ := fingerprintApp.Call(uintptr(unsafe.Pointer(cHeaders)))
	if retPtr == 0 { return nil }
	jsonStr := goString(retPtr)
	freeFingerStr.Call(retPtr)
	var res AppFingerprint
	json.Unmarshal([]byte(jsonStr), &res)
	return &res
}

func callCppServiceIdentifier(port int, banner string) string {
	cBanner, _ := syscall.BytePtrFromString(banner)
	retPtr, _, _ := identifySvc.Call(uintptr(port), uintptr(unsafe.Pointer(cBanner)))
	if retPtr == 0 {
		return "Unknown"
	}
	svc := goString(retPtr)
	freeSvcStr.Call(retPtr)
	return svc
}

func callLuaServiceIdentifier(port int, banner string) string {
	cmd := exec.Command("lua", "../lua/service_rules.lua", fmt.Sprintf("%d", port), banner)
	out, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(out))
}

func callRustWAFDetector(headers map[string]string) *WAFResult {
	hJson, _ := json.Marshal(headers)
	cHeaders, _ := syscall.BytePtrFromString(string(hJson))
	retPtr, _, _ := detectWAFProc.Call(uintptr(unsafe.Pointer(cHeaders)))
	if retPtr == 0 {
		return &WAFResult{Provider: "Direct", WAFType: "None", Detected: false}
	}
	jsonStr := goString(retPtr)
	freeWAFStr.Call(retPtr)
	var waf WAFResult
	json.Unmarshal([]byte(jsonStr), &waf)
	return &waf
}

func callRubyOriginDiscovery(domain string, history []string) *OriginResult {
	hJson, _ := json.Marshal(history)
	cmd := exec.Command("ruby", "../ruby/origin_discovery.rb", domain, string(hJson))
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res OriginResult
	json.Unmarshal(out, &res)
	return &res
}

func callRustDNSHistory(domain string) *DNSHistoryResult {
	cDomain, _ := syscall.BytePtrFromString(domain)
	retPtr, _, _ := fetchDNSHist.Call(uintptr(unsafe.Pointer(cDomain)))
	if retPtr == 0 {
		return nil
	}
	jsonStr := goString(retPtr)
	freeDNSHistStr.Call(retPtr)
	var hist DNSHistoryResult
	json.Unmarshal([]byte(jsonStr), &hist)
	return &hist
}

func callSSLVulnChecker(host string) string {
	cHost, _ := syscall.BytePtrFromString(host)
	retPtr, _, _ := checkSSLVulns.Call(uintptr(unsafe.Pointer(cHost)))
	if retPtr == 0 {
		return ""
	}
	vulns := goString(retPtr)
	freeSSLVulns.Call(retPtr)
	return vulns
}

func callProtoChecker(host string) string {
	cHost, _ := syscall.BytePtrFromString(host)
	retPtr, _, _ := auditProtocols.Call(uintptr(unsafe.Pointer(cHost)))
	if retPtr == 0 {
		return ""
	}
	protos := goString(retPtr)
	freeProtoStr.Call(retPtr)
	return protos
}

func callRubyPassiveDNS(domain string) *PassiveDNSResult {
	cmd := exec.Command("ruby", "../ruby/passive_dns.rb", domain)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res PassiveDNSResult
	json.Unmarshal(out, &res)
	return &res
}

func callRustFetcher(target string, opts *Options) RustScanResult {
	cUrl, _ := syscall.BytePtrFromString(target)
	cUa, _ := syscall.BytePtrFromString("TechHunter/3.0")
	cEmpty, _ := syscall.BytePtrFromString("")

	ffiMutex.Lock()
	defer ffiMutex.Unlock()

	retPtr, _, _ := fetchUrl.Call(
		uintptr(unsafe.Pointer(cUrl)),
		uintptr(opts.Timeout),
		uintptr(1),
		uintptr(0),
		uintptr(unsafe.Pointer(cUa)),
		uintptr(unsafe.Pointer(cEmpty)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

	if retPtr == 0 {
		return RustScanResult{}
	}
	jsonStr := goString(retPtr)
	freeStr.Call(retPtr)

	var rs RustScanResult
	json.Unmarshal([]byte(jsonStr), &rs)
	return rs
}

func callCppForensics(body string, headers map[string]string) string {
	cBody, _ := syscall.BytePtrFromString(body)
	hStr, _ := json.Marshal(headers)
	cHeaders, _ := syscall.BytePtrFromString(string(hStr))

	retPtr, _, _ := analyzeSec.Call(uintptr(unsafe.Pointer(cBody)), uintptr(unsafe.Pointer(cHeaders)))
	if retPtr == 0 {
		return ""
	}

	report := goString(retPtr)
	freeForensics.Call(retPtr)
	return report
}

func callDeepScanner(body string) string {
	cBody, _ := syscall.BytePtrFromString(body)
	retPtr, _, _ := deepScanProc.Call(uintptr(unsafe.Pointer(cBody)))
	if retPtr == 0 {
		return ""
	}
	return goString(retPtr)
}

func callLowLevelCheck(headers map[string]string) string {
	hStr, _ := json.Marshal(headers)
	cHeaders, _ := syscall.BytePtrFromString(string(hStr))
	retPtr, _, _ := checkAnom.Call(uintptr(unsafe.Pointer(cHeaders)))
	if retPtr == 0 {
		return ""
	}
	return goString(retPtr)
}

func callEntropy(body string) float64 {
	cBody, _ := syscall.BytePtrFromString(body)
	ret, _, _ := calcEntropy.Call(uintptr(unsafe.Pointer(cBody)))
	return *(*float64)(unsafe.Pointer(&ret))
}

func callVulnMatcher(name, version string) string {
	cName, _ := syscall.BytePtrFromString(name)
	cVer, _ := syscall.BytePtrFromString(version)
	retPtr, _, _ := matchVuln.Call(uintptr(unsafe.Pointer(cName)), uintptr(unsafe.Pointer(cVer)))
	if retPtr == 0 {
		return ""
	}
	return goString(retPtr)
}

func callRubyFingerprinter(body string, headers map[string]string) []TechInfo {
	input, _ := json.Marshal(map[string]interface{}{"body": body, "headers": headers})
	cmd := exec.Command("ruby", "../ruby/fingerprint.rb")
	cmd.Stdin = bytes.NewReader(input)

	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil
	}

	var techs []TechInfo
	json.Unmarshal(out.Bytes(), &techs)
	return techs
}

func callPythonBrain(results []Result) {
	data, _ := json.Marshal(results)
	fmt.Println("---JSON_START---")
	fmt.Println(string(data))
	fmt.Println("---JSON_END---")
}

func performDNSRecon(target string) *DNSInfo {
	u, _ := url.Parse(target)
	host := u.Hostname()
	info := &DNSInfo{}
	ips, _ := net.LookupHost(host)
	info.A = ips
	return info
}

func callRubyOSINT(domain string) []string {
	input, _ := json.Marshal(map[string]string{"domain": domain})
	cmd := exec.Command("ruby", "../ruby/osint.rb")
	cmd.Stdin = strings.NewReader(string(input))
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res []string
	json.Unmarshal(out, &res)
	return res
}

func goString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var res []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if b == 0 {
			break
		}
		res = append(res, b)
		if i > 5000000 {
			break
		}
	}
	return string(res)
}

func printBanner() {
	c := color.New(color.FgHiMagenta).Add(color.Bold)
	c.Println(`
   ╦ ╦ ╦ ╦ ╔╗╔ ╔╦╗ ╔═╗ ╦═╗
   ╠═╣ ║ ║ ║║║  ║  ║╣  ╠╦╝
   ╩ ╩ ╚═╝ ╝╚╝  ╩  ╚═╝ ╩╚═
   [ FULL INTELLIGENCE MAP ENGINE V2.0 ]
	`)
}

func displayResult(res Result) {
	fmt.Printf("\n[%s] %s (%d)\n", color.HiGreenString("+"), color.HiWhiteString(res.URL), res.Status)
	if res.Forensics != "" {
		fmt.Printf(" |- Forensics: %s\n", color.YellowString(res.Forensics))
	}
	for name, t := range res.Technologies {
		fmt.Printf(" |  - %s %s [%s]\n", color.HiCyanString(name), t.Version, color.HiBlackString(t.Category))
	}
}

type RustScanResult struct {
	URL           string                  `json:"url"`
	Status        int                     `json:"status"`
	Headers       map[string]string       `json:"headers"`
	BodySnippet   string                  `json:"body_snippet"`
	DetectedTechs map[string]RustTechInfo `json:"detected_techs"`
	IndustryHint  string                  `json:"industry_hint,omitempty"`
	Description   string                  `json:"description,omitempty"`
	OSInfo        string                  `json:"os_info,omitempty"`
	TLSIssuer     string                  `json:"tls_issuer,omitempty"`
	Phone         string                  `json:"phone,omitempty"`
	Address       string                  `json:"address,omitempty"`
}

type RustTechInfo struct {
	Name       string `json:"name"`
	Confidence int    `json:"confidence"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
}
