package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
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

func getTechHunterRoot() string {
	if env := os.Getenv("TECH_HUNTER_HOME"); env != "" {
		return env
	}
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Dir(exe)
	for i := 0; i < 4; i++ {
		if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
			return filepath.Dir(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return filepath.Dir(filepath.Dir(exe))
}

// --- Full Intelligence Map Structs ---

type Result struct {
	URL             string              `json:"url"`
	Status          int                 `json:"status"`
	Title           string              `json:"title"`
	IP              string              `json:"ip"`
	Server          string              `json:"server"`
	Technologies    map[string]TechInfo `json:"technologies"`
	Headers         map[string]string   `json:"headers"`
	BodySnippet     string              `json:"body_snippet"`
	DNS             *DNSInfo            `json:"dns,omitempty"`
	Whois           *WhoisInfo          `json:"whois,omitempty"`
	Forensics       string              `json:"forensics,omitempty"`
	Industry        string              `json:"industry,omitempty"`
	Description     string              `json:"description,omitempty"`
	Aliases         []string            `json:"aliases,omitempty"`
	Network         []*NetworkInfo      `json:"network,omitempty"`
	DNSEnum         *DNSEnumResult      `json:"dns_enum,omitempty"`
	DNSEC           *DNSECResult        `json:"dns_sec,omitempty"`
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
	AuthSession     string              `json:"auth_session,omitempty"`
	OSINTData       *OSINTResult        `json:"osint_data,omitempty"`
	LuaTech     string   `json:"lua_tech,omitempty"`
	LuaHttp     string   `json:"lua_http,omitempty"`
	LuaCookies  string   `json:"lua_cookies,omitempty"`
	RubySSL     string   `json:"ruby_ssl,omitempty"`
	RubyEmails  string   `json:"ruby_emails,omitempty"`
	RubyJS      string   `json:"ruby_js,omitempty"`
	RubyCloud   string              `json:"ruby_cloud,omitempty"`
	PluginResults map[string]string `json:"plugin_results,omitempty"`

	// New Intelligence Modules
	TechReport  *TechReport         `json:"tech_report,omitempty"`
	APIDiscovery *APIDiscoveryResult `json:"api_discovery,omitempty"`
	ThreatIntel *ThreatIntelResult   `json:"threat_intel,omitempty"`
	Wayback     *WaybackResult       `json:"wayback,omitempty"`
	HeaderAnalysis map[string]string `json:"header_analysis,omitempty"`
}

type ContactResult struct {
	Emails      []string `json:"emails"`
	Phones      []string `json:"phones"`
	SocialMedia []string `json:"social_media,omitempty"`
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
	Registrar      string   `json:"registrar"`
	IanaID         string   `json:"iana_id"`
	Org            string   `json:"org"`
	Email          string   `json:"email"`
	AdminEmail     string   `json:"admin_email"`
	AdminOrg       string   `json:"admin_org"`
	AdminPhone     string   `json:"admin_phone"`
	TechEmail      string   `json:"tech_email"`
	TechOrg        string   `json:"tech_org"`
	TechPhone      string   `json:"tech_phone"`
	Phone          string   `json:"phone"`
	Address        string   `json:"address"`
	Created        string   `json:"created"`
	Updated        string   `json:"updated"`
	Expires        string   `json:"expires"`
	Abuse          string   `json:"abuse"`
	DNSSEC         string   `json:"dnssec"`
	WhoisServer    string   `json:"whois_server"`
	RegistrantName string   `json:"registrant_name"`
	RegistrantID   string   `json:"registrant_id"`
	NameServers    []string `json:"name_servers"`
	DomainStatuses []string `json:"domain_statuses"`
	PrivacyEnabled bool     `json:"privacy_enabled"`
}
type TechInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Confidence int    `json:"confidence"`
}

type DNSInfo struct {
	A     []string      `json:"a"`
	MX    []string      `json:"mx"`
	TXT   []string      `json:"txt"`
	NS    []string      `json:"ns"`
	DNSEC *DNSECResult `json:"dns_sec"`
}

type Options struct {
	Target  string
	Threads int
	Timeout int
	Full    bool
	DNS     bool
	Tech    bool
}

func main() {
	opts := &Options{}

	flag.StringVar(&opts.Target, "t", "", "Target URL")
	flag.IntVar(&opts.Threads, "threads", 10, "Threads")
	flag.IntVar(&opts.Timeout, "timeout", 8, "Timeout")
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

	// Final Step: Output JSON (only in json mode)
	if jsonMode {
		callPythonBrain(results)
	}
}

func processTarget(target string, opts *Options) Result {
	ensureFFI()
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	res := Result{URL: target, Technologies: make(map[string]TechInfo)}

	// 1. Rust Core Fetching (now Go native HTTP)
	fetchResult := callRustFetcher(target, opts)
	res.Status = fetchResult.Status
	res.Headers = fetchResult.Headers
	res.BodySnippet = fetchResult.BodySnippet
	res.Title = fetchResult.Description
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

	// 5. Ruby Extended Fingerprinting (skipped - use Go native header detection instead)
	// (fingerprint.rb expects stdin JSON, not args; Go native detection covers common cases)

	u, _ := url.Parse(target)
	domain := u.Hostname()

	// Pre-resolve hostname using custom DNS resolver before parallel tasks
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	dnsResolver.LookupIPAddr(dnsCtx, domain)
	dnsCancel()

	// 6. Subdomain Recon
	res.AddSubdomains(domain)

	// 7-12. Run all network-heavy operations in parallel
	var preNetWg sync.WaitGroup
	var preNetMu sync.Mutex
	var whoisResult *WhoisInfo
	var aliasesResult []string
	var tlsForensics string
	var dnsResult *DNSInfo
	var dnsEnumResult *DNSEnumResult
	var dnsSecResult *DNSECResult
	var dnsHistoryResult *DNSHistoryResult
	var sslResult *SSLAnalysisResult
	var osintResult *OSINTResult

	preNetWg.Add(8)
	go func() {
		defer preNetWg.Done()
		w := ParseWhois(domain)
		preNetMu.Lock()
		whoisResult = w
		preNetMu.Unlock()
	}()
	go func() {
		defer preNetWg.Done()
		preNetMu.Lock()
		aliasesResult = callRubyOSINT(domain)
		preNetMu.Unlock()
	}()
	go func() {
		defer preNetWg.Done()
		tls := GetRealTLSInfo(domain)
		if tls.Issuer != "" {
			preNetMu.Lock()
			tlsForensics = "REAL_TLS_Issuer:" + tls.Issuer + "|"
			preNetMu.Unlock()
		}
	}()
	go func() {
		defer preNetWg.Done()
		d := performDNSRecon(domain)
		preNetMu.Lock()
		dnsResult = d
		preNetMu.Unlock()
	}()
	go func() {
		defer preNetWg.Done()
		de := PerformFullDNSEnum(domain)
		preNetMu.Lock()
		dnsEnumResult = de
		preNetMu.Unlock()
	}()
	go func() {
		defer preNetWg.Done()
		dnsSecResult = PerformDNSECEnum(domain)
	}()
	go func() {
		defer preNetWg.Done()
		o := CollectOSINT(domain)
		preNetMu.Lock()
		osintResult = o
		h := []string{}
		if o != nil {
			seen := make(map[string]bool)
			for _, ip := range o.HackerTargetIPs {
				if !seen[ip] {
					h = append(h, ip)
					seen[ip] = true
				}
			}
		}
		if len(h) > 0 {
			dnsHistoryResult = &DNSHistoryResult{HistoricalA: h}
		}
		preNetMu.Unlock()
	}()
	go func() {
		defer preNetWg.Done()
		if cert, err := AnalyzeSSL(domain); err == nil && cert != nil {
			protos := callProtoChecker(domain)
			vulns := callSSLVulnChecker(domain)
			preNetMu.Lock()
			sslResult = &SSLAnalysisResult{Certificate: cert, Protocols: protos, Vulns: vulns}
			preNetMu.Unlock()
		}
	}()

	// Wait for network operations to complete
	preNetWg.Wait()

	// Assign parallel network results
	res.Whois = whoisResult
	res.Aliases = aliasesResult
	if tlsForensics != "" {
		res.Forensics += tlsForensics
	}
	dnsResult.DNSEC = dnsSecResult
	res.DNS = dnsResult
	res.DNSEC = dnsResult.DNSEC
	res.DNSEnum = dnsEnumResult
	res.DNSHistory = dnsHistoryResult
	res.SSLAnalysis = sslResult

	// Merge A/AAAA records from both DNS sources
	allIPs := []string{}
	if res.DNS != nil {
		allIPs = append(allIPs, res.DNS.A...)
	}
	if res.DNSEnum != nil {
		for _, ip := range res.DNSEnum.A {
			if !contains(allIPs, ip) {
				allIPs = append(allIPs, ip)
			}
		}
		if res.DNS == nil {
			res.DNS = &DNSInfo{}
		}
		if len(res.DNS.A) == 0 {
			res.DNS.A = append(res.DNS.A, allIPs...)
		}
	}

	// Prefer IPv4 for the IP field
	res.IP = firstIPv4(allIPs)
	if res.IP == "" && len(allIPs) > 0 {
		res.IP = allIPs[0]
	}

	// Network & Infrastructure Recon
	if len(res.DNS.A) > 0 {
		res.Network = PerformNetworkRecon(res.DNS.A)
	} else if res.IP != "" {
		res.Network = PerformNetworkRecon([]string{res.IP})
	}

	// DNS Security Analysis (SPF, DMARC, DKIM)
	if res.DNSEnum != nil {
		var spfFound, dmarcFound, dkimFound bool
		var spfRecord, dmarcRecord string
		for _, t := range res.DNSEnum.TXT {
			lower := strings.ToLower(t)
			if strings.HasPrefix(lower, "v=spf") {
				spfFound = true
				spfRecord = t
			}
			if strings.HasPrefix(lower, "v=dmarc") {
				dmarcFound = true
				dmarcRecord = t
			}
			if strings.Contains(lower, "v=dkim") || strings.Contains(lower, "dkim") {
				dkimFound = true
			}
		}
		res.Forensics += fmt.Sprintf("SPF:%s|DMARC:%s|DKIM:%s|",
			map[bool]string{true: "CONFIGURED", false: "NOT_FOUND"}[spfFound],
			map[bool]string{true: "CONFIGURED", false: "NOT_FOUND"}[dmarcFound],
			map[bool]string{true: "CONFIGURED", false: "NOT_FOUND"}[dkimFound])
		if spfRecord != "" {
			res.Forensics += fmt.Sprintf("SPF_RAW:%s|", spfRecord)
		}
		if dmarcRecord != "" {
			res.Forensics += fmt.Sprintf("DMARC_RAW:%s|", dmarcRecord)
		}
	}

	// CDN/WAF Detection (Go native)
	res.WAF = &WAFResult{Provider: "Direct", WAFType: "None", Detected: false}
	waf := detectWAF(res.Headers)
	if waf != "" {
		res.WAF = &WAFResult{Provider: waf, WAFType: "Cloud/CDN", Detected: true}
	}

	// Web Application Audit
	res.WebAudit = AuditWebApplication(res.Headers)

	// Tier 3 Advanced Intelligence
	res.InfraForensics = callCppInfraForensics(domain)

	// Tier 4 Advanced Intelligence
	res.ThirdParty = callCThirdPartyMapper(fetchResult.BodySnippet)
	res.AuthSession = callCSessionAnalyzer(fetchResult.BodySnippet, res.Headers)
	res.OSINTData = osintResult

	// Run Ruby scripts in parallel
	var wgRuby sync.WaitGroup
	var pDNSMu, rubyMu, scrapeMu sync.Mutex
	var pDNS *PassiveDNSResult
	var origin *OriginResult
	var contacts *ContactResult
	var luaTech string
	var rubySSL, rubyEmails, rubyJS, rubyCloud string

	// Passive DNS (Ruby)
	wgRuby.Add(1)
	go func() {
		defer wgRuby.Done()
		if out, err := runRuby(filepath.Join(rubyPath, "passive_dns.rb"), domain); err == nil {
			var p PassiveDNSResult
			if json.Unmarshal(out, &p) == nil {
				pDNSMu.Lock()
				pDNS = &p
				pDNSMu.Unlock()
			}
		}
	}()

	// 21. Lua Plugin Integrations - parallel
	wgRuby.Add(1)
	go func() {
		defer wgRuby.Done()
		if out, err := runLua(filepath.Join(luaPath, "tech_detector.lua"), fetchResult.BodySnippet); err == nil {
			rubyMu.Lock()
			luaTech = strings.TrimSpace(string(out))
			rubyMu.Unlock()
		}
	}()

	// 22. Ruby Plugin Integrations - parallel
	wgRuby.Add(1)
	go func() {
		defer wgRuby.Done()
		if out, err := runRuby(filepath.Join(rubyPath, "ssl_audit.rb"), domain); err == nil {
			rubyMu.Lock()
			rubySSL = strings.TrimSpace(string(out))
			rubyMu.Unlock()
		}
	}()
	wgRuby.Add(2)
	go func() {
		defer wgRuby.Done()
		if out, err := runRuby(filepath.Join(rubyPath, "origin_discovery.rb"), domain, strings.Join(res.DNS.A, ",")); err == nil {
			var od OriginResult
			if json.Unmarshal(out, &od) == nil {
				rubyMu.Lock()
				origin = &od
				rubyMu.Unlock()
			}
		}
	}()
	go func() {
		defer wgRuby.Done()
		if out, err := runRuby(filepath.Join(rubyPath, "contact_scraper.rb"), fetchResult.BodySnippet); err == nil {
			var tmp struct {
				Emails []string `json:"scraped_emails"`
				Phones []string `json:"scraped_phones"`
			}
			if json.Unmarshal(out, &tmp) == nil {
				scrapeMu.Lock()
				contacts = &ContactResult{Emails: tmp.Emails, Phones: tmp.Phones}
				scrapeMu.Unlock()
			}
		}
	}()
	wgRuby.Add(1)
	go func() {
		defer wgRuby.Done()
		if out, err := runRuby(filepath.Join(rubyPath, "email_finder.rb"), fetchResult.BodySnippet, domain); err == nil {
			rubyMu.Lock()
			rubyEmails = strings.TrimSpace(string(out))
			rubyMu.Unlock()
		}
	}()
	wgRuby.Add(1)
	go func() {
		defer wgRuby.Done()
		if out, err := runRuby(filepath.Join(rubyPath, "js_analyzer.rb"), fetchResult.BodySnippet, target); err == nil {
			rubyMu.Lock()
			rubyJS = strings.TrimSpace(string(out))
			rubyMu.Unlock()
		}
	}()
	hJson, _ := json.Marshal(res.Headers)
	if string(hJson) == "null" {
		hJson = []byte("{}")
	}
	wgRuby.Add(1)
	go func() {
		defer wgRuby.Done()
		if out, err := runRuby(filepath.Join(rubyPath, "cloud_detector.rb"), fetchResult.BodySnippet, string(hJson), domain); err == nil {
			rubyMu.Lock()
			rubyCloud = strings.TrimSpace(string(out))
			rubyMu.Unlock()
		}
	}()

	// ──────────────────────────────────────────────────────────────
	// New Lua plugins (7)
	// ──────────────────────────────────────────────────────────────
	var pluginMu sync.Mutex
	pluginResults := make(map[string]string)
	luaPlugins := map[string]string{
		"csp_analyzer":        "csp_analyzer.lua",
		"link_extractor":      "link_extractor.lua",
		"seo_scanner":         "seo_scanner.lua",
		"pwa_detector":        "pwa_detector.lua",
		"form_scanner":        "form_scanner.lua",
		"meta_extractor":      "meta_extractor.lua",
		"security_header_analyzer": "security_header_analyzer.lua",
	}
	for name, script := range luaPlugins {
		wgRuby.Add(1)
		n, s := name, script
		go func() {
			defer wgRuby.Done()
			var args []string
			switch n {
			case "security_header_analyzer":
				args = []string{string(hJson)}
			default:
				args = []string{fetchResult.BodySnippet}
			}
			if out, err := runLua(filepath.Join(luaPath, s), args...); err == nil {
				pluginMu.Lock()
				pluginResults["lua_"+n] = strings.TrimSpace(string(out))
				pluginMu.Unlock()
			}
		}()
	}

	// ──────────────────────────────────────────────────────────────
	// New Ruby plugins (7)
	// ──────────────────────────────────────────────────────────────
	rubyPlugins := map[string]struct{
		script string
		argsFn func() []string
	}{
		"dns_bruteforcer":           {"dns_bruteforcer.rb", func() []string { return []string{domain} }},
		"tech_fingerprinter":        {"tech_fingerprinter.rb", func() []string { return []string{fetchResult.BodySnippet, string(hJson)} }},
		"content_security_checker":  {"content_security_checker.rb", func() []string { return []string{string(hJson)} }},
		"link_discovery":            {"link_discovery.rb", func() []string { return []string{fetchResult.BodySnippet, target} }},
		"waf_detector":              {"waf_detector.rb", func() []string { return []string{string(hJson), domain} }},
		"cms_detector":              {"cms_detector.rb", func() []string { return []string{fetchResult.BodySnippet, string(hJson)} }},
		"cdn_detector":              {"cdn_detector.rb", func() []string { return []string{res.IP, string(hJson), domain} }},
	}
	for name, plug := range rubyPlugins {
		wgRuby.Add(1)
		n, p := name, plug
		go func() {
			defer wgRuby.Done()
			if out, err := runRuby(filepath.Join(rubyPath, p.script), p.argsFn()...); err == nil {
				pluginMu.Lock()
				pluginResults["ruby_"+n] = strings.TrimSpace(string(out))
				pluginMu.Unlock()
			}
		}()
	}

	wgRuby.Wait()

	// Store all plugin results
	res.PluginResults = pluginResults

	// Assign parallel results
	if pDNS != nil {
		res.PassiveDNS = pDNS
	}
	if origin != nil {
		res.OriginDiscovery = origin
	}
	if contacts != nil {
		res.ScrapedContacts = contacts
	}
	res.LuaTech = luaTech
	res.LuaHttp = ""
	res.LuaCookies = ""
	res.RubySSL = rubySSL
	res.RubyEmails = rubyEmails
	res.RubyJS = rubyJS
	res.RubyCloud = rubyCloud

	// 24-28. Run expensive post-processing in parallel
	var wgPost sync.WaitGroup

	// 24. Advanced Technology Fingerprinting
	wgPost.Add(1)
	go func() {
		defer wgPost.Done()
		tr := PerformTechDetection(fetchResult.BodySnippet, res.Headers)
		if tr != nil {
			res.TechReport = tr
			for _, lib := range tr.JSLibs {
				res.Technologies["JS:"+lib.Name] = TechInfo{Name: lib.Name, Category: lib.Category, Confidence: lib.Confidence}
			}
			for _, css := range tr.CSSFrameworks {
				res.Technologies["CSS:"+css.Name] = TechInfo{Name: css.Name, Category: css.Category, Confidence: css.Confidence}
			}
			for _, an := range tr.Analytics {
				res.Technologies["Analytics:"+an.Name] = TechInfo{Name: an.Name, Category: an.Category, Confidence: an.Confidence}
			}
			if tr.CMS != "" {
				res.Technologies["CMS"] = TechInfo{Name: tr.CMS, Category: "CMS", Confidence: 80}
			}
			if tr.Frontend != "" {
				res.Technologies["Frontend"] = TechInfo{Name: tr.Frontend, Category: "JavaScript Framework", Confidence: 75}
			}
			if tr.Backend != "" {
				res.Technologies["Backend"] = TechInfo{Name: tr.Backend, Category: "Backend", Confidence: 70}
			}
		}
	}()

	// 25. Directory & File Fuzzing (hidden endpoints)
	if fetchResult.Status > 0 && fetchResult.Status < 500 {
		wgPost.Add(1)
		go func() {
			defer wgPost.Done()
			res.Endpoints = ActiveFuzz(target, 2*time.Second)
		}()
	}

	// 26. Wayback Machine historical URL discovery
	wgPost.Add(1)
	go func() {
		defer wgPost.Done()
		res.Wayback = fetchWaybackData(domain)
	}()

	// 27. API Discovery from JS/HTML
	wgPost.Add(1)
	go func() {
		defer wgPost.Done()
		res.APIDiscovery = DiscoverAPIs(fetchResult.BodySnippet, res.Headers, domain)
	}()

	// 28. Threat Intelligence
	wgPost.Add(1)
	go func() {
		defer wgPost.Done()
		res.ThreatIntel = CollectThreatIntel(domain)
	}()

	wgPost.Wait()

	// Merge Wayback URLs into Endpoints
	if res.Wayback != nil && len(res.Wayback.URLs) > 0 {
		if res.Endpoints == nil {
			res.Endpoints = res.Wayback.URLs[:min(20, len(res.Wayback.URLs))]
		} else {
			seen := make(map[string]bool)
			for _, e := range res.Endpoints {
				seen[e] = true
			}
			for _, u := range res.Wayback.URLs {
				if !seen[u] && len(res.Endpoints) < 30 {
					res.Endpoints = append(res.Endpoints, u)
					seen[u] = true
				}
			}
		}
	}

	// 23 (continued). HTTP Security Header Analysis
	res.HeaderAnalysis = analyzeHTTPHeaders(res.Headers)

	// 29. DNS Security Summary
	if res.DNSEnum != nil && len(res.DNSEnum.TXT) > 0 {
		for _, t := range res.DNSEnum.TXT {
			lower := strings.ToLower(t)
			if strings.HasPrefix(lower, "v=spf") {
				res.Forensics += fmt.Sprintf("SPF_RECORD:%s|", t[:min(80, len(t))])
			}
			if strings.HasPrefix(lower, "v=dmarc") {
				res.Forensics += fmt.Sprintf("DMARC_RECORD:%s|", t[:min(80, len(t))])
			}
		}
	}

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

	return res
}

func callRubyCMSCloudMapper(domain, body string, headers map[string]string) *CMSCloudResult {
	hJson, _ := json.Marshal(headers)
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "cms_cloud_mapper.rb"), domain, body, string(hJson))
	out, err := cmd.Output()
	if err != nil { return nil }
	var res CMSCloudResult
	json.Unmarshal(out, &res)
	return &res
}

func callRustTechScanner(headers map[string]string, body string) *TechStackAdvanced {
	return nil
}

func callCppEndpointForensics(domain string, body string) []string {
	cDomain, _ := syscall.BytePtrFromString(domain)
	cBody, _ := syscall.BytePtrFromString(body)
	retPtr, _, _ := scanEndpoints.Call(uintptr(unsafe.Pointer(cDomain)), uintptr(unsafe.Pointer(cBody)))
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

func callCSessionAnalyzer(body string, headers map[string]string) string {
	cBody, _ := syscall.BytePtrFromString(body)
	hStr, _ := json.Marshal(headers)
	cHeaders, _ := syscall.BytePtrFromString(string(hStr))
	retPtr, _, _ := analyzeSessProc.Call(uintptr(unsafe.Pointer(cBody)), uintptr(unsafe.Pointer(cHeaders)))
	if retPtr == 0 { return "" }
	res := goString(retPtr)
	freeSessStr.Call(retPtr)
	return res
}

func callRubyContactScraper(body string, headers map[string]string) *ContactResult {

	hJson, _ := json.Marshal(headers)
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "contact_scraper.rb"), body, string(hJson))
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
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "subsidiary_discovery.rb"), domain)
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
	cmd := exec.Command("lua", filepath.Join(luaPath, "waf_bypass.lua"), wafType)
	out, err := cmd.Output()
	if err != nil { return "Standard bypass heuristics" }
	return strings.TrimSpace(string(out))
}

func callRustAppFingerprinter(headers map[string]string) *AppFingerprint {
	return nil
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
	cmd := exec.Command("lua", filepath.Join(luaPath, "service_rules.lua"), fmt.Sprintf("%d", port), banner)
	out, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(out))
}

func callRustWAFDetector(headers map[string]string) *WAFResult {
	return &WAFResult{Provider: "Direct", WAFType: "None", Detected: false}
}

func callRubyOriginDiscovery(domain string, history []string) *OriginResult {
	hJson, _ := json.Marshal(history)
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "origin_discovery.rb"), domain, string(hJson))
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res OriginResult
	json.Unmarshal(out, &res)
	return &res
}

func callRustDNSHistory(domain string) *DNSHistoryResult {
	return nil
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
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "passive_dns.rb"), domain)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res PassiveDNSResult
	json.Unmarshal(out, &res)
	return &res
}

func callRustFetcher(target string, opts *Options) RustScanResult {
	start := time.Now()
	fmt.Fprintf(os.Stderr, "[callRustFetcher] Starting for target=%s timeout=%d\n", target, opts.Timeout)

	// Parse URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[callRustFetcher] Invalid URL: %v\n", err)
		return RustScanResult{URL: target}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" { port = "443" } else { port = "80" }
	}
	fmt.Fprintf(os.Stderr, "[callRustFetcher] Parsed: scheme=%s host=%s port=%s path=%s\n", u.Scheme, host, port, u.Path)

	// Pre-resolve hostname to IP using custom DNS server (8.8.8.8), fallback to `host` command
	rCtx, rCancel := context.WithTimeout(context.Background(), 2*time.Second)
	ips, resolveErr := dnsResolver.LookupIPAddr(rCtx, host)
	rCancel()
	if resolveErr != nil {
		fmt.Fprintf(os.Stderr, "[callRustFetcher] Custom DNS failed (%v), trying `host` command...\n", resolveErr)
		cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cmdCancel()
		cmd := exec.CommandContext(cmdCtx, "host", host)
		cmdOut, cmdErr := cmd.Output()
		if cmdErr == nil {
			lines := strings.Split(string(cmdOut), "\n")
			var foundIPs []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "has address") {
					parts := strings.Split(line, "has address ")
					if len(parts) == 2 {
						ip := strings.TrimSpace(parts[1])
						if net.ParseIP(ip) != nil {
							foundIPs = append(foundIPs, ip)
						}
					}
				}
				if strings.Contains(line, "has IPv6 address") {
					parts := strings.Split(line, "has IPv6 address ")
					if len(parts) == 2 {
						ip := strings.TrimSpace(parts[1])
						if net.ParseIP(ip) != nil {
							foundIPs = append(foundIPs, ip)
						}
					}
				}
			}
			if len(foundIPs) > 0 {
				resolveErr = nil
				ips = make([]net.IPAddr, len(foundIPs))
				for i, s := range foundIPs {
					ips[i] = net.IPAddr{IP: net.ParseIP(s)}
				}
				fmt.Fprintf(os.Stderr, "[callRustFetcher] `host` command succeeded for %s: %v\n", host, foundIPs)
			}
		}
	}
	if resolveErr != nil {
		fmt.Fprintf(os.Stderr, "[callRustFetcher] DNS resolution failed for %s: %v\n", host, resolveErr)
		return RustScanResult{URL: target, Headers: map[string]string{"error": resolveErr.Error()}}
	}
	fmt.Fprintf(os.Stderr, "[callRustFetcher] Resolved %s to %d IPs\n", host, len(ips))

	// Pick first IPv4 address
	var targetIP string
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			targetIP = ip.IP.String()
			break
		}
	}
	if targetIP == "" && len(ips) > 0 {
		targetIP = ips[0].IP.String()
	}
	if targetIP == "" {
		fmt.Fprintf(os.Stderr, "[callRustFetcher] No IP resolved for %s\n", host)
		return RustScanResult{URL: target}
	}
	fmt.Fprintf(os.Stderr, "[callRustFetcher] Using IP=%s for host=%s\n", targetIP, host)

	// Custom transport that dials directly to pre-resolved IP
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest := net.JoinHostPort(targetIP, port)
			fmt.Fprintf(os.Stderr, "[callRustFetcher] DialContext: %s -> %s (bypassing Go DNS for %s)\n", network, dest, addr)
			d := &net.Dialer{Timeout: time.Duration(opts.Timeout) * time.Second}
			return d.DialContext(ctx, network, dest)
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, ServerName: host},
		MaxIdleConns:          5,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Timeout: time.Duration(opts.Timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 { return fmt.Errorf("too many redirects") }
			return nil
		},
	}

	// Re-construct URL with explicit port, use IP for dial and Host header for virtual hosting
	urlStr := u.Scheme + "://" + host + ":" + port + u.Path
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[callRustFetcher] Request creation failed: %v\n", err)
		return RustScanResult{URL: target}
	}
	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[callRustFetcher] HTTP request failed: %v\n", err)
		return RustScanResult{URL: target, Headers: map[string]string{"error": err.Error()}}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 { headers[k] = v[0] }
	}

	desc := "No brief available."
	bodyLower := strings.ToLower(body)
	if idx := strings.Index(bodyLower, "<title>"); idx != -1 {
		if endIdx := strings.Index(bodyLower[idx:], "</title>"); endIdx != -1 {
			title := body[idx+7 : idx+endIdx]
			if title != "" { desc = title }
		}
	}

	server := headers["Server"]
	if server == "" { server = headers["server"] }

	industry := ""
	if strings.Contains(bodyLower, "e-commerce") || strings.Contains(bodyLower, "shop") || strings.Contains(bodyLower, "buy") || strings.Contains(bodyLower, "cart") {
		industry = "E-Commerce / Retail"
	} else if strings.Contains(bodyLower, "classified") || strings.Contains(bodyLower, "olx") {
		industry = "Classifieds / Marketplace"
	} else if strings.Contains(bodyLower, "social") || strings.Contains(bodyLower, "login") || strings.Contains(bodyLower, "signup") {
		industry = "Social / Community"
	}

	fmt.Fprintf(os.Stderr, "[callRustFetcher] Completed in %s: status=%d body_len=%d\n", time.Since(start), resp.StatusCode, len(body))
	return RustScanResult{
		URL:           target,
		Status:        resp.StatusCode,
		Headers:       headers,
		BodySnippet:   body,
		Description:   desc,
		IndustryHint:  industry,
		DetectedTechs: guessTechFromHeaders(headers, body),
	}
}

func guessTechFromHeaders(headers map[string]string, body string) map[string]RustTechInfo {
	techs := make(map[string]RustTechInfo)
	if srv, ok := headers["Server"]; ok {
		techs["Server"] = RustTechInfo{Name: srv, Confidence: 90, Category: "Web Server"}
	}
	if pw, ok := headers["X-Powered-By"]; ok {
		techs["PoweredBy"] = RustTechInfo{Name: pw, Confidence: 85, Category: "Framework"}
	}
	// Detect common technologies from body
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-json") {
		techs["CMS"] = RustTechInfo{Name: "WordPress", Confidence: 80, Category: "CMS"}
	}
	if strings.Contains(bodyLower, "drupal") || strings.Contains(bodyLower, "drupal.js") {
		techs["CMS"] = RustTechInfo{Name: "Drupal", Confidence: 80, Category: "CMS"}
	}
	if strings.Contains(bodyLower, "joomla") {
		techs["CMS"] = RustTechInfo{Name: "Joomla", Confidence: 80, Category: "CMS"}
	}
	if strings.Contains(bodyLower, "react") || strings.Contains(bodyLower, "reactdom") || strings.Contains(bodyLower, "react.") {
		techs["Frontend"] = RustTechInfo{Name: "React", Confidence: 70, Category: "JavaScript Framework"}
	}
	if strings.Contains(bodyLower, "vue") || strings.Contains(bodyLower, "vue.js") {
		techs["Frontend"] = RustTechInfo{Name: "Vue.js", Confidence: 70, Category: "JavaScript Framework"}
	}
	if strings.Contains(bodyLower, "angular") || strings.Contains(bodyLower, "ng-") {
		techs["Frontend"] = RustTechInfo{Name: "Angular", Confidence: 70, Category: "JavaScript Framework"}
	}
	if strings.Contains(bodyLower, "jquery") {
		techs["JSLib"] = RustTechInfo{Name: "jQuery", Confidence: 80, Category: "JavaScript Library"}
	}
	if strings.Contains(bodyLower, "bootstrap") {
		techs["CSSFramework"] = RustTechInfo{Name: "Bootstrap", Confidence: 75, Category: "CSS Framework"}
	}
	if strings.Contains(bodyLower, "google-analytics") || strings.Contains(bodyLower, "ga('") || strings.Contains(bodyLower, "gtag") {
		techs["Analytics"] = RustTechInfo{Name: "Google Analytics", Confidence: 85, Category: "Analytics"}
	}
	if strings.Contains(bodyLower, "facebook.com/tr") || strings.Contains(bodyLower, "fbq(") {
		techs["Analytics"] = RustTechInfo{Name: "Facebook Pixel", Confidence: 85, Category: "Analytics"}
	}
	return techs
}

func callCppForensics(body string, headers map[string]string) string {
	if len(body) > 100000 {
		body = body[:100000]
	}
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
	if len(body) > 50000 {
		body = body[:50000]
	}
	cBody, _ := syscall.BytePtrFromString(body)
	retPtr, _, _ := deepScanProc.Call(uintptr(unsafe.Pointer(cBody)))
	if retPtr == 0 {
		return ""
	}
	report := goString(retPtr)
	freeDeepStr.Call(retPtr)
	return report
}

func callLowLevelCheck(headers map[string]string) string {
	hStr, _ := json.Marshal(headers)
	cHeaders, _ := syscall.BytePtrFromString(string(hStr))
	retPtr, _, _ := checkAnom.Call(uintptr(unsafe.Pointer(cHeaders)))
	if retPtr == 0 {
		return ""
	}
	res := goString(retPtr)
	freeAnomStr.Call(retPtr)
	return res
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
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "fingerprint.rb"))
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

func callLuaTechDetector(body string) string {
	cmd := exec.Command("lua", filepath.Join(luaPath, "tech_detector.lua"), body)
	out, err := cmd.Output()
	if err != nil { return "" }
	return strings.TrimSpace(string(out))
}

func callLuaHttpMethods(headers, body string) string {
	cmd := exec.Command("lua", filepath.Join(luaPath, "http_methods.lua"), headers, body)
	out, err := cmd.Output()
	if err != nil { return "" }
	return strings.TrimSpace(string(out))
}

func callLuaCookieAnalyzer(headers string) string {
	cmd := exec.Command("lua", filepath.Join(luaPath, "cookie_analyzer.lua"), headers)
	out, err := cmd.Output()
	if err != nil { return "" }
	return strings.TrimSpace(string(out))
}

func callRubySSLAudit(domain string) string {
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "ssl_audit.rb"), domain)
	out, err := cmd.Output()
	if err != nil { return "" }
	return strings.TrimSpace(string(out))
}

func callRubyEmailFinder(body, domain string) string {
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "email_finder.rb"), body, domain)
	out, err := cmd.Output()
	if err != nil { return "" }
	return strings.TrimSpace(string(out))
}

func callRubyJSAnalyzer(body, baseURL string) string {
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "js_analyzer.rb"), body, baseURL)
	out, err := cmd.Output()
	if err != nil { return "" }
	return strings.TrimSpace(string(out))
}

func callRubyCloudDetector(body string, headers map[string]string, domain string) string {
	hJson, _ := json.Marshal(headers)
	cmd := exec.Command("ruby", filepath.Join(rubyPath, "cloud_detector.rb"), body, string(hJson), domain)
	out, err := cmd.Output()
	if err != nil { return "" }
	return strings.TrimSpace(string(out))
}

func callPythonBrain(results []Result) {
	data, _ := json.Marshal(results)
	fmt.Println("---JSON_START---")
	fmt.Println(string(data))
	fmt.Println("---JSON_END---")
}

func performDNSRecon(host string) *DNSInfo {
	info := &DNSInfo{}
	ips, _ := lookupHostTimeout(host)
	info.A = ips
	return info
}

func detectWAF(headers map[string]string) string {
	if srv, ok := headers["Server"]; ok {
		s := strings.ToLower(srv)
		if strings.Contains(s, "cloudflare") {
			return "Cloudflare"
		}
		if strings.Contains(s, "akamai") {
			return "Akamai"
		}
		if strings.Contains(s, "fastly") {
			return "Fastly"
		}
	}
	if _, ok := headers["CF-Ray"]; ok {
		return "Cloudflare"
	}
	if _, ok := headers["X-Sucuri-ID"]; ok {
		return "Sucuri"
	}
	if _, ok := headers["X-CDN"]; ok {
		return "CDN"
	}
	if _, ok := headers["Akamai-Origin-Hop"]; ok {
		return "Akamai"
	}
	// Check common CDN cookies
	if ck, ok := headers["Set-Cookie"]; ok {
		if strings.Contains(ck, "__cfduid") || strings.Contains(ck, "__cf_bm") {
			return "Cloudflare"
		}
	}
	return ""
}

func fetchHistoricalIPs(domain string) []string {
	// Use OSINT data to extract historical IPs
	osint := CollectOSINT(domain)
	var ips []string
	seen := make(map[string]bool)
	if osint != nil {
		for _, ip := range osint.HackerTargetIPs {
			if !seen[ip] {
				ips = append(ips, ip)
				seen[ip] = true
			}
		}
	}
	return ips
}

func callRubyOSINT(domain string) []string {
	input, _ := json.Marshal(map[string]string{"domain": domain})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ruby", filepath.Join(rubyPath, "osint.rb"))
	cmd.Stdin = strings.NewReader(string(input))
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res []string
	json.Unmarshal(out, &res)
	return res
}

func analyzeHTTPHeaders(headers map[string]string) map[string]string {
	analysis := make(map[string]string)
	if csp, ok := headers["Content-Security-Policy"]; ok {
		analysis["CSP"] = csp[:min(100, len(csp))]
	} else {
		analysis["CSP"] = "MISSING"
	}
	if xfo, ok := headers["X-Frame-Options"]; ok {
		analysis["X-Frame-Options"] = xfo
	} else {
		analysis["X-Frame-Options"] = "MISSING"
	}
	if hsts, ok := headers["Strict-Transport-Security"]; ok {
		analysis["HSTS"] = hsts[:min(80, len(hsts))]
	} else {
		analysis["HSTS"] = "MISSING"
	}
	if xcto, ok := headers["X-Content-Type-Options"]; ok {
		analysis["X-Content-Type-Options"] = xcto
	} else {
		analysis["X-Content-Type-Options"] = "MISSING"
	}
	if cors, ok := headers["Access-Control-Allow-Origin"]; ok {
		analysis["CORS"] = cors
	} else {
		analysis["CORS"] = "Not Set"
	}
	if rr, ok := headers["Referrer-Policy"]; ok {
		analysis["Referrer-Policy"] = rr
	} else {
		analysis["Referrer-Policy"] = "MISSING"
	}
	if pp, ok := headers["Permissions-Policy"]; ok {
		analysis["Permissions-Policy"] = pp[:min(80, len(pp))]
	} else {
		analysis["Permissions-Policy"] = "MISSING"
	}
	if sc, ok := headers["Set-Cookie"]; ok {
		analysis["Set-Cookie"] = sc[:min(100, len(sc))]
	}
	if pw, ok := headers["X-Powered-By"]; ok {
		analysis["X-Powered-By"] = pw
	}
	if ct, ok := headers["Content-Type"]; ok {
		analysis["Content-Type"] = ct
	}
	return analysis
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
	fmt.Printf("\n%s %s (%d)\n", color.HiGreenString("▸"), color.HiWhiteString(res.URL), res.Status)

	if res.Title != "" {
		fmt.Printf("  %s Title: %s\n", color.HiBlackString("├"), color.HiCyanString(res.Title))
	}
	if res.Server != "" {
		fmt.Printf("  %s Server: %s\n", color.HiBlackString("├"), color.YellowString(res.Server))
	}
	if res.IP != "" {
		fmt.Printf("  %s IP: %s\n", color.HiBlackString("├"), color.HiWhiteString(res.IP))
	}
	if res.Industry != "" {
		fmt.Printf("  %s Industry: %s\n", color.HiBlackString("├"), color.HiMagentaString(res.Industry))
	}
	if res.Description != "" {
		fmt.Printf("  %s Desc: %s\n", color.HiBlackString("├"), color.HiBlackString(res.Description))
	}

	if res.DNS != nil {
		fmt.Printf("  %s DNS A: %s\n", color.HiBlackString("├"), color.HiWhiteString(strings.Join(res.DNS.A, ", ")))
	}
	if res.DNSEnum != nil {
		fmt.Printf("  %s DNS Enum: %d A · %d MX · %d NS · %d TXT\n", color.HiBlackString("├"),
			len(res.DNSEnum.A), len(res.DNSEnum.MX), len(res.DNSEnum.NS), len(res.DNSEnum.TXT))
	}
	if res.DNSHistory != nil && len(res.DNSHistory.HistoricalA) > 0 {
		fmt.Printf("  %s DNS History: %s\n", color.HiBlackString("├"), color.HiWhiteString(strings.Join(res.DNSHistory.HistoricalA, ", ")))
	}

	if res.Whois != nil {
		fmt.Printf("  %s Whois: %s | %s | %s\n", color.HiBlackString("├"),
			res.Whois.Registrar, res.Whois.Email, res.Whois.Org)
	}

	if res.SSLAnalysis != nil && res.SSLAnalysis.Certificate != nil {
		c := res.SSLAnalysis.Certificate
		fmt.Printf("  %s TLS: %s · %s · %dd left\n", color.HiBlackString("├"),
			c.Issuer, c.PublicKey, c.DaysRemaining)
	}

	if res.Network != nil && len(res.Network) > 0 {
		n := res.Network[0]
		fmt.Printf("  %s Geo: %s | ISP: %s | ASN: %s\n", color.HiBlackString("├"),
			n.Geo, n.ISP, n.ASN)
	}

	if res.PassiveDNS != nil && len(res.PassiveDNS.LastSeenIPs) > 0 {
		fmt.Printf("  %s Passive DNS: %s\n", color.HiBlackString("├"),
			color.HiWhiteString(strings.Join(res.PassiveDNS.LastSeenIPs, ", ")))
	}
	if res.PassiveDNS != nil && len(res.PassiveDNS.PossibleInternalDomains) > 0 {
		fmt.Printf("  %s Internal: %s\n", color.HiBlackString("├"),
			color.HiYellowString(strings.Join(res.PassiveDNS.PossibleInternalDomains, ", ")))
	}

	if res.WAF != nil && res.WAF.Detected {
		fmt.Printf("  %s WAF: %s (%s)\n", color.HiBlackString("├"),
			color.HiRedString(res.WAF.Provider), res.WAF.WAFType)
	}
	if res.WebAudit != nil {
		fmt.Printf("  %s Web Audit: %d findings\n", color.HiBlackString("├"), len(res.WebAudit.Findings))
	}
	if res.CMSCloud != nil {
		c := res.CMSCloud
		cloud := ""
		if len(c.CloudAssets.S3Buckets) > 0 { cloud += "S3:" + strings.Join(c.CloudAssets.S3Buckets, ",") + " " }
		if len(c.CloudAssets.GCPBuckets) > 0 { cloud += "GCP:" + strings.Join(c.CloudAssets.GCPBuckets, ",") + " " }
		if len(c.CloudAssets.Firebase) > 0 { cloud += "Firebase:" + strings.Join(c.CloudAssets.Firebase, ",") + " " }
		if c.CloudAssets.GithubOrg != "" { cloud += "GH:" + c.CloudAssets.GithubOrg }
		if cloud == "" { cloud = "None" }
		fmt.Printf("  %s CMS: %s | Framework: %s | Cloud: %s\n", color.HiBlackString("├"),
			c.CMS, c.Framework, cloud)
	}
	if res.AppFingerprint != nil {
		fmt.Printf("  %s App: %s | %s\n", color.HiBlackString("├"),
			res.AppFingerprint.Framework, res.AppFingerprint.CMS)
	}
	if res.TechStackAdvanced != nil {
		t := res.TechStackAdvanced
		fmt.Printf("  %s Stack: %s + %s\n", color.HiBlackString("├"), t.Frontend, t.Backend)
		if len(t.JSLibs) > 0 {
			fmt.Printf("  %s JS Libs: %s\n", color.HiBlackString("│"), strings.Join(t.JSLibs, ", "))
		}
	}

	if len(res.Technologies) > 0 {
		// Separate web technologies from subdomains
		var subdomains []string
		var webTechs []string
		for name, t := range res.Technologies {
			if t.Category == "Infrastructure" && (strings.Contains(name, ".") || t.Version == "HackerTarget" || t.Version == "Brute" || t.Version == "AlienVault" || t.Version == "crt.sh") {
				subdomains = append(subdomains, name)
			} else {
				ver := ""
				if t.Version != "" {
					ver = " " + t.Version
				}
				webTechs = append(webTechs, fmt.Sprintf("  %s   • %s%s [%s]", color.HiBlackString("│"),
					color.HiCyanString(name), ver, color.HiBlackString(t.Category)))
			}
		}
		if len(webTechs) > 0 {
			fmt.Printf("  %s Technologies (%d):\n", color.HiBlackString("├"), len(webTechs))
			for _, t := range webTechs {
				fmt.Println(t)
			}
		}
		if len(subdomains) > 0 {
			fmt.Printf("  %s Subdomains (%d): %s\n", color.HiBlackString("├"),
				len(subdomains), color.HiWhiteString(strings.Join(subdomains[:min(10, len(subdomains))], ", ")))
			if len(subdomains) > 10 {
				fmt.Printf("  %s   ... and %d more\n", color.HiBlackString("│"), len(subdomains)-10)
			}
		}
	}

	// New Lua plugin results
	if res.LuaTech != "" {
		fmt.Printf("  %s Lua Tech: %s\n", color.HiBlackString("├"), color.HiCyanString(res.LuaTech))
	}
	if res.LuaHttp != "" {
		fmt.Printf("  %s Lua HTTP: %s\n", color.HiBlackString("├"), color.HiYellowString(res.LuaHttp))
	}
	if res.LuaCookies != "" {
		fmt.Printf("  %s Lua Cookies: %s\n", color.HiBlackString("├"), color.HiYellowString(res.LuaCookies))
	}

	// New Ruby plugin results
	if res.RubySSL != "" && !strings.HasPrefix(res.RubySSL, "{") {
		fmt.Printf("  %s Ruby SSL: %s\n", color.HiBlackString("├"), color.HiCyanString(res.RubySSL))
	}
	if res.RubyEmails != "" && !strings.HasPrefix(res.RubyEmails, "{") {
		fmt.Printf("  %s Ruby Emails: %s\n", color.HiBlackString("├"), color.HiWhiteString(res.RubyEmails))
	}
	if res.RubyJS != "" && !strings.HasPrefix(res.RubyJS, "{") {
		fmt.Printf("  %s Ruby JS: %s\n", color.HiBlackString("├"), color.HiMagentaString(res.RubyJS))
	}
	if res.RubyCloud != "" && !strings.HasPrefix(res.RubyCloud, "{") {
		fmt.Printf("  %s Ruby Cloud: %s\n", color.HiBlackString("├"), color.HiBlueString(res.RubyCloud))
	}

	if res.ThirdParty != "" {
		fmt.Printf("  %s 3rd Party: %s\n", color.HiBlackString("├"), color.YellowString(res.ThirdParty))
	}
	if res.AuthSession != "" {
		fmt.Printf("  %s Auth: %s\n", color.HiBlackString("├"), color.YellowString(res.AuthSession))
	}
	if res.Forensics != "" {
		fmt.Printf("  %s Forensics: %s\n", color.HiBlackString("├"), color.YellowString(res.Forensics))
	}
	if res.OriginDiscovery != nil && res.OriginDiscovery.OriginIP != "" {
		fmt.Printf("  %s Origin: %s\n", color.HiBlackString("├"), color.HiWhiteString(res.OriginDiscovery.OriginIP))
	}
	if res.ScrapedContacts != nil {
		if len(res.ScrapedContacts.Emails) > 0 {
			fmt.Printf("  %s Emails: %s\n", color.HiBlackString("├"),
				color.HiWhiteString(strings.Join(res.ScrapedContacts.Emails, ", ")))
		}
		if len(res.ScrapedContacts.SocialMedia) > 0 {
			fmt.Printf("  %s Social: %s\n", color.HiBlackString("├"),
				color.HiCyanString(strings.Join(res.ScrapedContacts.SocialMedia, ", ")))
		}
	}
	if res.Aliases != nil && len(res.Aliases) > 0 {
		fmt.Printf("  %s Aliases: %s\n", color.HiBlackString("├"),
			color.HiWhiteString(strings.Join(res.Aliases, ", ")))
	}

	if res.Subsidiaries != nil && len(res.Subsidiaries.Aliases) > 0 {
		fmt.Printf("  %s Subsidiaries: %s\n", color.HiBlackString("├"),
			color.HiWhiteString(strings.Join(res.Subsidiaries.Aliases, ", ")))
	}
	if res.OSINTData != nil {
		if len(res.OSINTData.CrtshSubdomains) > 0 {
			fmt.Printf("  %s CRT.sh: %d subdomains\n", color.HiBlackString("├"),
				len(res.OSINTData.CrtshSubdomains))
		}
		if len(res.OSINTData.HackerTargetIPs) > 0 {
			fmt.Printf("  %s HackerTarget: %d results\n", color.HiBlackString("├"),
				len(res.OSINTData.HackerTargetIPs))
		}
	}
	if res.Endpoints != nil && len(res.Endpoints) > 0 {
		findings := res.Endpoints
		if len(findings) > 5 {
			fmt.Printf("  %s Endpoints (%d): %s\n", color.HiBlackString("├"),
				len(findings), color.HiCyanString(strings.Join(findings[:5], ", ")))
			fmt.Printf("  %s   ... and %d more\n", color.HiBlackString("│"), len(findings)-5)
		} else {
			fmt.Printf("  %s Endpoints: %s\n", color.HiBlackString("├"),
				color.HiCyanString(strings.Join(findings, ", ")))
		}
	}

	// New display: Header Analysis Summary
	if res.HeaderAnalysis != nil {
		csp := res.HeaderAnalysis["CSP"]
		xfo := res.HeaderAnalysis["X-Frame-Options"]
		hsts := res.HeaderAnalysis["HSTS"]
		if csp != "MISSING" || xfo != "MISSING" || hsts != "MISSING" {
			summary := ""
			if csp != "MISSING" { summary += "CSP ✓|" }
			if xfo != "MISSING" { summary += "XFO ✓|" }
			if hsts != "MISSING" { summary += "HSTS ✓|" }
			fmt.Printf("  %s Security Headers: %s\n", color.HiBlackString("├"), color.HiGreenString(summary))
		}
	}

	// New display: Tech Report
	if res.TechReport != nil {
		t := res.TechReport
		fmt.Printf("  %s Frontend: %s | Backend: %s | CMS: %s\n", color.HiBlackString("├"),
			color.HiCyanString(t.Frontend), color.YellowString(t.Backend), color.HiMagentaString(t.CMS))
		if len(t.Analytics) > 0 {
			anNames := make([]string, len(t.Analytics))
			for i, a := range t.Analytics { anNames[i] = a.Name }
			fmt.Printf("  %s Analytics: %s\n", color.HiBlackString("├"), strings.Join(anNames, ", "))
		}
		if len(t.ChatWidgets) > 0 {
			cwNames := make([]string, len(t.ChatWidgets))
			for i, c := range t.ChatWidgets { cwNames[i] = c.Name }
			fmt.Printf("  %s Chat: %s\n", color.HiBlackString("├"), strings.Join(cwNames, ", "))
		}
		if len(t.PaymentGatways) > 0 {
			pgNames := make([]string, len(t.PaymentGatways))
			for i, p := range t.PaymentGatways { pgNames[i] = p.Name }
			fmt.Printf("  %s Payments: %s\n", color.HiBlackString("├"), strings.Join(pgNames, ", "))
		}
	}

	// New display: API Discovery
	if res.APIDiscovery != nil {
		api := res.APIDiscovery
		if len(api.Endpoints) > 0 || len(api.SpecFiles) > 0 || api.GraphQL {
			var parts []string
			if len(api.Endpoints) > 0 { parts = append(parts, fmt.Sprintf("%d endpoints", len(api.Endpoints))) }
			if len(api.SpecFiles) > 0 { parts = append(parts, fmt.Sprintf("%d specs", len(api.SpecFiles))) }
			if api.GraphQL { parts = append(parts, "GraphQL") }
			if api.RESTFul { parts = append(parts, "RESTful") }
			if len(api.APIVersions) > 0 { parts = append(parts, strings.Join(api.APIVersions, ",")) }
			fmt.Printf("  %s API: %s\n", color.HiBlackString("├"), strings.Join(parts, " | "))
		}
	}

	// New display: Wayback
	if res.Wayback != nil && len(res.Wayback.URLs) > 0 {
		fmt.Printf("  %s Wayback: %d historical snapshots\n", color.HiBlackString("├"), len(res.Wayback.URLs))
		if len(res.Wayback.ForgottenPaths) > 0 {
			fmt.Printf("  %s   Forgotten paths: %s\n", color.HiBlackString("│"),
				strings.Join(res.Wayback.ForgottenPaths[:min(5, len(res.Wayback.ForgottenPaths))], ", "))
		}
	}

	// New display: Threat Intel
	if res.ThreatIntel != nil {
		ti := res.ThreatIntel
		if ti.Blacklisted {
			fmt.Printf("  %s Threat: BLACKLISTED on %s\n", color.HiBlackString("├"),
				color.HiRedString(strings.Join(ti.BlacklistSources, ", ")))
		}
		if len(ti.AlienVault.URLs) > 0 {
			fmt.Printf("  %s AlienVault: %d URLs\n", color.HiBlackString("├"), len(ti.AlienVault.URLs))
		}
	}

	fmt.Printf("  %s\n", color.HiBlackString("└───────────"))
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

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func firstIPv4(ips []string) string {
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			return ip
		}
	}
	return ""
}
