package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fatih/color"
)

type PathDiscovery struct {
	Path          string `json:"path"`
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
	Title         string `json:"title"`
	Risk          string `json:"risk"`
}

// RustScanResult matches the Rust struct
type SubdomainInfo struct {
	Subdomain string `json:"subdomain"`
	IP        string `json:"ip"`
	Status    string `json:"status"`
}

type RustScanResult struct {
	URL              string            `json:"url"`
	Status           int               `json:"status"`
	Headers          map[string]string `json:"headers"`
	BodySnippet      string            `json:"body_snippet"`
	ResponseTimeMs   int64             `json:"response_time_ms"`
	Error            string            `json:"error"`
	FaviconHash      string            `json:"favicon_hash"`
	TLSInfo          *TLSInfo          `json:"tls_info"`
	Technologies     map[string]string `json:"detected_techs"`
	WAFInfo          []string          `json:"waf_info"`
	Vulnerabilities  []Vulnerability   `json:"vulnerabilities"`
	Whois            *WhoisInfo        `json:"whois"`
	OpenPorts        []PortInfo        `json:"open_ports"`
	ContactInfo      ContactInfo       `json:"contact_info"`
	DNSInfo          *DNSInfo          `json:"dns_info"`
	HeaderSecurity   *HeaderSecurity   `json:"header_security"`
	PathDiscoveries  []PathDiscovery   `json:"path_discoveries"`
	Subdomains       []SubdomainInfo   `json:"subdomains"`
	ServerDetails    ServerDetails     `json:"server_details"`
	DBDetails        *DBDetails        `json:"db_details"`
	AdvancedAnalysis *AdvancedAnalysis `json:"advanced_analysis"`
	ExpertVulns      []ExpertVuln      `json:"expert_vulnerabilities"`
	BehavioralTechs  []string          `json:"behavioral_techs"`
	CloudAudit       *CloudAudit       `json:"cloud_audit"`
}

type ExpertVuln struct {
	Name            string `json:"name"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	CVEID           string `json:"cve_id"`
	PotentialImpact string `json:"potential_impact"`
}

type CloudAudit struct {
	Provider        string `json:"provider"`
	ExposedMetadata bool   `json:"exposed_metadata"`
	SecurityScore   int    `json:"security_score"`
}

type AdvancedAnalysis struct {
	SuspectedBehaviours []string `json:"suspected_behaviours"`
	SecurityScore       int      `json:"security_score"`
	TechnologyDepth     []string `json:"technology_depth"`
}

type DNSInfo struct {
	ARecords    []string `json:"a_records"`
	AAAARecords []string `json:"aaaa_records"`
	MXRecords   []string `json:"mx_records"`
	TXTRecords  []string `json:"txt_records"`
	NSRecords   []string `json:"ns_records"`
	SOARecord   string   `json:"soa_record"`
}

type HeaderSecurity struct {
	HSTS                bool   `json:"hsts"`
	CSP                 bool   `json:"csp"`
	XFrameOptions       string `json:"x_frame_options"`
	XXSSProtection      string `json:"x_xss_protection"`
	XContentTypeOptions bool   `json:"x_content_type_options"`
	ReferrerPolicy      string `json:"referrer_policy"`
	PermissionsPolicy   bool   `json:"permissions_policy"`
	ServerHeader        string `json:"server_header"`
	PoweredBy           string `json:"powered_by"`
}

type ServerDetails struct {
	ServerName      string `json:"server_name"`
	HostingProvider string `json:"hosting_provider"`
	CloudPlatform   string `json:"cloud_platform"`
	OSInfo          string `json:"os_info"`
	IPOrg           string `json:"ip_org"`
	DataCenter      string `json:"data_center"`
	ReverseProxy    string `json:"reverse_proxy"`
}

type DBDetails struct {
	DBType          string `json:"db_type"`
	Version         string `json:"version"`
	Confidence      int    `json:"confidence"`
	DetectionMethod string `json:"detection_method"`
}

type WhoisInfo struct {
	Registrar      string   `json:"registrar"`
	CreationDate   string   `json:"creation_date"`
	ExpirationDate string   `json:"expiration_date"`
	NameServers    []string `json:"name_servers"`
	Raw            string   `json:"raw,omitempty"`
}

// PortInfo holds information about an open port
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	State   string `json:"state"`
}

// TechInfo holds information about a detected technology
type TechInfo struct {
	Name       string   `json:"name"`
	Confidence int      `json:"confidence"`
	Version    string   `json:"version,omitempty"`
	Category   string   `json:"category,omitempty"`
	Sources    []string `json:"sources"`
	Evidence   []string `json:"evidence"`
}

// IPInfo holds network information about the target
type IPInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	ASN     string `json:"asn,omitempty"`
}

// TLSInfo holds TLS certificate information
type TLSInfo struct {
	Version            string   `json:"version"`
	Cipher             string   `json:"cipher"`
	Issuer             string   `json:"issuer"`
	Subject            string   `json:"subject"`
	Expiry             string   `json:"expiry"`
	SerialNumber       string   `json:"serial_number"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKey          string   `json:"public_key"`
	SANs               []string `json:"sans"`
}

// Result is the main output structure for TechHunter
type Vulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type ContactInfo struct {
	Emails      []string `json:"emails,omitempty"`
	Phones      []string `json:"phones,omitempty"`
	SocialLinks []string `json:"social_links,omitempty"`
}

type Result struct {
	URL              string              `json:"url"`
	Status           int                 `json:"status"`
	Title            string              `json:"title"`
	IPInfo           IPInfo              `json:"ip_info"`
	TLSInfo          *TLSInfo            `json:"tls_info,omitempty"`
	Headers          map[string]string   `json:"headers"`
	Technologies     map[string]TechInfo `json:"technologies"`
	Vulnerabilities  []Vulnerability     `json:"vulnerabilities,omitempty"`
	RiskScore        float64             `json:"risk_score,omitempty"`
	FaviconHash      string              `json:"favicon_hash,omitempty"`
	ResponseTime     time.Duration       `json:"response_time"`
	OpenPorts        []PortInfo          `json:"open_ports,omitempty"`
	ContactInfo      ContactInfo         `json:"contact_info,omitempty"`
	Whois            *WhoisInfo          `json:"whois,omitempty"`
	DNSInfo          *DNSInfo            `json:"dns_info,omitempty"`
	HeaderSecurity   *HeaderSecurity     `json:"header_security,omitempty"`
	PathDiscoveries  []PathDiscovery     `json:"path_discoveries,omitempty"`
	Subdomains       []SubdomainInfo     `json:"subdomains,omitempty"`
	ServerDetails    ServerDetails       `json:"server_details"`
	DBDetails        *DBDetails          `json:"db_details,omitempty"`
	AdvancedAnalysis *AdvancedAnalysis   `json:"advanced_analysis,omitempty"`
	ExpertVulns      []ExpertVuln        `json:"expert_vulnerabilities,omitempty"`
	BehavioralTechs  []string            `json:"behavioral_techs,omitempty"`
	CloudAudit       *CloudAudit         `json:"cloud_audit,omitempty"`
	WAFInfo          []string            `json:"waf_info,omitempty"`
	Error            string              `json:"error,omitempty"`
	BodySnippet      string              `json:"body_snippet,omitempty"`
}

type arrayFlags []string

func (i *arrayFlags) String() string { return "array flags" }
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Options holds all CLI configuration
type Options struct {
	URL   string
	List  string
	CIDR  string
	Port  string
	HTTP  bool
	HTTPS bool

	Threads      int
	Timeout      int
	Retries      int
	RateLimit    int
	Delay        int
	Proxy        string
	RandomAgent  bool
	CustomHeader arrayFlags

	Profile         string
	TechOnly        bool
	HeadersOnly     bool
	NoBody          bool
	DetectWAF       bool
	DetectCDN       bool
	DetectCMS       bool
	DetectFramework bool
	ShowConfidence  bool
	Heuristic       bool

	CVE           bool
	RiskScore     bool
	FingerprintDB string
	UpdateSigs    bool

	Output     string
	Format     string
	Pretty     bool
	Silent     bool
	Raw        bool
	ReportHTML bool

	DeepScan       bool
	Path           string
	BrutePath      string
	FaviconHash    bool
	TLSInfo        bool
	HTTP2          bool
	FollowRedirect bool

	Verbose bool
	Debug   bool
	Trace   bool
	DryRun  bool
}

var (
	rustLib        *syscall.LazyDLL
	rustFetchUrl   *syscall.LazyProc
	freeRustString *syscall.LazyProc
)

func initRust() {
	libPath := filepath.Join("rust_engine", "target", "release", "tech_hunter_rust.dll")
	if runtime.GOOS != "windows" {
		libPath = filepath.Join("rust_engine", "target", "release", "libtech_hunter_rust.so")
	}

	rustLib = syscall.NewLazyDLL(libPath)
	rustFetchUrl = rustLib.NewProc("rust_fetch_url")
	freeRustString = rustLib.NewProc("free_rust_string")
}

func main() {
	opts := &Options{}

	// Flag registration
	flag.StringVar(&opts.URL, "u", "", "Target URL")
	flag.StringVar(&opts.List, "l", "", "File berisi daftar target")
	flag.StringVar(&opts.CIDR, "cidr", "", "Scan target dari CIDR")
	flag.StringVar(&opts.Port, "p", "", "Custom port")
	flag.BoolVar(&opts.HTTP, "http", false, "Force HTTP")
	flag.BoolVar(&opts.HTTPS, "https", false, "Force HTTPS")

	flag.BoolVar(&opts.FaviconHash, "favicon", false, "Fetch and hash favicon")
	flag.BoolVar(&opts.DeepScan, "deep", false, "Enable deep scanning (crawling)")
	flag.IntVar(&opts.Threads, "threads", 50, "Jumlah concurrent worker")
	flag.IntVar(&opts.Timeout, "timeout", 10, "Timeout per request")
	flag.IntVar(&opts.Retries, "retries", 1, "Retry count")
	flag.IntVar(&opts.RateLimit, "rate", 0, "Max request per second")
	flag.IntVar(&opts.Delay, "delay", 0, "Delay antar request")
	flag.StringVar(&opts.Proxy, "proxy", "", "Gunakan proxy (http/socks)")
	flag.BoolVar(&opts.RandomAgent, "random-agent", true, "Random user-agent")

	flag.StringVar(&opts.Profile, "profile", "full", "fast | stealth | full | deep")
	flag.BoolVar(&opts.TechOnly, "tech-only", false, "Hanya tampilkan teknologi")
	flag.BoolVar(&opts.HeadersOnly, "headers-only", false, "Hanya analisa header")
	flag.BoolVar(&opts.NoBody, "no-body", false, "Jangan ambil body response")
	flag.BoolVar(&opts.DetectWAF, "detect-waf", false, "Aktifkan deteksi WAF")
	flag.BoolVar(&opts.DetectCDN, "detect-cdn", false, "Aktifkan deteksi CDN")
	flag.BoolVar(&opts.DetectCMS, "detect-cms", false, "Fokus deteksi CMS")
	flag.BoolVar(&opts.DetectFramework, "detect-framework", false, "Fokus framework detection")
	flag.BoolVar(&opts.ShowConfidence, "confidence", false, "Tampilkan confidence score")
	flag.BoolVar(&opts.Heuristic, "heuristic", false, "Aktifkan heuristic detection")

	flag.BoolVar(&opts.CVE, "cve", false, "Mapping CVE jika tersedia")
	flag.BoolVar(&opts.RiskScore, "risk-score", false, "Hitung risk score")
	flag.StringVar(&opts.FingerprintDB, "fingerprint-db", "", "Custom signature database")
	flag.Var(&opts.CustomHeader, "header", "Custom header (format: 'Key: Value')")
	flag.BoolVar(&opts.UpdateSigs, "update-signature", false, "Update signature database")

	flag.StringVar(&opts.Output, "o", "", "Simpan hasil ke file")
	flag.StringVar(&opts.Format, "format", "json", "json | table | csv | ndjson")
	flag.BoolVar(&opts.Pretty, "pretty", false, "Pretty JSON output")
	flag.BoolVar(&opts.Silent, "silent", false, "Hanya tampilkan hasil penting")
	flag.BoolVar(&opts.Raw, "raw", false, "Tampilkan raw response")
	flag.BoolVar(&opts.ReportHTML, "report-html", false, "Generate HTML report")

	flag.StringVar(&opts.Path, "path", "", "Scan specific path")
	flag.StringVar(&opts.BrutePath, "brutepath", "", "Bruteforce common paths")
	flag.BoolVar(&opts.HTTP2, "http2", false, "Force HTTP/2")
	flag.BoolVar(&opts.FollowRedirect, "follow-redirect", false, "Ikuti redirect")

	flag.BoolVar(&opts.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&opts.Debug, "debug", false, "Debug mode")
	flag.BoolVar(&opts.Trace, "trace", false, "Trace request")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Simulasi tanpa request")

	flag.Parse()

	if opts.URL == "" && opts.List == "" && opts.CIDR == "" {
		fmt.Println("Error: Target (-u, -l, or --cidr) is required")
		os.Exit(1)
	}

	initRust()

	var allResults []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	targetsChan := make(chan string)

	// Worker Pool
	numWorkers := opts.Threads
	if numWorkers <= 0 {
		numWorkers = 10
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetsChan {
				res := scanTarget(target, opts)
				mu.Lock()
				allResults = append(allResults, res)
				mu.Unlock()
			}
		}()
	}

	// Send targets to workers
	if opts.URL != "" {
		targets := strings.Split(opts.URL, ",")
		for _, target := range targets {
			target = strings.TrimSpace(target)
			if target != "" {
				targetsChan <- target
			}
		}
	}

	if opts.CIDR != "" {
		targets := expandCIDR(opts.CIDR)
		for _, target := range targets {
			targetsChan <- target
		}
	}

	if opts.List != "" {
		data, err := os.ReadFile(opts.List)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					targetsChan <- line
				}
			}
		}
	}
	close(targetsChan)
	wg.Wait()

	// Output all results as a JSON array
	outputAllResults(allResults, opts)
}

func scanTarget(target string, opts *Options) Result {
	target = normalizeURL(target, opts)
	// 1. Call Rust for High-Speed Execution
	cUrl, _ := syscall.BytePtrFromString(target)

	ua := "TechHunter/1.0 (Hybrid Engine)"
	if opts.RandomAgent {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" // Simplified random agent
	}
	cUa, _ := syscall.BytePtrFromString(ua)

	followRedir := 0
	if opts.FollowRedirect {
		followRedir = 1
	}

	cProxy, _ := syscall.BytePtrFromString(opts.Proxy)

	http2Only := 0
	if opts.HTTP2 {
		http2Only = 1
	}

	fetchFavicon := 0
	if opts.FaviconHash {
		fetchFavicon = 1
	}

	deepScan := 0
	if opts.DeepScan {
		deepScan = 1
	}

	retPtr, _, _ := rustFetchUrl.Call(
		uintptr(unsafe.Pointer(cUrl)),
		uintptr(opts.Timeout),
		uintptr(followRedir),
		uintptr(0), // verify_ssl = false by default to match previous behavior
		uintptr(unsafe.Pointer(cUa)),
		uintptr(unsafe.Pointer(cProxy)),
		uintptr(http2Only),
		uintptr(fetchFavicon),
		uintptr(deepScan),
	)

	rustJson := goString(retPtr)
	defer freeRustString.Call(retPtr)

	var rustRes RustScanResult
	if err := json.Unmarshal([]byte(rustJson), &rustRes); err != nil {
		return Result{URL: target, Error: fmt.Sprintf("Failed to parse Rust output: %s", err)}
	}

	if rustRes.Error != "" {
		return Result{URL: target, Error: rustRes.Error}
	}

	// 2. Detection Logic (using Go analyzer + Python brain)
	res := Result{
		URL:          rustRes.URL,
		Status:       rustRes.Status,
		Headers:      rustRes.Headers,
		BodySnippet:  rustRes.BodySnippet,
		ResponseTime: time.Duration(rustRes.ResponseTimeMs) * time.Millisecond,
		FaviconHash:  rustRes.FaviconHash,
		OpenPorts:    rustRes.OpenPorts,
	}

	// Title Detection
	titleRe := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	if matches := titleRe.FindStringSubmatch(rustRes.BodySnippet); len(matches) > 1 {
		res.Title = matches[1]
	}

	// If title is still empty, try to get it from headers or use default
	if res.Title == "" || res.Title == "No Title" {
		if t, ok := rustRes.Headers["Title"]; ok {
			res.Title = t
		} else {
			res.Title = "Untitled Page"
		}
	}

	// 3. IP and GeoIP Info
	res.IPInfo = fetchIPInfo(rustRes.URL)

	// Extract IP properly
	host := ""
	u, err := url.Parse(rustRes.URL)
	if err == nil {
		host = u.Hostname()
	} else {
		host = rustRes.URL
	}

	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		var ipStrings []string
		for _, ip := range ips {
			ipStrings = append(ipStrings, ip.String())
		}
		res.IPInfo.IP = strings.Join(ipStrings, ", ")
	} else {
		res.IPInfo.IP = "Lookup Failed"
	}
	res.TLSInfo = rustRes.TLSInfo

	// Update URL if redirected
	if rustRes.URL != "" && rustRes.URL != target {
		res.URL = rustRes.URL
	}

	// Run Go signatures first
	res.Technologies = analyze(rustRes)

	// Call Python Brain if requested or always for deep intelligence
	pyRes := callPythonBrain(res, opts)
	// Merge results
	for k, v := range pyRes.Technologies {
		res.Technologies[k] = v
	}
	res.RiskScore = pyRes.RiskScore

	// Merge Rust-detected technologies
	for name := range rustRes.Technologies {
		if _, exists := res.Technologies[name]; !exists {
			res.Technologies[name] = TechInfo{
				Name:       name,
				Confidence: 100,
				Sources:    []string{"rust-core"},
			}
		}
	}

	// Add Contact info
	res.ContactInfo = ContactInfo{
		Emails:      rustRes.ContactInfo.Emails,
		Phones:      rustRes.ContactInfo.Phones,
		SocialLinks: rustRes.ContactInfo.SocialLinks,
	}

	// Merge WAF info
	for _, waf := range rustRes.WAFInfo {
		if _, exists := res.Technologies[waf]; !exists {
			res.Technologies[waf] = TechInfo{
				Name:       waf,
				Confidence: 100,
				Category:   "WAF/CDN",
				Sources:    []string{"rust-core"},
			}
		}
	}

	// Merge Path Discoveries
	res.PathDiscoveries = rustRes.PathDiscoveries

	// Merge Subdomains
	res.Subdomains = rustRes.Subdomains

	// Merge Rust vulnerabilities
	for _, v := range rustRes.Vulnerabilities {
		res.Vulnerabilities = append(res.Vulnerabilities, Vulnerability{
			ID:          v.ID,
			Severity:    v.Severity,
			Description: v.Description,
		})
	}

	// Add DNS Info
	res.DNSInfo = rustRes.DNSInfo

	// Add Header Security
	res.HeaderSecurity = rustRes.HeaderSecurity

	// Add Server & DB Details
	res.ServerDetails = rustRes.ServerDetails
	res.DBDetails = rustRes.DBDetails
	res.AdvancedAnalysis = rustRes.AdvancedAnalysis
	res.ExpertVulns = rustRes.ExpertVulns
	res.BehavioralTechs = rustRes.BehavioralTechs
	res.CloudAudit = rustRes.CloudAudit
	res.WAFInfo = rustRes.WAFInfo

	// Add Whois info if available
	if rustRes.Whois != nil {
		res.Whois = &WhoisInfo{
			Registrar:      rustRes.Whois.Registrar,
			CreationDate:   rustRes.Whois.CreationDate,
			ExpirationDate: rustRes.Whois.ExpirationDate,
			NameServers:    rustRes.Whois.NameServers,
			Raw:            rustRes.Whois.Raw,
		}
	}

	// 4. Output
	if res.Title == "" || res.Title == "Untitled Page" {
		res.Title = extractTitle(rustRes.BodySnippet)
	}
	return res
}

func outputAllResults(results []Result, opts *Options) {
	if len(results) == 0 {
		return
	}

	// Tampilkan output cantik jika --pretty atau mode interaktif
	fmt.Printf("\n[+] Scanning complete. Found %d targets.\n", len(results))

	for _, res := range results {
		fmt.Printf("\nTarget: %s [%d]\n", res.URL, res.Status)
		if res.Title != "" {
			fmt.Printf("Title : %s\n", res.Title)
		}
		fmt.Printf("IP    : %s (%s, %s)\n", res.IPInfo.IP, res.IPInfo.Org, res.IPInfo.Country)

		if len(res.Technologies) > 0 {
			fmt.Println("Detected Technologies:")
			for name := range res.Technologies {
				fmt.Printf("  - %s\n", name)
			}
		}

		if len(res.ContactInfo.Emails) > 0 || len(res.ContactInfo.Phones) > 0 {
			fmt.Println("Contact Information:")
			if len(res.ContactInfo.Emails) > 0 {
				fmt.Printf("  Emails: %s\n", strings.Join(res.ContactInfo.Emails, ", "))
			}
			if len(res.ContactInfo.Phones) > 0 {
				fmt.Printf("  Phones: %s\n", strings.Join(res.ContactInfo.Phones, ", "))
			}
			if len(res.ContactInfo.SocialLinks) > 0 {
				fmt.Printf("  Social: %s\n", strings.Join(res.ContactInfo.SocialLinks, ", "))
			}
		}

		if len(res.OpenPorts) > 0 {
			ports := []string{}
			for _, p := range res.OpenPorts {
				ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Service))
			}
			fmt.Printf("Open Ports: %s\n", strings.Join(ports, ", "))
		}

		if res.TLSInfo != nil {
			fmt.Println("SSL/TLS Information:")
			fmt.Printf("  Version: %s\n", res.TLSInfo.Version)
			fmt.Printf("  Issuer: %s\n", res.TLSInfo.Issuer)
			fmt.Printf("  Subject: %s\n", res.TLSInfo.Subject)
			fmt.Printf("  Expiry: %s\n", res.TLSInfo.Expiry)
			fmt.Printf("  Public Key: %s\n", res.TLSInfo.PublicKey)
			if len(res.TLSInfo.SANs) > 0 {
				fmt.Printf("  SANs: %s\n", strings.Join(res.TLSInfo.SANs, ", "))
			}
		}

		if res.Whois != nil {
			fmt.Println("WHOIS Information:")
			fmt.Printf("  Registrar: %s\n", res.Whois.Registrar)
			fmt.Printf("  Created  : %s\n", res.Whois.CreationDate)
			fmt.Printf("  Expires  : %s\n", res.Whois.ExpirationDate)
			if len(res.Whois.NameServers) > 0 {
				fmt.Printf("  NS       : %s\n", strings.Join(res.Whois.NameServers, ", "))
			}
		}

		if res.DNSInfo != nil {
			fmt.Println("DNS Records:")
			if len(res.DNSInfo.ARecords) > 0 {
				fmt.Printf("  A    : %s\n", strings.Join(res.DNSInfo.ARecords, ", "))
			}
			if len(res.DNSInfo.MXRecords) > 0 {
				fmt.Printf("  MX   : %s\n", strings.Join(res.DNSInfo.MXRecords, ", "))
			}
			if len(res.DNSInfo.TXTRecords) > 0 {
				fmt.Printf("  TXT  : %s\n", strings.Join(res.DNSInfo.TXTRecords, ", "))
			}
			if res.DNSInfo.SOARecord != "" {
				fmt.Printf("  SOA  : %s\n", res.DNSInfo.SOARecord)
			}
		}

		if res.HeaderSecurity != nil {
			fmt.Printf("\n%s\n", color.CyanString("Header Security Analysis:"))
			fmt.Printf("  HSTS: %v, CSP: %v, NoSniff: %v\n", res.HeaderSecurity.HSTS, res.HeaderSecurity.CSP, res.HeaderSecurity.XContentTypeOptions)
			if res.HeaderSecurity.XFrameOptions != "" {
				fmt.Printf("  X-Frame: %s\n", res.HeaderSecurity.XFrameOptions)
			}
			if res.HeaderSecurity.ServerHeader != "" {
				fmt.Printf("  Server : %s\n", res.HeaderSecurity.ServerHeader)
			}
		}

		// New: Server & DB Details Output
		fmt.Printf("\n%s\n", color.HiMagentaString("Infrastructure Details:"))
		if res.ServerDetails.ServerName != "" {
			fmt.Printf("  Server    : %s\n", color.HiWhiteString(res.ServerDetails.ServerName))
		}
		if res.ServerDetails.HostingProvider != "" {
			fmt.Printf("  Hosting   : %s\n", color.HiGreenString(res.ServerDetails.HostingProvider))
		}
		if res.ServerDetails.CloudPlatform != "" {
			fmt.Printf("  Cloud     : %s\n", color.HiBlueString(res.ServerDetails.CloudPlatform))
		}
		if res.ServerDetails.OSInfo != "" {
			fmt.Printf("  OS        : %s\n", color.HiCyanString(res.ServerDetails.OSInfo))
		}
		if res.ServerDetails.ReverseProxy != "" {
			fmt.Printf("  Proxy     : %s\n", color.HiYellowString(res.ServerDetails.ReverseProxy))
		}

		if res.DBDetails != nil {
			fmt.Printf("\n%s\n", color.HiRedString("Database Detection:"))
			fmt.Printf("  Type      : %s\n", color.HiWhiteString(res.DBDetails.DBType))
			fmt.Printf("  Method    : %s\n", res.DBDetails.DetectionMethod)
			fmt.Printf("  Confidence: %d%%\n", res.DBDetails.Confidence)
		}

		if res.AdvancedAnalysis != nil {
			fmt.Printf("\n%s\n", color.HiGreenString("Advanced Behavioral Analysis:"))
			fmt.Printf("  Security Score : %s/100\n", color.HiWhiteString(fmt.Sprintf("%d", res.AdvancedAnalysis.SecurityScore)))
			if len(res.AdvancedAnalysis.SuspectedBehaviours) > 0 {
				fmt.Printf("  Behaviours     : %s\n", color.HiYellowString(strings.Join(res.AdvancedAnalysis.SuspectedBehaviours, ", ")))
			}
			if len(res.AdvancedAnalysis.TechnologyDepth) > 0 {
				fmt.Printf("  Tech Depth     : %s\n", color.HiBlueString(strings.Join(res.AdvancedAnalysis.TechnologyDepth, ", ")))
			}
		}

		if len(res.BehavioralTechs) > 0 {
			fmt.Printf("\n%s\n", color.HiMagentaString("Expert Behavioral Detection:"))
			for _, t := range res.BehavioralTechs {
				fmt.Printf("  - %s\n", color.HiWhiteString(t))
			}
		}

		if res.CloudAudit != nil && res.CloudAudit.Provider != "" {
			fmt.Printf("\n%s\n", color.HiBlueString("Expert Cloud Audit:"))
			fmt.Printf("  Provider  : %s\n", color.HiWhiteString(res.CloudAudit.Provider))
			fmt.Printf("  Sec Score : %d/100\n", res.CloudAudit.SecurityScore)
		}

		if len(res.ExpertVulns) > 0 {
			fmt.Printf("\n%s\n", color.RedString("Expert Vulnerability Detection:"))
			for _, v := range res.ExpertVulns {
				fmt.Printf("  [%s] %s: %s\n", color.HiRedString(v.Severity), color.HiWhiteString(v.Name), v.Description)
				if v.CVEID != "" {
					fmt.Printf("    CVE: %s\n", color.YellowString(v.CVEID))
				}
				fmt.Printf("    Impact: %s\n", color.HiRedString(v.PotentialImpact))
			}
		}

		if len(res.PathDiscoveries) > 0 {
			fmt.Printf("\n%s\n", color.YellowString("Sensitive Path Discovery:"))
			for _, p := range res.PathDiscoveries {
				riskColor := color.New(color.FgWhite).SprintFunc()
				switch p.Risk {
				case "High":
					riskColor = color.New(color.FgRed, color.Bold).SprintFunc()
				case "Medium":
					riskColor = color.New(color.FgYellow).SprintFunc()
				case "Low":
					riskColor = color.New(color.FgBlue).SprintFunc()
				}
				fmt.Printf("  [%s] %-20s (Status: %d, Size: %d) %s\n", riskColor(p.Risk), p.Path, p.Status, p.ContentLength, p.Title)
			}
		}

		if len(res.Subdomains) > 0 {
			fmt.Printf("\n%s\n", color.MagentaString("Subdomain Enumeration:"))
			for _, s := range res.Subdomains {
				fmt.Printf("  %-30s -> %s [%s]\n", s.Subdomain, s.IP, color.GreenString(s.Status))
			}
		}

		if res.Error != "" {
			fmt.Printf("[!] Error: %s\n", res.Error)
		}
	}

	// Selalu output JSON ke stdout untuk dikonsumsi Python
	jsonData, _ := json.Marshal(results)
	fmt.Println("\n---JSON_START---")
	fmt.Println(string(jsonData))
	fmt.Println("---JSON_END---")
}

func fetchIPInfo(targetURL string) IPInfo {
	info := IPInfo{IP: "Unknown", Country: "Unknown", City: "Unknown", ISP: "Unknown"}

	u, err := net.LookupHost(extractHostname(targetURL))
	if err == nil && len(u) > 0 {
		info.IP = u[0]

		// Simple GeoIP via ip-api.com (no API key needed for basic)
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://ip-api.com/json/" + info.IP)
		if err == nil {
			defer resp.Body.Close()
			var geo struct {
				Country string `json:"country"`
				City    string `json:"city"`
				ISP     string `json:"isp"`
				Org     string `json:"org"`
				AS      string `json:"as"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&geo); err == nil {
				info.Country = geo.Country
				info.City = geo.City
				info.ISP = geo.ISP
				info.Org = geo.Org
				info.ASN = geo.AS
			}
		}
	}
	return info
}

func extractHostname(targetURL string) string {
	targetURL = strings.TrimSpace(targetURL)
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	host := u.Hostname()
	if host == "" {
		return targetURL
	}
	return host
}

func expandCIDR(cidr string) []string {
	var ips []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for CIDR < 31
	ones, _ := ipnet.Mask.Size()
	if ones < 31 && len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	match := re.FindStringSubmatch(body)
	if len(match) > 1 {
		return match[1]
	}
	return "No Title"
}

func normalizeURL(target string, opts *Options) string {
	// If it already has a protocol, leave it
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}

	// If user forced HTTP
	if opts.HTTP {
		return "http://" + target
	}

	// Default to HTTPS if not specified, then let redirects handle it
	// Most modern sites are HTTPS.
	return "https://" + target
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
	}
	return string(res)
}

func callPythonBrain(res Result, opts *Options) Result {
	// Implementation for calling Python brain via subprocess
	// For now, return original result
	return res
}
