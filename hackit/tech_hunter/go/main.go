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

// RustTechInfo matches the Rust TechInfo struct
type RustTechInfo struct {
	Name       string `json:"name"`
	Confidence int    `json:"confidence"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
}

type RustScanResult struct {
	URL             string                  `json:"url"`
	Status          int                     `json:"status"`
	Headers         map[string]string       `json:"headers"`
	BodySnippet     string                  `json:"body_snippet"`
	ResponseTimeMs  int64                   `json:"response_time_ms"`
	Error           string                  `json:"error"`
	FaviconHash     string                  `json:"favicon_hash"`
	TLSInfo         *TLSInfo                `json:"tls_info"`
	Technologies    map[string]RustTechInfo `json:"detected_techs"`
	WAFInfo         []string                `json:"waf_info"`
	Vulnerabilities []Vulnerability         `json:"vulnerabilities"`
	Whois           *WhoisInfo              `json:"whois"`
	OpenPorts       []PortInfo              `json:"open_ports"`
	ContactInfo     ContactInfo             `json:"contact_info"`
	JSRecon         JSReconInfo             `json:"js_recon"`
	DNSInfo         *DNSInfo                `json:"dns_info"`
	HeaderSecurity  *HeaderSecurity         `json:"header_security"`
	PathDiscoveries []PathDiscovery         `json:"path_discoveries"`
	Subdomains      []SubdomainInfo         `json:"subdomains"`
	ServerDetails   ServerDetails           `json:"server_details"`
	DBDetails       *DBDetails              `json:"db_details"`
	RedirectChain   []string                `json:"redirect_chain"`
	DOMVars         []string                `json:"dom_vars"`
}

type JSReconInfo struct {
	Endpoints    []string `json:"endpoints"`
	APICalls     []string `json:"api_calls"`
	HiddenRoutes []string `json:"hidden_routes"`
	APIKeys      []string `json:"api_keys"`
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
	JSRecon          JSReconInfo         `json:"js_recon,omitempty"`
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

	// Output all results
	if !opts.Silent {
		outputAllResults(allResults, opts)
	}

	// Always output JSON for bridge
	jsonData, err := json.Marshal(allResults)
	if err == nil {
		fmt.Println("---JSON_START---")
		fmt.Println(string(jsonData))
		fmt.Println("---JSON_END---")
	}
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

	// DEBUG: Print body snippet to see if it's correct
	if opts.Verbose {
		fmt.Printf("[DEBUG] Body Snippet Length: %d\n", len(rustRes.BodySnippet))
	}

	// Override Title if it's "No Title" but body snippet has something better
	if res.Title == "No Title" || res.Title == "Untitled Page" {
		titleRe := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
		if matches := titleRe.FindStringSubmatch(rustRes.BodySnippet); len(matches) > 1 {
			res.Title = strings.TrimSpace(matches[1])
		}
	}

	// Call Python Brain if requested or always for deep intelligence
	pyRes := callPythonBrain(res, opts)
	// Merge results
	for k, v := range pyRes.Technologies {
		res.Technologies[k] = v
	}
	res.RiskScore = pyRes.RiskScore

	// Merge Rust-detected technologies with categorization
	for name, rTech := range rustRes.Technologies {
		if _, exists := res.Technologies[name]; !exists {
			res.Technologies[name] = TechInfo{
				Name:       name,
				Confidence: rTech.Confidence,
				Category:   rTech.Category,
				Version:    rTech.Version,
				Sources:    []string{"rust-core"},
			}
		}
	}

	// Add Redirect Chain & DOM Vars
	// (We can add these to Result struct if needed, but let's at least process them)

	// Add Contact info
	res.ContactInfo = ContactInfo{
		Emails:      rustRes.ContactInfo.Emails,
		Phones:      rustRes.ContactInfo.Phones,
		SocialLinks: rustRes.ContactInfo.SocialLinks,
	}

	// Add JS Recon
	res.JSRecon = JSReconInfo{
		Endpoints:    rustRes.JSRecon.Endpoints,
		APICalls:     rustRes.JSRecon.APICalls,
		HiddenRoutes: rustRes.JSRecon.HiddenRoutes,
		APIKeys:      rustRes.JSRecon.APIKeys,
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

	cGreen := color.New(color.FgGreen).Add(color.Bold)
	cCyan := color.New(color.FgCyan).Add(color.Bold)
	cYellow := color.New(color.FgYellow).Add(color.Bold)
	cRed := color.New(color.FgRed).Add(color.Bold)
	cWhite := color.New(color.FgWhite).Add(color.Bold)
	cBlue := color.New(color.FgBlue).Add(color.Bold)
	cMagenta := color.New(color.FgMagenta).Add(color.Bold)

	fmt.Printf("\n%s Scanning complete. Found %d targets.\n", cGreen.Sprint("[+]"), len(results))

	for _, res := range results {
		fmt.Println(cCyan.Sprint("\n┌──────────────────────────────────────────────────────────┐"))
		fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("TARGET URL"), cGreen.Sprint(res.URL))
		fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("STATUS CODE"), getStatusColor(res.Status).Sprint(fmt.Sprintf("%d", res.Status)))

		if res.Title != "" {
			fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("PAGE TITLE"), cYellow.Sprint(res.Title))
		}

		fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("IP ADDRESS"), cBlue.Sprint(res.IPInfo.IP))
		fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("LOCATION"), cMagenta.Sprint(fmt.Sprintf("%s, %s", res.IPInfo.Country, res.IPInfo.Org)))

		if res.DNSInfo != nil && len(res.DNSInfo.NSRecords) > 0 {
			nsStr := strings.Join(res.DNSInfo.NSRecords, ", ")
			if len(nsStr) > 38 {
				nsStr = nsStr[:35] + "..."
			}
			fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("NAMESERVERS"), cCyan.Sprint(nsStr))
		}

		if res.FaviconHash != "" {
			fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("FAVICON HASH"), cYellow.Sprint(res.FaviconHash))
		}

		if res.Whois != nil && res.Whois.Registrar != "" && res.Whois.Registrar != "Unknown" {
			regStr := res.Whois.Registrar
			if len(regStr) > 38 {
				regStr = regStr[:35] + "..."
			}
			fmt.Printf("│ %-15s : %-38s │\n", cWhite.Sprint("REGISTRAR"), cYellow.Sprint(regStr))
		}

		fmt.Println(cCyan.Sprint("└──────────────────────────────────────────────────────────┘"))

		if len(res.PathDiscoveries) > 0 {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("Sensitive Path Discovery:"))
			for _, p := range res.PathDiscoveries {
				riskColor := cGreen
				if p.Risk == "High" {
					riskColor = cRed
				} else if p.Risk == "Medium" {
					riskColor = cYellow
				}
				fmt.Printf("  %s %-20s [%d] %s\n", riskColor.Sprint("»"), p.Path, p.Status, cWhite.Sprint(p.Title))
			}
		}

		if len(res.JSRecon.Endpoints) > 0 || len(res.JSRecon.APICalls) > 0 || len(res.JSRecon.APIKeys) > 0 {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("JavaScript Recon & API Discovery:"))
			if len(res.JSRecon.Endpoints) > 0 {
				fmt.Printf("  %s Endpoints: %s\n", cGreen.Sprint("»"), cCyan.Sprint(strings.Join(limitList(res.JSRecon.Endpoints, 5), ", ")))
			}
			if len(res.JSRecon.APICalls) > 0 {
				fmt.Printf("  %s API Calls: %s\n", cGreen.Sprint("»"), cYellow.Sprint(strings.Join(limitList(res.JSRecon.APICalls, 5), ", ")))
			}
			if len(res.JSRecon.HiddenRoutes) > 0 {
				fmt.Printf("  %s Routes   : %s\n", cGreen.Sprint("»"), cWhite.Sprint(strings.Join(limitList(res.JSRecon.HiddenRoutes, 5), ", ")))
			}
			if len(res.JSRecon.APIKeys) > 0 {
				fmt.Printf("  %s API Keys : %s\n", cRed.Sprint("»"), cYellow.Sprint(strings.Join(limitList(res.JSRecon.APIKeys, 5), ", ")))
			}
		}

		if len(res.WAFInfo) > 0 {
			fmt.Printf("\n%s %s\n", cRed.Sprint("[!]"), cWhite.Sprint("Security & Infrastructure:"))
			for _, waf := range res.WAFInfo {
				fmt.Printf("  %s %s\n", cRed.Sprint("»"), cYellow.Sprint(waf))
			}
		}

		if res.TLSInfo != nil {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("SSL/TLS Encryption:"))
			fmt.Printf("  %s Version : %s\n", cGreen.Sprint("»"), cYellow.Sprint(res.TLSInfo.Version))
			fmt.Printf("  %s Issuer  : %s\n", cGreen.Sprint("»"), cCyan.Sprint(res.TLSInfo.Issuer))
			fmt.Printf("  %s Expiry  : %s\n", cGreen.Sprint("»"), cRed.Sprint(res.TLSInfo.Expiry))
		}

		if res.DNSInfo != nil {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("DNS Intelligence:"))
			if len(res.DNSInfo.ARecords) > 0 {
				fmt.Printf("  %s A Records   : %s\n", cGreen.Sprint("»"), strings.Join(res.DNSInfo.ARecords, ", "))
			}
			if len(res.DNSInfo.MXRecords) > 0 {
				fmt.Printf("  %s MX Records  : %s\n", cGreen.Sprint("»"), strings.Join(res.DNSInfo.MXRecords, ", "))
			}
			if len(res.DNSInfo.NSRecords) > 0 {
				fmt.Printf("  %s Name Servers: %s\n", cGreen.Sprint("»"), strings.Join(res.DNSInfo.NSRecords, ", "))
			}
		}

		if res.Whois != nil {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("Whois Discovery:"))
			fmt.Printf("  %s Registrar  : %s\n", cGreen.Sprint("»"), cCyan.Sprint(res.Whois.Registrar))
			fmt.Printf("  %s Created    : %s\n", cGreen.Sprint("»"), cWhite.Sprint(res.Whois.CreationDate))
			fmt.Printf("  %s Expiry     : %s\n", cGreen.Sprint("»"), cRed.Sprint(res.Whois.ExpirationDate))
			if len(res.Whois.NameServers) > 0 {
				fmt.Printf("  %s Nameservers: %s\n", cGreen.Sprint("»"), cYellow.Sprint(strings.Join(res.Whois.NameServers, ", ")))
			}
		}

		if len(res.OpenPorts) > 0 {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("Exposed Services (Fast-Scan):"))
			for _, p := range res.OpenPorts {
				fmt.Printf("  %s %-5d %s\n", cGreen.Sprint("»"), p.Port, cCyan.Sprint(strings.ToUpper(p.Service)))
			}
		}

		if len(res.ContactInfo.Emails) > 0 || len(res.ContactInfo.Phones) > 0 || len(res.ContactInfo.SocialLinks) > 0 {
			fmt.Printf("\n%s %s\n", cMagenta.Sprint("[*]"), cWhite.Sprint("Contact & OSINT Intelligence:"))
			if len(res.ContactInfo.Emails) > 0 {
				fmt.Printf("  %s Emails     : %s\n", cGreen.Sprint("»"), cCyan.Sprint(strings.Join(res.ContactInfo.Emails, ", ")))
			}
			if len(res.ContactInfo.Phones) > 0 {
				fmt.Printf("  %s Phones     : %s\n", cGreen.Sprint("»"), cWhite.Sprint(strings.Join(res.ContactInfo.Phones, ", ")))
			}
			if len(res.ContactInfo.SocialLinks) > 0 {
				fmt.Printf("  %s Social     : %s\n", cGreen.Sprint("»"), cBlue.Sprint(strings.Join(res.ContactInfo.SocialLinks, ", ")))
			}
		}

		if len(res.Vulnerabilities) > 0 {
			fmt.Printf("\n%s %s\n", cRed.Sprint("[!]"), cWhite.Sprint("Potential Vulnerabilities Found:"))
			for _, v := range res.Vulnerabilities {
				fmt.Printf("  %s %s - %s\n", cRed.Sprint("»"), getSeverityColor(v.Severity).Sprint(v.ID), v.Description)
			}
		}

		if res.HeaderSecurity != nil {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("Header Security Analysis:"))
			fmt.Printf("  %s HSTS: %v, CSP: %v, NoSniff: %v\n", cGreen.Sprint("»"), res.HeaderSecurity.HSTS, res.HeaderSecurity.CSP, res.HeaderSecurity.XContentTypeOptions)
			if res.HeaderSecurity.XFrameOptions != "" {
				fmt.Printf("  %s X-Frame: %s\n", cGreen.Sprint("»"), cYellow.Sprint(res.HeaderSecurity.XFrameOptions))
			}
		}

		// --- MOVED TECHNOLOGY FINGERPRINTING HERE ---
		// Group technologies by category
		catMap := make(map[string][]TechInfo)
		for _, info := range res.Technologies {
			cat := info.Category
			if cat == "" {
				cat = "Others"
			}
			catMap[cat] = append(catMap[cat], info)
		}

		// Custom sort order for categories
		order := []string{"Web Server", "CMS", "Backend Framework", "Frontend Framework", "JS Library", "Programming Language", "Database", "CDN/WAF", "Analytics", "Monitoring", "Others"}

		if len(catMap) > 0 {
			fmt.Printf("\n%s %s\n", cBlue.Sprint("[*]"), cWhite.Sprint("Web Framework & Server Info:"))

			for _, cat := range order {
				if techs, ok := catMap[cat]; ok {
					// Specific header for CMS
					if cat == "CMS" {
						fmt.Printf("\n  %s %s\n", cMagenta.Sprint("::"), cWhite.Sprint("CMS Discovery"))
					} else {
						fmt.Printf("\n  %s %s\n", cMagenta.Sprint("::"), cWhite.Sprint(cat))
					}

					for _, t := range techs {
						version := ""
						if t.Version != "" {
							version = fmt.Sprintf(" %s", cCyan.Sprint(t.Version))
						}

						confColor := cGreen
						if t.Confidence < 70 {
							confColor = cYellow
						} else if t.Confidence < 40 {
							confColor = cRed
						}

						fmt.Printf("    %s %-18s %s %s\n",
							cGreen.Sprint("»"),
							cWhite.Sprint(t.Name),
							version,
							confColor.Sprint(fmt.Sprintf("[%d%% Confidence]", t.Confidence)))
					}
				}
			}
		}
		// --- END MOVED SECTION ---

		// Infrastructure Details
		fmt.Printf("\n%s %s\n", cMagenta.Sprint("[*]"), cWhite.Sprint("Infrastructure Details:"))
		if res.ServerDetails.ServerName != "" {
			fmt.Printf("  %s Server    : %s\n", cGreen.Sprint("»"), cWhite.Sprint(res.ServerDetails.ServerName))
		}
		if res.ServerDetails.HostingProvider != "" {
			fmt.Printf("  %s Hosting   : %s\n", cGreen.Sprint("»"), cGreen.Sprint(res.ServerDetails.HostingProvider))
		}
		if res.ServerDetails.OSInfo != "" {
			fmt.Printf("  %s OS        : %s\n", cGreen.Sprint("»"), cCyan.Sprint(res.ServerDetails.OSInfo))
		}

		if res.DBDetails != nil {
			fmt.Printf("\n%s %s\n", cRed.Sprint("[!]"), cWhite.Sprint("Database Detection:"))
			fmt.Printf("  %s Type      : %s (%d%% Confidence)\n", cGreen.Sprint("»"), cWhite.Sprint(res.DBDetails.DBType), res.DBDetails.Confidence)
		}

		// Summary Section
		fmt.Printf("\n%s %s\n", cCyan.Sprint("[*]"), cWhite.Sprint("Target Intelligence Summary (Hybrid Engine Analysis):"))
		fmt.Printf("  %s Technologies Detected: %d items across %d categories\n", cGreen.Sprint("»"), len(res.Technologies), len(catMap))
		fmt.Printf("  %s Infrastructure: %s (%s)\n", cGreen.Sprint("»"), res.ServerDetails.ServerName, res.IPInfo.ISP)
		fmt.Printf("  %s OSINT Discovery: %d emails, %d phones, %d social links\n", cGreen.Sprint("»"), len(res.ContactInfo.Emails), len(res.ContactInfo.Phones), len(res.ContactInfo.SocialLinks))
		fmt.Printf("  %s Attack Surface: %d endpoints, %d hidden routes, %d sensitive paths\n", cGreen.Sprint("»"), len(res.JSRecon.Endpoints), len(res.JSRecon.HiddenRoutes), len(res.PathDiscoveries))

		riskLevel := cGreen.Sprint("Low")
		if res.RiskScore >= 7.0 {
			riskLevel = cRed.Sprint("Critical")
		} else if res.RiskScore >= 4.0 {
			riskLevel = cYellow.Sprint("Medium")
		}
		fmt.Printf("  %s Overall Risk: %s (Score: %.1f/10.0)\n", cGreen.Sprint("»"), riskLevel, res.RiskScore)

		fmt.Println(cCyan.Sprint("\n" + strings.Repeat("─", 60)))
	}
}

func getStatusColor(status int) *color.Color {
	switch {
	case status >= 200 && status < 300:
		return color.New(color.FgGreen).Add(color.Bold)
	case status >= 300 && status < 400:
		return color.New(color.FgYellow).Add(color.Bold)
	case status == 403 || status == 401:
		return color.New(color.FgMagenta).Add(color.Bold)
	case status == 404:
		return color.New(color.FgRed).Add(color.Bold)
	default:
		return color.New(color.FgBlue).Add(color.Bold)
	}
}

func getSeverityColor(sev string) *color.Color {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return color.New(color.FgRed).Add(color.Bold)
	case "MEDIUM":
		return color.New(color.FgYellow).Add(color.Bold)
	case "LOW":
		return color.New(color.FgBlue).Add(color.Bold)
	default:
		return color.New(color.FgWhite).Add(color.Bold)
	}
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

func limitList(list []string, max int) []string {
	if len(list) <= max {
		return list
	}
	res := make([]string, max)
	copy(res, list[:max])
	res = append(res, "...")
	return res
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
