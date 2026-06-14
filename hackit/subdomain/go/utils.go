package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"unsafe"
)

var defaultTransport = &http.Transport{
	MaxIdleConns:        200,
	MaxIdleConnsPerHost: 20,
	IdleConnTimeout:     30 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
}

var defaultClient = &http.Client{
	Transport: defaultTransport,
}

// cleanSubdomain cleans and validates a subdomain
func cleanSubdomain(sub, rootDomain string) string {
	sub = strings.ToLower(strings.TrimSpace(sub))
	sub = strings.TrimSuffix(sub, ".")
	sub = strings.TrimPrefix(sub, "*.")
	sub = strings.TrimPrefix(sub, ".")

	// Remove protocol if present (some sources return full URLs)
	if idx := strings.Index(sub, "://"); idx != -1 {
		sub = sub[idx+3:]
	}
	// Remove path
	if idx := strings.Index(sub, "/"); idx != -1 {
		sub = sub[:idx]
	}
	// Remove port
	if idx := strings.Index(sub, ":"); idx != -1 {
		sub = sub[:idx]
	}

	if strings.HasSuffix(sub, "."+rootDomain) || sub == rootDomain {
		return sub
	}
	return ""
}

// unique deduplicates a string slice
func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// getRandomUserAgent returns a random User-Agent string
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/119.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
		"Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/118.0",
		"Mozilla/5.0 (Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
	}
	// Note: rand.Seed is deprecated in newer Go, but for simple needs it's fine
	// or just use crypto/rand if absolute randomness is needed.
	return userAgents[rand.Intn(len(userAgents))]
}

// safeGet performs an HTTP GET with better reliability headers
func safeGet(url string, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{
		Timeout:   timeout,
		Transport: defaultTransport,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close") // Avoid keeping too many idle conns

	return client.Do(req)
}

// CommonSubdomains is a built-in wordlist of ~350 common subdomain prefixes
var CommonSubdomains = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
	"smtp", "secure", "vpn", "admin", "mx", "api", "dev", "ftp", "test",
	"www2", "mail2", "static", "app", "m", "img", "cdn", "video", "wiki",
	"forum", "news", "shop", "store", "portal", "help", "support", "chat",
	"docs", "status", "analytics", "tracker", "data", "backup", "db",
	"mysql", "sql", "redis", "git", "svn", "jenkins", "jira", "confluence",
	"docker", "k8s", "kube", "swarm", "prod", "staging", "stage", "qa",
	"demo", "beta", "alpha", "preprod", "sandbox", "edge", "origin",
	"ns", "ns3", "ns4", "dns", "dns1", "dns2", "mx1", "mx2", "mx3",
	"pop3", "imap", "imap4", "mail1", "mail3", "email",
	"owa", "exchange", "outlook", "autodiscover", "msoid",
	"lync", "lyncdiscover", "sip", "teams", "skype",
	"mg", "eu", "us", "uk", "de", "jp", "cn", "br", "au", "in", "ca",
	"en", "fr", "es", "it", "nl", "ru", "pl", "se", "no", "fi", "dk",
	"sg", "hk", "kr", "tw", "th", "my", "id", "ph", "vn",
	"web", "web1", "web2", "web3", "web4", "web5",
	"lb", "lb1", "lb2", "loadbalancer", "balancer",
	"proxy", "proxy1", "proxy2", "gateway", "edge", "waf",
	"firewall", "fw", "fw1", "ips", "ids", "splunk", "elk", "elastic",
	"kibana", "logstash", "grafana", "prometheus", "alertmanager",
	"monitor", "monitoring", "nagios", "zabbix", "cacti", "munin",
	"puppet", "chef", "ansible", "salt", "terraform",
	"ldap", "ldaps", "radius", "sso", "oauth", "auth", "login",
	"signin", "signup", "register", "account", "accounts",
	"billing", "pay", "payment", "checkout", "cart", "shop",
	"crm", "erp", "hr", "intranet", "extranet", "partner",
	"wholesale", "retail", "dealer", "distributor",
	"mta", "mda", "mua", "spam", "antispam", "barracuda",
	"mx", "relay", "send", "mailout", "mailer", "bounce",
	"newsletter", "marketing", "campaign", "mailchimp",
	"survey", "forms", "feedback", "bug", "bugs", "issues",
	"roadmap", "changelog", "releases", "download", "downloads",
	"software", "sdk", "api", "developer", "developers", "devs",
	"code", "source", "repo", "repository", "bitbucket", "gitlab",
	"ci", "cd", "build", "builder", "artifact", "artifacts",
	"maven", "nexus", "npm", "pypi", "dockerhub", "registry",
	"cloud", "cloud1", "cloud2", "console", "dashboard", "control",
	"panel", "cpanel", "whm", "plesk", "directadmin",
	"host", "hosting", "server", "dedicated", "vps",
	"node", "node1", "node2", "node3", "cluster", "cluster1",
	"dc", "dc1", "dc2", "rack", "rack1", "rack2",
	"sw", "switch", "router", "core", "border",
	"san", "nas", "storage", "backup", "tape", "archive",
	"phone", "voip", "pbx", "asterisk", "freeswitch",
	"printer", "print", "scan", "scanner", "fax",
	"camera", "cam", "cam1", "cam2", "webcam", "cctv",
	"atm", "pos", "terminal", "kiosk",
	"sensor", "iot", "device", "devices", "gateway",
	"office", "floor1", "floor2", "floor3", "basement",
	"lab", "labs", "research", "rd", "innovation",
	"temp", "tmp", "test1", "test2", "tests", "testing",
	"example", "sample", "demo", "demo1", "demo2",
	"training", "learn", "education", "e-learning", "elearning",
	"student", "teacher", "faculty", "staff", "alumni",
	"library", "lib", "books", "catalog", "catalogue",
	"event", "events", "calendar", "schedule",
	"ticket", "tickets", "booking", "reservation",
	"media", "gallery", "photo", "photos", "image", "images",
	"assets", "upload", "uploads", "download", "downloads",
	"content", "contents", "feed", "feeds", "rss", "atom",
	"xmlrpc", "soap", "rest", "graphql", "websocket", "wss",
	"service", "services", "microservice", "ms", "svc",
	"health", "healthcheck", "ping", "heartbeat",
	"metrics", "stats", "statistics", "reports", "reporting",
	"audit", "audits", "compliance",
	"license", "licensing", "activation",
	"partner", "partners", "vendor", "vendors",
	"affiliate", "affiliates", "referral", "referrals",
	"ad", "ads", "advertising", "adserver", "advert",
	"jobs", "career", "careers", "recruit", "recruiting",
	"about", "contact", "info", "faq", "help", "manual",
	"terms", "privacy", "legal", "gdpr", "security",
	"status", "uptime", "incident", "incidents",
	"brand", "branding", "press", "newsroom",
	"investor", "investors", "ir", "financial",
	"corp", "corporate", "company", "about-us",
	"community", "forum", "discuss", "discourse",
	"blog", "blogs", "wordpress", "wp", "wp-admin",
	"cms", "drupal", "joomla", "magento", "shopify",
	"squarespace", "wix", "weebly", "ghost",
	"static", "static1", "static2", "static3",
	"assets", "assets1", "assets2",
	"upload", "uploads", "files", "file", "data",
	"media", "media1", "media2",
	"img", "img1", "img2", "image", "images",
	"css", "js", "scripts", "styles", "fonts",
	"theme", "themes", "template", "templates",
	"plugin", "plugins", "extension", "extensions",
	"widget", "widgets", "module", "modules",
	"mobile", "mobi", "iphone", "ipad", "android",
	"ios", "windows", "mac", "linux",
}

func loadBuiltinWordlist(domain string, jobs chan<- string) int {
	count := 0
	for _, word := range CommonSubdomains {
		sub := fmt.Sprintf("%s.%s", word, domain)
		jobs <- sub
		count++
	}
	return count
}

// CStrToGo converts a C-style string pointer (from Rust FFI) to a Go string
func CStrToGo(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}

	// Assuming UTF-8/ASCII for C strings
	var length int
	for {
		if *(*byte)(unsafe.Pointer(ptr + uintptr(length))) == 0 {
			break
		}
		length++
	}

	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
	}
	return string(b)
}
