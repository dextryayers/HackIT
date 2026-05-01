package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	rustLib              *syscall.LazyDLL
	rustCheckSubTakeover *syscall.LazyProc
	rustResolveDNS       *syscall.LazyProc
	rustResolveDNSBatch  *syscall.LazyProc
	rustOSINTScan        *syscall.LazyProc
	rustGetTitle         *syscall.LazyProc
)

func init() {
	// Initialize Rust FFI for Windows
	if runtime.GOOS == "windows" {
		rustLib = syscall.NewLazyDLL("rust_engine/target/release/subdomain_rust_engine.dll")
		rustCheckSubTakeover = rustLib.NewProc("rust_check_subdomain_takeover")
		rustResolveDNS = rustLib.NewProc("rust_resolve_dns")
		rustResolveDNSBatch = rustLib.NewProc("rust_resolve_dns_batch")
		rustOSINTScan = rustLib.NewProc("rust_osint_scan")
		rustGetTitle = rustLib.NewProc("rust_get_title")
	}
}

// Signature represents a takeover fingerprint
type Signature struct {
	Service string
	CNAME   []string
	Content string
}

var signatures = []Signature{
	{Service: "GitHub Pages", CNAME: []string{"github.io"}, Content: "There isn't a GitHub Pages site here."},
	{Service: "Heroku", CNAME: []string{"herokuapp.com"}, Content: "Heroku | Welcome to your new app!"},
	{Service: "Heroku", CNAME: []string{"herokuapp.com"}, Content: "no-such-app.html"},
	{Service: "Shopify", CNAME: []string{"myshopify.com"}, Content: "Sorry, this shop is currently unavailable."},
	{Service: "Tumblr", CNAME: []string{"tumblr.com"}, Content: "There's nothing here."},
	{Service: "WordPress.com", CNAME: []string{"wordpress.com"}, Content: "Do you want to register"},
	{Service: "AWS S3", CNAME: []string{"amazonaws.com"}, Content: "The specified bucket does not exist"},
	{Service: "Bitbucket", CNAME: []string{"bitbucket.io"}, Content: "Repository not found"},
	{Service: "Zendesk", CNAME: []string{"zendesk.com"}, Content: "Help Center Closed"},
	{Service: "Surge.sh", CNAME: []string{"surge.sh"}, Content: "project not found"},
	{Service: "Ghost", CNAME: []string{"ghost.io"}, Content: "The thing you were looking for is no longer here"},
	{Service: "Cargo", CNAME: []string{"cargo.site"}, Content: "If you're the owner of this site"},
	{Service: "Feedpress", CNAME: []string{"redirect.feedpress.me"}, Content: "The feed you're looking for doesn't exist"},
	{Service: "Help Juice", CNAME: []string{"helpjuice.com"}, Content: "We could not find what you're looking for"},
	{Service: "Help Scout", CNAME: []string{"helpscoutdocs.com"}, Content: "No settings found"},
	{Service: "Intercom", CNAME: []string{"intercom.help"}, Content: "This page is reserved for a customer"},
	{Service: "JetBrains", CNAME: []string{"youtrack.cloud"}, Content: "is not a registered InCloud"},
	{Service: "LaunchRock", CNAME: []string{"launchrock.com"}, Content: "It looks like you may have taken a wrong turn"},
	{Service: "Netlify", CNAME: []string{"netlify.app", "netlify.com"}, Content: "Not Found"},
	{Service: "Pantheon", CNAME: []string{"pantheonsite.io"}, Content: "The site you were looking for couldn't be found"},
	{Service: "Read the Docs", CNAME: []string{"readthedocs.io"}, Content: "is unknown to Read the Docs"},
	{Service: "Statuspage", CNAME: []string{"statuspage.io"}, Content: "Better status pages for your users"},
	{Service: "Strikingly", CNAME: []string{"strikingly.com"}, Content: "But if you are the owner"},
	{Service: "Tictail", CNAME: []string{"tictail.com"}, Content: "to see this store"},
	{Service: "Unbounce", CNAME: []string{"unbouncepages.com"}, Content: "The requested URL was not found on this server"},
	{Service: "UserVoice", CNAME: []string{"uservoice.com"}, Content: "This UserVoice subdomain is currently available"},
	{Service: "Wix", CNAME: []string{"wixdns.net"}, Content: "The domain is not connected to a website"},
}

func checkTakeovers(results []*Result, concurrency int) {
	fmt.Println("[*] Checking for Subdomain Takeover vulnerabilities...")

	sem := make(chan bool, concurrency)
	var wg sync.WaitGroup

	for _, r := range results {
		wg.Add(1)
		sem <- true
		go func(res *Result) {
			defer wg.Done()
			defer func() { <-sem }()

			// 1. Rust-powered Takeover Check (Expert & Fast)
			if rustCheckSubTakeover != nil && rustCheckSubTakeover.Find() == nil {
				cDomain := []byte(res.Subdomain + "\x00")
				ptr, _, _ := rustCheckSubTakeover.Call(uintptr(unsafe.Pointer(&cDomain[0])))
				if ptr != 0 {
					rustResult := strings.TrimSpace(os.ExpandEnv(string(CStrToGo(ptr))))
					if strings.HasPrefix(rustResult, "VULNERABLE:") {
						vulnInfo := strings.TrimPrefix(rustResult, "VULNERABLE:")
						res.TakeoverVuln = vulnInfo
						fmt.Printf("[!] POTENTIAL TAKEOVER (RUST): %s [%s]\n", res.Subdomain, vulnInfo)
						return
					}
				}
			}

			// 2. Fallback to Go implementation
			// 1. Check CNAME
			cnames, err := net.LookupCNAME(res.Subdomain)
			if err != nil {
				return
			}

			// Clean CNAME (remove trailing dot)
			cnames = strings.TrimSuffix(cnames, ".")

			for _, sig := range signatures {
				matchedCNAME := false
				for _, c := range sig.CNAME {
					if strings.Contains(strings.ToLower(cnames), strings.ToLower(c)) {
						matchedCNAME = true
						break
					}
				}

				if matchedCNAME {
					// Potentially vulnerable, check content
					if checkContent(res.Subdomain, sig.Content) {
						res.TakeoverVuln = sig.Service
						fmt.Printf("%s[!] POTENTIAL TAKEOVER: %s [%s] (CNAME: %s)%s\n", "\033[31m", res.Subdomain, sig.Service, cnames, "\033[0m")
						return
					}
				}
			}
		}(r)
	}
	wg.Wait()
}

func checkContent(domain string, signature string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + domain)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return strings.Contains(string(body), signature)
}
