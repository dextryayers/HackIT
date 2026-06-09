package native

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type TakeoverResult struct {
	Subdomain string
	Vulnerable bool
	Platform  string
}

// Fingerprints for common subdomain takeover platforms
var takeoverSignatures = map[string]string{
	"AWS S3":         "The specified bucket does not exist",
	"GitHub Pages":   "There isn't a GitHub Pages site here",
	"Heroku":         "No such app",
	"Pantheon":       "The lack of a trailing slash",
	"Tumblr":         "Whatever you were looking for doesn't currently exist at this address",
	"WordPress":      "Do you want to register",
	"Shopify":        "Sorry, this shop is currently unavailable",
	"Ghost":          "The thing you were looking for is no longer here",
}

// CheckSubdomainTakeover concurrently checks a list of subdomains for takeover vulnerabilities
func CheckSubdomainTakeover(subdomains []string, concurrency int) []TakeoverResult {
	subsChan := make(chan string, len(subdomains))
	resultsChan := make(chan TakeoverResult, len(subdomains))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go takeoverWorker(subsChan, resultsChan, &wg)
	}

	for _, sub := range subdomains {
		subsChan <- sub
	}
	close(subsChan)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []TakeoverResult
	for res := range resultsChan {
		if res.Vulnerable {
			results = append(results, res)
		}
	}

	return results
}

func takeoverWorker(subs <-chan string, results chan<- TakeoverResult, wg *sync.WaitGroup) {
	defer wg.Done()
	
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	for sub := range subs {
		// Only check subdomains that have CNAME records pointing elsewhere
		cname, err := net.LookupCNAME(sub)
		if err != nil || cname == "" || cname == sub+"." {
			continue // No CNAME, likely not a dangling record takeover
		}

		// Try HTTP and HTTPS
		vulnerable, platform := checkHTTP(client, "http://"+sub)
		if !vulnerable {
			vulnerable, platform = checkHTTP(client, "https://"+sub)
		}

		if vulnerable {
			results <- TakeoverResult{
				Subdomain:  sub,
				Vulnerable: true,
				Platform:   platform,
			}
		}
	}
}

func checkHTTP(client *http.Client, url string) (bool, string) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 200 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		bodyStr := string(bodyBytes)
		
		for platform, sig := range takeoverSignatures {
			if strings.Contains(bodyStr, sig) {
				return true, platform
			}
		}
	}
	
	return false, ""
}
