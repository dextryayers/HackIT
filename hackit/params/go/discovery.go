package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ArchiveSource struct {
	Name   string
	URL    string
	Parser func(body string, domain string) []string
}

var archiveSources = []ArchiveSource{
	{
		Name: "wayback",
		URL:  "https://web.archive.org/cdx/search/cdx?url=%s/*&output=txt&collapse=urlkey&fl=original&limit=10000",
		Parser: func(body, domain string) []string {
			return strings.Split(strings.TrimSpace(body), "\n")
		},
	},
	{
		Name: "otx",
		URL:  "https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500&page=1",
		Parser: func(body, domain string) []string {
			var result struct {
				URLList []struct {
					URL string `json:"url"`
				} `json:"url_list"`
			}
			if err := jsonUnmarshal([]byte(body), &result); err != nil {
				return nil
			}
			var urls []string
			for _, u := range result.URLList {
				urls = append(urls, u.URL)
			}
			return urls
		},
	},
	{
		Name: "urlscan",
		URL:  "https://urlscan.io/api/v1/search/?q=domain:%s&size=100",
		Parser: func(body, domain string) []string {
			var result struct {
				Results []struct {
					Page struct {
						URL string `json:"url"`
					} `json:"page"`
				} `json:"results"`
			}
			if err := jsonUnmarshal([]byte(body), &result); err != nil {
				return nil
			}
			var urls []string
			for _, r := range result.Results {
				urls = append(urls, r.Page.URL)
			}
			return urls
		},
	},
	{
		Name: "commoncrawl",
		URL:  "https://index.commoncrawl.org/CC-MAIN-2025-18-index?url=*.%s&output=json&fl=url&limit=5000",
		Parser: func(body, domain string) []string {
			var urls []string
			for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
				var result struct {
					URL string `json:"url"`
				}
				if err := jsonUnmarshal([]byte(line), &result); err != nil {
					continue
				}
				if result.URL != "" {
					urls = append(urls, result.URL)
				}
			}
			return urls
		},
	},
}

var boringParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true,
	"utm_term": true, "utm_content": true, "fbclid": true,
	"gclid": true, "gclsrc": true, "dclid": true, "msclkid": true,
	"twclid": true, "igshid": true, "mc_cid": true, "mc_eid": true,
	"_ga": true, "_gl": true, "mtm_source": true, "mtm_medium": true,
	"mtm_campaign": true, "mtm_keyword": true, "mtm_content": true,
	"pk_source": true, "pk_medium": true, "pk_campaign": true,
	"pk_keyword": true, "pk_content": true, "yclid": true,
	"_openstat": true, "from": true, "ref": true, "referrer": true,
	"source": true, "si": true,
}

var sensitiveParams = map[string]bool{
	"token": true, "access_token": true, "api_key": true, "apikey": true,
	"secret": true, "password": true, "passwd": true, "pass": true,
	"auth": true, "authorization": true, "bearer": true, "jwt": true,
	"session": true, "sessionid": true, "sid": true, "csrf": true,
	"csrf_token": true, "xsrf": true, "xsrf_token": true,
	"private_key": true, "key": true, "auth_token": true,
	"refresh_token": true, "id_token": true, "client_secret": true,
}

func discoverFromArchive(domain string, sources []string, placeholder string) ([]DiscoResult, []string) {
	var allURLs []string
	var allResults []DiscoResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sema := make(chan struct{}, 3)

	uniqueParams := make(map[string]bool)

	for _, src := range archiveSources {
		if !sourceEnabled(sources, src.Name) {
			continue
		}
		wg.Add(1)
		sema <- struct{}{}
		go func(s ArchiveSource) {
			defer wg.Done()
			defer func() { <-sema }()
			urls := fetchArchiveURLs(s, domain)
			if len(urls) == 0 {
				return
			}
			mu.Lock()
			allURLs = append(allURLs, urls...)
			mu.Unlock()
		}(src)
	}
	wg.Wait()

	// Dedup and filter URLs
	seen := make(map[string]bool)
	for _, rawURL := range allURLs {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" || seen[rawURL] {
			continue
		}
		seen[rawURL] = true

		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		// Filter by domain
		if !strings.Contains(parsed.Host, domain) && !strings.Contains(domain, parsed.Host) {
			continue
		}

		// Filter static extensions
		if hasBoringExtension(parsed.Path) {
			continue
		}

		params := parsed.Query()
		if len(params) == 0 {
			continue
		}

		// Clean boring params and build result
		cleanParams := make(map[string]string)
		var paramNames []string
		for k, vals := range params {
			if boringParams[strings.ToLower(k)] {
				continue
			}
			v := ""
			if len(vals) > 0 {
				v = vals[0]
			}
			cleanParams[k] = v
			paramNames = append(paramNames, k)
			uniqueParams[k] = true
		}

		if len(cleanParams) == 0 {
			continue
		}

		ext := ""
		if idx := strings.LastIndex(parsed.Path, "."); idx >= 0 {
			ext = parsed.Path[idx:]
		}

		allResults = append(allResults, DiscoResult{
			URL:        rawURL,
			Domain:     parsed.Host,
			Source:     "archive",
			Params:     cleanParams,
			ParamNames: paramNames,
			ParamCount: len(cleanParams),
			Path:       parsed.Path,
			FileExt:    ext,
		})
	}

	return allResults, sortedKeys(uniqueParams)
}

func fetchArchiveURLs(source ArchiveSource, domain string) []string {
	apiURL := fmt.Sprintf(source.URL, domain)
	debugLog("Fetching %s from %s: %s", source.Name, domain, apiURL)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/plain,application/json,*/*")

	resp, err := client.Do(req)
	if err != nil {
		debugLog("Error fetching %s: %v", source.Name, err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	urls := source.Parser(string(body), domain)
	debugLog("Fetched %d URLs from %s", len(urls), source.Name)
	return urls
}

func hasBoringExtension(path string) bool {
	exts := []string{
		".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg",
		".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf",
		".otf", ".mp4", ".ico", ".zip", ".tar",
		".gz", ".bz2", ".mp3", ".avi", ".mov", ".webm", ".avi",
	}
	path = strings.ToLower(path)
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func isSensitiveParam(name string) bool {
	return sensitiveParams[strings.ToLower(name)]
}

func sourceEnabled(sources []string, name string) bool {
	if len(sources) == 0 {
		return true // all enabled by default
	}
	for _, s := range sources {
		if s == name {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	// Simple sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
