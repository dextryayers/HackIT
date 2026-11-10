// cdxfan — concurrent wayback CDX fan-out for per-subdomain parameter mining.
// Server-side filter keeps only parameter-bearing URLs (like ParamSpider does),
// so archive traffic is small and fast. Reads host names (one per line,
// from -list or stdin), queries each host in parallel, and prints normalized,
// signature-deduplicated parameter-bearing URLs (one per line).
// Emits a JSON stats line on stderr: per-host outcome + totals.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var extBlacklist = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".webp": true, ".ico": true, ".bmp": true, ".css": true, ".js": true,
	".mjs": true, ".jsx": true, ".map": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".otf": true, ".mp4": true, ".mp3": true,
	".avi": true, ".mov": true, ".mkv": true, ".webm": true, ".wav": true,
	".zip": true, ".gz": true, ".rar": true, ".7z": true, ".tar": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".apk": true, ".iso": true, ".bin": true,
}

type result struct {
	Host   string `json:"host"`
	Count  int    `json:"count"`
	Status string `json:"status"` // "ok", "empty", "http_<code>", "error"
}

type stats struct {
	mu      sync.Mutex
	results []result
	printed int
}

func (s *stats) record(host string, count int, status string) {
	s.mu.Lock()
	s.results = append(s.results, result{host, count, status})
	s.mu.Unlock()
}

func sig(u *url.URL) string {
	path := u.Path
	query := u.Query()
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(u.Hostname()), path, strings.Join(keys, ","),
	}, "|")))
	return fmt.Sprintf("%x", h[:16])
}

func validParamURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || !strings.Contains(host, ".") {
		return false
	}
	path := strings.ToLower(u.Path)
	ext := ""
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		ext = path[idx:]
	}
	if extBlacklist[ext] {
		return false
	}
	q := u.Query()
	if len(q) == 0 {
		return false
	}
	for k := range q {
		if k == "" || len(k) > 128 {
			return false
		}
		for _, r := range k {
			switch {
			case r >= 'A' && r <= 'Z':
			case r >= 'a' && r <= 'z':
			case r >= '0' && r <= '9':
			case r == '_' || r == '-' || r == '.' || r == '[' || r == ']' || r == ':':
			default:
				return false
			}
		}
	}
	return true
}

func fetchHost(client *http.Client, host string, from, to int, limit int, domainSweep bool) ([]string, string) {
	// Server-side filter: only rows whose original URL contains a query string.
	filter := "original:.*\\?.*"
	var u string
	if domainSweep {
		// One sweep over the entire domain tree (all subdomains) via matchType=domain.
		u = fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s&matchType=domain&output=json&fl=original&collapse=urlkey&limit=%d&from=%d&to=%d&filter=%s",
			url.QueryEscape(host), limit, from, to, url.QueryEscape(filter))
	} else {
		u = fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s&output=json&fl=original&collapse=urlkey&limit=%d&from=%d&to=%d&filter=%s",
			url.QueryEscape(host+"/*"), limit, from, to, url.QueryEscape(filter))
	}
	var lastStatus string = "error"
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, "error"
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			lastStatus = "error"
			time.Sleep(time.Duration(2+attempt*3) * time.Second)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		code := resp.StatusCode
		resp.Body.Close()
		if code == 429 || code == 503 || code == 502 || code == 504 || code == 500 {
			lastStatus = fmt.Sprintf("http_%d", code)
			time.Sleep(time.Duration(2+attempt*2) * time.Second)
			continue
		}
		if code != 200 {
			return nil, fmt.Sprintf("http_%d", code)
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(body, &rows); err != nil {
			// Could be an XML/HTML error page instead of JSON — treat as empty/retry.
			lastStatus = "badjson"
			time.Sleep(2 * time.Second)
			continue
		}
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			var arr []string
			if err := json.Unmarshal(row, &arr); err != nil {
				continue
			}
			if len(arr) >= 1 {
				if validParamURL(arr[0]) {
					out = append(out, arr[0])
				}
			}
		}
		if len(out) == 0 {
			return out, "empty"
		}
		return out, "ok"
	}
	return nil, lastStatus
}

func main() {
	var listFile string
	var from, to, limit int
	var domainSweep bool
	from, to, limit = 2018, 2026, 250
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-list":
			i++
			listFile = os.Args[i]
		case "-from":
			i++
			fmt.Sscanf(os.Args[i], "%d", &from)
		case "-to":
			i++
			fmt.Sscanf(os.Args[i], "%d", &to)
		case "-limit":
			i++
			fmt.Sscanf(os.Args[i], "%d", &limit)
		case "-domain":
			domainSweep = true
		}
	}
	var input io.Reader = os.Stdin
	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "list:", err)
			os.Exit(2)
		}
		defer f.Close()
		input = f
	}
	hosts := []string{}
	sc := bufio.NewScanner(input)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		h := strings.TrimSpace(strings.ToLower(sc.Text()))
		h = strings.TrimPrefix(h, "*.")
		h = strings.TrimPrefix(h, ".")
		if idx := strings.IndexAny(h, "/:?#"); idx >= 0 {
			h = h[:idx]
		}
		if h != "" && strings.Contains(h, ".") {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)

	tr := &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     45 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   false,
	}
	client := &http.Client{Timeout: 35 * time.Second, Transport: tr}

	seen := map[string]struct{}{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	st := &stats{}
	total := 0
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			urls, status := fetchHost(client, host, from, to, limit, domainSweep)
			st.record(host, len(urls), status)
			mu.Lock()
			for _, u := range urls {
				p, err := url.Parse(u)
				if err != nil {
					continue
				}
				s := sig(p)
				if _, exists := seen[s]; !exists {
					seen[s] = struct{}{}
					fmt.Println(u)
					total++
				}
			}
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	// Emit machine-readable stats on stderr.
	sj, _ := json.Marshal(map[string]interface{}{
		"hosts": len(hosts), "unique_urls": total, "per_host": st.results,
	})
	fmt.Fprintf(os.Stderr, "CDXFAN_STATS:%s\n", sj)
}
