// cdxfan — concurrent wayback CDX fan-out for per-subdomain parameter mining.
// Reads host names (one per line, from -list or stdin), fetches the CDX API
// for each host in parallel, and prints normalized, signature-deduplicated
// parameter-bearing URLs (one per line, JSON-safe text).
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

var keyRe = strings.NewReplacer(".", "", "-", "", ":", "", "[", "", "]", "")

type collector struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	count int
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

func fetchHost(client *http.Client, host string, from, to int, limit int) []string {
	u := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=%d&from=%d&to=%d",
		url.QueryEscape(host)+"/*", limit, from, to)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	var rows []json.RawMessage
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		var arr []string
		if err := json.Unmarshal(row, &arr); err != nil {
			continue
		}
		var raw string
		switch len(arr) {
		case 1:
			raw = arr[0]
		default:
			if len(arr) >= 1 {
				raw = arr[0]
			}
		}
		if validParamURL(raw) {
			out = append(out, raw)
		}
	}
	return out
}

func main() {
	var listFile string
	var from, to, limit int
	from, to, limit = 2021, 2026, 1000
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
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	client := &http.Client{Timeout: 90 * time.Second, Transport: tr}

	col := &collector{seen: map[string]struct{}{}}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, u := range fetchHost(client, host, from, to, limit) {
				p, err := url.Parse(u)
				if err != nil {
					continue
				}
				s := sig(p)
				col.mu.Lock()
				_, exists := col.seen[s]
				if !exists {
					col.seen[s] = struct{}{}
					fmt.Println(u)
				}
				col.mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
}
