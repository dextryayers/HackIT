// prober — hidden parameter discovery for a target URL.
// Fetches a baseline response, then probes each word in a wordlist with a
// unique marker value and reports which parameters changed the response.
// Passive-baseline, active-probe. No fuzzing payloads — discovery only.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"crypto/tls"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var errorPattern = regexp.MustCompile(`(?i)(you have an error in your sql|sql syntax|mysql|ora-\d{5}|postgresql|pg_query|warning:|fatal error|uncaught exception|stack trace|unterminated|unclosed quotation|sqlite|ODBC|syntax error near)`)

const maxBody = 1 << 20

type finding struct {
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
	Status   int    `json:"status"`
	Delta    int    `json:"delta"`
}

type baselineT struct {
	Status int
	Body   []byte
	Length int
	Hash   [32]byte
}

func main() {
	var target, wordlist string
	var concurrency int
	var timeoutSec float64
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-target":
			i++
			target = os.Args[i]
		case "-list":
			i++
			wordlist = os.Args[i]
		case "-c":
			i++
			fmt.Sscanf(os.Args[i], "%d", &concurrency)
		case "-t":
			i++
			fmt.Sscanf(os.Args[i], "%f", &timeoutSec)
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: prober -target <url> [-list wordlist.txt] [-c 16] [-t 8]")
		os.Exit(2)
	}
	if concurrency <= 0 {
		concurrency = 16
	}
	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	if wordlist == "" {
		wordlist = filepath.Join(filepath.Dir(os.Args[0]), "wordlist.txt")
	}

	u, err := url.Parse(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad target:", err)
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSec * float64(time.Second)),
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: 64,
			MaxConnsPerHost:     64,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	// baseline: GET the target as-is
	baseReq, _ := http.NewRequest("GET", u.String(), nil)
	baseReq.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36")
	baseline := baselineT{}
	if resp, err := client.Do(baseReq); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		baseline.Status = resp.StatusCode
		baseline.Body = body
		baseline.Length = len(body)
		baseline.Hash = sha256.Sum256(body)
	}

	data, err := os.ReadFile(wordlist)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wordlist:", err)
		os.Exit(2)
	}
	words := []string{}
	for _, w := range strings.Split(string(data), "\n") {
		w = strings.TrimSpace(w)
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}

	markerPrefix := fmt.Sprintf("q%x", time.Now().UnixNano()%0xFFFFFF)
	findings := make([]finding, 0, 32)
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string, concurrency)
	results := make(chan finding, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				// Marker pass first: reflection-based evidence is the strongest signal
				if f, ok := probeWithValue(client, u, word, markerPrefix+word, baseline); ok {
					results <- f
					continue
				}
				// Toggle activation: many hidden params only respond to value "1"
				if f, ok := probeWithValue(client, u, word, "1", baseline); ok {
					results <- f
				}
			}
		}()
	}
	go func() {
		for _, w := range words {
			jobs <- w
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	for f := range results {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Param < findings[j].Param })
	for _, f := range findings {
		out, _ := json.Marshal(f)
		fmt.Println(string(out))
	}
}

func probeWithValue(client *http.Client, u *url.URL, word, value string, baseline baselineT) (finding, bool) {
	probeURL := *u
	q := probeURL.Query()
	q.Set(word, value)
	probeURL.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", probeURL.String(), nil)
	if err != nil {
		return finding{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return finding{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	delta := len(body) - baseline.Length

	// Evidence 1: marker reflected in the response body
	if strings.Contains(string(body), value) && value != "1" {
		return finding{Param: word, Evidence: "reflected", Status: resp.StatusCode, Delta: delta}, true
	}
	// Evidence 2: status change vs baseline
	if baseline.Status != 0 && resp.StatusCode != baseline.Status {
		return finding{Param: word, Evidence: "status", Status: resp.StatusCode, Delta: delta}, true
	}
	// Evidence 3: significant body length change
	limit := baseline.Length / 8
	if limit < 24 {
		limit = 24
	}
	if abs(delta) > limit {
		return finding{Param: word, Evidence: "length", Status: resp.StatusCode, Delta: delta}, true
	}
	// Evidence 4: error strings appearing only with this parameter present
	if e := errorPattern.Find(body); e != nil && !errorPattern.Match(baseline.Body) {
		return finding{Param: word, Evidence: "error", Status: resp.StatusCode, Delta: delta}, true
	}
	return finding{}, false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
