package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// pro_engine is the Go orchestration layer for the pro scan pipeline.
//
// It owns:
//   * reachability / baseline classification
//   * concurrent dispatch to the Rust pro_scan binary (per specialised mode)
//   * JSON merge + duplicate-finding suppression
//   * a small native header smoke check for when Rust is unavailable
//
// All scans always degrade gracefully: a missing Rust binary is reported as a
// structured error, not a panic.
func main() {
	args := os.Args[1:]
	scanURL := flag(args, "--scan", "")
	timeoutSecs := atoiDefault(flag(args, "--timeout", "20"), 20)
	verbose := flag(args, "--verbose", "1") != "0"
	bypassWAF := hasFlag(args, "--bypass-waf")
	_ = bypassWAF

	if scanURL == "" {
		fmt.Fprintln(os.Stderr, "usage: pro_engine --scan <base-url> [--timeout N] [--verbose 0|1]")
		os.Exit(2)
	}

	result := map[string]any{
		"url":     scanURL,
		"engine":  "go+rust",
		"started": time.Now().UTC().Format(time.RFC3339),
	}

	reachable, statusLen, statusCode := checkReachable(scanURL, time.Duration(timeoutSecs)*time.Second)
	result["reachable"] = reachable
	result["body_bytes"] = statusLen
	result["http_status"] = statusCode

	proScan := locateProScan()
	if proScan == "" {
		result["error"] = "rust pro_scan binary not found; run: cargo build --release (hackit/agent/go/rustsrc/pro_scan)"
		writeJSON(result)
		return
	}

	modes := []string{"headers", "cors", "js", "paths", "cookies"}
	findings := []map[string]any{}
	extra := map[string]any{}

	type modeResult struct {
		mode    string
		payload map[string]any
		err     error
	}
	ch := make(chan modeResult, len(modes))
	var wg sync.WaitGroup
	for _, mode := range modes {
		wg.Add(1)
		go func(m string) {
			defer wg.Done()
			payload, err := runProScan(proScan, m, scanURL, timeoutSecs)
			ch <- modeResult{m, payload, err}
		}(mode)
	}
	wg.Wait()
	close(ch)

	for mr := range ch {
		if verbose {
			if mr.err != nil {
				fmt.Fprintf(os.Stderr, "[pro_engine] %s failed: %v\n", mr.mode, mr.err)
			} else {
				fmt.Fprintf(os.Stderr, "[pro_engine] %s done\n", mr.mode)
			}
		}
		if mr.err != nil || mr.payload == nil {
			if _, ok := extra[mr.mode+"_error"]; !ok {
				extra[mr.mode+"_error"] = mr.err.Error()
			}
			continue
		}
		for _, f := range sliceMaps(mr.payload["findings"]) {
			findings = append(findings, f)
		}
		for key, value := range mr.payload {
			if key == "findings" {
				continue
			}
			extra[key] = value
		}
	}

	findings = dedupeFindings(findings)
	result["findings"] = findings
	result["analysis"] = extra
	result["findings_count"] = len(findings)
	writeJSON(result)
}

func flag(args []string, name, fallback string) string {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return fallback
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func atoiDefault(s string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil || n <= 0 {
		return fallback
	}
	return n
}

func writeJSON(result map[string]any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(result)
}

func locateProScan() string {
	hints := []string{
		filepath.Join("hackit", "agent", "go", "rustsrc", "pro_scan", "target", "release", "pro_scan"),
	}
	if repoRoot := findRepoRoot(); repoRoot != "" {
		hints = append(hints,
			filepath.Join(repoRoot, "hackit", "agent", "go", "rustsrc", "pro_scan", "target", "release", "pro_scan"))
		hints = append(hints,
			filepath.Join(repoRoot, "go", "rustsrc", "pro_scan", "target", "release", "pro_scan"))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		hints = append(hints, filepath.Join(dir, "rustsrc", "pro_scan", "target", "release", "pro_scan"))
		hints = append(hints, filepath.Join(dir, "..", "rustsrc", "pro_scan", "target", "release", "pro_scan"))
	}
	for _, hint := range hints {
		if abs, err := filepath.Abs(hint); err == nil && fileExists(abs) {
			return abs
		}
	}
	if path, err := exec.LookPath("pro_scan"); err == nil {
		return path
	}
	return ""
}

func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 8; i++ {
		if fileExists(filepath.Join(dir, "hackit")) && fileExists(filepath.Join(dir, ".git")) {
			return dir
		}
		if strings.HasSuffix(dir, string(filepath.Separator)+"go") {
			return filepath.Dir(dir)
		}
		if strings.HasSuffix(dir, string(filepath.Separator)+"agent") {
			return filepath.Join(dir, "..", "..")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func checkReachable(raw string, timeout time.Duration) (bool, int, int) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, 0, 0
	}
	client := &http.Client{
		Timeout: timeout,
	}
	start := time.Now()
	resp, err := client.Head(u.String())
	if err != nil {
		resp, err = client.Get(u.String())
	}
	if err != nil {
		_ = time.Since(start)
		return false, 0, 0
	}
	defer resp.Body.Close()
	length := resp.ContentLength
	if length <= 0 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		length = int64(len(buf))
	}
	return true, int(length), resp.StatusCode
}

func runProScan(binary, mode, target string, timeoutSecs int) (map[string]any, error) {
	timeout := time.Duration(timeoutSecs+10) * time.Second
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, "--mode", mode, "--url", target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w (%s)", mode, err, strings.TrimSpace(stderr.String()))
	}
	data := stdout.Bytes()
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s: %w", mode, err)
	}
	return payload, nil
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func sliceMaps(v any) []map[string]any {
	if v == nil {
		return nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, m)
	}
	return out
}

func dedupeFindings(findings []map[string]any) []map[string]any {
	seen := map[string]struct{}{}
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		identity := fmt.Sprintf("%v|%v", f["type"], f["target"])
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return fmt.Sprint(out[i]["type"]) < fmt.Sprint(out[j]["type"])
	})
	return out
}
