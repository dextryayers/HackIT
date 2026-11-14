package main

import (
	"path/filepath"
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
)

type TargetInfo struct {
	URL      string
	Host     string
	Scheme   string
	IP       string
	Resolved bool
}

func ResolveTargets(config *ScanConfig) []TargetInfo {
	var targets []TargetInfo

	if config.Target != "" {
		targets = append(targets, parseTarget(config.Target, config))
	}
	if config.URLsFile != "" {
		file, err := os.Open(config.URLsFile)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, parseTarget(line, config))
				}
			}
		}
	}

	return targets
}

func parseTarget(raw string, config *ScanConfig) TargetInfo {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		if config.Scheme != "" {
			raw = config.Scheme + "://" + raw
		} else {
			raw = "https://" + raw
		}
	}
	if config.IP != "" {
		parsed, err := url.Parse(raw)
		if err == nil {
			raw = parsed.Scheme + "://" + config.IP + parsed.Path
			if parsed.RawQuery != "" {
				raw += "?" + parsed.RawQuery
			}
		}
	}

	parsed, _ := url.Parse(raw)
	host := parsed.Host
	if h, err := parseHostPort(host); err == nil {
		host = h
	}

	return TargetInfo{
		URL:    raw,
		Host:   host,
		Scheme: parsed.Scheme,
		IP:     config.IP,
	}
}

func parseHostPort(host string) (string, error) {
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return host, nil
	}
	return host[:idx], nil
}

func buildFullURL(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	path = strings.TrimPrefix(path, "/")
	parsed, err := url.Parse(base)
	if err != nil {
		return base + "/" + path
	}
	joined := parsed.JoinPath(path)
	if joined != nil {
		return joined.String()
	}
	return base + "/" + path
}

func PrintTargetInfo(targets []TargetInfo, config *ScanConfig) {
	for _, t := range targets {
		fmt.Fprintf(color.Output, "%s %s", color.CyanString("[*]"), color.BlueString(t.URL))
		if t.IP != "" {
			fmt.Fprintf(color.Output, " | %s", t.IP)
		}
		fmt.Println()
	}
}


// === DIR/FUZZ sniper marker helpers ===
// A "DIR" or "FUZZ" token in the target URL is substituted with each wordlist
// entry, instead of joining entries as paths to the base URL.

var validMarkers = []string{"FUZZ", "DIR"}

func detectMarker(target string) (string, string) {
	for _, m := range validMarkers {
		if strings.Contains(target, m) {
			mode := "path"
			rest := target
			if i := strings.Index(rest, "://"); i != -1 {
				rest = rest[i+3:]
			}
			host := rest
			if j := strings.Index(rest, "/"); j != -1 {
				host = rest[:j]
			}
			if strings.Contains(host, m) {
				mode = "host"
			} else if i := strings.Index(target, m); i > 0 && target[i-1] == '.' {
				mode = "ext"
			}
			return m, mode
		}
	}
	return "", ""
}

func sniperWordlist(mode string) (string, string) {
	type candidate struct{ rel, name string }
	candidates := []candidate{}
	switch mode {
	case "ext":
		candidates = []candidate{{filepath.Join("hackit", "dir_finder", "db", "extensions.txt"), "db/extensions.txt"}}
	case "host":
		candidates = []candidate{{filepath.Join("hackit", "dir_finder", "db", "subdomains.txt"), "db/subdomains.txt"},
			{filepath.Join("wordlists", "subdomains.txt"), "wordlists/subdomains.txt"}}
	default: // path position
		candidates = []candidate{{filepath.Join("hackit", "dir_finder", "db", "categories", "common.txt"), "db/categories/common.txt"}}
	}

	abs := []string{}
	if dir := os.Getenv("HACKIT_WORDLISTS"); dir != "" {
		name := filepath.Base(candidates[0].rel)
		abs = append(abs, filepath.Join(dir, name))
	}
	// <repo>/<rel> relative to this binary: <repo>/hackit/dir_finder/go/dir_finder
	if exe, err := os.Executable(); err == nil {
		repo := filepath.Clean(filepath.Join(filepath.Dir(exe), "..", "..", ".."))
		for _, c := range candidates {
			abs = append(abs, filepath.Join(repo, c.rel))
		}
	}
	for _, c := range candidates {
		abs = append(abs, c.rel)
	}

	for _, c := range abs {
		if info, err := os.Stat(c); err == nil && !info.IsDir() && info.Size() > 0 {
			return c, filepath.Base(c)
		}
	}
	return "", candidates[0].name
}

