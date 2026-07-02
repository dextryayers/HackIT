package main

import (
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
