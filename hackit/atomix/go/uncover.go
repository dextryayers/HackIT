package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type UncoverSource struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	APIKey string `json:"api_key,omitempty"`
}

type UncoverResult struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Host     string `json:"host,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Product  string `json:"product,omitempty"`
	Country  string `json:"country,omitempty"`
	Org      string `json:"org,omitempty"`
	Source   string `json:"source"`
}

type UncoverEngine struct {
	Config    *ScanConfig
	Client    *http.Client
	Sources   []UncoverSource
	Results   []UncoverResult
}

func NewUncoverEngine(cfg *ScanConfig) *UncoverEngine {
	e := &UncoverEngine{
		Config: cfg,
		Client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns: 20,
			},
		},
	}
	e.initSources()
	return e
}

func (e *UncoverEngine) initSources() {
	e.Sources = []UncoverSource{
		{Name: "shodan", URL: "https://internetdb.shodan.io/%s"},
		{Name: "censys", URL: "https://search.censys.io/api/v2/hosts/search"},
		{Name: "fofa", URL: "https://fofa.info/api/v1/search/all"},
		{Name: "hunter", URL: "https://hunter.how/api/v1/search"},
	}
}

func (e *UncoverEngine) SearchShodan(query string) ([]UncoverResult, error) {
	clean := strings.TrimSpace(strings.ReplaceAll(query, " ", ""))
	clean = url.PathEscape(clean)
	apiURL := fmt.Sprintf("https://internetdb.shodan.io/%s", clean)

	resp, err := e.Client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("shodan request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		IP      string   `json:"ip"`
		Ports   []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Org     string   `json:"org"`
		Country string   `json:"country"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var results []UncoverResult
	for _, port := range result.Ports {
		results = append(results, UncoverResult{
			IP:       result.IP,
			Port:     port,
			Host:     strings.Join(result.Hostnames, ", "),
			Country:  result.Country,
			Org:      result.Org,
			Source:   "shodan",
		})
	}
	if len(results) == 0 {
		results = append(results, UncoverResult{IP: result.IP, Source: "shodan"})
	}
	return results, nil
}

func (e *UncoverEngine) Search(query string) []UncoverResult {
	var all []UncoverResult
	engine := strings.ToLower(e.Config.UncoverEngine)
	if engine == "" {
		engine = "shodan"
	}

	switch engine {
	case "shodan":
		results, err := e.SearchShodan(query)
		if err == nil {
			all = append(all, results...)
		}
	case "all":
		results, err := e.SearchShodan(query)
		if err == nil {
			all = append(all, results...)
		}
	}

	limit := e.Config.UncoverLimit
	if limit <= 0 {
		limit = 100
	}
	if len(all) > limit {
		all = all[:limit]
	}

	e.Results = all
	return all
}

func (e *UncoverEngine) CollectTargets() []string {
	targets := make(map[string]struct{})
	field := strings.ToLower(e.Config.UncoverField)

	for _, r := range e.Results {
		switch field {
		case "ip":
			if r.IP != "" {
				targets[r.IP] = struct{}{}
			}
		case "host", "hostname":
			if r.Host != "" {
				for _, h := range strings.Split(r.Host, ",") {
					targets[strings.TrimSpace(h)] = struct{}{}
				}
			}
		default:
			if r.IP != "" {
				targets[fmt.Sprintf("%s:%d", r.IP, r.Port)] = struct{}{}
			}
		}
	}

	var result []string
	for t := range targets {
		result = append(result, t)
	}
	return result
}

func PrintUncoverResults(results []UncoverResult) {
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "%s No results from uncover\n", SColor(ColorYellow, "[!]"))
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s Uncover Results (%d found):\n",
		SColor(ColorBCyan, "►"), len(results))
	fmt.Fprintf(os.Stderr, "  %-20s %-8s %-30s %s\n",
		SColor(ColorBWhite, "IP"), SColor(ColorBWhite, "Port"),
		SColor(ColorBWhite, "Host"), SColor(ColorBWhite, "Source"))
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("─", 80))
	for _, r := range results {
		host := r.Host
		if len(host) > 30 { host = host[:27] + "..." }
		fmt.Fprintf(os.Stderr, "  %-20s %-8d %-30s %s\n",
			r.IP, r.Port, host, r.Source)
	}
}

func HandleUncoverMode(cfg *ScanConfig) []string {
	if !cfg.Uncover || cfg.UncoverQuery == "" {
		return nil
	}

	if !cfg.Silent {
		fmt.Fprintf(os.Stderr, "%s Uncover: searching %s for '%s'\n",
			SColor(ColorBCyan, "►"), cfg.UncoverEngine, cfg.UncoverQuery)
	}

	engine := NewUncoverEngine(cfg)
	results := engine.Search(cfg.UncoverQuery)
	PrintUncoverResults(results)

	targets := engine.CollectTargets()
	if len(targets) > 0 && !cfg.Silent {
		fmt.Fprintf(os.Stderr, "%s Collected %d targets for scanning\n",
			SColor(ColorGreen, "[+]"), len(targets))
	}
	return targets
}
