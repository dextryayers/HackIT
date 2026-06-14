package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"
)

type DiffEntry struct {
	Type      string `json:"type"`
	Template  string `json:"template"`
	URL       string `json:"url"`
	Severity  string `json:"severity"`
	OldStatus string `json:"old_status,omitempty"`
	NewStatus string `json:"new_status,omitempty"`
}

func DiffResults(oldFile, newFile string) ([]DiffEntry, error) {
	oldResults, err := loadResultsFile(oldFile)
	if err != nil { return nil, fmt.Errorf("old: %w", err) }
	newResults, err := loadResultsFile(newFile)
	if err != nil { return nil, fmt.Errorf("new: %w", err) }

	oldMap := makeResultMap(oldResults)
	newMap := makeResultMap(newResults)

	var entries []DiffEntry
	// New findings
	for key, r := range newMap {
		if _, exists := oldMap[key]; !exists {
			entries = append(entries, DiffEntry{
				Type: "new", Template: r.TemplateName,
				URL: r.URL, Severity: r.Severity, NewStatus: "found",
			})
		}
	}
	// Fixed findings
	for key, r := range oldMap {
		if _, exists := newMap[key]; !exists {
			entries = append(entries, DiffEntry{
				Type: "fixed", Template: r.TemplateName,
				URL: r.URL, Severity: r.Severity, OldStatus: "found", NewStatus: "fixed",
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Type < entries[j].Type
	})
	return entries, nil
}

func loadResultsFile(path string) ([]Result, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var results []Result
	err = json.Unmarshal(data, &results)
	return results, err
}

func makeResultMap(results []Result) map[string]Result {
	m := make(map[string]Result)
	for _, r := range results {
		key := r.TemplateID + "|" + r.URL + "|" + r.MatcherName
		m[key] = r
	}
	return m
}

func PrintDiff(entries []DiffEntry) {
	if noColor {
		fmt.Printf("\n=== DIFF RESULTS ===\n")
		for _, e := range entries {
			fmt.Printf("[%s] %s - %s\n", e.Type, e.URL, e.Template)
		}
		return
	}
	fmt.Printf("\n%s %s\n", SColor(ColorBCyan, "═══"), SColor(ColorBWhite, fmt.Sprintf("DIFF RESULTS (%d changes)", len(entries))))
	for _, e := range entries {
		switch e.Type {
		case "new":
			fmt.Printf("  %s %s %s %s\n",
				SColor(ColorBRed, "[NEW]"),
				SColor(ColorBWhite, e.URL),
				SColor(ColorCyan, e.Template),
				SColor(ColorRed, e.Severity))
		case "fixed":
			fmt.Printf("  %s %s %s\n",
				SColor(ColorBGreen, "[FIXED]"),
				SColor(ColorBWhite, e.URL),
				SColor(ColorCyan, e.Template))
		}
	}
}

type ReplayRunner struct {
	scanner *Scanner
}

func NewReplayRunner(s *Scanner) *ReplayRunner {
	return &ReplayRunner{scanner: s}
}

func (rr *ReplayRunner) ReplayFinding(result Result) {
	fmt.Fprintf(os.Stderr, "%s Replaying: %s (%s)\n",
		SColor(ColorBCyan, "►"), result.TemplateID, result.URL)
	for _, t := range rr.scanner.Templates {
		if t.ID == result.TemplateID {
			rr.scanner.Templates = []*Template{t}
			rr.scanner.Scan(result.URL)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "%s Template not found: %s\n",
		SColor(ColorRed, "[!]"), result.TemplateID)
}

type DashboardServer struct {
	Port    int
	Path    string
	Auth    string
}

func (ds *DashboardServer) Start() {
	fmt.Fprintf(os.Stderr, "%s Dashboard starting on :%d%s\n",
		SColor(ColorGreen, "[+]"), ds.Port, ds.Path)
	go func() {
		http.HandleFunc(ds.Path+"/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","version":"2.1.0","time":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
		})
		addr := fmt.Sprintf(":%d", ds.Port)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Fprintf(os.Stderr, "%s Dashboard error: %v\n",
				SColor(ColorRed, "[!]"), err)
		}
	}()
}
