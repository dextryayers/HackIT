package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type MultiTargetCoordinator struct {
	Targets       []string
	ScannerConfig *ScanConfig
	Results       map[string][]Result
	Errors        map[string]error
	GlobalStats   *ScanStats
	mu            sync.RWMutex
	taskCh        chan string
	resultCh      chan targetResult
	doneCh        chan bool
}

type targetResult struct {
	target  string
	results []Result
	err     error
}

func NewMultiTargetCoordinator(targets []string, config *ScanConfig) *MultiTargetCoordinator {
	return &MultiTargetCoordinator{
		Targets:       targets,
		ScannerConfig: config,
		Results:       make(map[string][]Result),
		Errors:        make(map[string]error),
		GlobalStats:   &ScanStats{StartedAt: time.Now().UTC().Format(time.RFC3339)},
		taskCh:        make(chan string, len(targets)),
		resultCh:      make(chan targetResult, len(targets)),
		doneCh:        make(chan bool),
	}
}

func (mtc *MultiTargetCoordinator) Run() {
	if len(mtc.Targets) == 0 {
		fmt.Fprintf(os.Stderr, "%s No targets to scan\n",
			SColor(ColorYellow, "[!]"))
		return
	}

	fmt.Fprintf(os.Stderr, "%s Multi-target scan: %d targets\n",
		SColor(ColorBCyan, "►"), len(mtc.Targets))

	for _, target := range mtc.Targets {
		mtc.taskCh <- target
	}
	close(mtc.taskCh)

	concurrency := mtc.ScannerConfig.Threads
	if concurrency > len(mtc.Targets) {
		concurrency = len(mtc.Targets)
	}
	if concurrency < 1 { concurrency = 1 }

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go mtc.worker(&wg)
	}

	go func() {
		wg.Wait()
		close(mtc.resultCh)
		mtc.doneCh <- true
	}()

	go func() {
		for res := range mtc.resultCh {
			mtc.mu.Lock()
			if res.err != nil {
				mtc.Errors[res.target] = res.err
				atomic.AddInt32(&mtc.GlobalStats.Errors, 1)
			} else {
				mtc.Results[res.target] = res.results
				atomic.AddInt32(&mtc.GlobalStats.Findings, int32(len(res.results)))
			}
			atomic.AddInt32(&mtc.GlobalStats.TargetsScanned, 1)
			mtc.mu.Unlock()
		}
	}()

	<-mtc.doneCh
	mtc.GlobalStats.Duration = time.Since(
		parseTime(mtc.GlobalStats.StartedAt),
	).Round(time.Second).String()

	mtc.printSummary()
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	if t.IsZero() {
		t, _ = time.Parse("2006-01-02T15:04:05", s)
	}
	return t
}

func (mtc *MultiTargetCoordinator) worker(wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range mtc.taskCh {
		fmt.Fprintf(os.Stderr, "\n%s Scanning: %s\n",
			SColor(ColorBCyan, "►"), SColor(ColorBWhite, target))

		scanner := NewScanner(mtc.ScannerConfig.Timeout, mtc.ScannerConfig.Threads)
		scanner.Config = mtc.ScannerConfig
		scanner.Verbose = mtc.ScannerConfig.Verbose
		scanner.Deduplicator = NewDeduplicator()
		scanner.Stats = &ScanStats{
			TemplatesTotal: int32(len(scanner.Templates)),
			StartedAt:      time.Now().UTC().Format(time.RFC3339),
		}

		templates, err := LoadTemplates(mtc.ScannerConfig.TemplateDir)
		if err != nil {
			mtc.resultCh <- targetResult{target: target, err: err}
			continue
		}

		filtered := FilterTemplates(templates, FilterOptions{
			Severity: mtc.ScannerConfig.Severity,
			Tags:     parseTags(mtc.ScannerConfig.Tags),
		})

		if len(filtered) == 0 {
			mtc.resultCh <- targetResult{target: target, results: []Result{}}
			continue
		}

		scanner.Templates = filtered
		results := scanner.Scan(target)

		mtc.resultCh <- targetResult{target: target, results: results}
	}
}

func (mtc *MultiTargetCoordinator) printSummary() {
	mtc.mu.RLock()
	defer mtc.mu.RUnlock()

	totalFindings := 0
	for _, results := range mtc.Results {
		totalFindings += len(results)
	}

	if noColor {
		fmt.Printf("\n=== MULTI-TARGET SCAN SUMMARY ===\n")
		fmt.Printf("Targets: %d/%d | Findings: %d | Errors: %d | Duration: %s\n",
			len(mtc.Results), len(mtc.Targets), totalFindings,
			mtc.GlobalStats.Errors, mtc.GlobalStats.Duration)
		return
	}

	fmt.Printf("\n%s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "MULTI-TARGET SCAN SUMMARY"))
	fmt.Printf("  %s %s\n",
		SColor(ColorBWhite, "Targets:"),
		SColor(ColorGreen, fmt.Sprintf("%d/%d scanned", len(mtc.Results), len(mtc.Targets))))
	fmt.Printf("  %s %s\n",
		SColor(ColorBWhite, "Findings:"),
		SColor(ColorBRed, fmt.Sprintf("%d total", totalFindings)))
	fmt.Printf("  %s %s\n",
		SColor(ColorBWhite, "Errors:"),
		SColor(ColorRed, fmt.Sprintf("%d", mtc.GlobalStats.Errors)))
	fmt.Printf("  %s %s\n",
		SColor(ColorBWhite, "Duration:"),
		SColor(ColorYellow, mtc.GlobalStats.Duration))

	for target, results := range mtc.Results {
		if len(results) > 0 {
			fmt.Printf("\n  %s %s (%d findings)\n",
				SColor(ColorBWhite, "Target:"),
				SColor(ColorCyan, target),
				len(results))
			for _, r := range results {
				fmt.Printf("    %s %s [%s]\n",
					SColor(SeverityColor(r.Severity), fmt.Sprintf("[%s]", strings.ToUpper(r.Severity))),
					r.TemplateID,
					r.MatcherName,
				)
			}
		}
	}
	fmt.Println()
}

func CorrelateResults(urlResults []struct {
	URL     string
	Results []Result
}) []Result {
	findings := make(map[string]*Result)

	for _, ur := range urlResults {
		for _, r := range ur.Results {
			key := fmt.Sprintf("%s|%s|%s", r.TemplateID, r.URL, r.MatcherName)
			if existing, ok := findings[key]; ok {
				if getSeverityWeight(r.Severity) > getSeverityWeight(existing.Severity) {
					findings[key] = &r
				}
			} else {
				entry := r
				findings[key] = &entry
			}
		}
	}

	deduped := make([]Result, 0, len(findings))
	for _, r := range findings {
		deduped = append(deduped, *r)
	}
	return deduped
}

func getSeverityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical": return 5
	case "high": return 4
	case "medium": return 3
	case "low": return 2
	case "info": return 1
	default: return 0
	}
}
