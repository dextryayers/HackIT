package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type TemplateStat struct {
	ID            string
	Name          string
	Severity      string
	TotalScans    int32
	Matches       int32
	TotalTime     time.Duration
	AvgTime       time.Duration
	LastMatch     time.Time
	ErrorCount    int32
}

type StatsCollector struct {
	mu         sync.Mutex
	stats      map[string]*TemplateStat
	startTime  time.Time
	httpErrors int64
	totalReqs  int64
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		stats:     make(map[string]*TemplateStat),
		startTime: time.Now(),
	}
}

func (sc *StatsCollector) RecordScan(id, name, severity string, duration time.Duration, matched bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	ts, ok := sc.stats[id]
	if !ok {
		ts = &TemplateStat{ID: id, Name: name, Severity: severity}
		sc.stats[id] = ts
	}
	ts.TotalScans++
	ts.TotalTime += duration
	ts.AvgTime = ts.TotalTime / time.Duration(ts.TotalScans)
	if matched {
		ts.Matches++
		ts.LastMatch = time.Now()
	}
	sc.totalReqs++
}

func (sc *StatsCollector) RecordError(id string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.httpErrors++
	if ts, ok := sc.stats[id]; ok {
		ts.ErrorCount++
	}
}

func (sc *StatsCollector) EffectivenessRatio(id string) float64 {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	ts, ok := sc.stats[id]
	if !ok || ts.TotalScans == 0 { return 0 }
	return float64(ts.Matches) / float64(ts.TotalScans)
}

func (sc *StatsCollector) TopTemplates(n int) []*TemplateStat {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	list := make([]*TemplateStat, 0, len(sc.stats))
	for _, ts := range sc.stats {
		list = append(list, ts)
	}
	for i := 0; i < len(list)-1; i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].Matches > list[i].Matches {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	if n > len(list) { n = len(list) }
	return list[:n]
}

func (sc *StatsCollector) BottomTemplates(n int) []*TemplateStat {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	list := make([]*TemplateStat, 0, len(sc.stats))
	for _, ts := range sc.stats {
		list = append(list, ts)
	}
	for i := 0; i < len(list)-1; i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].Matches < list[i].Matches {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	if n > len(list) { n = len(list) }
	return list[:n]
}

func (sc *StatsCollector) Summary() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	duration := time.Since(sc.startTime).Round(time.Second)
	totalMatches := int32(0)
	totalScans := int32(0)
	for _, ts := range sc.stats {
		totalMatches += ts.Matches
		totalScans += ts.TotalScans
	}
	return fmt.Sprintf("Scanned %d templates (%d matches, %d errors) in %s",
		totalScans, totalMatches, sc.httpErrors, duration)
}

func (sc *StatsCollector) PrintAnalytics() {
	if noColor {
		fmt.Printf("\n=== TEMPLATE ANALYTICS ===\n")
		fmt.Printf("%-30s %-8s %-6s %-6s %-12s %-8s\n",
			"Template", "Sev", "Scans", "Matches", "AvgTime", "Effect%")
		top := sc.TopTemplates(20)
		for _, ts := range top {
			eff := float64(0)
			if ts.TotalScans > 0 {
				eff = float64(ts.Matches) / float64(ts.TotalScans) * 100
			}
			fmt.Printf("%-30s %-8s %-6d %-6d %-12s %6.1f%%\n",
				ts.ID, ts.Severity, ts.TotalScans, ts.Matches,
				ts.AvgTime.Round(time.Millisecond), eff)
		}
		return
	}

	fmt.Printf("\n%s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "TEMPLATE ANALYTICS"))
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		SColor(ColorBWhite, "Duration:"),
		SColor(ColorYellow, time.Since(sc.startTime).Round(time.Second).String()))
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		SColor(ColorBWhite, "Errors:"),
		SColor(ColorRed, fmt.Sprintf("%d", sc.httpErrors)))

	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		SColor(ColorBWhite, "Top 20 by matches:"),
		SColor(ColorDim, "(template | severity | scans | matches | avg time | effectiveness)"))
	top := sc.TopTemplates(20)
	for _, ts := range top {
		eff := float64(0)
		if ts.TotalScans > 0 {
			eff = float64(ts.Matches) / float64(ts.TotalScans) * 100
		}
		effStr := fmt.Sprintf("%.1f%%", eff)
		effColor := ColorGreen
		if eff < 1 { effColor = ColorRed }
		if eff < 10 { effColor = ColorYellow }
		if eff < 0.1 { effColor = ColorDim }
		fmt.Fprintf(os.Stderr, "  %s %-30s %s | %s | %s | %s\n",
			SColor(ColorCyan, "•"),
			SColor(ColorBWhite, ts.ID),
			SColor(SeverityColor(ts.Severity), fmt.Sprintf("%-8s", ts.Severity)),
			SColor(ColorBWhite, fmt.Sprintf("%d/%d", ts.Matches, ts.TotalScans)),
			SColor(ColorDim, ts.AvgTime.Round(time.Millisecond).String()),
			SColor(effColor, effStr),
		)
	}

	if bo := sc.BottomTemplates(5); len(bo) > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n",
			SColor(ColorBWhite, "Bottom 5 (no matches):"),
			SColor(ColorDim, "templates with 0 matches"))
		for _, ts := range bo {
			if ts.Matches > 0 { continue }
			fmt.Fprintf(os.Stderr, "  %s %s (%d scans)\n",
				SColor(ColorDim, "•"),
				ts.ID, ts.TotalScans)
		}
	}
	fmt.Fprintf(os.Stderr, "\n")
}

func PrintTemplateAnalytics(scanner *Scanner) {
	if scanner.StatsCollector == nil {
		fmt.Fprintf(os.Stderr, "%s No analytics data collected\n",
			SColor(ColorYellow, "[!]"))
		return
	}
	scanner.StatsCollector.PrintAnalytics()
}
