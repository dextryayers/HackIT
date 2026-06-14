package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

type ProgressDisplay struct {
	Total      int32
	Current    int32
	Findings   int32
	Requests   int32
	Errors     int32
	StartTime  time.Time
	done       chan struct{}
	curTplID   string
}

func NewProgressDisplay() *ProgressDisplay {
	return &ProgressDisplay{
		StartTime: time.Now(),
		done:      make(chan struct{}),
	}
}

func (p *ProgressDisplay) Start() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		p.Stop()
		os.Exit(130)
	}()
}

func (p *ProgressDisplay) Stop() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

func (p *ProgressDisplay) Render() {
	select {
	case <-p.done:
		return
	default:
	}
	total := atomic.LoadInt32(&p.Total)
	current := atomic.LoadInt32(&p.Current)
	findings := atomic.LoadInt32(&p.Findings)
	reqs := atomic.LoadInt32(&p.Requests)
	errs := atomic.LoadInt32(&p.Errors)
	elapsed := time.Since(p.StartTime).Round(time.Second)

	if noColor {
		fmt.Fprintf(os.Stderr, "\r[*] %d/%d templates | %d findings | %d reqs | %d errors | %s       ",
			current, total, findings, reqs, errs, elapsed)
	} else {
		progress := float64(current) / float64(total) * 100
		if total == 0 {
			progress = 0
		}
		bar := renderBar(progress, 20)
		col := ColorCyan
		if findings > 0 {
			col = ColorYellow
		}
		pctStr := fmt.Sprintf("%3.0f%%", progress)
		fmt.Fprintf(os.Stderr, "\r%s %s %s | %s %d/%d | %s %d | %s %d reqs | %s %d errs | %s       ",
			SColor(col, "►"),
			SColor(ColorBWhite, pctStr),
			bar,
			SColor(ColorGreen, "✔"),
			current, total,
			SColor(ColorBRed, "✘"),
			findings,
			SColor(ColorBlue, "↻"),
			reqs,
			SColor(ColorRed, "✗"),
			errs,
			SColor(ColorDim, elapsed.String()),
		)
	}
}

func renderBar(pct float64, width int) string {
	filled := int(pct * float64(width) / 100)
	if filled > width {
		filled = width
	}
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	col := ColorGreen
	switch {
	case pct >= 100:
		col = ColorBGreen
	case pct >= 75:
		col = ColorGreen
	case pct >= 50:
		col = ColorYellow
	case pct >= 25:
		col = ColorBlue
	default:
		col = ColorDim
	}
	if noColor {
		return bar
	}
	return SColor(col, bar)
}

func (p *ProgressDisplay) Summary() {
	total := atomic.LoadInt32(&p.Total)
	findings := atomic.LoadInt32(&p.Findings)
	errs := atomic.LoadInt32(&p.Errors)
	reqs := atomic.LoadInt32(&p.Requests)
	elapsed := time.Since(p.StartTime).Round(time.Second)

	if !noColor {
		fmt.Fprintf(os.Stderr, "\r%s\n", stringsRepeat(" ", 80))
	}
	fmt.Fprintf(os.Stderr, "\n")
	if !noColor {
		fmt.Fprintf(os.Stderr, "%s %s\n", SColor(ColorBCyan, "═══════════════════════════════"), SColor(ColorBCyan, " SCAN SUMMARY "))
		fmt.Fprintf(os.Stderr, "%s %s\n", SColor(ColorBCyan, "═══════════════════════════════"), SColor(ColorBCyan, ""))
		fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Templates tested:"), SColor(ColorGreen, fmt.Sprintf("%d/%d", total, total)))
		fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Requests sent:"), SColor(ColorCyan, fmt.Sprintf("%d", reqs)))
		fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Findings:"), SColor(ColorBRed, fmt.Sprintf("%d", findings)))
		fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Errors:"), SColor(ColorRed, fmt.Sprintf("%d", errs)))
		fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Duration:"), SColor(ColorYellow, elapsed.String()))
	} else {
		fmt.Fprintf(os.Stderr, "=== SCAN SUMMARY ===\n")
		fmt.Fprintf(os.Stderr, "  Templates tested: %d/%d\n", total, total)
		fmt.Fprintf(os.Stderr, "  Requests sent:    %d\n", reqs)
		fmt.Fprintf(os.Stderr, "  Findings:         %d\n", findings)
		fmt.Fprintf(os.Stderr, "  Errors:           %d\n", errs)
		fmt.Fprintf(os.Stderr, "  Duration:         %s\n", elapsed)
	}
}

func stringsRepeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
