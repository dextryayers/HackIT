package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type MonitorTarget struct {
	URL      string
	Interval int
}

func ParseMonitorConfig(raw string) *MonitorTarget {
	if raw == "" { return nil }
	parts := strings.Split(raw, ":")
	mt := &MonitorTarget{URL: parts[0], Interval: 60}
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &mt.Interval)
	}
	return mt
}

func RunMonitor(target *MonitorTarget, scanner *Scanner) {
	fmt.Fprintf(os.Stderr, "%s Monitor mode: %s (every %ds)\n",
		SColor(ColorBCyan, "►"), target.URL, target.Interval)
	ticker := time.NewTicker(time.Duration(target.Interval) * time.Second)
	defer ticker.Stop()

	previousFindings := 0
	for range ticker.C {
		fmt.Fprintf(os.Stderr, "%s Monitor check: %s\n",
			SColor(ColorCyan, "↻"), time.Now().Format("15:04:05"))
		results := scanner.Scan(target.URL)
		if len(results) > previousFindings {
			newFindings := len(results) - previousFindings
			fmt.Fprintf(os.Stderr, "%s %d new findings detected!\n",
				SColor(ColorBRed, "!"), newFindings)
			for _, r := range results[previousFindings:] {
				PrintResultRealTime(r)
			}
		}
		previousFindings = len(results)
	}
}
