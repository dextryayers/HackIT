package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type ReportConfig struct {
	OutputFile        string
	JSONLines         bool
	TerminalDashboard bool
	Interval          time.Duration
}

type AttackSnapshot struct {
	Timestamp time.Time `json:"timestamp"`
	Sent      uint64    `json:"sent"`
	Rate      float64   `json:"rate"`
	Errors    uint64    `json:"errors"`
	Workers   int       `json:"workers"`
	Method    string    `json:"method"`
	Elapsed   float64   `json:"elapsed"`
}

type ReportEngine struct {
	startTime time.Time
	mu        sync.Mutex
	snapshots []AttackSnapshot
	config    ReportConfig
	done      chan struct{}
}

func NewReportEngine(cfg ReportConfig) *ReportEngine {
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Second
	}
	return &ReportEngine{
		startTime: time.Now(),
		config:    cfg,
		done:      make(chan struct{}),
	}
}

func (r *ReportEngine) Start(ctx context.Context) {
	ticker := time.NewTicker(r.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.Stop()
			return
		case <-ticker.C:
			r.mu.Lock()
			if len(r.snapshots) > 0 {
				last := r.snapshots[len(r.snapshots)-1]
				if r.config.TerminalDashboard {
					r.PrintDashboard(last)
				}
				if r.config.JSONLines {
					r.emitJSONLine(last)
				}
			}
			r.mu.Unlock()
		case <-r.done:
			return
		}
	}
}

func (r *ReportEngine) Record(snapshot AttackSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot.Timestamp = time.Now()
	r.snapshots = append(r.snapshots, snapshot)
}

func (r *ReportEngine) Summary() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()

	totalSent := uint64(0)
	totalErrors := uint64(0)
	var avgRate float64

	for _, s := range r.snapshots {
		totalSent += s.Sent
		totalErrors += s.Errors
	}

	elapsed := time.Since(r.startTime).Seconds()
	if elapsed > 0 && len(r.snapshots) > 0 {
		avgRate = float64(totalSent) / elapsed
	}

	method := ""
	if len(r.snapshots) > 0 {
		method = r.snapshots[len(r.snapshots)-1].Method
	}

	return map[string]any{
		"total_sent":   totalSent,
		"total_errors": totalErrors,
		"avg_rate":     avgRate,
		"elapsed":      elapsed,
		"snapshots":    len(r.snapshots),
		"method":       method,
	}
}

func (r *ReportEngine) ToJSON() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	data := map[string]any{
		"start_time": r.startTime.Format(time.RFC3339),
		"end_time":   time.Now().Format(time.RFC3339),
		"summary":    r.buildSummary(),
		"snapshots":  r.snapshots,
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (r *ReportEngine) ToCSV() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var buf strings.Builder
	writer := csv.NewWriter(&buf)
	writer.Write([]string{"timestamp", "sent", "rate", "errors", "workers", "method"})

	for _, s := range r.snapshots {
		writer.Write([]string{
			s.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("%d", s.Sent),
			fmt.Sprintf("%.2f", s.Rate),
			fmt.Sprintf("%d", s.Errors),
			fmt.Sprintf("%d", s.Workers),
			s.Method,
		})
	}
	writer.Flush()
	return buf.String()
}

func (r *ReportEngine) WriteToFile(path string) error {
	data := r.ToJSON()
	return os.WriteFile(path, []byte(data), 0644)
}

func (r *ReportEngine) Stop() {
	select {
	case <-r.done:
	default:
		close(r.done)
	}

	if r.config.OutputFile != "" {
		r.WriteToFile(r.config.OutputFile)
	}
}

func (r *ReportEngine) PrintDashboard(snapshot AttackSnapshot) {
	t := snapshot.Timestamp.Format("15:04:05")
	line := fmt.Sprintf(
		"\r[%s] SENT: %d | RATE: %.0f/s | ERR: %d | WORKERS: %d | METHOD: %s | ELAPSED: %.0fs",
		t, snapshot.Sent, snapshot.Rate, snapshot.Errors,
		snapshot.Workers, snapshot.Method, snapshot.Elapsed,
	)
	os.Stderr.WriteString(line)
}

func (r *ReportEngine) emitJSONLine(snapshot AttackSnapshot) {
	b, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	fmt.Fprintln(os.Stderr, string(b))
}

func (r *ReportEngine) buildSummary() map[string]any {
	totalSent := uint64(0)
	totalErrors := uint64(0)

	for _, s := range r.snapshots {
		totalSent += s.Sent
		totalErrors += s.Errors
	}

	elapsed := time.Since(r.startTime).Seconds()
	avgRate := 0.0
	if elapsed > 0 {
		avgRate = float64(totalSent) / elapsed
	}

	return map[string]any{
		"total_sent":   totalSent,
		"total_errors": totalErrors,
		"avg_rate":     avgRate,
		"elapsed":      elapsed,
		"snapshots":    len(r.snapshots),
	}
}
