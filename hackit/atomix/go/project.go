package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ProjectEntry struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	StartTime time.Time `json:"start_time"`
	Duration  string    `json:"duration"`
	Findings  int       `json:"findings"`
	Status    string    `json:"status"`
	Templates int       `json:"templates_tested"`
	Errors    int       `json:"errors"`
	Results   []Result  `json:"results"`
}

type ProjectDB struct {
	Name        string          `json:"name"`
	Path        string          `json:"path"`
	CreatedAt   time.Time       `json:"created_at"`
	Scans       []ProjectEntry  `json:"scans"`
	mu          sync.RWMutex
}

func NewProject(name, basePath string) (*ProjectDB, error) {
	if name == "" {
		name = fmt.Sprintf("scan-%d", time.Now().Unix())
	}
	projPath := basePath
	if projPath == "" {
		home, _ := os.UserHomeDir()
		projPath = filepath.Join(home, ".atomix", "projects", name)
	}
	if err := os.MkdirAll(projPath, 0755); err != nil {
		return nil, fmt.Errorf("create project dir: %w", err)
	}
	p := &ProjectDB{
		Name:      name,
		Path:      projPath,
		CreatedAt: time.Now(),
	}
	if data, err := os.ReadFile(filepath.Join(projPath, "project.json")); err == nil {
		json.Unmarshal(data, p)
	}
	return p, nil
}

func (p *ProjectDB) SaveScan(entry ProjectEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Scans = append(p.Scans, entry)
	return p.save()
}

func (p *ProjectDB) ListScans() []ProjectEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Scans
}

func (p *ProjectDB) GetScan(id string) *ProjectEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, s := range p.Scans {
		if s.ID == id {
			return &s
		}
	}
	return nil
}

func (p *ProjectDB) save() error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.Path, "project.json"), data, 0644)
}

func (p *ProjectDB) SaveResults(results []Result) error {
	if len(results) == 0 {
		return nil
	}
	fn := filepath.Join(p.Path, fmt.Sprintf("results-%d.json", time.Now().Unix()))
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fn, data, 0644)
}

func (p *ProjectDB) GetResultFiles() ([]string, error) {
	entries, err := os.ReadDir(p.Path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "results-") {
			files = append(files, filepath.Join(p.Path, e.Name()))
		}
	}
	return files, nil
}

func CreateScanEntry(target string, results []Result, duration time.Duration, stats *ScanStats) ProjectEntry {
	return ProjectEntry{
		ID:        fmt.Sprintf("scan-%d", time.Now().Unix()),
		Target:    target,
		StartTime: time.Now(),
		Duration:  duration.Round(time.Second).String(),
		Findings:  len(results),
		Status:    "completed",
		Templates: int(stats.TemplatesTested),
		Errors:    int(stats.Errors),
		Results:   results,
	}
}

func HandleProjectMode(cfg *ScanConfig, results []Result, duration time.Duration, stats *ScanStats) {
	if cfg.Project == "" {
		return
	}
	project, err := NewProject(cfg.Project, cfg.ProjectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Project error: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}
	entry := CreateScanEntry(cfg.URL, results, duration, stats)
	if err := project.SaveScan(entry); err != nil {
		fmt.Fprintf(os.Stderr, "%s Save error: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}
	if err := project.SaveResults(results); err != nil {
		fmt.Fprintf(os.Stderr, "%s Results save error: %v\n", SColor(ColorRed, "[!]"), err)
		return
	}
	if !cfg.Silent {
		totalFindings := 0
		for _, s := range project.ListScans() {
			totalFindings += s.Findings
		}
		fmt.Fprintf(os.Stderr, "%s Project '%s': %d scans, %d findings\n",
			SColor(ColorGreen, "[+]"), cfg.Project,
			len(project.Scans), totalFindings)
	}
}

func PrintProjectInfo(cfg *ScanConfig) {
	project, err := NewProject(cfg.Project, cfg.ProjectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", SColor(ColorRed, "[!]"), err)
		return
	}
	fmt.Fprintf(os.Stderr, "%s Project: %s\n", SColor(ColorBCyan, "►"), project.Name)
	fmt.Fprintf(os.Stderr, "  Path: %s\n", project.Path)
	fmt.Fprintf(os.Stderr, "  Created: %s\n", project.CreatedAt.Format(time.RFC3339))
	scans := project.ListScans()
	fmt.Fprintf(os.Stderr, "  Scans: %d\n", len(scans))
	for _, s := range scans {
		statusColor := ColorGreen
		if s.Status == "failed" { statusColor = ColorRed }
		fmt.Fprintf(os.Stderr, "  %s %s %s (%d findings, %d templates)\n",
			SColor(statusColor, s.Status), s.Target, s.Duration,
			s.Findings, s.Templates)
	}
}
