package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Italic = "\033[3m"

	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	BgRed    = "\033[41m"
	BgGreen  = "\033[42m"
	BgYellow = "\033[43m"
	BgBlue   = "\033[44m"
	BgPurple = "\033[45m"
	BgCyan   = "\033[46m"

	ClearLine = "\033[2K\r"
	SavePos   = "\033[s"
	Restore   = "\033[u"
	HideCur   = "\033[?25l"
	ShowCur   = "\033[?25h"
)

var Spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type SwarmState struct {
	SessionID   string                 `json:"session_id"`
	StartTime   time.Time              `json:"start_time"`
	Target      TargetScope            `json:"target"`
	ReconData   ReconIntelligence      `json:"recon_data"`
	Discovered  []Service              `json:"discovered_services"`
	Vulns       []Vulnerability        `json:"vulnerabilities"`
	Logs        []SwarmLog             `json:"logs"`
	ContextData map[string]interface{} `json:"context_data"`
	Mu          sync.RWMutex

	spinnerIdx  int
	spinnerDone chan struct{}
}

type TargetScope struct {
	PrimaryDomain string   `json:"primary_domain"`
	IPRange       string   `json:"ip_range"`
	ScopeType     string   `json:"scope_type"`
	Rules         []string `json:"rules_of_engagement"`
}

type ReconIntelligence struct {
	Subdomains []string `json:"subdomains"`
	ASN        string   `json:"asn"`
	CloudInfra string   `json:"cloud_infra"`
	Emails     []string `json:"emails"`
	TechStack  []string `json:"tech_stack"`
}

type Service struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner"`
	Tech     string `json:"tech"`
	Hostname string `json:"hostname"`
}

type Vulnerability struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Port        int     `json:"port"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
	Category    string  `json:"category"`
}

type SwarmLog struct {
	Timestamp time.Time `json:"timestamp"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Message   string    `json:"message"`
	Level     string    `json:"level"`
}

type Agent interface {
	Name() string
	Description() string
	Execute(state *SwarmState) error
}

func colorForAgent(name string) string {
	switch {
	case contains(name, "Orchestrator"):
		return Magenta
	case contains(name, "Planning"):
		return Cyan
	case contains(name, "Recon"):
		return Blue
	case contains(name, "Discovery"):
		return Green
	case contains(name, "Fingerprint"):
		return Yellow
	case contains(name, "Enumeration"):
		return Red
	case contains(name, "Vuln"):
		return BgRed
	case contains(name, "Correlation"):
		return BgPurple
	case contains(name, "Exploit"):
		return BgRed
	case contains(name, "Risk"):
		return BgYellow
	case contains(name, "Report"):
		return BgGreen
	case contains(name, "Memory"):
		return Dim
	case contains(name, "Attack"):
		return BgRed
	case contains(name, "MCP"):
		return Cyan
	case contains(name, "Evasion"):
		return BgBlue
	case contains(name, "Zero"):
		return BgPurple
	case contains(name, "Business"):
		return Yellow
	case contains(name, "Bounty"):
		return BgYellow
	default:
		return White
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func InitSwarm(domain string, scopeType string) *SwarmState {
	s := &SwarmState{
		SessionID:   fmt.Sprintf("HACKIT-SWARM-%d", time.Now().Unix()),
		StartTime:   time.Now(),
		Target:      TargetScope{PrimaryDomain: domain, ScopeType: scopeType},
		ContextData: make(map[string]interface{}),
		spinnerDone: make(chan struct{}),
	}
	fmt.Print(HideCur)
	return s
}

func (s *SwarmState) StartSpinner(msg string) {
	s.spinnerIdx = 0
	s.spinnerDone = make(chan struct{})
	go func() {
		for {
			select {
			case <-s.spinnerDone:
				return
			default:
				fmt.Printf("\r%s%s %s %s%s", SavePos, Cyan, Spinner[s.spinnerIdx%len(Spinner)], msg, Reset)
				s.spinnerIdx++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

func (s *SwarmState) StopSpinner() {
	defer func() { recover() }()
	close(s.spinnerDone)
	fmt.Printf("\r%s", ClearLine)
}

func (s *SwarmState) Log(agentName, action, message string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	clr := colorForAgent(agentName)
	entry := SwarmLog{
		Timestamp: time.Now(),
		Agent:     agentName,
		Action:    action,
		Message:   message,
		Level:     "info",
	}
	s.Logs = append(s.Logs, entry)

	elapsed := time.Since(s.StartTime).Round(time.Second)
	timeStr := fmt.Sprintf("%s[%s]%s", Dim, elapsed, Reset)
	agentStr := fmt.Sprintf("%s%s%s%s", Bold, clr, agentName, Reset)
	actionStr := fmt.Sprintf("%s%s%s", Green, action, Reset)

	fmt.Printf("%s %s %s %s\n", timeStr, agentStr, actionStr, message)
}

func (s *SwarmState) LogOk(agentName, action, message string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	clr := colorForAgent(agentName)
	s.Logs = append(s.Logs, SwarmLog{Timestamp: time.Now(), Agent: agentName, Action: action, Message: message, Level: "ok"})
	elapsed := time.Since(s.StartTime).Round(time.Second)
	fmt.Printf("%s[%s]%s %s%s%s %s[OK]%s %s %s\n", Dim, elapsed, Reset, Bold, clr, agentName, BgGreen, Reset, action, message)
}

func (s *SwarmState) LogWarn(agentName, action, message string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.Logs = append(s.Logs, SwarmLog{Timestamp: time.Now(), Agent: agentName, Action: action, Message: message, Level: "warn"})
	elapsed := time.Since(s.StartTime).Round(time.Second)
	fmt.Printf("%s[%s]%s %s%s%s %s[WARN]%s %s %s\n", Dim, elapsed, Reset, Bold, clr(agentName), Reset, BgYellow, Reset, action, message)
}

func (s *SwarmState) LogErr(agentName, action, message string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.Logs = append(s.Logs, SwarmLog{Timestamp: time.Now(), Agent: agentName, Action: action, Message: message, Level: "error"})
	elapsed := time.Since(s.StartTime).Round(time.Second)
	fmt.Printf("%s[%s]%s %s%s%s %s[ERR]%s %s %s\n", Dim, elapsed, Reset, Bold, clr(agentName), Reset, BgRed, Reset, action, message)
}

func (s *SwarmState) Progress(current, total int) {
	pct := float64(current) * 100 / float64(total)
	bar := ""
	for i := 0; i < 40; i++ {
		if i < int(pct*40/100) {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	fmt.Printf("\r%s %s[%s] %s%.1f%%%s%s", Cyan, bar, Reset, Bold, pct, Reset, ClearLine)
}

func (s *SwarmState) Section(title string) {
	fmt.Printf("\n%s%s━━━ %s ━━━%s\n", Bold, Cyan, title, Reset)
}

func (s *SwarmState) Summary() string {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	fmt.Print(ShowCur)
	return fmt.Sprintf(`
%s[ SWARM SUMMARY ]%s
%sSession:%s %s
%sTarget:%s %s
%sScope:%s %s
%sDuration:%s %s
%sSubdomains:%s %d
%sServices:%s %d
%sVulnerabilities:%s %d
%sLog Events:%s %d
`,
		Bold+BgGreen, Reset,
		Bold, Reset, s.SessionID,
		Bold, Reset, s.Target.PrimaryDomain,
		Bold, Reset, s.Target.ScopeType,
		Bold, Reset, time.Since(s.StartTime).Round(time.Second),
		Bold, Reset, len(s.ReconData.Subdomains),
		Bold, Reset, len(s.Discovered),
		Bold, Reset, len(s.Vulns),
		Bold, Reset, len(s.Logs),
	)
}

func (s *SwarmState) Dump(filepath string) error {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath[:max(1, len(filepath))]
	if idx := strings.LastIndex(filepath, "/"); idx != -1 {
		dir = filepath[:idx]
	}
	os.MkdirAll(dir, 0755)
	return os.WriteFile(filepath, data, 0644)
}

func clr(name string) string {
	return colorForAgent(name)
}
