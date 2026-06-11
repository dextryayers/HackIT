package core

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// SwarmState is the shared memory context for all 20 Autonomous Agents
// It passes critical intelligence from one agent to the next across the DAG.
type SwarmState struct {
	SessionID   string                 `json:"session_id"`
	StartTime   time.Time              `json:"start_time"`
	Target      TargetScope            `json:"target"`
	ReconData   ReconIntelligence      `json:"recon_data"`
	Discovered  []Service              `json:"discovered_services"`
	Vulns       []Vulnerability        `json:"vulnerabilities"`
	Logs        []SwarmLog             `json:"logs"`
	ContextData map[string]interface{} `json:"context_data"` // For unstructured Python/LLM data
	Mu          sync.RWMutex
}

type TargetScope struct {
	PrimaryDomain string   `json:"primary_domain"`
	IPRange       string   `json:"ip_range"`
	ScopeType     string   `json:"scope_type"` // Active, Passive, Internal, External
	Rules         []string `json:"rules_of_engagement"`
}

type ReconIntelligence struct {
	Subdomains []string `json:"subdomains"`
	ASN        string   `json:"asn"`
	CloudInfra string   `json:"cloud_infra"`
}

type Service struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner"`
	Tech     string `json:"tech"`
}

type Vulnerability struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
}

type SwarmLog struct {
	Timestamp time.Time `json:"timestamp"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Message   string    `json:"message"`
}

// Agent is the fundamental interface for all 20 HackIT Swarm engines
type Agent interface {
	Name() string
	Description() string
	Execute(state *SwarmState) error
}

// InitSwarm creates a new autonomous session state
func InitSwarm(domain string, scopeType string) *SwarmState {
	return &SwarmState{
		SessionID: fmt.Sprintf("HACKIT-SWARM-%d", time.Now().Unix()),
		StartTime: time.Now(),
		Target: TargetScope{
			PrimaryDomain: domain,
			ScopeType:     scopeType,
		},
		ContextData: make(map[string]interface{}),
	}
}

// Log records actions taken by any agent
func (s *SwarmState) Log(agentName, action, message string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.Logs = append(s.Logs, SwarmLog{
		Timestamp: time.Now(),
		Agent:     agentName,
		Action:    action,
		Message:   message,
	})
	fmt.Printf("[%s] %s: %s\n", agentName, action, message)
}

// Dump writes the state to a JSON file for Python to read if needed
func (s *SwarmState) Dump(filepath string) error {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}
