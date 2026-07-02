package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

func ResumeSession(config *ScanConfig) (*SessionData, error) {
	var path string

	if config.SessionFile != "" {
		path = config.SessionFile
	} else if config.SessionID > 0 {
		sessions := ListSessions()
		for _, s := range sessions {
			var id int
			fmt.Sscanf(s, "session_%d.json", &id)
			if id == config.SessionID {
				path = filepath.Join("sessions", s)
				break
			}
		}
		if path == "" {
			return nil, fmt.Errorf("session ID %d not found", config.SessionID)
		}
	}

	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read session: %w", err)
	}

	var session SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("invalid session file: %w", err)
	}

	return &session, nil
}

func ListSessions() []string {
	sessionDir := "sessions"
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		return nil
	}
	var sessions []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "session_") && strings.HasSuffix(e.Name(), ".json") {
			sessions = append(sessions, e.Name())
		}
	}
	return sessions
}

func SaveSession(config *ScanConfig, results []DirResult, remaining []string, stats *ScanStats) {
	session := SessionData{
		Target:    config.Target,
		Remaining: remaining,
		Found:     results,
		Stats:     *stats,
		Timestamp: time.Now(),
	}

	sessionDir := "sessions"
	os.MkdirAll(sessionDir, 0755)
	sessionFile := filepath.Join(sessionDir, fmt.Sprintf("session_%d.json", time.Now().Unix()))

	data, _ := json.MarshalIndent(session, "", "  ")
	os.WriteFile(sessionFile, data, 0644)

	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Session saved: %s\n", color.GreenString("[+]"), sessionFile)
	}
}

func PrintSessionResume(session *SessionData) {
	fmt.Fprintf(color.Output, "%s Resuming session for: %s\n", color.GreenString("[+]"), session.Target)
	fmt.Fprintf(color.Output, "%s Previous results: %d\n", color.CyanString("[*]"), len(session.Found))
	fmt.Fprintf(color.Output, "%s Remaining paths: %d\n", color.CyanString("[*]"), len(session.Remaining))
	fmt.Fprintf(color.Output, "%s Session date: %s\n", color.CyanString("[*]"), session.Timestamp.Format(time.RFC3339))
}
