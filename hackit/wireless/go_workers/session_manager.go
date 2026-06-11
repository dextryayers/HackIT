package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type CaptureSession struct {
	ID        string    `json:"id"`
	BSSID     string    `json:"bssid"`
	SSID      string    `json:"ssid"`
	Channel   int       `json:"channel"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	FilePath  string    `json:"file_path"`
	HashType  string    `json:"hash_type"`
	Status    string    `json:"status"`
	PSK       string    `json:"psk,omitempty"`
}

func generateSessionID() string {
	return fmt.Sprintf("SES-%d", time.Now().UnixNano())
}

type SessionManager struct {
	mu       sync.Mutex
	sessions []CaptureSession
	dbPath   string
}

func NewSessionManager(dbPath string) *SessionManager {
	return &SessionManager{
		sessions: make([]CaptureSession, 0),
		dbPath:   dbPath,
	}
}

func (sm *SessionManager) CreateSession(bssid, ssid string, channel int, filePath, hashType string) *CaptureSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session := &CaptureSession{
		ID:        generateSessionID(),
		BSSID:     bssid,
		SSID:      ssid,
		Channel:   channel,
		StartTime: time.Now(),
		FilePath:  filePath,
		HashType:  hashType,
		Status:    "captured",
	}

	sm.sessions = append(sm.sessions, *session)
	return session
}

func (sm *SessionManager) ListSessions() []CaptureSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	result := make([]CaptureSession, len(sm.sessions))
	copy(result, sm.sessions)
	return result
}

func (sm *SessionManager) GetSession(id string) (*CaptureSession, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i := range sm.sessions {
		if sm.sessions[i].ID == id {
			return &sm.sessions[i], true
		}
	}
	return nil, false
}

func (sm *SessionManager) UpdateStatus(id, status string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i := range sm.sessions {
		if sm.sessions[i].ID == id {
			sm.sessions[i].Status = status
			return
		}
	}
}

func (sm *SessionManager) SetPsk(id, psk string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i := range sm.sessions {
		if sm.sessions[i].ID == id {
			sm.sessions[i].PSK = psk
			sm.sessions[i].Status = "cracked"
			sm.sessions[i].EndTime = time.Now()
			return
		}
	}
}

func (sm *SessionManager) Save() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	data, err := json.MarshalIndent(sm.sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}

	err = os.WriteFile(sm.dbPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write session file %s: %w", sm.dbPath, err)
	}

	return nil
}

func (sm *SessionManager) Load() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	data, err := os.ReadFile(sm.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			sm.sessions = make([]CaptureSession, 0)
			return nil
		}
		return fmt.Errorf("failed to read session file %s: %w", sm.dbPath, err)
	}

	var sessions []CaptureSession
	err = json.Unmarshal(data, &sessions)
	if err != nil {
		return fmt.Errorf("failed to unmarshal sessions: %w", err)
	}

	sm.sessions = sessions
	return nil
}
