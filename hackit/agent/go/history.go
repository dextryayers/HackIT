package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// HistoryManager handles persistent conversation history to make AI smarter (context-aware)
type HistoryManager struct {
	HistoryPath string
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func NewHistoryManager() *HistoryManager {
	home, _ := os.UserHomeDir()
	return &HistoryManager{
		HistoryPath: filepath.Join(home, ".hackit_ai_history.json"),
	}
}

func (h *HistoryManager) Load() []Message {
	data, err := os.ReadFile(h.HistoryPath)
	if err != nil {
		return []Message{}
	}
	var history []Message
	json.Unmarshal(data, &history)
	return history
}

func (h *HistoryManager) Save(history []Message) {
	// Limit history to last 20 messages to prevent token bloat
	if len(history) > 20 {
		history = history[len(history)-20:]
	}
	data, _ := json.MarshalIndent(history, "", "  ")
	os.WriteFile(h.HistoryPath, data, 0644)
}

func (h *HistoryManager) Clear() {
	os.Remove(h.HistoryPath)
}
