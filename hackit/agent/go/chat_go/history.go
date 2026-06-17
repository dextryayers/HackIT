package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type HistoryManager struct {
	HistoryPath string
}

func NewHistoryManager() *HistoryManager {
	home, _ := os.UserHomeDir()
	return &HistoryManager{
		HistoryPath: filepath.Join(home, ".hackit_chat_history.json"),
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
	if len(history) > 50 {
		history = history[len(history)-50:]
	}
	data, _ := json.MarshalIndent(history, "", "  ")
	os.WriteFile(h.HistoryPath, data, 0644)
}

func (h *HistoryManager) Clear() {
	os.Remove(h.HistoryPath)
}
