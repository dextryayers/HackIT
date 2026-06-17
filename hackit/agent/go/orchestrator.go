package main

import (
	"fmt"
)

// IntelligenceOrchestrator manages multi-provider logic and optimal routing
type IntelligenceOrchestrator struct {
	AvailableProviders []string
}

func NewIntelligenceOrchestrator(keys map[string]string) *IntelligenceOrchestrator {
	var available []string
	for p, k := range keys {
		if k != "" {
			available = append(available, p)
		}
	}
	return &IntelligenceOrchestrator{AvailableProviders: available}
}

func (o *IntelligenceOrchestrator) GetOptimalModel(provider string) string {
	switch provider {
	case "gemini":
		return "gemini-3.5-flash"
	case "openai":
		return "gpt-4o-mini"
	case "claude":
		return "claude-4-sonnet-20250514"
	case "deepseek":
		return "deepseek-chat"
	case "groq":
		return "llama-3.3-70b-versatile"
	case "openrouter":
		return "google/gemini-2.5-flash:free"
	case "mistral":
		return "mistral-small-latest"
	case "togetherai":
		return "meta-llama/Llama-3.3-70B-Instruct-Turbo"
	case "ollama":
		return "llama3"
	default:
		return ""
	}
}

func (o *IntelligenceOrchestrator) ValidateRoute(provider string) error {
	if provider == "ollama" {
		return nil // Ollama is local, doesn't strictly need a key
	}
	for _, p := range o.AvailableProviders {
		if p == provider {
			return nil
		}
	}
	return fmt.Errorf("provider %s is not configured with an API key", provider)
}
