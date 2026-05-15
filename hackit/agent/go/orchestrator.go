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
		return "gemini-2.5-flash"
	case "openai":
		return "gpt-4o"
	case "claude":
		return "claude-3-opus-20240229"
	case "deepseek":
		return "deepseek-chat"
	case "groq":
		return "llama3-70b-8192"
	case "openrouter":
		return "google/gemini-pro-1.5"
	default:
		return ""
	}
}

func (o *IntelligenceOrchestrator) ValidateRoute(provider string) error {
	for _, p := range o.AvailableProviders {
		if p == provider {
			return nil
		}
	}
	return fmt.Errorf("provider %s is not configured with an API key", provider)
}
