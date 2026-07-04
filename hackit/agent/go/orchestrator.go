package main

import (
	"fmt"
	"net/http"
	"sort"
	"time"
)

type ProviderLatency struct {
	Name    string
	Latency time.Duration
}

// IntelligenceOrchestrator manages multi-provider logic and optimal routing
type IntelligenceOrchestrator struct {
	Providers     map[string]string
	FallbackChain []string
	LatencyIndex  []ProviderLatency
}

func NewIntelligenceOrchestrator(keys map[string]string) *IntelligenceOrchestrator {
	chain := []string{"gemini", "groq", "openrouter", "deepseek", "mistral", "togetherai", "openai", "claude", "ollama"}
	available := make([]string, 0)
	for _, p := range chain {
		if k, ok := keys[p]; ok && k != "" {
			available = append(available, p)
		}
	}
	if _, ok := keys["ollama"]; ok {
		available = append(available, "ollama")
	}
	return &IntelligenceOrchestrator{
		Providers:     keys,
		FallbackChain: available,
	}
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

func (o *IntelligenceOrchestrator) RankByLatency() []string {
	if len(o.LatencyIndex) > 0 {
		sort.Slice(o.LatencyIndex, func(i, j int) bool {
			return o.LatencyIndex[i].Latency < o.LatencyIndex[j].Latency
		})
		ranked := make([]string, len(o.LatencyIndex))
		for i, pl := range o.LatencyIndex {
			ranked[i] = pl.Name
		}
		return ranked
	}
	return o.FallbackChain
}

func (o *IntelligenceOrchestrator) ProbeLatency(timeout time.Duration) {
	probeURLs := map[string]string{
		"gemini":     "https://generativelanguage.googleapis.com",
		"groq":       "https://api.groq.com",
		"openrouter": "https://openrouter.ai",
		"deepseek":   "https://api.deepseek.com",
		"mistral":    "https://api.mistral.ai",
		"togetherai": "https://api.together.xyz",
		"openai":     "https://api.openai.com",
		"claude":     "https://api.anthropic.com",
	}
	client := &http.Client{Timeout: timeout}
	for name, url := range probeURLs {
		if _, ok := o.Providers[name]; !ok {
			continue
		}
		start := time.Now()
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			o.LatencyIndex = append(o.LatencyIndex, ProviderLatency{
				Name:    name,
				Latency: time.Since(start),
			})
		}
	}
}

func (o *IntelligenceOrchestrator) ValidateRoute(provider string) error {
	if provider == "ollama" {
		return nil
	}
	for _, p := range o.FallbackChain {
		if p == provider {
			return nil
		}
	}
	return fmt.Errorf("provider %s is not configured with an API key", provider)
}
