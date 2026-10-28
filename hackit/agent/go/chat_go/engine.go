package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// defaultModels holds a sensible first choice for each provider.  Every
// request still walks a fallback list because provider model catalogues change
// frequently.
var defaultModels = map[string]string{
	"gemini":     "gemini-2.5-flash",
	"openai":     "gpt-4o-mini",
	"claude":     "claude-sonnet-4-20250514",
	"deepseek":   "deepseek-chat",
	"groq":       "llama-3.3-70b-versatile",
	"openrouter": "google/gemini-2.5-flash:free",
	"mistral":    "mistral-small-latest",
	"togetherai": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
	"ollama":     "llama3",
}

var providerOrder = []string{
	"gemini", "groq", "openrouter", "deepseek", "openai", "claude",
	"mistral", "togetherai", "ollama",
}

var envKeys = map[string][]string{
	"gemini":     {"GEMINI_API_KEY", "GOOGLE_API_KEY", "HACKIT_GEMINI_API_KEY"},
	"groq":       {"GROQ_API_KEY", "HACKIT_GROQ_API_KEY"},
	"openai":     {"OPENAI_API_KEY", "HACKIT_OPENAI_API_KEY"},
	"claude":     {"ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "HACKIT_CLAUDE_API_KEY"},
	"deepseek":   {"DEEPSEEK_API_KEY", "HACKIT_DEEPSEEK_API_KEY"},
	"openrouter": {"OPENROUTER_API_KEY", "HACKIT_OPENROUTER_API_KEY"},
	"mistral":    {"MISTRAL_API_KEY", "HACKIT_MISTRAL_API_KEY"},
	"togetherai": {"TOGETHER_API_KEY", "TOGETHERAI_API_KEY", "HACKIT_TOGETHER_API_KEY"},
}

// collectKeys merges the key supplied on the command line with keys available
// in the environment so the engine can fall back between providers.
func collectKeys(requested, key string) map[string]string {
	keys := make(map[string]string)
	for provider, names := range envKeys {
		for _, name := range names {
			if value := strings.TrimSpace(os.Getenv(name)); value != "" {
				keys[provider] = value
				break
			}
		}
	}
	if key != "" && requested != "ollama" {
		keys[requested] = key
	}
	if ollamaAvailable() {
		keys["ollama"] = "ollama"
	}
	return keys
}

func providerChain(requested string, keys map[string]string) []string {
	chain := []string{}
	seen := map[string]bool{}
	add := func(provider string) {
		if provider == "" || seen[provider] {
			return
		}
		seen[provider] = true
		chain = append(chain, provider)
	}
	add(requested)
	for _, provider := range providerOrder {
		if key, ok := keys[provider]; ok && key != "" {
			add(provider)
		}
	}
	return chain
}

func optimalModel(provider string) string {
	if model, ok := defaultModels[provider]; ok {
		return model
	}
	return ""
}

func ollamaBaseURL() string {
	host := strings.TrimSpace(os.Getenv("OLLAMA_HOST"))
	if host == "" {
		host = strings.TrimSpace(os.Getenv("HACKIT_OLLAMA_HOST"))
	}
	if host == "" {
		host = "http://127.0.0.1:11434"
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}
	host = strings.TrimRight(host, "/")
	// OLLAMA_HOST commonly omits the port.
	if !strings.Contains(strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://"), ":") {
		host += ":11434"
	}
	return host
}

func ollamaAvailable() bool {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(ollamaBaseURL() + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func autoOllamaModel() string {
	client := &http.Client{Timeout: 2000 * time.Millisecond}
	resp, err := client.Get(ollamaBaseURL() + "/api/tags")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var payload struct {
		Models []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	best := ""
	for _, model := range payload.Models {
		name := strings.TrimSpace(model.Name)
		if name == "" {
			continue
		}
		if best == "" {
			best = name
		}
		if strings.Contains(strings.ToLower(name), "llama3") {
			return name
		}
	}
	return best
}

func callProvider(client *http.Client, provider, key, prompt, system, model string, hist []Message) (string, error) {
	switch provider {
	case "gemini":
		return callGemini(client, key, prompt, system, model, hist)
	case "groq", "openai", "openrouter", "deepseek", "mistral", "togetherai":
		return callOpenAI(client, provider, key, prompt, system, model, hist)
	case "claude":
		return callClaude(client, key, prompt, system, model, hist)
	case "ollama":
		return callOllama(client, key, prompt, system, model, hist)
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func streamProvider(client *http.Client, provider, key, prompt, system, model string,
	hist []Message, emit func(kind, text string) error) (string, error) {
	switch provider {
	case "gemini":
		return streamGemini(client, key, prompt, system, model, hist, emit)
	case "groq", "openai", "openrouter", "deepseek", "mistral", "togetherai":
		return streamOpenAI(client, provider, key, prompt, system, model, hist, emit)
	case "claude":
		return streamClaude(client, key, prompt, system, model, hist, emit)
	case "ollama":
		return streamOllama(client, key, prompt, system, model, hist, emit)
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

// readBody drains and closes a body, returning its content.
func readBody(body io.ReadCloser) []byte {
	defer body.Close()
	data, _ := io.ReadAll(body)
	return data
}
