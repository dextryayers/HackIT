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

var providerPriority = []string{
	"gemini", "groq", "openrouter", "deepseek", "openai", "claude",
	"mistral", "togetherai", "ollama",
}

var providerEnvKeys = map[string][]string{
	"gemini":     {"GEMINI_API_KEY", "GOOGLE_API_KEY", "HACKIT_GEMINI_API_KEY"},
	"groq":       {"GROQ_API_KEY", "HACKIT_GROQ_API_KEY"},
	"openai":     {"OPENAI_API_KEY", "HACKIT_OPENAI_API_KEY"},
	"claude":     {"ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "HACKIT_CLAUDE_API_KEY"},
	"deepseek":   {"DEEPSEEK_API_KEY", "HACKIT_DEEPSEEK_API_KEY"},
	"openrouter": {"OPENROUTER_API_KEY", "HACKIT_OPENROUTER_API_KEY"},
	"mistral":    {"MISTRAL_API_KEY", "HACKIT_MISTRAL_API_KEY"},
	"togetherai": {"TOGETHER_API_KEY", "TOGETHERAI_API_KEY", "HACKIT_TOGETHER_API_KEY"},
}

func defaultModelFor(provider string) string {
	switch provider {
	case "gemini":
		return "gemini-2.5-flash"
	case "openai":
		return "gpt-4o-mini"
	case "claude":
		return "claude-sonnet-4-20250514"
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

func collectProviderKeys(requested, key string) map[string]string {
	keys := make(map[string]string)
	for provider, names := range providerEnvKeys {
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
	if ollamaReachable() {
		keys["ollama"] = "ollama"
	}
	return keys
}

func buildProviderChain(requested string, keys map[string]string) []string {
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
	for _, provider := range providerPriority {
		if key, ok := keys[provider]; ok && key != "" {
			add(provider)
		}
	}
	return chain
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
	bare := strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	if !strings.Contains(bare, ":") {
		host += ":11434"
	}
	return host
}

func ollamaReachable() bool {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(ollamaBaseURL() + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func ollamaModelNames(client *http.Client) []string {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := client.Get(ollamaBaseURL() + "/api/tags")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var payload struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	names := make([]string, 0, len(payload.Models))
	for _, model := range payload.Models {
		if name := strings.TrimSpace(model.Name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func pickOllamaModel(available []string, requested string) string {
	requested = strings.TrimSpace(requested)
	if requested != "" && requested != "llama3" && requested != "AUTO_DETECT" {
		for _, name := range available {
			if name == requested || strings.HasPrefix(name, requested+":") {
				return name
			}
		}
		return requested
	}
	for _, name := range available {
		lower := strings.ToLower(name)
		for _, preferred := range []string{"llama3", "qwen", "mistral", "gemma", "phi"} {
			if strings.HasPrefix(lower, preferred) {
				return name
			}
		}
	}
	if len(available) > 0 {
		return available[0]
	}
	return "llama3"
}

func geminiFallbackModels() []string {
	return []string{
		"gemini-2.5-flash",
		"gemini-2.5-pro",
		"gemini-2.0-flash",
		"gemini-1.5-flash",
		"gemini-1.5-pro",
	}
}

func claudeFallbackModels() []string {
	return []string{
		"claude-sonnet-4-20250514",
		"claude-3-7-sonnet-20250219",
		"claude-3-5-haiku-20241022",
		"claude-3-5-sonnet-20241022",
	}
}

func openAIFallbackModels(provider string) []string {
	switch provider {
	case "groq":
		return []string{"llama-3.3-70b-versatile", "llama-3.1-8b-instant"}
	case "openrouter":
		return []string{
			"google/gemini-2.5-flash:free",
			"meta-llama/llama-3.3-70b-instruct:free",
			"deepseek/deepseek-chat-v3-0324:free",
		}
	case "deepseek":
		return []string{"deepseek-chat", "deepseek-reasoner"}
	case "openai":
		return []string{"gpt-4o-mini", "gpt-4.1-mini", "gpt-4o"}
	case "mistral":
		return []string{"mistral-small-latest", "mistral-large-latest", "open-mistral-7b"}
	case "togetherai":
		return []string{
			"meta-llama/Llama-3.3-70B-Instruct-Turbo",
			"Qwen/Qwen2.5-72B-Instruct-Turbo",
		}
	default:
		return nil
	}
}

func modelCandidates(model, provider string, defaults ...string) []string {
	result := []string{}
	seen := map[string]bool{}
	add := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == provider || seen[candidate] {
			return
		}
		seen[candidate] = true
		result = append(result, candidate)
	}
	add(model)
	for _, candidate := range defaults {
		add(candidate)
	}
	return result
}

func openAIEndpoint(provider string) (string, error) {
	switch provider {
	case "groq":
		return "https://api.groq.com/openai/v1/chat/completions", nil
	case "openrouter":
		return "https://openrouter.ai/api/v1/chat/completions", nil
	case "deepseek":
		return "https://api.deepseek.com/v1/chat/completions", nil
	case "openai":
		return "https://api.openai.com/v1/chat/completions", nil
	case "mistral":
		return "https://api.mistral.ai/v1/chat/completions", nil
	case "togetherai":
		return "https://api.together.xyz/v1/chat/completions", nil
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func providerErrorMessage(body []byte) string {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err == nil {
		if errorObj, ok := payload["error"].(map[string]interface{}); ok {
			if message, ok := errorObj["message"].(string); ok && message != "" {
				return message
			}
		}
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 240 {
		text = text[:240]
	}
	return text
}

func isAuthStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func isModelRetryStatus(status int) bool {
	return status == http.StatusBadRequest ||
		status == http.StatusNotFound ||
		status == http.StatusUnprocessableEntity
}

func openAIMessages(system, prompt string, hist []Message) []Message {
	messages := make([]Message, 0, len(hist)+2)
	if system != "" {
		messages = append(messages, Message{Role: "system", Content: system})
	}
	for _, message := range hist {
		if message.Role == "user" || message.Role == "assistant" || message.Role == "system" {
			messages = append(messages, message)
		}
	}
	messages = append(messages, Message{Role: "user", Content: prompt})
	return messages
}

func sanitizeClaudeMessages(hist []Message, prompt string) []Message {
	messages := make([]Message, 0, len(hist)+1)
	for _, message := range hist {
		if message.Role != "user" && message.Role != "assistant" {
			continue
		}
		if len(messages) == 0 && message.Role == "assistant" {
			messages = append(messages, Message{Role: "user", Content: "(continuing previous conversation)"})
		}
		if len(messages) > 0 && messages[len(messages)-1].Role == message.Role {
			messages[len(messages)-1].Content += "\n\n" + message.Content
			continue
		}
		messages = append(messages, message)
	}
	if len(messages) > 0 && messages[len(messages)-1].Role == "user" {
		messages[len(messages)-1].Content += "\n\n" + prompt
	} else {
		messages = append(messages, Message{Role: "user", Content: prompt})
	}
	return messages
}

func geminiContents(hist []Message, prompt string) []GeminiContent {
	contents := make([]GeminiContent, 0, len(hist)+1)
	for _, message := range hist {
		role := message.Role
		if role == "assistant" {
			role = "model"
		}
		if role != "user" && role != "model" {
			continue
		}
		contents = append(contents, GeminiContent{
			Role: role, Parts: []GeminiPart{{Text: message.Content}},
		})
	}
	contents = append(contents, GeminiContent{Role: "user", Parts: []GeminiPart{{Text: prompt}}})
	return contents
}

func readBody(body io.ReadCloser) []byte {
	defer body.Close()
	data, _ := io.ReadAll(body)
	return data
}
