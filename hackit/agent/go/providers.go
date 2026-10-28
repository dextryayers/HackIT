package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Set from -max-tokens / -json.  Payload generation uses both to keep local
// models fast and to force syntactically valid JSON.
var maxTokensSetting = 0
var jsonModeSetting = false
var thinkModeSetting = "auto"

var (
	ollamaCapMu    sync.Mutex
	ollamaCapCache = map[string]bool{}
)

// ollamaThinkOption decides whether to request separate reasoning tokens.
// Thinking models must use think:true; with think:false they emit their
// chain-of-thought as ordinary content, which contaminates the final answer.
func ollamaThinkOption(model string) *bool {
	mode := strings.ToLower(strings.TrimSpace(thinkModeSetting))
	if mode == "" || mode == "auto" {
		mode = strings.ToLower(strings.TrimSpace(os.Getenv("HACKIT_OLLAMA_THINK")))
	}
	switch mode {
	case "1", "true", "yes", "on", "always":
		enabled := true
		return &enabled
	case "0", "false", "no", "off", "never":
		enabled := false
		return &enabled
	}
	enabled := ollamaSupportsThinking(model)
	return &enabled
}

func ollamaSupportsThinking(model string) bool {
	model = strings.TrimSpace(model)
	if model == "" {
		return false
	}
	ollamaCapMu.Lock()
	if value, ok := ollamaCapCache[model]; ok {
		ollamaCapMu.Unlock()
		return value
	}
	ollamaCapMu.Unlock()

	enabled := false
	payload, _ := json.Marshal(map[string]string{"model": model})
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Post(
		ollamaBaseURL()+"/api/show", "application/json", bytes.NewReader(payload),
	)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var info struct {
				Capabilities []string `json:"capabilities"`
			}
			if json.NewDecoder(resp.Body).Decode(&info) == nil {
				for _, capability := range info.Capabilities {
					if strings.EqualFold(strings.TrimSpace(capability), "thinking") {
						enabled = true
						break
					}
				}
			}
		}
	}
	if !enabled {
		lower := strings.ToLower(model)
		for _, needle := range []string{
			"qwen3", "deepseek-r1", "reasoning", "thinking", "qwq",
			"phi4-reasoning", "magistral",
		} {
			if strings.Contains(lower, needle) {
				enabled = true
				break
			}
		}
	}

	ollamaCapMu.Lock()
	ollamaCapCache[model] = enabled
	ollamaCapMu.Unlock()
	return enabled
}

func ollamaNumCtx() int {
	value := strings.TrimSpace(os.Getenv("HACKIT_OLLAMA_NUM_CTX"))
	if value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 512 {
			return parsed
		}
	}
	return 8192
}

func ollamaKeepAlive() string {
	value := strings.TrimSpace(os.Getenv("HACKIT_OLLAMA_KEEP_ALIVE"))
	if value != "" {
		return value
	}
	return "30m"
}

func ollamaOptions() map[string]interface{} {
	options := map[string]interface{}{
		"temperature":    0.6,
		"top_p":          0.9,
		"repeat_penalty": 1.05,
		"num_ctx":        ollamaNumCtx(),
	}
	if maxTokensSetting > 0 {
		options["num_predict"] = maxTokensSetting
	}
	return options
}

func requestMaxTokens(fallback int) int {
	if maxTokensSetting > 0 {
		return maxTokensSetting
	}
	return fallback
}

func callProvider(client *http.Client, provider, key, prompt, system, model string,
	hist []Message) (string, error) {
	switch provider {
	case "gemini":
		return handleGemini(client, key, prompt, system, model, hist)
	case "groq", "openai", "openrouter", "deepseek", "mistral", "togetherai":
		return handleOpenAICompatible(client, provider, key, prompt, system, model, hist)
	case "claude":
		return handleClaude(client, key, prompt, system, model, hist)
	case "ollama":
		return handleOllama(client, key, prompt, system, model, hist)
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func handleGemini(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	candidates := modelCandidates(model, "gemini", geminiFallbackModels()...)
	apiVersions := []string{"v1beta", "v1"}
	var errs []string

	for _, candidate := range candidates {
		for _, apiVersion := range apiVersions {
			url := fmt.Sprintf(
				"https://generativelanguage.googleapis.com/%s/models/%s:generateContent",
				apiVersion, candidate,
			)
			reqData := GeminiRequest{
				Contents: geminiContents(hist, prompt),
				GenerationConfig: &GeminiGenerationConfig{
					Temperature: 0.7, MaxOutputTokens: requestMaxTokens(8192),
				},
			}
			if system != "" {
				reqData.SystemInstruction = &GeminiContent{Parts: []GeminiPart{{Text: system}}}
			}
			jsonData, _ := json.Marshal(reqData)
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): %v", candidate, apiVersion, err))
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Goog-Api-Key", key)

			resp, err := client.Do(req)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): %v", candidate, apiVersion, err))
				continue
			}
			body := readBody(resp.Body)
			if resp.StatusCode != http.StatusOK {
				message := providerErrorMessage(body)
				if isAuthStatus(resp.StatusCode) {
					return "", fmt.Errorf("[GEMINI] HTTP %d — check API key: %s", resp.StatusCode, message)
				}
				errs = append(errs, fmt.Sprintf("%s(%s): HTTP %d %s", candidate, apiVersion, resp.StatusCode, message))
				continue
			}

			var response GeminiResponse
			if err := json.Unmarshal(body, &response); err != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): parse error", candidate, apiVersion))
				continue
			}
			if response.Error != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): %s", candidate, apiVersion, response.Error.Message))
				continue
			}
			if len(response.Candidates) == 0 {
				errs = append(errs, fmt.Sprintf("%s(%s): no candidates", candidate, apiVersion))
				continue
			}
			var builder strings.Builder
			for _, part := range response.Candidates[0].Content.Parts {
				if part.Thought {
					continue
				}
				builder.WriteString(part.Text)
			}
			if strings.TrimSpace(builder.String()) == "" {
				errs = append(errs, fmt.Sprintf("%s(%s): empty response", candidate, apiVersion))
				continue
			}
			return strings.TrimSpace(builder.String()), nil
		}
	}
	return "", fmt.Errorf("[GEMINI] all attempts failed: %s", strings.Join(errs, "; "))
}

func handleOpenAICompatible(client *http.Client, provider, key, prompt, system, model string,
	hist []Message) (string, error) {
	url, err := openAIEndpoint(provider)
	if err != nil {
		return "", err
	}
	candidates := modelCandidates(model, provider, openAIFallbackModels(provider)...)
	var errs []string

	for _, candidate := range candidates {
		activeModel := candidate
		if activeModel == "" {
			activeModel = defaultModelFor(provider)
		}
		if activeModel == "" {
			continue
		}
		for attempt := 0; attempt < 2; attempt++ {
			reqBody := OpenAIRequest{
				Model: activeModel, MaxTokens: requestMaxTokens(8192), Temperature: 0.7,
				Messages: openAIMessages(system, prompt, hist),
			}
			jsonData, _ := json.Marshal(reqBody)
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				return "", fmt.Errorf("[%s] request: %v", provider, err)
			}
			req.Header.Set("Authorization", "Bearer "+key)
			req.Header.Set("Content-Type", "application/json")
			if provider == "openrouter" {
				req.Header.Set("HTTP-Referer", "https://hackit.dev")
				req.Header.Set("X-Title", "HackIt AI")
			}

			resp, err := client.Do(req)
			if err != nil {
				return "", fmt.Errorf("[%s] connection: %v", provider, err)
			}
			body := readBody(resp.Body)
			if resp.StatusCode == http.StatusOK {
				return parseOpenAIChoice(body, provider)
			}
			if isAuthStatus(resp.StatusCode) {
				return "", fmt.Errorf("[%s] HTTP %d — check API key: %s",
					provider, resp.StatusCode, providerErrorMessage(body))
			}
			message := providerErrorMessage(body)
			if attempt == 0 && provider == "openrouter" &&
				!strings.HasSuffix(activeModel, ":free") &&
				isOpenRouterBillingIssue(message) {
				activeModel += ":free"
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: HTTP %d %s", activeModel, resp.StatusCode, message))
			break
		}
	}
	return "", fmt.Errorf("[%s] all models failed: %s", provider, strings.Join(errs, "; "))
}

func isOpenRouterBillingIssue(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "credits") ||
		strings.Contains(lower, "insufficient") ||
		strings.Contains(lower, "paid model") ||
		strings.Contains(lower, "upgrade") ||
		strings.Contains(lower, "quota")
}

func parseOpenAIChoice(body []byte, provider string) (string, error) {
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("[%s] parse error: %v", provider, err)
	}
	choices, ok := response["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("[%s] no choices: %s", provider, providerErrorMessage(body))
	}
	choice, ok := choices[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("[%s] malformed choice", provider)
	}
	message, ok := choice["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("[%s] malformed message", provider)
	}
	text, _ := message["content"].(string)
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("[%s] empty content", provider)
	}
	return strings.TrimSpace(text), nil
}

func handleClaude(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	candidates := modelCandidates(model, "claude", claudeFallbackModels()...)
	var errs []string

	for _, candidate := range candidates {
		reqBody := ClaudeRequest{
			Model: candidate, System: system, MaxTokens: requestMaxTokens(8192),
			Messages: sanitizeClaudeMessages(hist, prompt),
		}
		jsonData, _ := json.Marshal(reqBody)
		req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonData))
		if err != nil {
			return "", fmt.Errorf("[CLAUDE] request: %v", err)
		}
		req.Header.Set("x-api-key", key)
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("[CLAUDE] connection: %v", err)
		}
		body := readBody(resp.Body)
		if resp.StatusCode == http.StatusOK {
			var response map[string]interface{}
			if err := json.Unmarshal(body, &response); err != nil {
				return "", fmt.Errorf("[CLAUDE] parse: %v", err)
			}
			content, ok := response["content"].([]interface{})
			if !ok || len(content) == 0 {
				errs = append(errs, fmt.Sprintf("%s: no content", candidate))
				continue
			}
			var builder strings.Builder
			for _, block := range content {
				if item, ok := block.(map[string]interface{}); ok {
					if blockType, _ := item["type"].(string); blockType == "thinking" {
						continue
					}
					if text, ok := item["text"].(string); ok {
						builder.WriteString(text)
					}
				}
			}
			if strings.TrimSpace(builder.String()) == "" {
				errs = append(errs, fmt.Sprintf("%s: empty content", candidate))
				continue
			}
			return strings.TrimSpace(builder.String()), nil
		}

		message := providerErrorMessage(body)
		if isAuthStatus(resp.StatusCode) {
			return "", fmt.Errorf("[CLAUDE] HTTP %d — check API key: %s", resp.StatusCode, message)
		}
		errs = append(errs, fmt.Sprintf("%s: HTTP %d %s", candidate, resp.StatusCode, message))
		if isModelRetryStatus(resp.StatusCode) {
			continue
		}
	}
	return "", fmt.Errorf("[CLAUDE] all models failed: %s", strings.Join(errs, "; "))
}

func handleOllama(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	available := ollamaModelNames(client)
	if model == "" {
		model = key
	}
	model = pickOllamaModel(available, model)

	think := ollamaThinkOption(model)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reqBody := OllamaRequest{
			Model: model, Stream: false,
			Options:   ollamaOptions(),
			Think:     think,
			KeepAlive: ollamaKeepAlive(),
		}
		if jsonModeSetting {
			reqBody.Format = "json"
		}
		if system != "" {
			reqBody.Messages = append(reqBody.Messages, Message{Role: "system", Content: system})
		}
		reqBody.Messages = append(reqBody.Messages, hist...)
		reqBody.Messages = append(reqBody.Messages, Message{Role: "user", Content: prompt})

		jsonData, _ := json.Marshal(reqBody)
		req, err := http.NewRequest("POST", ollamaBaseURL()+"/api/chat", bytes.NewBuffer(jsonData))
		if err != nil {
			return "", fmt.Errorf("[OLLAMA] request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("[OLLAMA] connection to %s: %v", ollamaBaseURL(), err)
		}
		body := readBody(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("[OLLAMA] HTTP %d: %s", resp.StatusCode, providerErrorMessage(body))
		}

		var response OllamaResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return "", fmt.Errorf("[OLLAMA] parse: %v", err)
		}
		if response.Error != "" {
			return "", fmt.Errorf("[OLLAMA] %s", response.Error)
		}
		content := strings.TrimSpace(response.Message.Content)
		if content != "" {
			return content, nil
		}
		lastErr = fmt.Errorf("[OLLAMA] empty response (model %s)", model)
		if attempt == 0 && strings.TrimSpace(response.Message.Thinking) != "" && think != nil && *think {
			disabled := false
			think = &disabled
			continue
		}
		break
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("[OLLAMA] empty response (model %s)", model)
}
