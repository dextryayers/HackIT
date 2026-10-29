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

var maxTokensSetting = 0
var jsonModeSetting = false
var thinkModeSetting = "auto"

var (
	ollamaCapMu    sync.Mutex
	ollamaCapCache = map[string]bool{}
)

// ollamaThinkOption decides whether to request separate reasoning tokens.
//
// HACKIT_OLLAMA_THINK / -think explicitly win.  In auto mode the model's
// /api/show capabilities are checked once and cached.  Thinking models must
// use think:true: with think:false they dump their chain-of-thought into the
// normal content stream, which is exactly the "nonsense answer" failure.
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
		// Older Ollama releases omit capabilities.  Recognise the common
		// reasoning families so they still get the correct mode.
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
		"temperature":    0.3,
		"top_p":          0.85,
		"repeat_penalty": 1.05,
		"num_ctx":        ollamaNumCtx(),
	}
	// Local reasoning models need a generous token budget so the separate
	// thinking channel can finish before the final answer is emitted.  Without
	// this, think:true exhausts the default num_predict and the model returns
	// only reasoning (or falls back to think:false and dumps CoT into content).
	if maxTokensSetting > 0 {
		options["num_predict"] = maxTokensSetting
	} else {
		options["num_predict"] = 2048
	}
	return options
}

func requestMaxTokens(fallback int) int {
	if maxTokensSetting > 0 {
		return maxTokensSetting
	}
	return fallback
}

func openAIURL(provider string) (string, error) {
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
		return "", fmt.Errorf("[%s] unsupported provider", provider)
	}
}

func openAIDefaults(provider string) []string {
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

func geminiDefaults() []string {
	return []string{
		"gemini-2.5-flash",
		"gemini-2.5-pro",
		"gemini-2.0-flash",
		"gemini-1.5-flash",
		"gemini-1.5-pro",
	}
}

func claudeDefaults() []string {
	return []string{
		"claude-sonnet-4-20250514",
		"claude-3-7-sonnet-20250219",
		"claude-3-5-haiku-20241022",
		"claude-3-5-sonnet-20241022",
	}
}

func buildModelList(model, provider string, defaults ...string) []string {
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

func isOpenRouterPaymentIssue(body []byte) bool {
	var errRes map[string]interface{}
	if err := json.Unmarshal(body, &errRes); err != nil {
		return false
	}
	errorObj, ok := errRes["error"].(map[string]interface{})
	if !ok {
		return false
	}
	msg, _ := errorObj["message"].(string)
	msgLower := strings.ToLower(msg)
	return strings.Contains(msgLower, "credits") ||
		strings.Contains(msgLower, "insufficient") ||
		strings.Contains(msgLower, "paid model") ||
		strings.Contains(msgLower, "upgrade") ||
		strings.Contains(msgLower, "quota")
}

func providerErrorMessage(body []byte) string {
	var errRes map[string]interface{}
	if err := json.Unmarshal(body, &errRes); err == nil {
		if errorObj, ok := errRes["error"].(map[string]interface{}); ok {
			if msg, ok := errorObj["message"].(string); ok && msg != "" {
				return msg
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

func isRetryableModelStatus(status int) bool {
	return status == http.StatusBadRequest ||
		status == http.StatusNotFound ||
		status == http.StatusUnprocessableEntity
}

// callGemini uses the native systemInstruction field instead of injecting a
// fake user turn.  Model and API-version fallbacks cover provider drift.
func callGemini(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	candidates := buildModelList(model, "gemini", geminiDefaults()...)
	apiVersions := []string{"v1beta", "v1"}
	var errs []string

	for _, m := range candidates {
		for _, apiVer := range apiVersions {
			url := fmt.Sprintf("https://generativelanguage.googleapis.com/%s/models/%s:generateContent", apiVer, m)

			contents := make([]GeminiContent, 0, len(hist)+1)
			for _, msg := range hist {
				role := msg.Role
				if role == "assistant" {
					role = "model"
				}
				if role != "user" && role != "model" {
					continue
				}
				contents = append(contents, GeminiContent{
					Role: role, Parts: []GeminiPart{{Text: msg.Content}},
				})
			}
			contents = append(contents, GeminiContent{Role: "user", Parts: []GeminiPart{{Text: prompt}}})

			reqData := GeminiRequest{
				Contents: contents,
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
				errs = append(errs, fmt.Sprintf("%s(%s): %v", m, apiVer, err))
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Goog-Api-Key", key)

			resp, err := client.Do(req)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): %v", m, apiVer, err))
				continue
			}
			body := readBody(resp.Body)

			if resp.StatusCode != http.StatusOK {
				message := providerErrorMessage(body)
				if isAuthStatus(resp.StatusCode) {
					return "", fmt.Errorf("[GEMINI] HTTP %d — check API key/permissions: %s", resp.StatusCode, message)
				}
				errs = append(errs, fmt.Sprintf("%s(%s): HTTP %d %s", m, apiVer, resp.StatusCode, message))
				continue
			}

			var res GeminiResponse
			if err := json.Unmarshal(body, &res); err != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): parse error", m, apiVer))
				continue
			}
			if res.Error != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): %s", m, apiVer, res.Error.Message))
				continue
			}
			if len(res.Candidates) == 0 {
				errs = append(errs, fmt.Sprintf("%s(%s): no candidates", m, apiVer))
				continue
			}
			var builder strings.Builder
			for _, part := range res.Candidates[0].Content.Parts {
				if part.Thought {
					continue
				}
				builder.WriteString(part.Text)
			}
			if strings.TrimSpace(builder.String()) == "" {
				errs = append(errs, fmt.Sprintf("%s(%s): empty response", m, apiVer))
				continue
			}
			return strings.TrimSpace(builder.String()), nil
		}
	}
	return "", fmt.Errorf("[GEMINI] all attempts failed: %s", strings.Join(errs, "; "))
}

func openAIMessages(system, prompt string, hist []Message) []Message {
	messages := make([]Message, 0, len(hist)+2)
	if system != "" {
		messages = append(messages, Message{Role: "system", Content: system})
	}
	for _, msg := range hist {
		if msg.Role == "user" || msg.Role == "assistant" || msg.Role == "system" {
			messages = append(messages, msg)
		}
	}
	messages = append(messages, Message{Role: "user", Content: prompt})
	return messages
}

func callOpenAI(client *http.Client, provider, key, prompt, system, model string, hist []Message) (string, error) {
	url, err := openAIURL(provider)
	if err != nil {
		return "", err
	}
	candidates := buildModelList(model, provider, openAIDefaults(provider)...)
	var errs []string

	for _, candidate := range candidates {
		activeModel := candidate
		if activeModel == "" {
			activeModel = optimalModel(provider)
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
				return parseOpenAIResponse(body, provider)
			}
			if isAuthStatus(resp.StatusCode) {
				return "", fmt.Errorf("[%s] HTTP %d — check API key: %s",
					provider, resp.StatusCode, providerErrorMessage(body))
			}
			if attempt == 0 && provider == "openrouter" &&
				!strings.HasSuffix(activeModel, ":free") && isOpenRouterPaymentIssue(body) {
				activeModel += ":free"
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: HTTP %d %s",
				activeModel, resp.StatusCode, providerErrorMessage(body)))
			break
		}
	}
	return "", fmt.Errorf("[%s] all models failed: %s", provider, strings.Join(errs, "; "))
}

func parseOpenAIResponse(body []byte, provider string) (string, error) {
	var res map[string]interface{}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("[%s] parse error: %v", provider, err)
	}
	choices, ok := res["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("[%s] no choices in response: %s", provider, providerErrorMessage(body))
	}
	choice, ok := choices[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("[%s] malformed choice", provider)
	}
	msg, ok := choice["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("[%s] malformed message", provider)
	}
	text, _ := msg["content"].(string)
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("[%s] empty content", provider)
	}
	return strings.TrimSpace(text), nil
}

func sanitizeClaudeMessages(hist []Message, prompt string) []Message {
	messages := make([]Message, 0, len(hist)+1)
	for _, msg := range hist {
		if msg.Role != "user" && msg.Role != "assistant" {
			continue
		}
		if len(messages) == 0 && msg.Role == "assistant" {
			// Claude requires the first turn to belong to the user.
			messages = append(messages, Message{Role: "user", Content: "(continuing previous conversation)"})
		}
		if len(messages) > 0 && messages[len(messages)-1].Role == msg.Role {
			messages[len(messages)-1].Content += "\n\n" + msg.Content
			continue
		}
		messages = append(messages, msg)
	}
	if len(messages) > 0 && messages[len(messages)-1].Role == "user" {
		messages[len(messages)-1].Content += "\n\n" + prompt
	} else {
		messages = append(messages, Message{Role: "user", Content: prompt})
	}
	return messages
}

func callClaude(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	url := "https://api.anthropic.com/v1/messages"
	candidates := buildModelList(model, "claude", claudeDefaults()...)
	var errs []string

	for _, candidate := range candidates {
		reqBody := ClaudeRequest{
			Model: candidate, System: system, MaxTokens: requestMaxTokens(8192),
			Messages: sanitizeClaudeMessages(hist, prompt),
		}
		jsonData, _ := json.Marshal(reqBody)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
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
			var res map[string]interface{}
			if err := json.Unmarshal(body, &res); err != nil {
				return "", fmt.Errorf("[CLAUDE] parse: %v", err)
			}
			content, ok := res["content"].([]interface{})
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
		if isRetryableModelStatus(resp.StatusCode) {
			continue
		}
	}
	return "", fmt.Errorf("[CLAUDE] all models failed: %s", strings.Join(errs, "; "))
}

func callOllama(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	if model == "" {
		model = autoOllamaModel()
	}
	if model == "" {
		model = "llama3"
	}

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

		var res OllamaResponse
		if err := json.Unmarshal(body, &res); err != nil {
			return "", fmt.Errorf("[OLLAMA] parse: %v", err)
		}
		if res.Error != "" {
			return "", fmt.Errorf("[OLLAMA] %s", res.Error)
		}
		content := strings.TrimSpace(res.Message.Content)
		if content != "" {
			return content, nil
		}
		lastErr = fmt.Errorf("[OLLAMA] empty response (model %s)", model)
		// Never fall back to think:false.  Reasoning models must keep their
		// chain-of-thought in the separate thinking channel; dumping it into
		// content is exactly the "nonsense answer" failure.  If content is
		// empty, increase num_predict or retry the same request instead.
		if attempt == 0 && strings.TrimSpace(res.Message.Thinking) != "" && think != nil && *think {
			// Same think:true request once more; a larger budget may let the
			// final answer appear after the reasoning block.
			continue
		}
		break
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("[OLLAMA] empty response (model %s)", model)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
