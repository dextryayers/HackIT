package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func callGemini(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	candidates := buildModelList(model, "gemini", "gemini-3.5-flash", "gemini-3.1-flash-lite", "gemini-3-flash", "gemini-2.5-flash", "gemini-2.0-flash")
	apiVersions := []string{"v1", "v1beta"}
	var errs []string

	for _, m := range candidates {
		if m == "" {
			continue
		}
		for _, apiVer := range apiVersions {
			url := fmt.Sprintf("https://generativelanguage.googleapis.com/%s/models/%s:generateContent", apiVer, m)

			var contents []GeminiContent
			if system != "" {
				contents = append(contents, GeminiContent{
					Role:  "user",
					Parts: []GeminiPart{{Text: fmt.Sprintf("[System]\n%s\n---\nFollow the system instruction.", system)}},
				})
			}
			for _, msg := range hist {
				contents = append(contents, GeminiContent{Role: msg.Role, Parts: []GeminiPart{{Text: msg.Content}}})
			}
			contents = append(contents, GeminiContent{Role: "user", Parts: []GeminiPart{{Text: prompt}}})

			reqData := GeminiRequest{Contents: contents}
			jsonData, _ := json.Marshal(reqData)

			req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Goog-Api-Key", key)

			resp, err := client.Do(req)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): %v", m, apiVer, err))
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				if resp.StatusCode == 403 {
					return "", fmt.Errorf("[GEMINI] %s: HTTP 403 — check API key/permissions", m)
				}
				errs = append(errs, fmt.Sprintf("%s(%s): HTTP %d", m, apiVer, resp.StatusCode))
				continue
			}

			var res GeminiResponse
			if err := json.Unmarshal(body, &res); err != nil {
				errs = append(errs, fmt.Sprintf("%s(%s): parse err", m, apiVer))
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
			parts := res.Candidates[0].Content.Parts
			if len(parts) == 0 || parts[0].Text == "" {
				errs = append(errs, fmt.Sprintf("%s(%s): empty response", m, apiVer))
				continue
			}
			return strings.TrimSpace(parts[0].Text), nil
		}
	}
	return "", fmt.Errorf("[GEMINI] all %d attempts failed: %s", len(errs), strings.Join(errs, "; "))
}

func buildModelList(model, provider string, defaults ...string) []string {
	if model == "" || model == provider {
		return defaults
	}
	result := []string{model}
	for _, d := range defaults {
		if d != model {
			result = append(result, d)
		}
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

func callOpenAI(client *http.Client, provider, key, prompt, system, model string, hist []Message) (string, error) {
	var url string
	switch provider {
	case "groq":
		url = "https://api.groq.com/openai/v1/chat/completions"
	case "openrouter":
		url = "https://openrouter.ai/api/v1/chat/completions"
	case "deepseek":
		url = "https://api.deepseek.com/v1/chat/completions"
	case "openai":
		url = "https://api.openai.com/v1/chat/completions"
	case "mistral":
		url = "https://api.mistral.ai/v1/chat/completions"
	case "togetherai":
		url = "https://api.together.xyz/v1/chat/completions"
	default:
		return "", fmt.Errorf("[%s] unsupported provider", provider)
	}

	if model == "" {
		switch provider {
		case "groq":
			model = "llama-3.3-70b-versatile"
		case "openrouter":
			model = "google/gemini-2.5-flash:free"
		case "deepseek":
			model = "deepseek-chat"
		case "openai":
			model = "gpt-4o-mini"
		case "mistral":
			model = "mistral-small-latest"
		case "togetherai":
			model = "meta-llama/Llama-3.3-70B-Instruct-Turbo"
		}
	}

	shouldRetryFree := provider == "openrouter" && !strings.HasSuffix(model, ":free")

	for attempt := 0; attempt < 2; attempt++ {
		reqBody := OpenAIRequest{Model: model, MaxTokens: 8192, Temperature: 0.7}
		if system != "" {
			reqBody.Messages = append(reqBody.Messages, struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{Role: "system", Content: system})
		}
		for _, msg := range hist {
			reqBody.Messages = append(reqBody.Messages, struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{Role: msg.Role, Content: msg.Content})
		}
		reqBody.Messages = append(reqBody.Messages, struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{Role: "user", Content: prompt})

		jsonData, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		if provider == "openrouter" {
			req.Header.Set("HTTP-Referer", "https://hackit.com")
			req.Header.Set("X-Title", "HackIt AI Chat")
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("[%s] connection: %v", provider, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return parseOpenAIResponse(body, provider)
		}

		if attempt == 0 && shouldRetryFree && isOpenRouterPaymentIssue(body) {
			model = strings.TrimSuffix(model, ":free") + ":free"
			continue
		}

		var errRes map[string]interface{}
		if json.Unmarshal(body, &errRes) == nil {
			if errorObj, ok := errRes["error"].(map[string]interface{}); ok {
				msg, _ := errorObj["message"].(string)
				return "", fmt.Errorf("[%s] %s", provider, msg)
			}
		}
		return "", fmt.Errorf("[%s] HTTP %d", provider, resp.StatusCode)
	}
	return "", fmt.Errorf("[%s] request failed after retry", provider)
}

func parseOpenAIResponse(body []byte, provider string) (string, error) {
	var res map[string]interface{}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("[%s] parse error: %v", provider, err)
	}
	choices, ok := res["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("[%s] no choices in response", provider)
	}
	msg, ok := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("[%s] malformed message", provider)
	}
	text, ok := msg["content"].(string)
	if !ok || text == "" {
		return "", fmt.Errorf("[%s] empty content", provider)
	}
	return strings.TrimSpace(text), nil
}

func callClaude(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	url := "https://api.anthropic.com/v1/messages"
	if model == "" {
		model = "claude-3-5-haiku-20241022"
	}

	reqBody := ClaudeRequest{Model: model, System: system, MaxTokens: 8192}
	for _, msg := range hist {
		reqBody.Messages = append(reqBody.Messages, struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{Role: msg.Role, Content: msg.Content})
	}
	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "user", Content: prompt})

	jsonData, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("[CLAUDE] connection: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var errRes map[string]interface{}
		if json.Unmarshal(body, &errRes) == nil {
			if errorObj, ok := errRes["error"].(map[string]interface{}); ok {
				return "", fmt.Errorf("[CLAUDE] %v", errorObj["message"])
			}
		}
		return "", fmt.Errorf("[CLAUDE] HTTP %d", resp.StatusCode)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("[CLAUDE] parse: %v", err)
	}
	content, ok := res["content"].([]interface{})
	if !ok || len(content) == 0 {
		return "", fmt.Errorf("[CLAUDE] no content")
	}
	text, ok := content[0].(map[string]interface{})["text"].(string)
	if !ok || text == "" {
		return "", fmt.Errorf("[CLAUDE] empty content")
	}
	return strings.TrimSpace(text), nil
}

func callOllama(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	if model == "" {
		model = key
	}
	if model == "" {
		model = "llama3"
	}

	reqBody := OllamaRequest{Model: model, Stream: false}
	if system != "" {
		reqBody.Messages = append(reqBody.Messages, Message{Role: "system", Content: system})
	}
	reqBody.Messages = append(reqBody.Messages, hist...)
	reqBody.Messages = append(reqBody.Messages, Message{Role: "user", Content: prompt})

	jsonData, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", "http://localhost:11434/api/chat", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("[OLLAMA] request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("[OLLAMA] connection: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("[OLLAMA] HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}

	var res OllamaResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("[OLLAMA] parse: %v", err)
	}
	if res.Error != "" {
		return "", fmt.Errorf("[OLLAMA] %s", res.Error)
	}
	content := strings.TrimSpace(res.Message.Content)
	if content == "" {
		return "", fmt.Errorf("[OLLAMA] empty response")
	}
	return content, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
