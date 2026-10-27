package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type tokenEmitter func(string) error

func streamProvider(client *http.Client, provider, key, prompt, system, model string,
	hist []Message, emit tokenEmitter) (string, error) {
	switch provider {
	case "gemini":
		return streamGemini(client, key, prompt, system, model, hist, emit)
	case "groq", "openai", "openrouter", "deepseek", "mistral", "togetherai":
		return streamOpenAICompatible(client, provider, key, prompt, system, model, hist, emit)
	case "claude":
		return streamClaude(client, key, prompt, system, model, hist, emit)
	case "ollama":
		return streamOllama(client, key, prompt, system, model, hist, emit)
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func scanLines(reader io.Reader, handle func(string) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		if err := handle(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func scanSSE(reader io.Reader, handle func(string) error) error {
	return scanLines(reader, func(line string) error {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "event:") {
			return nil
		}
		if !strings.HasPrefix(line, "data:") {
			return nil
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			return nil
		}
		if data == "[DONE]" {
			return io.EOF
		}
		if err := handle(data); err != nil && err != io.EOF {
			return err
		}
		return nil
	})
}

func streamOpenAICompatible(client *http.Client, provider, key, prompt, system, model string,
	hist []Message, emit tokenEmitter) (string, error) {
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

		reqBody := OpenAIRequest{
			Model: activeModel, MaxTokens: 8192, Temperature: 0.7, Stream: true,
			Messages: openAIMessages(system, prompt, hist),
		}
		jsonData, _ := json.Marshal(reqBody)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return "", fmt.Errorf("[%s] request: %v", provider, err)
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")
		if provider == "openrouter" {
			req.Header.Set("HTTP-Referer", "https://hackit.dev")
			req.Header.Set("X-Title", "HackIt AI")
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("[%s] connection: %v", provider, err)
		}
		if resp.StatusCode != http.StatusOK {
			body := readBody(resp.Body)
			message := providerErrorMessage(body)
			if isAuthStatus(resp.StatusCode) {
				return "", fmt.Errorf("[%s] HTTP %d — check API key: %s",
					provider, resp.StatusCode, message)
			}
			errs = append(errs, fmt.Sprintf("%s: HTTP %d %s", activeModel, resp.StatusCode, message))
			continue
		}

		var builder strings.Builder
		streamErr := scanSSE(resp.Body, func(data string) error {
			var chunk struct {
				Choices []struct {
					Delta   struct{ Content string `json:"content"` } `json:"delta"`
					Message struct{ Content string `json:"content"` } `json:"message"`
					Text    string                                   `json:"text"`
				} `json:"choices"`
				Error *struct{ Message string `json:"message"` } `json:"error"`
			}
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				return nil
			}
			if chunk.Error != nil && chunk.Error.Message != "" {
				return fmt.Errorf("%s", chunk.Error.Message)
			}
			for _, choice := range chunk.Choices {
				text := choice.Delta.Content
				if text == "" {
					text = choice.Message.Content
				}
				if text == "" {
					text = choice.Text
				}
				if text == "" {
					continue
				}
				builder.WriteString(text)
				if err := emit(text); err != nil {
					return io.EOF
				}
			}
			return nil
		})
		resp.Body.Close()

		if streamErr != nil && streamErr != io.EOF && streamErr.Error() != "EOF" {
			if builder.Len() > 0 {
				return builder.String(), streamErr
			}
			errs = append(errs, fmt.Sprintf("%s: %v", activeModel, streamErr))
			continue
		}
		if builder.Len() == 0 {
			errs = append(errs, fmt.Sprintf("%s: empty stream", activeModel))
			continue
		}
		return builder.String(), nil
	}
	return "", fmt.Errorf("[%s] all streams failed: %s", provider, strings.Join(errs, "; "))
}

func streamGemini(client *http.Client, key, prompt, system, model string,
	hist []Message, emit tokenEmitter) (string, error) {
	candidates := modelCandidates(model, "gemini", geminiFallbackModels()...)
	apiVersions := []string{"v1beta", "v1"}
	var errs []string

	for _, candidate := range candidates {
		for _, apiVersion := range apiVersions {
			url := fmt.Sprintf(
				"https://generativelanguage.googleapis.com/%s/models/%s:streamGenerateContent?alt=sse",
				apiVersion, candidate,
			)
			reqData := GeminiRequest{
				Contents: geminiContents(hist, prompt),
				GenerationConfig: &GeminiGenerationConfig{
					Temperature: 0.7, MaxOutputTokens: 8192,
				},
			}
			if system != "" {
				reqData.SystemInstruction = &GeminiContent{Parts: []GeminiPart{{Text: system}}}
			}
			jsonData, _ := json.Marshal(reqData)
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				return "", fmt.Errorf("[GEMINI] request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "text/event-stream")
			req.Header.Set("X-Goog-Api-Key", key)

			resp, err := client.Do(req)
			if err != nil {
				return "", fmt.Errorf("[GEMINI] connection: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				body := readBody(resp.Body)
				message := providerErrorMessage(body)
				if isAuthStatus(resp.StatusCode) {
					return "", fmt.Errorf("[GEMINI] HTTP %d — check API key: %s", resp.StatusCode, message)
				}
				errs = append(errs, fmt.Sprintf("%s(%s): HTTP %d %s", candidate, apiVersion, resp.StatusCode, message))
				continue
			}

			var builder strings.Builder
			streamErr := scanSSE(resp.Body, func(data string) error {
				var chunk GeminiResponse
				if err := json.Unmarshal([]byte(data), &chunk); err != nil {
					return nil
				}
				if chunk.Error != nil && chunk.Error.Message != "" {
					return fmt.Errorf("%s", chunk.Error.Message)
				}
				for _, entry := range chunk.Candidates {
					for _, part := range entry.Content.Parts {
						if part.Text == "" {
							continue
						}
						builder.WriteString(part.Text)
						if err := emit(part.Text); err != nil {
							return io.EOF
						}
					}
				}
				return nil
			})
			resp.Body.Close()

			if streamErr != nil && streamErr != io.EOF && streamErr.Error() != "EOF" {
				if builder.Len() > 0 {
					return builder.String(), streamErr
				}
				errs = append(errs, fmt.Sprintf("%s(%s): %v", candidate, apiVersion, streamErr))
				continue
			}
			if builder.Len() == 0 {
				errs = append(errs, fmt.Sprintf("%s(%s): empty stream", candidate, apiVersion))
				continue
			}
			return builder.String(), nil
		}
	}
	return "", fmt.Errorf("[GEMINI] all streams failed: %s", strings.Join(errs, "; "))
}

func streamClaude(client *http.Client, key, prompt, system, model string,
	hist []Message, emit tokenEmitter) (string, error) {
	candidates := modelCandidates(model, "claude", claudeFallbackModels()...)
	var errs []string

	for _, candidate := range candidates {
		reqBody := ClaudeRequest{
			Model: candidate, System: system, MaxTokens: 8192, Stream: true,
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
		req.Header.Set("Accept", "text/event-stream")

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("[CLAUDE] connection: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			body := readBody(resp.Body)
			message := providerErrorMessage(body)
			if isAuthStatus(resp.StatusCode) {
				return "", fmt.Errorf("[CLAUDE] HTTP %d — check API key: %s", resp.StatusCode, message)
			}
			errs = append(errs, fmt.Sprintf("%s: HTTP %d %s", candidate, resp.StatusCode, message))
			continue
		}

		var builder strings.Builder
		streamErr := scanSSE(resp.Body, func(data string) error {
			var event struct {
				Type  string `json:"type"`
				Delta struct {
					Text string `json:"text"`
				} `json:"delta"`
				Error *struct{ Message string `json:"message"` } `json:"error"`
			}
			if err := json.Unmarshal([]byte(data), &event); err != nil {
				return nil
			}
			if event.Type == "error" && event.Error != nil {
				return fmt.Errorf("%s", event.Error.Message)
			}
			if event.Delta.Text == "" {
				return nil
			}
			builder.WriteString(event.Delta.Text)
			if err := emit(event.Delta.Text); err != nil {
				return io.EOF
			}
			return nil
		})
		resp.Body.Close()

		if streamErr != nil && streamErr != io.EOF && streamErr.Error() != "EOF" {
			if builder.Len() > 0 {
				return builder.String(), streamErr
			}
			errs = append(errs, fmt.Sprintf("%s: %v", candidate, streamErr))
			continue
		}
		if builder.Len() == 0 {
			errs = append(errs, fmt.Sprintf("%s: empty stream", candidate))
			continue
		}
		return builder.String(), nil
	}
	return "", fmt.Errorf("[CLAUDE] all streams failed: %s", strings.Join(errs, "; "))
}

func streamOllama(client *http.Client, key, prompt, system, model string,
	hist []Message, emit tokenEmitter) (string, error) {
	available := ollamaModelNames(client)
	if model == "" {
		model = key
	}
	model = pickOllamaModel(available, model)

	reqBody := OllamaRequest{
		Model: model, Stream: true,
		Options: map[string]interface{}{"temperature": 0.7},
		Think:   ollamaThinkOption(),
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
	if resp.StatusCode != http.StatusOK {
		body := readBody(resp.Body)
		return "", fmt.Errorf("[OLLAMA] HTTP %d: %s", resp.StatusCode, providerErrorMessage(body))
	}

	var builder strings.Builder
	streamErr := scanLines(resp.Body, func(line string) error {
		line = strings.TrimSpace(line)
		if line == "" {
			return nil
		}
		var chunk OllamaResponse
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			return nil
		}
		if chunk.Error != "" {
			return fmt.Errorf("%s", chunk.Error)
		}
		if chunk.Message.Content != "" {
			builder.WriteString(chunk.Message.Content)
			if err := emit(chunk.Message.Content); err != nil {
				return io.EOF
			}
		}
		if chunk.Done {
			return io.EOF
		}
		return nil
	})
	resp.Body.Close()

	if streamErr != nil && streamErr != io.EOF && streamErr.Error() != "EOF" {
		if builder.Len() > 0 {
			return builder.String(), streamErr
		}
		return "", fmt.Errorf("[OLLAMA] %v", streamErr)
	}
	if builder.Len() == 0 {
		return "", fmt.Errorf("[OLLAMA] empty response (model %s)", model)
	}
	return builder.String(), nil
}
