package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	provider := flag.String("provider", "", "AI Provider")
	apiKey := flag.String("key", "", "API Key")
	prompt := flag.String("prompt", "", "User Prompt")
	system := flag.String("system", "", "System Prompt")
	model := flag.String("model", "", "Model Name")
	analyze := flag.Bool("analyze", false, "Enable Vulnerability Analysis Mode")
	toolName := flag.String("tool", "", "Name of the tool being analyzed")
	clearHist := flag.Bool("clear", false, "Clear conversation history")
	mode := flag.String("mode", "", "Specialized Command Mode (e.g., risk, attack)")
	flag.Parse()

	history := NewHistoryManager()
	if *clearHist {
		history.Clear()
		fmt.Println(`{"text": "History cleared successfully"}`)
		return
	}

	if *provider == "" || (*apiKey == "" && *provider != "ollama") || (*prompt == "" && !*analyze) {
		fmt.Println(`{"error": "Missing required flags"}`)
		os.Exit(1)
	}

	finalPrompt := *prompt
	finalSystem := *system

	if *mode != "" {
		finalSystem += GetCommandInstruction(*mode)
	}

	if *analyze {
		analyzer := NewVulnerabilityAnalyzer()
		finalPrompt = analyzer.GenerateAnalysisPrompt(*toolName, analyzer.CleanScanData(*prompt))
		finalSystem = analyzer.SystemPrompt
	}

	client := &http.Client{Timeout: 60 * time.Second}
	var response string
	var err error

	// Multi-Intelligence Orchestration
	orchestrator := NewIntelligenceOrchestrator(map[string]string{*provider: *apiKey})
	if *model == "" {
		*model = orchestrator.GetOptimalModel(*provider)
	}

	histData := history.Load()

	switch *provider {
	case "gemini":
		response, err = handleGemini(client, *apiKey, finalPrompt, finalSystem, *model, histData)
	case "groq":
		response, err = handleOpenAICompatible(client, "groq", *apiKey, finalPrompt, finalSystem, *model, histData)
	case "claude":
		response, err = handleClaude(client, *apiKey, finalPrompt, finalSystem, *model, histData)
	case "openai", "openrouter", "deepseek":
		response, err = handleOpenAICompatible(client, *provider, *apiKey, finalPrompt, finalSystem, *model, histData)
	case "ollama":
		response, err = handleOllama(client, *apiKey, finalPrompt, finalSystem, *model, histData)
	default:
		err = fmt.Errorf("unsupported provider: %s", *provider)
	}

	if err != nil {
		errResp := map[string]string{"error": err.Error()}
		jsonErr, _ := json.Marshal(errResp)
		fmt.Println(string(jsonErr))
		os.Exit(1)
	}

	// Save history
	histData = append(histData, Message{Role: "user", Content: finalPrompt})
	histData = append(histData, Message{Role: "assistant", Content: response})
	history.Save(histData)

	out := AIResponse{Text: response}
	jsonOut, _ := json.Marshal(out)
	fmt.Println(string(jsonOut))
}

func handleGemini(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	// Deep Repair: Try multiple endpoints and models to find what's active for this key
	// In 2026, Gemini 1.5 is retired. We must try 2.5, 3, and aliases.
	modelsToTry := []string{model, "gemini-2.5-flash", "gemini-flash-latest", "gemini-3-flash", "gemini-pro-latest", "gemini-1.5-flash"}
	versionsToTry := []string{"v1", "v1beta"}

	var lastErr error
	for _, v := range versionsToTry {
		for _, m := range modelsToTry {
			if m == "" {
				continue
			}
			
			url := fmt.Sprintf("https://generativelanguage.googleapis.com/%s/models/%s:generateContent?key=%s", v, m, key)
			
			fullPrompt := system + "\n\n"
			for _, msg := range hist {
				fullPrompt += fmt.Sprintf("%s: %s\n", msg.Role, msg.Content)
			}
			fullPrompt += fmt.Sprintf("User: %s", prompt)

			reqData := GeminiRequest{}
			reqData.Contents = append(reqData.Contents, struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			}{
				Parts: []struct {
					Text string `json:"text"`
				}{{Text: fullPrompt}},
			})

			jsonData, _ := json.Marshal(reqData)
			resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				lastErr = err
				continue
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
				continue
			}

			var res map[string]interface{}
			json.Unmarshal(body, &res)

			candidates, ok := res["candidates"].([]interface{})
			if !ok || len(candidates) == 0 {
				lastErr = fmt.Errorf("no candidates in response")
				continue
			}
			
			content, ok := candidates[0].(map[string]interface{})["content"].(map[string]interface{})
			if !ok {
				lastErr = fmt.Errorf("no content in candidate")
				continue
			}
			
			parts, ok := content["parts"].([]interface{})
			if !ok || len(parts) == 0 {
				lastErr = fmt.Errorf("no parts in content")
				continue
			}
			
			text, ok := parts[0].(map[string]interface{})["text"].(string)
			if !ok {
				lastErr = fmt.Errorf("text is not a string")
				continue
			}

			return text, nil
		}
	}

	return "", fmt.Errorf("[GEMINI ALL FAILED] Last Error: %v", lastErr)
}

func handleGroq(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	if model == "" {
		model = "llama3-70b-8192"
	}
	return handleOpenAICompatible(client, "groq", key, prompt, system, model, hist)
}

func handleOpenAICompatible(client *http.Client, provider, key, prompt, system, model string, hist []Message) (string, error) {
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
	}

	if model == "" {
		switch provider {
		case "openrouter": model = "google/gemini-pro-1.5"
		case "deepseek": model = "deepseek-chat"
		case "openai": model = "gpt-4o"
		}
	}

	reqBody := OpenAIRequest{
		Model: model,
	}
	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "system", Content: system})

	// Add history
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
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var res map[string]interface{}
	json.Unmarshal(body, &res)

	choices, ok := res["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		if errorObj, ok := res["error"].(map[string]interface{}); ok {
			return "", fmt.Errorf("[%s ERROR] %v", provider, errorObj["message"])
		}
		return "", fmt.Errorf("[%s ERROR] Unexpected response: %s", provider, string(body))
	}
	
	message, ok := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("malformed message in choices")
	}
	
	text, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("content field is missing or not a string")
	}
	
	return text, nil
}

func handleClaude(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	url := "https://api.anthropic.com/v1/messages"
	if model == "" {
		model = "claude-3-haiku-20240307"
	}

	reqBody := ClaudeRequest{
		Model:     model,
		System:    system,
		MaxTokens: 1024,
	}
	
	// Add history
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
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var res map[string]interface{}
	json.Unmarshal(body, &res)

	content, ok := res["content"].([]interface{})
	if !ok || len(content) == 0 {
		if errorObj, ok := res["error"].(map[string]interface{}); ok {
			return "", fmt.Errorf("[CLAUDE ERROR] %v", errorObj["message"])
		}
		return "", fmt.Errorf("[CLAUDE ERROR] Unexpected response: %s", string(body))
	}
	
	text, ok := content[0].(map[string]interface{})["text"].(string)
	if !ok {
		return "", fmt.Errorf("text field is missing in content")
	}
	
	return text, nil
}

func getOllamaModels(client *http.Client) []string {
	url := "http://localhost:11434/api/tags"
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var res struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &res)

	var names []string
	for _, m := range res.Models {
		names = append(names, m.Name)
	}
	return names
}

func handleOllama(client *http.Client, modelName, prompt, system, model string, hist []Message) (string, error) {
	// 1. Resolve the model name correctly
	if model == "" {
		model = modelName
	}
	
	available := getOllamaModels(client)
	
	// Smart Match: If model is empty, default, or AUTO_DETECT, try to find best match
	found := false
	if model == "" || model == "llama3" || model == "AUTO_DETECT" {
		if len(available) > 0 {
			// Prefer high-performance ones if they exist
			for _, m := range available {
				if strings.HasPrefix(m, "llama3") || strings.HasPrefix(m, "mistral") || strings.HasPrefix(m, "qwen") {
					model = m
					found = true
					break
				}
			}
			if !found {
				model = available[0]
				found = true
			}
		}
	} else {
		// Specific model requested, verify it exists
		for _, m := range available {
			if m == model {
				found = true
				break
			}
		}
		// If not found exactly, try with prefix matching (tag resolution)
		if !found {
			for _, m := range available {
				if strings.HasPrefix(m, model+":") {
					model = m
					found = true
					break
				}
			}
		}
	}

	if model == "" {
		model = "llama3" // Final fallback attempt
	}

	url := "http://localhost:11434/api/chat"

	// Construct chat request
	reqBody := struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Stream bool `json:"stream"`
	}{
		Model:  model,
		Stream: false,
	}

	// System prompt
	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "system", Content: system})

	// History
	for _, msg := range hist {
		reqBody.Messages = append(reqBody.Messages, struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{Role: msg.Role, Content: msg.Content})
	}

	// User prompt
	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "user", Content: prompt})

	jsonData, _ := json.Marshal(reqBody)
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama connection failed: %v (is 'ollama serve' running?)", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama error %d: %s", resp.StatusCode, string(body))
	}

	var res map[string]interface{}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("failed to parse ollama response: %v", err)
	}

	message, ok := res["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response format from ollama: %s", string(body))
	}

	content, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("content is missing in assistant response")
	}

	return content, nil
}
