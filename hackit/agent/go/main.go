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

	"hackit_ai_engine/swarm/orchestrator"
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
	autopilot := flag.String("autopilot", "", "Target for Autonomous AI Bug Hunter")
	swarmMode := flag.String("swarm", "", "Trigger 20-Node Autonomous Swarm on Target")
	swarmScope := flag.String("swarm-scope", "passive", "Scope for Swarm (passive, active_stealth, aggressive)")
	stream := flag.Bool("stream", false, "Enable token-by-token streaming output")
	flag.Parse()

	history := NewHistoryManager()
	if *clearHist {
		history.Clear()
		fmt.Println(`{"text": "History cleared successfully"}`)
		return
	}

	if *autopilot != "" {
		hunter := &AutonomousHunter{Target: *autopilot}
		hunter.Run()
		return
	}

	if *swarmMode != "" {
		masterNode := orchestrator.NewOrchestratorAgent()
		err := masterNode.Execute(*swarmMode, *swarmScope)
		if err != nil {
			fmt.Printf(`{"error": "Swarm execution failed: %v"}`+"\n", err)
			os.Exit(1)
		}
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

	client := &http.Client{Timeout: 120 * time.Second}
	var response string
	var err error

	keys := make(map[string]string)
	keys[*provider] = *apiKey
	orchestrator := NewIntelligenceOrchestrator(keys)

	// Response cache for non-analysis queries
	cache := NewResponseCache()
	if !*analyze && *autopilot == "" && *swarmMode == "" {
		if cached, ok := cache.Get(*provider, *model, *prompt, *system); ok {
			out := AIResponse{Text: cached}
			jsonOut, _ := json.Marshal(out)
			fmt.Println(string(jsonOut))
			return
		}
	}

	// Probe provider latencies in background
	go orchestrator.ProbeLatency(5 * time.Second)

	histData := history.Load()

	// Try requested provider first, then fallback chain
	providersToTry := []string{*provider}
	if *model == "" {
		*model = orchestrator.GetOptimalModel(*provider)
	}

	for _, p := range orchestrator.FallbackChain {
		if p != *provider {
			providersToTry = append(providersToTry, p)
		}
		if len(providersToTry) >= 5 {
			break
		}
	}

	for _, p := range providersToTry {
		key := orchestrator.Providers[p]
		if p == "ollama" {
			response, err = handleOllama(client, "", finalPrompt, finalSystem, "", histData)
		} else if key == "" {
			continue
		} else {
			switch p {
			case "gemini":
				response, err = handleGemini(client, key, finalPrompt, finalSystem, "", histData)
			case "claude":
				response, err = handleClaude(client, key, finalPrompt, finalSystem, "", histData)
			default:
				response, err = handleOpenAICompatible(client, p, key, finalPrompt, finalSystem, "", histData)
			}
		}
		if err == nil {
			break
		}
		if p != *provider {
			fmt.Fprintf(os.Stderr, `{"fallback":"%s failed, trying %s: %v"}`+"\n", p, providersToTry[1], err)
		}
	}

	if err != nil {
		ranked := orchestrator.RankByLatency()
		hint := ""
		if len(ranked) > 0 {
			hint = fmt.Sprintf(" Fastest available: %s", ranked[0])
		}
		errResp := map[string]string{
			"error": fmt.Sprintf("All %d providers failed. Last error: %v.%s",
				len(providersToTry), err, hint),
		}
		jsonErr, _ := json.Marshal(errResp)
		fmt.Println(string(jsonErr))
		os.Exit(1)
	}

	// Handle streaming output
	if *stream {
		words := strings.Fields(response)
		for _, word := range words {
			token := map[string]string{"token": word + " "}
			tokenJSON, _ := json.Marshal(token)
			fmt.Println(string(tokenJSON))
			time.Sleep(15 * time.Millisecond)
		}
		fmt.Println(`{"done":true}`)
		return
	}

	// Save history
	histData = append(histData, Message{Role: "user", Content: finalPrompt})
	histData = append(histData, Message{Role: "assistant", Content: response})
	history.Save(histData)

	// Cache result (300s TTL for non-analysis queries)
	if !*analyze && *autopilot == "" && *swarmMode == "" {
		cache.Set(*provider, *model, *prompt, *system, response, 300)
	}

	out := AIResponse{Text: response}
	jsonOut, _ := json.Marshal(out)
	fmt.Println(string(jsonOut))
}

func handleGemini(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	defaults := []string{"gemini-3.5-flash", "gemini-3.1-flash-lite", "gemini-3-flash", "gemini-2.5-flash", "gemini-2.0-flash"}
	modelsToTry := defaults
	if model != "" {
		modelsToTry = []string{model}
		modelsToTry = append(modelsToTry, defaults...)
	}

	apiVersions := []string{"v1", "v1beta"}
	var errs []string

	for _, m := range modelsToTry {
		if m == "" {
			continue
		}
		for _, apiVer := range apiVersions {
			url := fmt.Sprintf("https://generativelanguage.googleapis.com/%s/models/%s:generateContent", apiVer, m)

			contents := []map[string]interface{}{}
			if system != "" {
				contents = append(contents, map[string]interface{}{
					"role": "user",
					"parts": []map[string]string{
						{"text": fmt.Sprintf("[System Instruction]\n%s\n\nUse the above system instruction to guide all responses.", system)},
					},
				})
			}
			for _, msg := range hist {
				contents = append(contents, map[string]interface{}{
					"role":  msg.Role,
					"parts": []map[string]string{{"text": msg.Content}},
				})
			}
			contents = append(contents, map[string]interface{}{
				"role":  "user",
				"parts": []map[string]string{{"text": prompt}},
			})

			reqData := map[string]interface{}{"contents": contents}
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

			var res map[string]interface{}
			json.Unmarshal(body, &res)

			candidates, ok := res["candidates"].([]interface{})
			if !ok || len(candidates) == 0 {
				if errObj, ok := res["error"].(map[string]interface{}); ok {
					errs = append(errs, fmt.Sprintf("%s(%s): %v", m, apiVer, errObj["message"]))
				} else {
					errs = append(errs, fmt.Sprintf("%s(%s): no candidates", m, apiVer))
				}
				continue
			}

			content, ok := candidates[0].(map[string]interface{})["content"].(map[string]interface{})
			if !ok {
				errs = append(errs, fmt.Sprintf("%s(%s): no content", m, apiVer))
				continue
			}
			parts, ok := content["parts"].([]interface{})
			if !ok || len(parts) == 0 {
				errs = append(errs, fmt.Sprintf("%s(%s): no parts", m, apiVer))
				continue
			}
			text, ok := parts[0].(map[string]interface{})["text"].(string)
			if !ok {
				errs = append(errs, fmt.Sprintf("%s(%s): not a string", m, apiVer))
				continue
			}
			return text, nil
		}
	}
	return "", fmt.Errorf("[GEMINI all %d attempts failed] %s", len(errs), strings.Join(errs, "; "))
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
	case "mistral":
		url = "https://api.mistral.ai/v1/chat/completions"
	case "togetherai":
		url = "https://api.together.xyz/v1/chat/completions"
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

	reqBody := OpenAIRequest{
		Model:     model,
		MaxTokens: 4096,
	}
	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "system", Content: system})

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
		req.Header.Set("X-Title", "HackIt AI")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errRes map[string]interface{}
		json.Unmarshal(body, &errRes)
		if errorObj, ok := errRes["error"].(map[string]interface{}); ok {
			errMsg, _ := errorObj["message"].(string)
			if provider == "openrouter" && !strings.HasSuffix(model, ":free") &&
				(strings.Contains(errMsg, "credits") || strings.Contains(errMsg, "paid") ||
					strings.Contains(errMsg, "upgrade") || strings.Contains(errMsg, "insufficient")) {
				model2 := model + ":free"
				return handleOpenAICompatible(client, provider, key, prompt, system, model2, hist)
			}
			return "", fmt.Errorf("[%s ERROR] %s", provider, errMsg)
		}
		return "", fmt.Errorf("[%s ERROR] HTTP %d: %s", provider, resp.StatusCode, string(body))
	}

	var res map[string]interface{}
	json.Unmarshal(body, &res)

	choices, ok := res["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("[%s ERROR] no choices in response: %s", provider, string(body))
	}

	message, ok := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("[%s ERROR] malformed message in choices", provider)
	}

	text, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("[%s ERROR] content field missing or not a string", provider)
	}

	return text, nil
}

func handleClaude(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	url := "https://api.anthropic.com/v1/messages"
	if model == "" {
		model = "claude-3-5-haiku-20241022"
	}

	reqBody := ClaudeRequest{
		Model:     model,
		System:    system,
		MaxTokens: 8192,
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
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errRes map[string]interface{}
		json.Unmarshal(body, &errRes)
		if errorObj, ok := errRes["error"].(map[string]interface{}); ok {
			return "", fmt.Errorf("[CLAUDE ERROR] %v", errorObj["message"])
		}
		return "", fmt.Errorf("[CLAUDE ERROR] HTTP %d: %s", resp.StatusCode, string(body))
	}

	var res map[string]interface{}
	json.Unmarshal(body, &res)

	content, ok := res["content"].([]interface{})
	if !ok || len(content) == 0 {
		return "", fmt.Errorf("[CLAUDE ERROR] no content in response: %s", string(body))
	}

	text, ok := content[0].(map[string]interface{})["text"].(string)
	if !ok {
		return "", fmt.Errorf("[CLAUDE ERROR] text field missing in content")
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

func handleOllama(client *http.Client, key, prompt, system, model string, hist []Message) (string, error) {
	if model == "" {
		model = key // Ollama uses model name from key field
	}

	available := getOllamaModels(client)

	found := false
	if model == "" || model == "llama3" || model == "AUTO_DETECT" {
		if len(available) > 0 {
			for _, m := range available {
				if strings.HasPrefix(m, "llama3") || strings.HasPrefix(m, "mistral") || strings.HasPrefix(m, "qwen") {
					model = m
					found = true
					break
				}
			}
			if !found {
				model = available[0]
			}
		}
	} else {
		for _, m := range available {
			if m == model || strings.HasPrefix(m, model+":") {
				model = m
				found = true
				break
			}
		}
	}

	if model == "" {
		model = "llama3"
	}

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

	reqBody.Messages = append(reqBody.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "system", Content: system})

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
	req, err := http.NewRequest("POST", "http://localhost:11434/api/chat", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("[OLLAMA] HTTP %d: %s", resp.StatusCode, string(body))
	}

	var res map[string]interface{}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("[OLLAMA] parse error: %v", err)
	}

	message, ok := res["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("[OLLAMA] unexpected response format: %s", string(body))
	}

	content, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("[OLLAMA] content missing in response")
	}

	return content, nil
}
