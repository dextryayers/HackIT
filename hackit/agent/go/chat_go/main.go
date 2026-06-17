package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
	cmd := flag.String("cmd", "", "Slash command mode")
	clearHist := flag.Bool("clear", false, "Clear conversation history")
	flag.Parse()

	history := NewHistoryManager()
	if *clearHist {
		history.Clear()
		fmt.Println(`{"text":"History cleared"}`)
		return
	}

	if *provider == "" || (*apiKey == "" && *provider != "ollama") || *prompt == "" {
		fmt.Println(`{"error":"Missing required flags"}`)
		os.Exit(1)
	}

	finalSystem := *system
	if finalSystem == "" {
		finalSystem = ChatSystemPrompt
	}
	if *cmd != "" {
		cmdSystem := GetCommandSystemPrompt(*cmd)
		if cmdSystem != "" {
			finalSystem = cmdSystem
		}
	}

	client := &http.Client{Timeout: 120 * time.Second}
	orch := NewIntelligenceOrchestrator(map[string]string{*provider: *apiKey})
	if *model == "" {
		*model = orch.GetOptimalModel(*provider)
	}

	histData := history.Load()

	var response string
	var err error

	switch *provider {
	case "gemini":
		response, err = callGemini(client, *apiKey, *prompt, finalSystem, *model, histData)
	case "groq", "openai", "openrouter", "deepseek", "mistral", "togetherai":
		response, err = callOpenAI(client, *provider, *apiKey, *prompt, finalSystem, *model, histData)
	case "claude":
		response, err = callClaude(client, *apiKey, *prompt, finalSystem, *model, histData)
	case "ollama":
		response, err = callOllama(client, *apiKey, *prompt, finalSystem, *model, histData)
	default:
		err = fmt.Errorf("unsupported provider: %s", *provider)
	}

	if err != nil {
		errResp := map[string]string{"error": err.Error()}
		jsonErr, _ := json.Marshal(errResp)
		fmt.Println(string(jsonErr))
		os.Exit(1)
	}

	histData = append(histData, Message{Role: "user", Content: *prompt})
	histData = append(histData, Message{Role: "assistant", Content: response})
	history.Save(histData)

	out := AIResponse{Text: strings.TrimSpace(response)}
	jsonOut, _ := json.Marshal(out)
	fmt.Println(string(jsonOut))
}
