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

func emitJSON(value interface{}) {
	data, err := json.Marshal(value)
	if err != nil {
		return
	}
	fmt.Println(string(data))
}

func emitToken(token string) error {
	if token == "" {
		return nil
	}
	emitJSON(TokenEvent{Token: token})
	return nil
}

func fail(message string) {
	emitJSON(TokenEvent{Error: message})
	os.Exit(1)
}

func main() {
	provider := flag.String("provider", "", "AI Provider")
	apiKey := flag.String("key", "", "API Key")
	prompt := flag.String("prompt", "", "User Prompt")
	system := flag.String("system", "", "System Prompt")
	model := flag.String("model", "", "Model Name")
	cmd := flag.String("cmd", "", "Slash command mode")
	clearHist := flag.Bool("clear", false, "Clear conversation history")
	stream := flag.Bool("stream", false, "Stream tokens as NDJSON")
	noHistory := flag.Bool("no-history", false, "Do not load or save engine history")
	timeoutSec := flag.Int("timeout", 300, "Request timeout in seconds")
	flag.Parse()

	history := NewHistoryManager()
	if *clearHist {
		history.Clear()
		emitJSON(AIResponse{Text: "History cleared"})
		return
	}

	if *provider == "" || *prompt == "" {
		fail("Missing required flags: -provider and -prompt are required")
	}
	if *apiKey == "" && *provider != "ollama" {
		fail(fmt.Sprintf("API key for %s is not configured", *provider))
	}

	finalSystem := strings.TrimSpace(*system)
	if finalSystem == "" {
		finalSystem = ChatSystemPrompt
	}
	if *cmd != "" {
		// Append the command directive instead of replacing the caller's
		// Python system prompt (the previous behaviour discarded memory and
		// security context).
		if instruction := GetCommandInstruction(*cmd); instruction != "" {
			finalSystem += instruction
		}
	}

	keys := collectKeys(*provider, *apiKey)
	chain := providerChain(*provider, keys)
	if len(chain) == 0 {
		fail("No AI provider is configured")
	}

	historyData := []Message{}
	if !*noHistory {
		historyData = history.Load()
	}

	if *timeoutSec <= 0 {
		*timeoutSec = 300
	}
	client := &http.Client{Timeout: time.Duration(*timeoutSec) * time.Second}

	effectiveModel := strings.TrimSpace(*model)
	if effectiveModel == "" && *provider != "ollama" {
		effectiveModel = optimalModel(*provider)
	}

	var response string
	var lastErr error
	usedProvider := ""

	for _, candidate := range chain {
		key := keys[candidate]
		candidateModel := effectiveModel
		if candidate != *provider {
			// A model configured for one provider is usually invalid for
			// another; let the fallback provider choose its own default.
			candidateModel = ""
		}

		if *stream {
			emitted := 0
			var builder strings.Builder
			response, lastErr = streamProvider(
				client, candidate, key, *prompt, finalSystem, candidateModel,
				historyData,
				func(token string) error {
					emitted++
					builder.WriteString(token)
					return emitToken(token)
				},
			)
			if response == "" && builder.Len() > 0 {
				response = builder.String()
			}
			if lastErr == nil {
				usedProvider = candidate
				break
			}
			if emitted > 0 {
				// Partial output has already been streamed; switching
				// providers now would duplicate or corrupt the answer.
				fail(lastErr.Error())
			}
			continue
		}

		response, lastErr = callProvider(
			client, candidate, key, *prompt, finalSystem, candidateModel, historyData,
		)
		if lastErr == nil {
			usedProvider = candidate
			break
		}
	}

	if lastErr != nil {
		fail(lastErr.Error())
	}

	response = strings.TrimSpace(response)
	if response == "" {
		fail("The AI provider returned an empty response")
	}

	if !*noHistory {
		historyData = append(historyData, Message{Role: "user", Content: *prompt})
		historyData = append(historyData, Message{Role: "assistant", Content: response})
		history.Save(historyData)
	}

	if *stream {
		emitJSON(TokenEvent{Done: true})
		return
	}

	_ = usedProvider // kept for future telemetry
	emitJSON(AIResponse{Text: response})
}
