package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"hackit_ai_engine/swarm/orchestrator"
)

func emitJSON(value interface{}) {
	data, err := json.Marshal(value)
	if err != nil {
		return
	}
	fmt.Println(string(data))
}

func emitToken(kind, token string) error {
	if token == "" {
		return nil
	}
	if kind == "" {
		kind = "answer"
	}
	emitJSON(TokenEvent{Token: token, Kind: kind})
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
	analyze := flag.Bool("analyze", false, "Enable Vulnerability Analysis Mode")
	toolName := flag.String("tool", "", "Name of the tool being analyzed")
	clearHist := flag.Bool("clear", false, "Clear conversation history")
	mode := flag.String("mode", "", "Specialized Command Mode (e.g., risk, attack)")
	autopilot := flag.String("autopilot", "", "Target for Autonomous AI Bug Hunter")
	swarmMode := flag.String("swarm", "", "Trigger 28-Node Autonomous Swarm on Target")
	swarmScope := flag.String("swarm-scope", "passive", "Scope for Swarm (passive, active_stealth, aggressive)")
	stream := flag.Bool("stream", false, "Stream tokens as NDJSON")
	noHistory := flag.Bool("no-history", false, "Do not load or save engine history")
	timeoutSec := flag.Int("timeout", 300, "Request timeout in seconds")
	jsonMode := flag.Bool("json", false, "Request JSON-formatted output (Ollama format=json)")
	maxTokens := flag.Int("max-tokens", 0, "Maximum response tokens (0 = provider default)")
	thinkMode := flag.String("think", "auto", "Ollama reasoning mode: auto|on|off")
	flag.Parse()

	maxTokensSetting = *maxTokens
	jsonModeSetting = *jsonMode
	thinkModeSetting = *thinkMode

	history := NewHistoryManager()
	if *clearHist {
		history.Clear()
		emitJSON(AIResponse{Text: "History cleared successfully"})
		return
	}

	if *autopilot != "" {
		hunter := &AutonomousHunter{Target: *autopilot}
		hunter.Run()
		return
	}

	if *swarmMode != "" {
		masterNode := orchestrator.NewOrchestratorAgent()
		if err := masterNode.Execute(*swarmMode, *swarmScope); err != nil {
			fail(fmt.Sprintf("Swarm execution failed: %v", err))
		}
		return
	}

	if *provider == "" || (*apiKey == "" && *provider != "ollama") ||
		(*prompt == "" && !*analyze) {
		fail("Missing required flags: -provider, -prompt and -key (except Ollama)")
	}

	finalPrompt := *prompt
	finalSystem := strings.TrimSpace(*system)

	if *mode != "" {
		if instruction := GetCommandInstruction(*mode); instruction != "" {
			finalSystem += "\n" + instruction
		}
	}

	if *analyze {
		analyzer := NewVulnerabilityAnalyzer()
		finalPrompt = analyzer.GenerateAnalysisPrompt(*toolName, analyzer.CleanScanData(*prompt))
		finalSystem = analyzer.SystemPrompt
	}

	keys := collectProviderKeys(*provider, *apiKey)
	if *provider != "ollama" && keys[*provider] == "" {
		fail(fmt.Sprintf("API key for %s is not configured", *provider))
	}
	keysOrchestrator := NewIntelligenceOrchestrator(keys)

	effectiveModel := strings.TrimSpace(*model)
	if effectiveModel == "" {
		effectiveModel = defaultModelFor(*provider)
	}

	client := &http.Client{Timeout: time.Duration(*timeoutSec) * time.Second}

	// The cache key must use the effective model, otherwise entries written
	// after auto-detection can never be found again.
	cache := NewResponseCache()
	cacheable := !*analyze && *autopilot == "" && *swarmMode == "" && !*stream
	cacheSystem := *system
	if cacheable {
		if cached, ok := cache.Get(*provider, effectiveModel, *prompt, cacheSystem); ok {
			emitJSON(AIResponse{Text: cached})
			return
		}
	}

	historyData := []Message{}
	if !*noHistory {
		historyData = history.Load()
	}

	// Probe provider latencies in the background only when there is more than
	// one provider to choose from.
	if len(keysOrchestrator.FallbackChain) > 1 {
		go keysOrchestrator.ProbeLatency(3 * time.Second)
	}

	chain := buildProviderChain(*provider, keys)
	var response string
	var lastErr error
	usedProvider := ""

	for _, candidate := range chain {
		key := keys[candidate]
		if key == "" && candidate != "ollama" {
			continue
		}
		candidateModel := ""
		if candidate == *provider {
			candidateModel = effectiveModel
		}

		if *stream {
			emitted := 0
			var builder strings.Builder
			response, lastErr = streamProvider(
				client, candidate, key, finalPrompt, finalSystem, candidateModel,
				historyData,
				func(kind, token string) error {
					if kind == "" || kind == "answer" {
						emitted++
						builder.WriteString(token)
					}
					return emitToken(kind, token)
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
				fail(lastErr.Error())
			}
			continue
		}

		response, lastErr = callProvider(
			client, candidate, key, finalPrompt, finalSystem, candidateModel, historyData,
		)
		if lastErr == nil {
			usedProvider = candidate
			break
		}
	}

	if lastErr != nil {
		ranked := keysOrchestrator.RankByLatency()
		hint := ""
		if len(ranked) > 0 {
			hint = fmt.Sprintf(" Fastest available: %s.", ranked[0])
		}
		fail(fmt.Sprintf("All %d provider(s) failed. Last error: %v.%s",
			len(chain), lastErr, hint))
	}

	response = strings.TrimSpace(response)
	if response == "" {
		fail("The AI provider returned an empty response")
	}

	if !*noHistory {
		historyData = append(historyData, Message{Role: "user", Content: finalPrompt})
		historyData = append(historyData, Message{Role: "assistant", Content: response})
		history.Save(historyData)
	}

	if cacheable {
		cache.Set(*provider, effectiveModel, *prompt, cacheSystem, response, 300)
	}

	if *stream {
		emitJSON(TokenEvent{Done: true})
		return
	}

	_ = usedProvider // reserved for future telemetry
	emitJSON(AIResponse{Text: response})
}
