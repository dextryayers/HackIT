package main

import (
	"fmt"
	"strings"
)

// IntelligenceEngine handles complex logic for decision making
type IntelligenceEngine struct {
	Results []Result
}

func NewIntelligenceEngine(results []Result) *IntelligenceEngine {
	return &IntelligenceEngine{Results: results}
}

// AnalyzeThreats performs cross-analysis of results to find hidden threats
func (ie *IntelligenceEngine) AnalyzeThreats() {
	for _, res := range ie.Results {
		if res.AdvancedAnalysis != nil {
			// Check for high risk combinations
			isProtected := false
			for _, b := range res.AdvancedAnalysis.SuspectedBehaviours {
				if strings.Contains(b, "Protection") || strings.Contains(b, "Anti-Bot") {
					isProtected = true
					break
				}
			}

			if isProtected && res.AdvancedAnalysis.SecurityScore < 50 {
				fmt.Printf("[!] High Risk detected for %s: Protected but has weak security headers.\n", res.URL)
			}
		}
	}
}

// GetStealthAdvice returns recommendations for stealthier scanning based on WAF detection
func (ie *IntelligenceEngine) GetStealthAdvice(res Result) string {
	if len(res.WAFInfo) > 0 {
		wafList := strings.Join(res.WAFInfo, ", ")
		return fmt.Sprintf("WAF Detected (%s). Recommendation: Use -deep flag with --proxy and high --delay.", wafList)
	}
	return "No major WAF detected. Standard scanning should be fine."
}
