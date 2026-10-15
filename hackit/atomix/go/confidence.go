package main

import (
	"sort"
	"strings"
)

// Confidence scoring: every finding carries high/medium/low confidence so
// operators can separate direct observations from weak heuristics.
// Evidence-only rules (no CVE/severity bump — a famous CVE name is not
// evidence by itself).

func confidenceRank(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// scoreMatcherConfidence grades one matcher that just fired.
func scoreMatcherConfidence(m MatcherCondition, data string, andMode bool) string {
	// Observed absence (missing header/protection) is direct evidence.
	if m.Negative {
		return "high"
	}
	// Compound logic passing as a whole is strong evidence.
	if andMode || m.Type == "dsl" || m.Type == "and" {
		return "high"
	}
	switch m.Type {
	case "status", "size":
		return "low" // status alone proves little
	case "regex":
		return "medium"
	case "or":
		return wordConfidence(data, m.Words)
	case "word", "":
		// Exact header value matches are strong observations.
		if (m.Part == "header" || m.Part == "all") && headerValueMatch(data, m.Words) {
			return "high"
		}
		return wordConfidence(data, m.Words)
	default:
		return wordConfidence(data, m.Words)
	}
}

// wordConfidence grades word matchers by specificity of the token that
// actually fired. Short generic tokens (e.g. "admin", "token") are weak;
// long distinctive strings are solid.
func wordConfidence(data string, words []string) string {
	best := 0
	for _, w := range words {
		if w == "" {
			continue
		}
		if strings.Contains(data, w) && len(w) > best {
			best = len(w)
		}
	}
	switch {
	case best >= 12:
		return "high"
	case best >= 6:
		return "medium"
	default:
		return "low"
	}
}

// headerValueMatch reports whether a full "Name: value" assertion fired.
func headerValueMatch(data string, words []string) bool {
	for _, w := range words {
		if strings.Contains(w, ":") && strings.Contains(data, w) {
			return true
		}
	}
	return false
}

// MeetsThreshold reports whether conf satisfies a minimum level.
func MeetsThreshold(conf, min string) bool {
	if min == "" {
		return true
	}
	return confidenceRank(conf) >= confidenceRank(min)
}

// FilterByConfidence keeps findings at or above min ("low", "medium", "high").
// Empty min keeps everything. Blank confidence counts as low.
func FilterByConfidence(results []Result, min string) []Result {
	if strings.TrimSpace(min) == "" {
		return results
	}
	out := results[:0]
	for _, r := range results {
		c := r.Confidence
		if c == "" {
			c = "low"
		}
		if MeetsThreshold(c, min) {
			out = append(out, r)
		}
	}
	return out
}

// SortResults orders by severity, then confidence, then template id for
// stable output across runs.
func SortResults(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		si, sj := severityRank(results[i].Severity), severityRank(results[j].Severity)
		if si != sj {
			return si > sj
		}
		ci, cj := confidenceRank(results[i].Confidence), confidenceRank(results[j].Confidence)
		if ci != cj {
			return ci > cj
		}
		return results[i].TemplateID < results[j].TemplateID
	})
}
