package core

import (
	"fmt"
	"math"
	"strings"
	"time"
)

type ResponseSignature struct {
	Length    int
	Body      string
	Words     []string
	Lines     int
	Time      time.Duration
	Hash      uint64
	Title     string
	StatusOK  bool
}

func (e *Engine) CreateSignature(body string, duration time.Duration) *ResponseSignature {
	sig := &ResponseSignature{
		Length:   len(body),
		Body:     body,
		Lines:    strings.Count(body, "\n"),
		Time:     duration,
		StatusOK: len(body) > 0,
	}

	words := strings.Fields(body)
	if len(words) > 50 {
		sig.Words = words[:50]
	} else {
		sig.Words = words
	}

	lower := strings.ToLower(body)
	if idx := strings.Index(lower, "<title>"); idx >= 0 {
		end := strings.Index(lower[idx:], "</title>")
		if end > 7 {
			sig.Title = body[idx+7 : idx+end]
		}
	}

	sig.Hash = hashString(body)
	return sig
}

func hashString(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

type DiffResult struct {
	IsDifferent    bool
	LengthDelta    int
	SimilarityPct  float64
	DiffSections   []string
	DynamicContent bool
	Reason         string
}

func (e *Engine) CompareResponses(base *ResponseSignature, test *ResponseSignature) *DiffResult {
	r := &DiffResult{}

	lenDiff := absInt(base.Length - test.Length)
	r.LengthDelta = lenDiff

	if base.Length == 0 && test.Length == 0 {
		r.IsDifferent = false
		r.Reason = "both empty"
		return r
	}
	if base.Length == 0 || test.Length == 0 {
		r.IsDifferent = true
		r.Reason = "one empty"
		return r
	}

	ratio := math.Min(float64(base.Length), float64(test.Length)) / math.Max(float64(base.Length), float64(test.Length))
	r.SimilarityPct = ratio * 100

	if ratio > 0.95 {
		r.IsDifferent = false
		r.Reason = fmt.Sprintf("similar (%.1f%%)", r.SimilarityPct)
		return r
	}

	if ratio < 0.85 {
		r.IsDifferent = true
		r.Reason = fmt.Sprintf("length diff: %d bytes (%.1f%%)", lenDiff, r.SimilarityPct)
		return r
	}

	if float64(absInt(base.Lines-test.Lines)) > float64(base.Lines)*0.2 {
		r.IsDifferent = true
		r.Reason = fmt.Sprintf("line count diff: %d vs %d", base.Lines, test.Lines)
		return r
	}

	if base.Title != test.Title {
		r.IsDifferent = true
		r.Reason = fmt.Sprintf("title changed: '%s' → '%s'", base.Title, test.Title)
		return r
	}

	wordMatches := 0
	maxWords := len(base.Words)
	if len(test.Words) < maxWords {
		maxWords = len(test.Words)
	}
	for i := 0; i < maxWords; i++ {
		if base.Words[i] == test.Words[i] {
			wordMatches++
		}
	}

	if maxWords > 0 {
		wordRatio := float64(wordMatches) / float64(maxWords)
		if wordRatio < 0.8 {
			r.IsDifferent = true
			r.DynamicContent = true
			r.Reason = fmt.Sprintf("word match: %.0f%%", wordRatio*100)
			return r
		}
	}

	r.IsDifferent = absInt(base.Length-test.Length) > 5
	if r.IsDifferent {
		r.Reason = fmt.Sprintf("slight diff: %d bytes", lenDiff)
	}
	return r
}

func (e *Engine) IsDynamicContent(baseBodies []string) bool {
	if len(baseBodies) < 3 {
		return false
	}
	sigs := make([]*ResponseSignature, len(baseBodies))
	for i, b := range baseBodies {
		sigs[i] = e.CreateSignature(b, e.LastResponseTime)
	}

	variance := 0
	for i := 1; i < len(sigs); i++ {
		diff := absInt(sigs[i].Length - sigs[0].Length)
		if diff > 50 {
			variance++
		}
	}

	return variance >= 2
}
