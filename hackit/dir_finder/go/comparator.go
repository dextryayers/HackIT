package main

import (
	"math"
	"strings"
	"unicode"
)

type ResponseProfile struct {
	Status   int
	Size     int64
	Words    int
	Lines    int
	Redirect string
	BodyHash string
}

func ProfileResponse(res *DirResult, body string) ResponseProfile {
	hash := bodyHash(body)
	return ResponseProfile{
		Status:   res.Status,
		Size:     res.Size,
		Words:    res.Words,
		Lines:    res.Lines,
		Redirect: res.Redirect,
		BodyHash: hash,
	}
}

func bodyHash(body string) string {
	if len(body) == 0 {
		return ""
	}
	step := len(body) / 128
	if step < 1 {
		step = 1
	}
	var sb strings.Builder
	for i := 0; i < len(body); i += step {
		sb.WriteByte(body[i])
	}
	return sb.String()
}

func CompareProfiles(a, b ResponseProfile) float64 {
	score := 0.0
	total := 6.0

	if a.Status == b.Status {
		score += 1.0
	}

	if a.Size == b.Size {
		score += 1.0
	} else {
		ratio := float64(a.Size) / float64(b.Size)
		if ratio < 1 {
			ratio = 1 / ratio
		}
		if ratio < 1.2 {
			score += 0.7
		} else if ratio < 2 {
			score += 0.3
		}
	}

	if a.Words == b.Words {
		score += 1.0
	} else {
		ratio := float64(a.Words) / float64(b.Words)
		if ratio < 1 {
			ratio = 1 / ratio
		}
		if ratio < 1.5 {
			score += 0.5
		}
	}

	if a.Lines == b.Lines {
		score += 1.0
	} else {
		ratio := float64(a.Lines) / float64(b.Lines)
		if ratio < 1 {
			ratio = 1 / ratio
		}
		if ratio < 1.5 {
			score += 0.5
		}
	}

	if a.Redirect == b.Redirect {
		score += 1.0
	} else if a.Redirect != "" && b.Redirect != "" {
		if strings.Contains(a.Redirect, b.Redirect) || strings.Contains(b.Redirect, a.Redirect) {
			score += 0.5
		}
	}

	if a.BodyHash == b.BodyHash {
		score += 1.0
	} else if len(a.BodyHash) > 0 && len(b.BodyHash) > 0 {
		match := 0
		for i := 0; i < int(math.Min(float64(len(a.BodyHash)), float64(len(b.BodyHash)))); i++ {
			if a.BodyHash[i] == b.BodyHash[i] {
				match++
			}
		}
		sim := float64(match) / float64(len(a.BodyHash))
		if sim > 0.8 {
			score += 0.7
		} else if sim > 0.5 {
			score += 0.3
		}
	}

	return score / total
}

func DetectSoft404(refBody, candidateBody string, refStatus, candidateStatus int) bool {
	if candidateStatus != 200 || refStatus != 200 {
		return false
	}
	refLower := strings.ToLower(refBody)
	candLower := strings.ToLower(candidateBody)

	notFoundKeywords := []string{
		"not found", "404", "page not found", "doesn't exist",
		"no results", "nothing found", "404 error",
		"could not be found", "not available", "http 404",
		"content not found", "no such page", "404 not found",
		"the requested url was not found", "page does not exist",
		"error 404", "page unavailable", "no page",
		"doesn't exist", "there is nothing here",
	}

	refCount := countKeywordOccurrences(refLower, notFoundKeywords)
	candCount := countKeywordOccurrences(candLower, notFoundKeywords)

	if candCount > refCount+2 {
		return true
	}

	if candCount >= 3 && candCount > refCount {
		return true
	}

	return false
}

func countKeywordOccurrences(text string, keywords []string) int {
	count := 0
	for _, kw := range keywords {
		count += strings.Count(text, kw)
	}
	return count
}

func AdaptiveWildcardThreshold(freq map[string]int, total int) (threshold int) {
	if total < 10 {
		return 0
	}
	highest := 0
	secondHighest := 0
	for _, count := range freq {
		if count > highest {
			secondHighest = highest
			highest = count
		} else if count > secondHighest {
			secondHighest = count
		}
	}

	if total >= 100 && highest > total/4 {
		return highest/2 + 1
	}
	if total >= 50 && highest > total/3 {
		return highest/3 + 1
	}
	if total >= 20 && highest > total/2 {
		return highest/2
	}
	return 0
}

func FuzzyBodySize(bodies []string, targetLen int) bool {
	if len(bodies) < 5 {
		return false
	}
	var sizes []int
	for _, b := range bodies {
		sizes = append(sizes, len(b))
	}
	mean := 0.0
	for _, s := range sizes {
		mean += float64(s)
	}
	mean /= float64(len(sizes))

	variance := 0.0
	for _, s := range sizes {
		diff := float64(s) - mean
		variance += diff * diff
	}
	variance /= float64(len(sizes))
	stdDev := math.Sqrt(variance)

	if stdDev < 10 {
		return true
	}

	return math.Abs(float64(targetLen)-mean) < stdDev*2
}

func CheckHoneypot(body string) bool {
	lower := strings.ToLower(body)
	honeypotSignals := []string{
		"<!-- do not delete",
		"<!-- honeypot",
		"class=\"honeypot\"",
		"id=\"honeypot\"",
		"display:none",
		"style=\"display:none\"",
		"visibility:hidden",
		"type=\"hidden\"",
		"autocomplete=\"off\"",
	}
	count := 0
	for _, sig := range honeypotSignals {
		if strings.Contains(lower, sig) {
			count++
		}
	}
	return count >= 3
}

func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimSuffix(path, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var result []rune
	for _, r := range path {
		if unicode.IsPrint(r) && r != '\x00' {
			result = append(result, r)
		}
	}
	return string(result)
}

func CleanURLPath(path string) string {
	path = NormalizePath(path)
	path = strings.ReplaceAll(path, "//", "/")
	path = strings.ReplaceAll(path, "/./", "/")
	for strings.Contains(path, "/../") {
		path = strings.ReplaceAll(path, "/../", "/")
	}
	return path
}

func PathDepth(path string) int {
	path = strings.Trim(path, "/")
	if path == "" {
		return 0
	}
	parts := strings.Split(path, "/")
	return len(parts)
}
