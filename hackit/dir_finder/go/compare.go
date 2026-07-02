package main

import (
	"crypto/sha1"
	"fmt"
	"math"
	"strings"
	"sync"
)

type RespProfile struct {
	Status      int
	Size        int64
	Words       int
	Lines       int
	BodyHash    string
	ContentType string
	Title       string
}

type ResponseCluster struct {
	Profile    RespProfile
	Count      int
	Paths      []string
	IsWildcard bool
}

type CompareEngine struct {
	mu          sync.Mutex
	profiles  map[string]*ResponseCluster
	wildcard  *RespProfile
	threshold   float64
}

var compareEngine = &CompareEngine{
	profiles:  make(map[string]*ResponseCluster),
	threshold: 0.85,
}

func (ce *CompareEngine) SetWildcard(status int, size int64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.wildcard = &RespProfile{Status: status, Size: size}
}

func (ce *CompareEngine) profileKey(res *DirResult) string {
	return fmt.Sprintf("%s-%d-%d", res.BodyHash, res.Status, res.Size)
}

func (ce *CompareEngine) AddResponse(res *DirResult) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	key := ce.profileKey(res)
	cluster, exists := ce.profiles[key]
	if exists {
		cluster.Count++
		cluster.Paths = append(cluster.Paths, res.Path)
		return cluster.Count <= 10
	}

	ce.profiles[key] = &ResponseCluster{
		Profile: RespProfile{
			Status:      res.Status,
			Size:        res.Size,
			Words:       res.Words,
			Lines:       res.Lines,
			BodyHash:    res.BodyHash,
			ContentType: res.ContentType,
			Title:       res.Title,
		},
		Count: 1,
		Paths: []string{res.Path},
	}
	return true
}

func (ce *CompareEngine) IsDuplicate(res *DirResult) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	key := ce.profileKey(res)
	cluster, exists := ce.profiles[key]
	return exists && cluster.Count > 10
}

func (ce *CompareEngine) ClusterCount(res *DirResult) int {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	key := ce.profileKey(res)
	cluster, exists := ce.profiles[key]
	if !exists {
		return 0
	}
	return cluster.Count
}

func (ce *CompareEngine) MatchesWildcard(res *DirResult) bool {
	if ce.wildcard == nil {
		return false
	}
	if res.Status == ce.wildcard.Status && res.Size == ce.wildcard.Size {
		return true
	}
	return false
}

func (ce *CompareEngine) BodySimilarity(body1, body2 string) float64 {
	if len(body1) == 0 && len(body2) == 0 {
		return 1.0
	}
	if len(body1) == 0 || len(body2) == 0 {
		return 0.0
	}
	h1 := sha1.Sum([]byte(body1))
	h2 := sha1.Sum([]byte(body2))
	if h1 == h2 {
		return 1.0
	}

	s1 := strings.TrimSpace(body1)
	s2 := strings.TrimSpace(body2)
	if len(s1) > 500 {
		s1 = s1[:500]
	}
	if len(s2) > 500 {
		s2 = s2[:500]
	}

	if len(s1) < 10 || len(s2) < 10 {
		return 0.0
	}

	// Simple word overlap similarity
	words1 := strings.Fields(s1)
	words2 := strings.Fields(s2)
	if len(words1) == 0 || len(words2) == 0 {
		return 0.0
	}

	set1 := make(map[string]bool)
	for _, w := range words1 {
		set1[strings.ToLower(w)] = true
	}
	overlap := 0
	total := len(set1)
	seen := make(map[string]bool)
	for _, w := range words2 {
		wl := strings.ToLower(w)
		if set1[wl] && !seen[wl] {
			overlap++
			seen[wl] = true
		}
	}
	if total == 0 || len(words2) == 0 {
		return 0.0
	}
	return float64(overlap) / math.Max(float64(total), float64(len(words2)))
}

func (ce *CompareEngine) IsSoft404(res *DirResult, body string) bool {
	bodyLower := strings.ToLower(body)
	title := strings.ToLower(res.Title)
	keywords := []string{
		"not found", "error 404", "page not found", "doesn't exist",
		"no results", "nothing found", "404 error", "page unavailable",
		"this page could not be found", "http 404", "not available",
		"content not found", "no such page", "404 not found",
		"the requested url was not found", "page does not exist",
		"halaman tidak ditemukan", "pagina no encontrada",
		"seite nicht gefunden", "page non trouvee",
	}
	for _, kw := range keywords {
		if strings.Contains(bodyLower, kw) || strings.Contains(title, kw) {
			return true
		}
	}
	return false
}

func (ce *CompareEngine) DetectLanguage(body string) string {
	bodyLower := strings.ToLower(body)
	scores := map[string]int{
		"en": 0, "id": 0, "es": 0, "fr": 0, "de": 0, "ja": 0,
	}

	langPatterns := map[string][]string{
		"en": {"the", "and", "this", "that", "with", "from", "page", "not found", "error"},
		"id": {"yang", "dan", "ini", "tidak", "dengan", "untuk", "halaman", "tidak ditemukan"},
		"es": {"que", "con", "para", "esta", "por", "como", "pagina", "no encontrada"},
		"fr": {"que", "avec", "cette", "dans", "pour", "sur", "page", "non trouve"},
		"de": {"die", "und", "mit", "dieser", "nicht", "gefunden", "seite"},
		"ja": {"さん", "の", "を", "は", "が", "ページ"},
	}

	for lang, patterns := range langPatterns {
		for _, p := range patterns {
			scores[lang] += strings.Count(bodyLower, p)
		}
	}

	bestLang := "en"
	bestScore := 0
	for lang, score := range scores {
		if score > bestScore {
			bestScore = score
			bestLang = lang
		}
	}

	return bestLang
}

func (ce *CompareEngine) DetectCharset(body string, contentType string) string {
	ctLower := strings.ToLower(contentType)
	if idx := strings.Index(ctLower, "charset="); idx != -1 {
		charset := ctLower[idx+8:]
		if semi := strings.Index(charset, ";"); semi != -1 {
			charset = charset[:semi]
		}
		return strings.TrimSpace(charset)
	}
	// Try <meta charset="...">
	if idx := strings.Index(body, `charset="`); idx != -1 {
		end := strings.Index(body[idx+9:], `"`)
		if end != -1 {
			return body[idx+9 : idx+9+end]
		}
	}
	if idx := strings.Index(body, `charset=`); idx != -1 {
		end := strings.Index(body[idx+8:], `"`)
		if end != -1 {
			return body[idx+8 : idx+8+end]
		}
	}
	return "utf-8"
}

func (ce *CompareEngine) ExtractBodyPreview(body string, maxLen int) string {
	// Strip HTML tags for a clean preview
	stripped := stripHTMLTags(body)
	// Take first meaningful line
	lines := strings.SplitN(stripped, "\n", 3)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 {
			if len(line) > maxLen {
				return line[:maxLen] + "..."
			}
			return line
		}
	}
	return ""
}

func stripHTMLTags(s string) string {
	var result strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}
	return result.String()
}
