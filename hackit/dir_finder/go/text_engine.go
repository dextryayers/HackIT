package main

import (
	"regexp"
	"strings"
)

type TextFilterResult struct {
	Filtered bool
	Reason   string
}

var regexCache = make(map[string]*regexp.Regexp)

func getRegex(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if re, ok := regexCache[pattern]; ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	regexCache[pattern] = re
	return re
}

func ExcludeByText(texts []string, body string) TextFilterResult {
	if len(texts) == 0 {
		return TextFilterResult{}
	}
	bodyLower := strings.ToLower(body)
	for _, t := range texts {
		if strings.Contains(bodyLower, strings.ToLower(t)) {
			return TextFilterResult{true, "text: " + t}
		}
	}
	return TextFilterResult{}
}

func ExcludeByRegex(pattern string, body string) TextFilterResult {
	if pattern == "" {
		return TextFilterResult{}
	}
	re := getRegex(pattern)
	if re == nil {
		return TextFilterResult{}
	}
	if re.MatchString(body) {
		return TextFilterResult{true, "regex"}
	}
	return TextFilterResult{}
}

func ExcludeByRedirect(pattern string, redirectURL string) TextFilterResult {
	if pattern == "" || redirectURL == "" {
		return TextFilterResult{}
	}
	re := getRegex(pattern)
	if re == nil {
		return TextFilterResult{}
	}
	if re.MatchString(redirectURL) {
		return TextFilterResult{true, "redirect"}
	}
	return TextFilterResult{}
}

func ExcludeByReference(res *DirResult, ref *DirResult) TextFilterResult {
	if ref == nil {
		return TextFilterResult{}
	}
	if res.Status == ref.Status && res.Size == ref.Size {
		if res.Words > 0 && ref.Words > 0 {
			diff := abs(res.Words - ref.Words)
			if diff*100/max(ref.Words, 1) < 10 {
				return TextFilterResult{true, "similar-to-reference"}
			}
		}
	}
	return TextFilterResult{}
}

func CheckResponseSimilarity(res1, res2 *DirResult) int {
	if res1 == nil || res2 == nil {
		return 0
	}
	score := 0
	if res1.Status == res2.Status {
		score += 30
	}
	if res1.Size == res2.Size {
		score += 30
	}
	if res1.Words > 0 && res2.Words > 0 {
		diff := abs(res1.Words - res2.Words)
		ratio := 100 - (diff * 100 / max(res2.Words, 1))
		if ratio > 0 {
			score += ratio / 3
		}
	}
	if res1.BodyHash != "" && res1.BodyHash == res2.BodyHash {
		score += 30
	}
	return min(score, 100)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
