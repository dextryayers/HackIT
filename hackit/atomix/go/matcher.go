package main

import (
	"regexp"
	"strings"
	"sync"
)

var regexCache sync.Map

func getRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err == nil {
		regexCache.Store(pattern, re)
	}
	return re, err
}

func getHeadersMap(headers string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			result[strings.ToLower(line[:idx])] = strings.TrimSpace(line[idx+1:])
		}
	}
	return result
}

func MatchTemplate(resp *ResponseInfo, t *Template, reqIdx int) *MatchResult {
	matchers := t.Matchers
	if len(matchers) == 0 && reqIdx < len(t.Requests) {
		matchers = t.Requests[reqIdx].Matchers
	}
	if len(matchers) == 0 && len(t.Requests) > 0 {
		matchers = []MatcherCondition{{Type: "word", Words: t.Requests[0].Payloads}}
	}
	if len(matchers) == 0 {
		return &MatchResult{Matched: false}
	}

	body := resp.Body
	headers := resp.Headers

	for _, m := range matchers {
		part := m.Part
		if part == "" {
			part = "body"
		}

		var data string
		switch part {
		case "header":
			data = headers
		case "body":
			data = body
		case "all":
			data = headers + "\n" + body
		case "status_code":
			data = ""
		default:
			data = body
		}

		match := false
		switch m.Type {
		case "word":
			match = matchWords(data, m.Words, m.Condition)
		case "regex":
			match = matchRegexFast(data, m.Regex, m.Condition)
		case "status":
			match = matchStatus(resp.StatusCode, m.Status)
		case "size":
			match = matchSize(len(body), m.Size)
		case "dsl":
			match = matchDSL(resp, m)
		case "and":
			match = matchAll(data, m.Words, m.Regex, m.Status, m.Size)
		case "or":
			match = matchAny(data, m.Words, m.Regex, m.Status, m.Size)
		default:
			match = matchWords(data, m.Words, m.Condition)
		}

		if match {
			extracted := ""
			if t.Extractor != nil {
				extracted = extractData(data, t.Extractor)
			}
			name := m.Name
			if name == "" {
				name = t.ID
			}
			return &MatchResult{Matched: true, Extracted: extracted, MatcherName: name}
		}
	}
	return &MatchResult{Matched: false}
}

func matchWords(data string, words []string, condition string) bool {
	if len(words) == 0 {
		return false
	}
	if condition == "and" {
		for _, w := range words {
			if !strings.Contains(data, w) {
				return false
			}
		}
		return true
	}
	for _, w := range words {
		if strings.Contains(data, w) {
			return true
		}
	}
	return false
}

func matchRegexFast(data string, patterns []string, condition string) bool {
	if len(patterns) == 0 {
		return false
	}
	if condition == "and" {
		for _, p := range patterns {
			re, err := getRegex(p)
			if err != nil || !re.MatchString(data) {
				return false
			}
		}
		return true
	}
	for _, p := range patterns {
		re, err := getRegex(p)
		if err == nil && re.MatchString(data) {
			return true
		}
	}
	return false
}

func matchStatus(code int, statuses []int) bool {
	for _, s := range statuses {
		if code == s {
			return true
		}
	}
	return false
}

func matchSize(size int, sizes []int) bool {
	for _, s := range sizes {
		if size == s {
			return true
		}
	}
	return false
}

func matchDSL(resp *ResponseInfo, m MatcherCondition) bool {
	for _, expr := range m.Words {
		expr = strings.TrimSpace(expr)
		switch {
		case strings.Contains(expr, "status_code"):
			for _, s := range m.Status {
				if resp.StatusCode == s {
					return true
				}
			}
		case strings.Contains(expr, "content_length"):
			for _, s := range m.Size {
				if resp.BodyLen == s {
					return true
				}
			}
		case strings.Contains(expr, "contains"):
			parts := strings.SplitN(expr, "(", 2)
			if len(parts) == 2 {
				arg := strings.TrimRight(parts[1], ")")
				arg = strings.Trim(arg, "'\"")
				return strings.Contains(resp.Body, arg) || strings.Contains(resp.Headers, arg)
			}
		}
	}
	return false
}

func matchAll(data string, words []string, patterns []string, statuses []int, sizes []int) bool {
	return matchWords(data, words, "and") && matchRegexFast(data, patterns, "and")
}

func matchAny(data string, words []string, patterns []string, statuses []int, sizes []int) bool {
	return matchWords(data, words, "or") || matchRegexFast(data, patterns, "or")
}

func extractData(data string, e *Extractor) string {
	if e == nil {
		return ""
	}
	for _, p := range e.Regex {
		re, err := getRegex(p)
		if err != nil {
			continue
		}
		matches := re.FindStringSubmatch(data)
		if len(matches) > 1 {
			return matches[1]
		}
		if len(matches) > 0 {
			return matches[0]
		}
	}
	return ""
}

func truncateMatch(data string, words []string, maxLen int) string {
	for _, w := range words {
		idx := strings.Index(data, w)
		if idx >= 0 {
			start := idx - 20
			if start < 0 {
				start = 0
			}
			end := idx + len(w) + 20
			if end > len(data) {
				end = len(data)
			}
			snippet := data[start:end]
			if len(snippet) > maxLen {
				snippet = snippet[:maxLen] + "..."
			}
			return snippet
		}
	}
	if len(data) > maxLen {
		return data[:maxLen] + "..."
	}
	return data
}
