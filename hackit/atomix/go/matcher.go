package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

var regexCache sync.Map
var regexCacheCount int32

func getRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Bound cache to avoid unbounded growth (nuclei-style precompile).
	if atomic.LoadInt32(&regexCacheCount) < 2000 {
		regexCache.Store(pattern, re)
		atomic.AddInt32(&regexCacheCount, 1)
	}
	return re, nil
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
	cond := t.MatchersCondition
	if len(matchers) == 0 && reqIdx < len(t.Requests) {
		matchers = t.Requests[reqIdx].Matchers
		if t.Requests[reqIdx].MatchersCondition != "" {
			cond = t.Requests[reqIdx].MatchersCondition
		}
	}
	if len(matchers) == 0 {
		return &MatchResult{Matched: false}
	}

	body := resp.Body
	headers := resp.Headers

	andMode := strings.ToLower(strings.TrimSpace(cond)) == "and"
	var firstHit *MatchResult

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

		if m.Negative {
			match = !match
		}

		if andMode && !match {
			return &MatchResult{Matched: false}
		}

		if match && firstHit == nil {
			extracted := extractAll(data, t)
			name := m.Name
			if name == "" {
				name = t.ID
			}
			firstHit = &MatchResult{Matched: true, Extracted: extracted, MatcherName: name}
			if !andMode {
				return firstHit
			}
		}
	}
	if andMode {
		if firstHit == nil {
			return &MatchResult{Matched: false}
		}
		return firstHit
	}
	return &MatchResult{Matched: false}
}

// extractAll runs the legacy single extractor plus the Nuclei plural form.
func extractAll(data string, t *Template) string {
	parts := []string{}
	if t.Extractor != nil {
		if e := extractData(data, t.Extractor); e != "" {
			parts = append(parts, e)
		}
	}
	for _, e := range t.Extractors {
		if e == nil {
			continue
		}
		if x := extractData(data, e); x != "" {
			parts = append(parts, x)
		}
	}
	return strings.Join(parts, "; ")
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
	if len(sizes) == 0 {
		return false
	}
	// Single value with negative sentinel encoding a range is not used;
	// exact match preserves nuclei `size` semantics.
	for _, s := range sizes {
		if size == s {
			return true
		}
	}
	return false
}

func matchDSL(resp *ResponseInfo, m MatcherCondition) bool {
	exprs := m.DSL
	if len(exprs) == 0 {
		exprs = m.Words
	}
	// Overall semantic: OR across || groups, AND within && atoms.
	for _, e := range exprs {
		for _, group := range strings.Split(e, "||") {
			ok := true
			any := false
			for _, atom := range strings.Split(group, "&&") {
				atom = strings.TrimSpace(atom)
				if atom == "" {
					continue
				}
				any = true
				if !evalDSLAtom(atom, resp) {
					ok = false
					break
				}
			}
			if any && ok {
				return true
			}
		}
	}
	return false
}

func dslStrArg(s string) string {
	s = strings.TrimSpace(s)
	return strings.Trim(s, "'\"")
}

func evalDSLAtom(expr string, resp *ResponseInfo) bool {
	neg := false
	if strings.HasPrefix(expr, "!") {
		neg = true
		expr = strings.TrimSpace(expr[1:])
	}
	out := evalDSLPositive(expr, resp)
	if neg {
		return !out
	}
	return out
}

func evalDSLPositive(expr string, resp *ResponseInfo) bool {
	low := strings.ToLower(expr)
	// Comparisons: status_code/content_length/body_size/duration OP number
	for _, field := range []struct {
		key string
		val float64
	}{
		{"status_code", float64(resp.StatusCode)},
		{"content_length", float64(resp.BodyLen)},
		{"body_size", float64(resp.BodyLen)},
		{"body_length", float64(resp.BodyLen)},
		{"duration", resp.Duration.Seconds()},
	} {
		if strings.HasPrefix(low, field.key) {
			rest := strings.TrimSpace(expr[len(field.key):])
			for _, op := range []string{">=", "<=", "!=", "==", ">", "<", "="} {
				if strings.HasPrefix(rest, op) {
					numStr := strings.TrimSpace(rest[len(op):])
					var want float64
					if _, err := fmt.Sscanf(numStr, "%f", &want); err != nil {
						return false
					}
					switch op {
					case ">=":
						return field.val >= want
					case "<=":
						return field.val <= want
					case "!=", "=":
						if op == "=" {
							return field.val == want
						}
						return field.val != want
					case "==":
						return field.val == want
					case ">":
						return field.val > want
					case "<":
						return field.val < want
					}
				}
			}
			return false
		}
	}
	arg2 := func(inner string) (string, string) {
		parts := strings.SplitN(inner, ",", 2)
		if len(parts) != 2 {
			return "", ""
		}
		return strings.TrimSpace(parts[0]), dslStrArg(parts[1])
	}
	innerOf := func(expr, fn string) (string, bool) {
		if !strings.HasPrefix(low, fn+"(") || !strings.HasSuffix(strings.TrimSpace(expr), ")") {
			return "", false
		}
		open := strings.Index(expr, "(")
		return expr[open+1 : len(strings.TrimSpace(expr))-1], true
	}
	body := resp.Body
	header := resp.Headers
	if inner, ok := innerOf(expr, "contains"); ok {
		target, needle := arg2(inner)
		hay := body
		if strings.ToLower(target) == "header" {
			hay = header
		}
		return strings.Contains(hay, needle)
	}
	if inner, ok := innerOf(expr, "contains_any"); ok {
		target, rest := arg2(inner)
		hay := body
		if strings.ToLower(target) == "header" {
			hay = header
		}
		for _, n := range strings.Split(rest, "|") {
			if strings.Contains(hay, strings.TrimSpace(n)) {
				return true
			}
		}
		return false
	}
	if inner, ok := innerOf(expr, "contains_all"); ok {
		target, rest := inner, ""
		if idx := strings.Index(inner, ","); idx >= 0 {
			target, rest = inner[:idx], inner[idx+1:]
		}
		hay := body
		if strings.ToLower(strings.TrimSpace(target)) == "header" {
			hay = header
		}
		for _, n := range strings.Split(rest, "|") {
			if !strings.Contains(hay, strings.TrimSpace(n)) {
				return false
			}
		}
		return true
	}
	if inner, ok := innerOf(expr, "regex"); ok {
		target, pattern := arg2(inner)
		hay := body
		if strings.ToLower(target) == "header" {
			hay = header
		}
		re, err := getRegex(pattern)
		return err == nil && re.MatchString(hay)
	}
	if inner, ok := innerOf(expr, "starts_with"); ok {
		target, needle := arg2(inner)
		hay := body
		if strings.ToLower(target) == "header" {
			hay = header
		}
		return strings.HasPrefix(hay, needle)
	}
	if inner, ok := innerOf(expr, "ends_with"); ok {
		target, needle := arg2(inner)
		hay := body
		if strings.ToLower(target) == "header" {
			hay = header
		}
		return strings.HasSuffix(hay, needle)
	}
	// Legacy single-arg contains(...) fallback.
	return legacyMatchDSL(resp, expr)
}

func legacyMatchDSL(resp *ResponseInfo, expr string) bool {
	expr = strings.TrimSpace(expr)
	switch {
	case strings.Contains(expr, "status_code"):
		return false
	case strings.Contains(expr, "content_length"):
		return false
	case strings.Contains(expr, "contains"):
		parts := strings.SplitN(expr, "(", 2)
		if len(parts) == 2 {
			arg := strings.TrimRight(parts[1], ")")
			arg = strings.Trim(arg, "'\"")
			return strings.Contains(resp.Body, arg) || strings.Contains(resp.Headers, arg)
		}
	}
	return false
}

func matchAll(data string, words []string, patterns []string, statuses []int, sizes []int) bool {
	if len(words) > 0 && !matchWords(data, words, "and") {
		return false
	}
	if len(patterns) > 0 && !matchRegexFast(data, patterns, "and") {
		return false
	}
	// status/size need response context; when only they are set, the
	// caller (MatchTemplate) already evaluated them. Here require at
	// least one body signal to avoid vacuous-true.
	if len(words) == 0 && len(patterns) == 0 {
		return false
	}
	return true
}

func matchAny(data string, words []string, patterns []string, statuses []int, sizes []int) bool {
	if matchWords(data, words, "or") {
		return true
	}
	if matchRegexFast(data, patterns, "or") {
		return true
	}
	return false
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
