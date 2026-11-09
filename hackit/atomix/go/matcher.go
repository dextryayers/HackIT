package main

import (
	"encoding/json"
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
	// Bound cache to avoid unbounded growth on large template libraries.
	if atomic.LoadInt32(&regexCacheCount) < 2000 {
		regexCache.Store(pattern, re)
		atomic.AddInt32(&regexCacheCount, 1)
	}
	return re, nil
}

// getRegexCI compiles pattern case-insensitively when ci is set. The
// cache key is prefixed so case variants stay distinct.
func getRegexCI(pattern string, ci bool) (*regexp.Regexp, error) {
	if !ci {
		return getRegex(pattern)
	}
	if strings.HasPrefix(pattern, "(?i)") {
		return getRegex(pattern)
	}
	return getRegex("(?i)" + pattern)
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

	andMode := strings.EqualFold(strings.TrimSpace(cond), "and")
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
		case "all", "response":
			data = headers + "\n" + body
		case "status_code":
			data = ""
		default:
			data = body
		}

		match := false
		switch m.Type {
		case "word":
			match = matchWords(data, m.Words, m.Condition, m.CaseInsensitive)
		case "regex":
			match = matchRegexFast(data, m.Regex, m.Condition, m.CaseInsensitive)
		case "status":
			match = matchStatus(resp.StatusCode, m.Status)
		case "size":
			match = matchSize(resp.BodyLen, m.Size)
		case "dsl":
			match = matchDSL(resp, m)
		case "and":
			match = matchAll(resp, data, m)
		case "or":
			match = matchAny(resp, data, m)
		default:
			match = matchWords(data, m.Words, m.Condition, m.CaseInsensitive)
		}

		if m.Negative {
			match = !match
		}

		if andMode && !match {
			return &MatchResult{Matched: false}
		}

		if match && firstHit == nil {
			extracted := extractAll(data, resp, t, reqIdx)
			name := m.Name
			if name == "" {
				name = t.ID
			}
			firstHit = &MatchResult{
				Matched:     true,
				Extracted:   extracted,
				MatcherName: name,
				Confidence:  scoreMatcherConfidence(m, data, andMode),
			}
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

// extractAll gathers output from request-scoped extractors, the legacy
// single template-level extractor and the plural template-level form.
func extractAll(data string, resp *ResponseInfo, t *Template, reqIdx ...int) string {
	parts := []string{}
	collect := func(list []*Extractor) {
		for _, e := range list {
			if e == nil {
				continue
			}
			if x := extractData(data, resp, e); x != "" {
				parts = append(parts, x)
			}
		}
	}
	if len(reqIdx) > 0 && reqIdx[0] >= 0 && reqIdx[0] < len(t.Requests) {
		collect(t.Requests[reqIdx[0]].Extractors)
	}
	if t.Extractor != nil {
		if e := extractData(data, resp, t.Extractor); e != "" {
			parts = append(parts, e)
		}
	}
	collect(t.Extractors)
	return strings.Join(parts, "; ")
}

func matchWords(data string, words []string, condition string, caseInsensitive ...bool) bool {
	if len(words) == 0 {
		return false
	}
	ci := len(caseInsensitive) > 0 && caseInsensitive[0]
	hay := data
	if ci {
		hay = strings.ToLower(data)
	}
	wordAt := func(w string) string {
		if ci {
			return strings.ToLower(w)
		}
		return w
	}
	if strings.EqualFold(condition, "and") {
		for _, w := range words {
			if !strings.Contains(hay, wordAt(w)) {
				return false
			}
		}
		return true
	}
	for _, w := range words {
		if strings.Contains(hay, wordAt(w)) {
			return true
		}
	}
	return false
}

func matchRegexFast(data string, patterns []string, condition string, caseInsensitive ...bool) bool {
	if len(patterns) == 0 {
		return false
	}
	ci := len(caseInsensitive) > 0 && caseInsensitive[0]
	if strings.EqualFold(condition, "and") {
		for _, p := range patterns {
			re, err := getRegexCI(p, ci)
			if err != nil || !re.MatchString(data) {
				return false
			}
		}
		return true
	}
	for _, p := range patterns {
		re, err := getRegexCI(p, ci)
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
	// Single value matches exactly; use DSL for range comparisons.
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
	results := make([]bool, 0, len(exprs))
	for _, e := range exprs {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		ok, err := evalDSLBool(e, resp)
		if err != nil {
			// Legacy fallback: the pre-expr engine understood a small
			// atom language; keep it alive for archaic templates.
			ok = matchDSLLegacyExpr(e, resp)
		}
		results = append(results, ok)
	}
	if len(results) == 0 {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(m.Condition), "and") {
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	}
	for _, r := range results {
		if r {
			return true
		}
	}
	return false
}

// matchDSLLegacyExpr handles one expression with the old atom language
// (`a && b || c`, function-call atoms like `contains(body, 'x')`).
func matchDSLLegacyExpr(e string, resp *ResponseInfo) bool {
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
					case "!=":
						return field.val != want
					case "=":
						return field.val == want
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
	return false
}

func matchAll(resp *ResponseInfo, data string, m MatcherCondition) bool {
	if len(m.Words) > 0 && !matchWords(data, m.Words, "and", m.CaseInsensitive) {
		return false
	}
	if len(m.Regex) > 0 && !matchRegexFast(data, m.Regex, "and", m.CaseInsensitive) {
		return false
	}
	if len(m.Status) > 0 && !matchStatus(resp.StatusCode, m.Status) {
		return false
	}
	if len(m.Size) > 0 && !matchSize(resp.BodyLen, m.Size) {
		return false
	}
	return true
}

func matchAny(resp *ResponseInfo, data string, m MatcherCondition) bool {
	if matchWords(data, m.Words, "or", m.CaseInsensitive) {
		return true
	}
	if matchRegexFast(data, m.Regex, "or", m.CaseInsensitive) {
		return true
	}
	if len(m.Status) > 0 && matchStatus(resp.StatusCode, m.Status) {
		return true
	}
	if len(m.Size) > 0 && matchSize(resp.BodyLen, m.Size) {
		return true
	}
	return false
}

// extractData supports regex, json, kval and dsl extractor types.
func extractData(data string, resp *ResponseInfo, e *Extractor) string {
	if e == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(e.Type)) {
	case "json":
		return extractJSON(resp.Body, e.JSON)
	case "kval":
		return extractKval(resp.Headers, e.Kval)
	case "dsl":
		return extractDSL(resp, e.DSL)
	default:
		return extractRegex(data, e.Regex)
	}
}

func extractRegex(data string, patterns []string) string {
	var found []string
	for _, p := range patterns {
		re, err := getRegex(p)
		if err != nil {
			continue
		}
		matches := re.FindStringSubmatch(data)
		if len(matches) > 1 {
			found = append(found, matches[1])
			continue
		}
		if len(matches) == 1 {
			found = append(found, matches[0])
		}
	}
	return strings.Join(found, "; ")
}

var jsonPathTokenRe = regexp.MustCompile(`[^.\[\]]+`)

// extractJSON walks dotted paths (`a.b`, `a.b[0]`) into the response body.
func extractJSON(body string, paths []string) string {
	if len(paths) == 0 || strings.TrimSpace(body) == "" {
		return ""
	}
	var doc interface{}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return ""
	}
	var found []string
	for _, p := range paths {
		p = strings.TrimPrefix(strings.TrimSpace(p), "$")
		p = strings.TrimPrefix(p, ".")
		if p == "" {
			found = append(found, toStr(doc))
			continue
		}
		cur := doc
		ok := true
		for _, tok := range jsonPathTokenRe.FindAllString(p, -1) {
			switch node := cur.(type) {
			case map[string]interface{}:
				v, exists := node[tok]
				if !exists {
					ok = false
					break
				}
				cur = v
			case []interface{}:
				var idx int
				if _, err := fmt.Sscanf(tok, "%d", &idx); err != nil || idx < 0 || idx >= len(node) {
					ok = false
					break
				}
				cur = node[idx]
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && cur != nil {
			found = append(found, toStr(cur))
		}
	}
	return strings.Join(found, "; ")
}

// extractKval turns `key: value` header lines into `value` entries
// (one per requested key, in request order).
func extractKval(headers string, keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	m := getHeadersMap(headers)
	var found []string
	for _, k := range keys {
		if v, ok := m[strings.ToLower(strings.TrimSpace(k))]; ok && v != "" {
			found = append(found, v)
		}
	}
	return strings.Join(found, "; ")
}

func extractDSL(resp *ResponseInfo, exprs []string) string {
	var found []string
	for _, e := range exprs {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		v, err := evalDSLValue(e, resp)
		if err == nil && v != "" {
			found = append(found, v)
		}
	}
	return strings.Join(found, "; ")
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
