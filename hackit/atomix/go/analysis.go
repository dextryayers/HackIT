package main

import (
	"strings"
)

type ResponseAnalysis struct {
	ContentType   string
	Charset       string
	IsHTML        bool
	IsJSON        bool
	IsXML         bool
	IsRedirect    bool
	IsError       bool
	ErrorType     string
	Server        string
	ContentLength int
	WordCount     int
	LineCount     int
	Technologies  []string
	Reflected     bool
	ReflectedVars []string
}

var errorPatterns = []struct {
	keyword  string
	errType  string
}{
	{"sql", "SQL"},
	{"syntax error", "SQL"},
	{"mysql_fetch", "SQL"},
	{"ORA-", "Oracle"},
	{"PostgreSQL", "PostgreSQL"},
	{"driver", "SQL"},
	{"SQLite", "SQLite"},
	{"Division by zero", "PHP"},
	{"PHP Parse error", "PHP"},
	{"Fatal error", "PHP"},
	{"Warning:", "PHP"},
	{"Parse error", "PHP"},
	{"Notice:", "PHP"},
	{"java.lang", "Java"},
	{"NullPointerException", "Java"},
	{"Exception in thread", "Java"},
	{"at org.apache", "Java"},
	{"at com.sun", "Java"},
	{"stack trace", "Generic"},
	{"Traceback", "Python"},
	{"File \"<string>\"", "Python"},
	{"TypeError:", "Python"},
	{"ValueError:", "Python"},
	{"KeyError:", "Python"},
	{"NameError:", "Python"},
	{"SyntaxError", "Python"},
	{"unclosed socket", "Node.js"},
	{"Cannot find module", "Node.js"},
	{"TypeError: Cannot read", "Node.js"},
	{"ReferenceError:", "Node.js"},
	{"ASP.NET", ".NET"},
	{"System.UnauthorizedAccessException", ".NET"},
	{"System.Data.SqlClient", ".NET"},
	{"InvalidOperationException", ".NET"},
	{"Stack Trace:</font>", ".NET"},
	{"root:x:0:0:root", "File Disclosure"},
	{"{", "JSON"},
	{"<?xml", "XML"},
	{"<html", "HTML"},
}

func AnalyzeResponse(resp *ResponseInfo) *ResponseAnalysis {
	ra := &ResponseAnalysis{
		ContentType:   resp.ContentType,
		ContentLength: resp.BodyLen,
		WordCount:     len(strings.Fields(resp.Body)),
		LineCount:     len(strings.Split(resp.Body, "\n")),
	}

	ct := strings.ToLower(resp.ContentType)
	ra.IsHTML = strings.Contains(ct, "html") || strings.Contains(ct, "text")
	ra.IsJSON = strings.Contains(ct, "json")
	ra.IsXML = strings.Contains(ct, "xml")
	ra.IsRedirect = resp.StatusCode >= 300 && resp.StatusCode < 400

	if strings.Contains(ct, "charset=") {
		parts := strings.Split(ct, "charset=")
		if len(parts) > 1 {
			ra.Charset = strings.TrimSpace(parts[1])
		}
	}

	if hdr := resp.Headers; hdr != "" {
		for _, line := range strings.Split(hdr, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				ra.Server = strings.TrimSpace(line[7:])
			}
		}
	}

	bodyLower := strings.ToLower(resp.Body)
	for _, ep := range errorPatterns {
		if strings.Contains(bodyLower, strings.ToLower(ep.keyword)) {
			ra.IsError = true
			ra.ErrorType = ep.errType
			break
		}
	}

	return ra
}

type FalsePositiveChecker struct {
	patterns []fpRule
}

type fpRule struct {
	name    string
	check   func(*ResponseInfo, *MatchResult) bool
}

func NewFalsePositiveChecker() *FalsePositiveChecker {
	return &FalsePositiveChecker{
		patterns: []fpRule{
			{name: "html_entity_encoded", check: checkHTMLEntityEncoded},
			{name: "reflection_in_error", check: checkErrorReflection},
			{name: "status_code_404", check: check404Reflection},
			{name: "self_reflection_only", check: checkSelfReflection},
		},
	}
}

func (fpc *FalsePositiveChecker) IsFalsePositive(resp *ResponseInfo, match *MatchResult) (bool, string) {
	for _, rule := range fpc.patterns {
		if rule.check(resp, match) {
			return true, rule.name
		}
	}
	return false, ""
}

func checkHTMLEntityEncoded(resp *ResponseInfo, match *MatchResult) bool {
	if match.Extracted == "" { return false }
	encoded := strings.Contains(resp.Body, "&lt;"+match.Extracted[1:]) ||
		strings.Contains(resp.Body, "&#" + match.Extracted[0:1]) ||
		strings.Contains(resp.Body, "&gt;")
	return encoded
}

func checkErrorReflection(resp *ResponseInfo, match *MatchResult) bool {
	bodyLower := strings.ToLower(resp.Body)
	errorIndicators := []string{"error", "warning", "notice", "fatal", "exception", "traceback"}
	count := 0
	for _, ind := range errorIndicators {
		if strings.Contains(bodyLower, ind) {
			count++
		}
	}
	return count >= 2
}

func check404Reflection(resp *ResponseInfo, match *MatchResult) bool {
	if resp.StatusCode == 404 {
		return true
	}
	bodyLower := strings.ToLower(resp.Body)
	return strings.Contains(bodyLower, "not found") || strings.Contains(bodyLower, "404")
}

func checkSelfReflection(resp *ResponseInfo, match *MatchResult) bool {
	if match.Extracted == "" { return false }
	occurrences := strings.Count(resp.Body, match.Extracted)
	return occurrences <= 1
}

var falsePositiveDomains = []string{
	"google.com", "facebook.com", "twitter.com", "github.com",
	"youtube.com", "instagram.com", "linkedin.com", "reddit.com",
	"amazon.com", "netflix.com", "wikipedia.org", "stackoverflow.com",
	"example.com", "test.com", "localhost",
}

func IsKnownSafeDomain(host string) bool {
	host = strings.ToLower(host)
	for _, d := range falsePositiveDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
