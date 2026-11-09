package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

var benchBody = strings.Repeat(`<html><body><div class="admin-panel"><h1>Dashboard</h1>welcome admin</div><script>var x=1;</script></body></html>`, 400) // ~52KB

func benchResp() *ResponseInfo {
	return &ResponseInfo{
		StatusCode:  200,
		Headers:     "Content-Type: text/html\r\nServer: nginx/1.25.3\nX-Powered-By: PHP/8.2.0\nSet-Cookie: session=abc123; HttpOnly\n",
		Body:        benchBody,
		BodyLen:     len(benchBody),
		Duration:    120 * time.Millisecond,
		ContentType: "text/html",
	}
}

func BenchmarkMatchWords(b *testing.B) {
	words := []string{"admin-panel", "Dashboard", "welcome"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchWords(benchBody, words, "or")
	}
}

func BenchmarkMatchWordsCaseInsensitivePreLogged(b *testing.B) {
	low := strings.ToLower(benchBody)
	words := []string{"ADMIN-PANEL", "DASHBOARD", "WELCOME"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchWordsPre(benchBody, low, words, "or", true)
	}
}

func BenchmarkMatchWordsCaseInsensitivePerCall(b *testing.B) {
	// v3.0.0 behavior: lower the body on every matcher call.
	words := []string{"ADMIN-PANEL", "DASHBOARD", "WELCOME"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchWords(benchBody, words, "or", true)
	}
}

func BenchmarkMatchRegexFast(b *testing.B) {
	patterns := []string{`admin-[a-z]+`, `(?i)x-powered-by`, `Server:`}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchRegexFast(benchBody, patterns, "or")
	}
}

func BenchmarkMatchTemplateAndMatchers(b *testing.B) {
	resp := benchResp()
	tmpl := &Template{
		ID: "bench",
		Requests: []Request{{
			Path: []string{"{{BaseURL}}"},
			Matchers: []MatcherCondition{
				{Type: "status", Status: []int{200}},
				{Type: "word", Words: []string{"admin-panel"}},
				{Type: "regex", Regex: []string{`Dash(board|board)`}},
			},
			MatchersCondition: "and",
		}},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MatchTemplate(resp, tmpl, 0)
	}
}

func BenchmarkDSLBool(b *testing.B) {
	resp := benchResp()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evalDSLBool("len(body) > 100 && status_code == 200 && contains(body, 'admin-panel')", resp)
	}
}

func BenchmarkNormalizeDSLExpr(b *testing.B) {
	expr := "status_code == 200 && contains(body, 'admin-panel') && regex(body, 'x-[a-z]+')"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeDSLExpr(expr)
	}
}

func BenchmarkExtractJSON(b *testing.B) {
	body := `{"data":{"items":[{"id":"first"},{"id":"second"}],"meta":{"count":2}}}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractJSON(body, []string{"data.items[1].id", "data.items[0].id", "data.meta.count"})
	}
}

func BenchmarkReadBodyPooled(b *testing.B) {
	payload := []byte(strings.Repeat("atomix-bench-payload", 8192)) // ~160KB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readBodyPooled(bytes.NewReader(payload), maxBodyBytes)
	}
}

func BenchmarkReadBodyPooledLimit(b *testing.B) {
	payload := []byte(strings.Repeat("atomix-bench-payload", 8192))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = io.ReadAll(io.LimitReader(bytes.NewReader(payload), maxBodyBytes))
	}
}

func BenchmarkJoinRequestURL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		joinRequestURL("https://example.com:8443/base/", "/login")
	}
}

func BenchmarkExpandAttackClusterbomb(b *testing.B) {
	block := HTTPRequestBlock{
		Method:   "GET",
		Path:     []string{"{{BaseURL}}/p?a=§a§&b=§b§&c=§c§"},
		Payloads: map[string][]string{"a": {"1", "2", "3"}, "b": {"x", "y"}, "c": {"p", "q"}},
		Attack:   "clusterbomb",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandAttack(block)
	}
}
