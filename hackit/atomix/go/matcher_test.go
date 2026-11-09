package main

import (
	"strings"
	"testing"
	"time"
)

func testResp() *ResponseInfo {
	return &ResponseInfo{
		StatusCode:  200,
		Headers:     "Content-Type: text/html\r\nSet-Cookie: session=abc123\nServer: nginx/1.25.3\n",
		Body:        `<html><body><title>Admin Panel</title>{"version":"9.9.9"}</body></html>`,
		BodyLen:     len(`<html><body><title>Admin Panel</title>{"version":"9.9.9"}</body></html>`),
		Duration:    150 * time.Millisecond,
		ContentType: "text/html",
	}
}

func TestMatchWordsOrAnd(t *testing.T) {
	data := "hello Admin World"
	if !matchWords(data, []string{"Admin"}, "") {
		t.Fatal("expected word match")
	}
	if matchWords(data, []string{"Admin", "Missing"}, "and") {
		t.Fatal("expected and-condition failure")
	}
	if !matchWords(data, []string{"Admin", "World"}, "and") {
		t.Fatal("expected and-condition success")
	}
	if matchWords(data, []string{"Nope", "Missing"}, "or") {
		t.Fatal("expected or-condition failure")
	}
}

func TestMatchWordsCaseInsensitive(t *testing.T) {
	data := "hello admin world"
	if matchWords(data, []string{"ADMIN"}, "", false) {
		t.Fatal("case-sensitive match must not hit")
	}
	if !matchWords(data, []string{"ADMIN"}, "", true) {
		t.Fatal("case-insensitive match must hit")
	}
}

func TestMatchRegexCaseInsensitive(t *testing.T) {
	data := "error code: ABC123"
	if matchRegexFast(data, []string{"abc123"}, "", false) {
		t.Fatal("case-sensitive regex must not hit")
	}
	if !matchRegexFast(data, []string{"abc123"}, "", true) {
		t.Fatal("case-insensitive regex must hit")
	}
}

func TestMatchStatus(t *testing.T) {
	if !matchStatus(404, []int{200, 404}) {
		t.Fatal("expected status match")
	}
	if matchStatus(500, []int{200, 404}) {
		t.Fatal("expected status mismatch")
	}
	if matchStatus(200, nil) {
		t.Fatal("empty status list must not match")
	}
}

func TestMatchSize(t *testing.T) {
	if !matchSize(1234, []int{1234}) {
		t.Fatal("expected size match")
	}
	if matchSize(1235, []int{1234}) {
		t.Fatal("expected size mismatch")
	}
}

func TestDSLBoolExpressions(t *testing.T) {
	resp := testResp()
	cases := []struct {
		expr string
		want bool
	}{
		{"status_code == 200", true},
		{"status_code == 404", false},
		{"status_code >= 200 && status_code < 300", true},
		{"contains(body, 'Admin Panel')", true},
		{"contains(body, 'missing-string')", false},
		{"contains(header, 'nginx')", true},
		{"len(body) > 10", true},
		{"len(body) > 10000", false},
		{"duration < 1", true},
		{"duration_ms >= 100", true},
		{"regex(body, 'Admin.{0,20}Panel')", true},
		{"to_number('42') == 42", true},
		{"to_lower('ADMIN') == 'admin'", true},
		{"starts_with(body, '<html>')", true},
		{"ends_with(body, '</html>')", true},
		{"contains_any(body, 'zzz|qqq|Admin Panel')", true},
		{"contains_all(body, 'Admin|Panel|title')", true},
		{"contains_all(body, 'Admin|missing')", false},
		{"status_code == 200 || status_code == 404", true},
		{"status_code == 200 && content_length > 5", true},
	}
	for _, tc := range cases {
		got, err := evalDSLBool(tc.expr, resp)
		if err != nil {
			t.Fatalf("expr %q: %v", tc.expr, err)
		}
		if got != tc.want {
			t.Errorf("expr %q: got %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestDSLMatcherAndOrCondition(t *testing.T) {
	resp := testResp()
	m := MatcherCondition{
		Type: "dsl",
		DSL:  []string{"status_code == 200", "contains(body, 'Admin Panel')"},
	}
	if !matchDSL(resp, m) { // default OR across list
		t.Fatal("or-dsl must match")
	}
	m.Condition = "and"
	if !matchDSL(resp, m) {
		t.Fatal("and-dsl must match")
	}
	m.DSL = []string{"status_code == 200", "contains(body, 'nope')"}
	if matchDSL(resp, m) {
		t.Fatal("and-dsl must not match when one atom fails")
	}
}

func TestMatchersConditionAnd(t *testing.T) {
	resp := testResp()
	tmpl := &Template{
		ID: "t1",
		Requests: []Request{{
			Path: []string{"{{BaseURL}}"},
			Matchers: []MatcherCondition{
				{Type: "status", Status: []int{200}},
				{Type: "word", Words: []string{"Admin Panel"}},
			},
			MatchersCondition: "and",
		}},
	}
	got := MatchTemplate(resp, tmpl, 0)
	if got == nil || !got.Matched {
		t.Fatal("and-matchers must both hold")
	}
	tmpl.Requests[0].Matchers[1] = MatcherCondition{Type: "word", Words: []string{"no-such-word"}}
	got = MatchTemplate(resp, tmpl, 0)
	if got == nil || got.Matched {
		t.Fatal("and-matchers must fail when one matcher fails")
	}
}

func TestTypeLevelAndOrWithStatusOnly(t *testing.T) {
	resp := testResp()
	// Regression: type-level `and` matcher that only checks status used to
	// report no-match due to the vacuous-true guard in matchAll.
	tmpl := &Template{
		ID: "status-only",
		Requests: []Request{{
			Path: []string{"{{BaseURL}}"},
			Matchers: []MatcherCondition{
				{Type: "and", Status: []int{200}},
			},
		}},
	}
	got := MatchTemplate(resp, tmpl, 0)
	if got == nil || !got.Matched {
		t.Fatal("status-only and matcher must match")
	}
	tmpl2 := &Template{
		ID: "or-status",
		Requests: []Request{{
			Path: []string{"{{BaseURL}}"},
			Matchers: []MatcherCondition{
				{Type: "or", Status: []int{404, 500}},
			},
		}},
	}
	got = MatchTemplate(resp, tmpl2, 0)
	if got == nil || got.Matched {
		t.Fatal("or matcher with non-matching status must not match")
	}
}

func TestNegativeMatcher(t *testing.T) {
	resp := testResp()
	tmpl := &Template{
		ID: "neg",
		Requests: []Request{{
			Path: []string{"{{BaseURL}}"},
			Matchers: []MatcherCondition{
				{Type: "word", Words: []string{"no-such-word"}, Negative: true},
			},
		}},
	}
	got := MatchTemplate(resp, tmpl, 0)
	if got == nil || !got.Matched {
		t.Fatal("negative matcher must invert the inner result")
	}
}

func TestExtractRegex(t *testing.T) {
	resp := testResp()
	extracted := extractData(resp.Body, resp, &Extractor{Type: "regex", Regex: []string{`<title>([^<]+)</title>`}})
	if extracted != "Admin Panel" {
		t.Fatalf("regex extractor got %q", extracted)
	}
}

func TestExtractJSON(t *testing.T) {
	resp := &ResponseInfo{
		StatusCode: 200,
		Body:       `{"data":{"items":[{"id":"first"},{"id":"second"}]},"plain":"top"}`,
		BodyLen:    62,
	}
	extracted := extractJSON(resp.Body, []string{"data.items[1].id", "plain"})
	if !strings.Contains(extracted, "second") || !strings.Contains(extracted, "top") {
		t.Fatalf("json extractor got %q", extracted)
	}
}

func TestExtractKval(t *testing.T) {
	resp := testResp()
	extracted := extractData("", resp, &Extractor{Type: "kval", Kval: []string{"server", "set-cookie"}})
	if !strings.Contains(extracted, "nginx/1.25.3") {
		t.Fatalf("kval extractor got %q", extracted)
	}
	if !strings.Contains(extracted, "session=abc123") {
		t.Fatalf("kval extractor got %q", extracted)
	}
}

func TestExtractDSL(t *testing.T) {
	resp := testResp()
	extracted := extractDSL(resp, []string{"to_upper('abc')", "status_code"})
	if !strings.Contains(extracted, "ABC") {
		t.Fatalf("dsl extractor got %q", extracted)
	}
}

func TestJoinRequestURL(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"https://a.example.com", "/login", "https://a.example.com/login"},
		{"https://a.example.com/", "login", "https://a.example.com/login"},
		{"https://a.example.com", "{{BaseURL}}/x", "https://a.example.com/{{BaseURL}}/x"}, // vars pre-resolved by engine
		{"https://a.example.com", "http://other.example.com/y", "http://other.example.com/y"},
		{"https://a.example.com/sub/", "/abs", "https://a.example.com/sub/abs"},
	}
	for _, tc := range cases {
		if got := joinRequestURL(tc.base, tc.path); got != tc.want {
			t.Errorf("joinRequestURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}
