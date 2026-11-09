package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const multiDocTemplate = `
id: tpl-one
info:
  name: One
  author: tester
  severity: high
  description: first
  tags: web,test
requests:
  - method: GET
    path:
      - "{{BaseURL}}/one"
    matchers:
      - type: word
        words:
          - one-hit
---
id: tpl-two
info:
  name: Two
  author: tester
  severity: low
  description: second
  tags: web
requests:
  - method: GET
    path:
      - "{{BaseURL}}/two"
    matchers:
      - type: status
        status:
          - 200
`

func TestLoadAllTemplatesFromFileMultiDoc(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.yaml")
	if err := os.WriteFile(path, []byte(multiDocTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	templates, err := LoadAllTemplatesFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(templates))
	}
	ids := map[string]bool{}
	for _, tpl := range templates {
		ids[tpl.ID] = true
	}
	if !ids["tpl-one"] || !ids["tpl-two"] {
		t.Fatalf("missing expected ids: %v", ids)
	}
}

func TestNormalizeHTTPBlock(t *testing.T) {
	raw := `
id: http-block
info:
  name: HTTP block
  author: tester
  severity: medium
  description: portable block
  tags: web
http:
  - method: GET
    path:
      - "{{BaseURL}}/a"
      - "{{BaseURL}}/b"
    matchers:
      - type: status
        status:
          - 200
`
	path := filepath.Join(t.TempDir(), "http.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl, err := LoadTemplate(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(tpl.Requests) != 1 {
		t.Fatalf("expected 1 normalized request, got %d", len(tpl.Requests))
	}
	if len(tpl.Requests[0].Path) != 2 {
		t.Fatalf("expected 2 paths, got %v", tpl.Requests[0].Path)
	}
}

func TestFilterTemplates(t *testing.T) {
	templates := []*Template{
		{ID: "a", Info: TemplateInfo{Severity: "high", Tags: "web,rce", Author: "aniipid"}},
		{ID: "b", Info: TemplateInfo{Severity: "low", Tags: "web", Author: "aniipid"}},
		{ID: "c", Info: TemplateInfo{Severity: "high", Tags: "dns", Author: "other"}},
	}
	got := FilterTemplates(templates, FilterOptions{Severity: "high"})
	if len(got) != 2 {
		t.Fatalf("severity filter: got %d", len(got))
	}
	got = FilterTemplates(templates, FilterOptions{Tags: []string{"rce"}})
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("tag filter: got %v", got)
	}
	got = FilterTemplates(templates, FilterOptions{ExcludeTags: []string{"dns"}})
	if len(got) != 2 {
		t.Fatalf("exclude-tags filter: got %d", len(got))
	}
	got = FilterTemplates(templates, FilterOptions{Author: "aniipid"})
	if len(got) != 2 {
		t.Fatalf("author filter: got %d", len(got))
	}
	got = FilterTemplates(templates, FilterOptions{ExcludeSeverity: "low"})
	if len(got) != 2 {
		t.Fatalf("exclude-severity filter: got %d", len(got))
	}
	got = FilterTemplates(templates, FilterOptions{ID: "a,c"})
	if len(got) != 2 {
		t.Fatalf("id filter: got %d", len(got))
	}
}

func TestExpandAttackClusterbomb(t *testing.T) {
	block := HTTPRequestBlock{
		Method: "GET",
		Path:   []string{"{{BaseURL}}/p?a=§a§&b=§b§"},
		Payloads: map[string][]string{
			"a": {"1", "2"},
			"b": {"x", "y"},
		},
		Attack: "clusterbomb",
	}
	requests := expandAttack(block)
	if len(requests) != 4 {
		t.Fatalf("clusterbomb must expand to 4 requests, got %d", len(requests))
	}
	joined := ""
	for _, r := range requests {
		joined += strings.Join(r.Path, ",") + "|"
	}
	for _, want := range []string{"a=1&b=x", "a=1&b=y", "a=2&b=x", "a=2&b=y"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("clusterbomb missing %q in %q", want, joined)
		}
	}
}

func TestExpandAttackBatteringram(t *testing.T) {
	block := HTTPRequestBlock{
		Method: "GET",
		Path:   []string{"{{BaseURL}}/p?a=§a§&b=§b§"},
		Payloads: map[string][]string{
			"a": {"1", "2"},
			"b": {"x", "y"},
		},
		Attack: "batteringram",
	}
	requests := expandAttack(block)
	if len(requests) != 2 {
		t.Fatalf("batteringram must expand to 2 requests, got %d", len(requests))
	}
	if requests[0].Path[0] != "{{BaseURL}}/p?a=1&b=x" {
		t.Fatalf("batteringram row 0: %q", requests[0].Path[0])
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"Critical":      "critical",
		"MED":           "medium",
		"crit":          "critical",
		"informational": "info",
		"warning":       "low",
		"high":          "high",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
