package main

// Nuclei-compat layer: translates native Nuclei template constructs into
// the engine's internal Request/Matcher model. Existing custom-schema
// templates keep working unchanged.

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// StringSlice accepts a YAML scalar or sequence (Nuclei uses both for
// tags, reference, cve-id, ...).
type StringSlice []string

func (s *StringSlice) UnmarshalYAML(value *yaml.Node) error {
	var single string
	if err := value.Decode(&single); err == nil {
		*s = []string{single}
		return nil
	}
	var multi []string
	if err := value.Decode(&multi); err == nil {
		*s = multi
		return nil
	}
	// Fallback: comma-separated scalar.
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	*s = out
	return nil
}

func (s StringSlice) Join() string {
	return strings.Join([]string(s), ",")
}

type NucleiClassification struct {
	CVEID       StringSlice `yaml:"cve-id,omitempty"`
	CWEID       StringSlice `yaml:"cwe-id,omitempty"`
	CVSSMetrics string      `yaml:"cvss-metrics,omitempty"`
	CVSSScore   float64     `yaml:"cvss-score,omitempty"`
}

type NucleiHTTPRequest struct {
	Method            string              `yaml:"method"`
	Path              []string            `yaml:"path"`
	Headers           map[string]string   `yaml:"headers,omitempty"`
	Body              string              `yaml:"body,omitempty"`
	Matchers          []MatcherCondition  `yaml:"matchers,omitempty"`
	MatchersCondition string              `yaml:"matchers-condition,omitempty"`
	Payloads          map[string][]string `yaml:"payloads,omitempty"`
	Attack            string              `yaml:"attack,omitempty"`
	StopAtFirstMatch  bool                `yaml:"stop-at-first-match,omitempty"`
	Redirects         bool                `yaml:"redirects,omitempty"`
	MaxRedirects       int                 `yaml:"max-redirects,omitempty"`
	Extractors        []*Extractor        `yaml:"extractors,omitempty"`
}

var attackMarkerRe = regexp.MustCompile(`§([^§]+)§`)

// expandAttack generates concrete (path, headers, body) triples from an
// attack definition. Supports batteringram (zip), pitchfork (parallel
// index) and clusterbomb (cartesian). Markers look like §param§.
func expandAttack(nr NucleiHTTPRequest) []Request {
	if len(nr.Payloads) == 0 || nr.Attack == "" {
		return []Request{{
			Method: nr.Method, Path: nr.Path, Headers: nr.Headers,
			Body: nr.Body, Matchers: nr.Matchers,
			MatchersCondition: nr.MatchersCondition,
			StopAtFirstMatch:  nr.StopAtFirstMatch,
			Redirects:         nr.Redirects,
			MaxRedirects:       nr.MaxRedirects,
		}}
	}

	names := make([]string, 0, len(nr.Payloads))
	for k := range nr.Payloads {
		names = append(names, k)
	}
	// Deterministic order for reproducible scans.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	lists := make([][]string, len(names))
	maxLen := 0
	for i, n := range names {
		lists[i] = nr.Payloads[n]
		if len(lists[i]) > maxLen {
			maxLen = len(lists[i])
		}
	}

	var combos [][]string
	switch strings.ToLower(nr.Attack) {
	case "clusterbomb":
		combos = cartesian(lists)
	case "pitchfork":
		for i := 0; i < maxLen; i++ {
			row := make([]string, len(names))
			for j := range names {
				row[j] = lists[j][i%len(lists[j])]
			}
			combos = append(combos, row)
		}
	default: // batteringram: same payload everywhere (zip by index)
		for i := 0; i < maxLen; i++ {
			row := make([]string, len(names))
			for j := range names {
				row[j] = lists[j][i%len(lists[j])]
			}
			combos = append(combos, row)
		}
	}

	out := make([]Request, 0, len(combos))
	for _, combo := range combos {
		sub := func(s string) string {
			for i, n := range names {
				s = strings.ReplaceAll(s, "§"+n+"§", combo[i])
			}
			return s
		}
		hdrs := map[string]string{}
		for k, v := range nr.Headers {
			hdrs[k] = sub(v)
		}
		paths := make([]string, 0, len(nr.Path))
		for _, p := range nr.Path {
			paths = append(paths, sub(p))
		}
		out = append(out, Request{
			Method: sub(nr.Method), Path: paths, Headers: hdrs,
			Body: sub(nr.Body), Matchers: nr.Matchers,
			MatchersCondition: nr.MatchersCondition,
			StopAtFirstMatch:  nr.StopAtFirstMatch,
			Redirects:         nr.Redirects,
			MaxRedirects:       nr.MaxRedirects,
		})
	}
	return out
}

func cartesian(lists [][]string) [][]string {
	if len(lists) == 0 {
		return nil
	}
	out := [][]string{{}}
	for _, l := range lists {
		if len(l) == 0 {
			continue
		}
		var next [][]string
		for _, prefix := range out {
			for _, v := range l {
				row := append(append([]string{}, prefix...), v)
				next = append(next, row)
			}
		}
		out = next
	}
	return out
}

// NormalizeTemplate converts Nuclei-native constructs into the engine
// model. Safe to call on custom-schema templates (no-op for them).
func NormalizeTemplate(t *Template) {
	if len(t.HTTP) > 0 {
		for _, nr := range t.HTTP {
		 expanded := expandAttack(nr)
			for i := range expanded {
				if expanded[i].MatchersCondition == "" {
					expanded[i].MatchersCondition = t.MatchersCondition
				}
				if !expanded[i].StopAtFirstMatch {
					expanded[i].StopAtFirstMatch = t.StopAtFirstMatch
				}
			}
			t.Requests = append(t.Requests, expanded...)
			t.Extractors = append(t.Extractors, nr.Extractors...)
		}
		t.HTTP = nil
	}
	// Fold classification into result-facing fields.
	if c := t.Info.Classification; c != nil {
		if len(c.CVEID) > 0 {
			t.Info.Description += fmt.Sprintf(" [CVE: %s]", strings.Join([]string(c.CVEID), ","))
		}
	}
}

// ResolveRequestPart substitutes template variables then engine vars.
func (t *Template) ResolveRequestPart(s string, vars *TemplateVars) string {
	for k, v := range t.Variables {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return vars.Resolve(s)
}
