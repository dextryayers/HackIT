package main

import "testing"

func TestLintFPFlagsReflectionMatcher(t *testing.T) {
	tpl := &Template{
		ID: "bad",
		Requests: []Request{{
			Method:   "GET",
			Path:     []string{"{{BaseURL}}?q=1' OR SLEEP(5)--"},
			Matchers: []MatcherCondition{{Type: "word", Words: []string{"SLEEP"}}},
		}},
	}
	issues := LintFPTemplates([]*Template{tpl})
	if len(issues["bad"]) == 0 {
		t.Fatal("expected reflection matcher to be flagged")
	}
}

func TestLintFPToleratesPreciseMatcher(t *testing.T) {
	tpl := &Template{
		ID: "good",
		Requests: []Request{{
			Method:   "GET",
			Path:     []string{"{{BaseURL}}/?q=x"},
			Matchers: []MatcherCondition{{Type: "regex", Regex: []string{"You have an error in your SQL"}}},
		}},
	}
	issues := LintFPTemplates([]*Template{tpl})
	if len(issues["good"]) != 0 {
		t.Fatalf("unexpected findings: %v", issues["good"])
	}
}
