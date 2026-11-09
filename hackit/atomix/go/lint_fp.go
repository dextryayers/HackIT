package main

// False-positive linter for the template library. Findings here are
// advisory: they flag matchers whose evidence can be produced by the
// request itself (reflection) or by arbitrary benign pages (weak tokens).
// Surfaced by --validate-deep as an "FP-RISK" section.

import (
	"fmt"
	"os"
	"strings"
)

var fpWeakTokens = map[string]bool{
	"ok": true, "up": true, "true": true, "yes": true, "null": true,
	"undefined": true, "login": true, "admin": true, "dashboard": true,
	"welcome": true, "token": true, "version": true, "table_name": true,
	"root": true, "data": true, "users": true, "test": true, "home": true,
	"hello": true, "pass": true, "id": true, "1": true, "text": true,
}

var fpStatusWordPrefixes = []string{"200 ", "201 ", "202 ", "204 ", "301 ", "302 ", "303 ", "304 ", "307 ", "308 "}

func lintMatcherFP(m MatcherCondition, req Request) []string {
	var issues []string

	token := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

	haystack := strings.ToLower(req.Body)
	for _, p := range req.Path {
		haystack += "\x00" + strings.ToLower(p)
	}

	// Payload-reflection: matcher word appears inside the request itself.
	for _, w := range m.Words {
		tw := token(w)
		if tw == "" {
			continue
		}
		if strings.Contains(haystack, tw) {
			issues = append(issues, fmt.Sprintf("matcher word %q appears in the request itself (reflection-friendly; can't distinguish injection success from echo)", w))
		}
	}

	// Weak tokens: match virtually any page.
	for _, w := range m.Words {
		if fpWeakTokens[token(w)] {
			issues = append(issues, fmt.Sprintf("matcher word %q is a high-frequency token (FP-prone on arbitrary pages)", w))
		}
	}

	// Regex that matches the request body or any request path.
	for _, r := range m.Regex {
		re, err := getRegex(r)
		if err != nil {
			continue
		}
		if re.MatchString(req.Body) {
			issues = append(issues, fmt.Sprintf("regex %q matches the request body (reflection-friendly)", r))
			continue
		}
		for _, p := range req.Path {
			if re.MatchString(p) {
				issues = append(issues, fmt.Sprintf("regex %q matches the request path (reflection-friendly)", r))
				break
			}
		}
	}

	// Header "status-as-word": "200 OK" proves only the status code.
	for _, w := range m.Words {
		tw := strings.ToUpper(strings.TrimSpace(w))
		for _, prefix := range fpStatusWordPrefixes {
			if strings.HasPrefix(tw, prefix) {
				issues = append(issues, fmt.Sprintf("matcher word %q is an HTTP status line — use type: status instead", w))
			}
		}
	}

	return issues
}

// LintFPTemplates returns template-id -> list of FP-risk findings.
func LintFPTemplates(templates []*Template) map[string][]string {
	out := map[string][]string{}
	for _, t := range templates {
		for _, req := range t.Requests {
			for _, m := range req.Matchers {
				for _, issue := range lintMatcherFP(m, req) {
					out[t.ID] = append(out[t.ID], issue)
				}
			}
		}
	}
	return out
}

// PrintFPLintReport renders the FP-risk section used by --validate-deep.
// Output goes to stderr; exit code is unaffected (advisory).
func PrintFPLintReport(templates []*Template) {
	issues := LintFPTemplates(templates)
	total := 0
	caps := 50
	fmt.Fprintf(os.Stderr, "\n%s FP-RISK LINT (advisory — matchers whose evidence the request can produce)\n", SColor(ColorBWhite, "═══"))
	fmt.Fprintf(os.Stderr, "   %d templates flagged, %d issues\n", len(issues), countIssues(issues))
	for id, list := range issues {
		fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorYellow, id))
		for _, i := range list {
			fmt.Fprintf(os.Stderr, "    - %s\n", i)
			caps--
			if caps <= 0 {
				fmt.Fprintf(os.Stderr, "    … truncated, run with -load <file> to inspect specific templates\n")
				return
			}
		}
		total += len(list)
	}
	if total == 0 {
		fmt.Fprintf(os.Stderr, "   %s library is clean — no advisory findings\n", SColor(ColorGreen, "✔"))
	}
}

func countIssues(m map[string][]string) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}
