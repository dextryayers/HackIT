package main

import (
	"fmt"
	"os"
	"strings"
)

const templateSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["id", "info", "requests"],
  "properties": {
    "id": {"type": "string", "pattern": "^[a-zA-Z0-9_-]+$"},
    "info": {
      "type": "object",
      "required": ["name", "severity"],
      "properties": {
        "name": {"type": "string"},
        "author": {"type": "string"},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "description": {"type": "string"},
        "tags": {"type": "string"}
      }
    },
    "requests": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["path"],
        "properties": {
          "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
          "path": {"type": "array", "items": {"type": "string"}},
          "headers": {"type": "object"},
          "body": {"type": "string"},
          "matchers": {"type": "array"},
          "payloads": {"type": "array", "items": {"type": "string"}}
        }
      }
    }
  }
}`

type ValidationResult struct {
	TemplateID  string
	FilePath    string
	Valid       bool
	Errors      []string
	Warnings    []string
}

func ValidateTemplateSchema(t *Template, filePath string) *ValidationResult {
	r := &ValidationResult{
		TemplateID: t.ID,
		FilePath:   filePath,
		Valid:      true,
		Errors:     []string{},
		Warnings:   []string{},
	}

	if t.ID == "" {
		r.Errors = append(r.Errors, "Missing required field: id")
		r.Valid = false
	}
	if !isValidID(t.ID) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("ID '%s' may contain special characters", t.ID))
	}

	if t.Info.Name == "" {
		r.Errors = append(r.Errors, "Missing required field: info.name")
		r.Valid = false
	}
	if t.Info.Severity == "" {
		r.Errors = append(r.Errors, "Missing required field: info.severity")
		r.Valid = false
	} else {
		validSev := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
		if !validSev[strings.ToLower(t.Info.Severity)] {
			r.Warnings = append(r.Warnings, fmt.Sprintf("Severity '%s' is non-standard", t.Info.Severity))
		}
	}

	if len(t.Requests) == 0 {
		r.Errors = append(r.Errors, "No requests defined in template")
		r.Valid = false
	}

	for ri, req := range t.Requests {
		prefix := fmt.Sprintf("requests[%d]", ri)
		if len(req.Path) == 0 {
			r.Errors = append(r.Errors, fmt.Sprintf("%s: No paths defined", prefix))
			r.Valid = false
		}
		if req.Method == "" {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: No method specified, defaulting to GET", prefix))
		}
		if req.Method != "" {
			validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "HEAD": true, "OPTIONS": true}
			if !validMethods[strings.ToUpper(req.Method)] {
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s: Unusual method '%s'", prefix, req.Method))
			}
		}
		if len(req.Matchers) == 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: No matchers defined", prefix))
		}
		for mi, m := range req.Matchers {
			if m.Type == "" {
				r.Errors = append(r.Errors, fmt.Sprintf("%s.matchers[%d]: Missing type field", prefix, mi))
				r.Valid = false
			}
			if m.Type == "word" && len(m.Words) == 0 {
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s.matchers[%d]: Word type with no words", prefix, mi))
			}
			if m.Type == "regex" && len(m.Regex) == 0 {
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s.matchers[%d]: Regex type with no patterns", prefix, mi))
			}
		}
	}

	// Check for potential false positive patterns
	bodyLenTotal := 0
	for _, req := range t.Requests {
		bodyLenTotal += len(req.Body)
	}
	if bodyLenTotal > 10000 {
		r.Warnings = append(r.Warnings, "Template has large request bodies (>10KB)")
	}

	return r
}

func isValidID(id string) bool {
	if len(id) == 0 { return false }
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func ValidateTemplateDeep(t *Template) *ValidationResult {
	return ValidateTemplateSchema(t, t.FilePath)
}

func BatchValidate(templates []*Template) ([]*ValidationResult, int, int) {
	var results []*ValidationResult
	valid, invalid := 0, 0
	for _, t := range templates {
		r := ValidateTemplateDeep(t)
		results = append(results, r)
		if r.Valid {
			valid++
		} else {
			invalid++
		}
	}
	return results, valid, invalid
}

func PrintValidationResults(results []*ValidationResult) {
	if noColor {
		fmt.Printf("\n=== TEMPLATE VALIDATION ===\n")
		for _, r := range results {
			status := "VALID"
			if !r.Valid { status = "INVALID" }
			fmt.Printf("[%s] %s (%s)\n", status, r.TemplateID, r.FilePath)
			for _, e := range r.Errors {
				fmt.Printf("  ERR:  %s\n", e)
			}
			for _, w := range r.Warnings {
				fmt.Printf("  WARN: %s\n", w)
			}
		}
		return
	}

	fmt.Printf("\n%s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "TEMPLATE VALIDATION"))

	for _, r := range results {
		if r.Valid {
			fmt.Printf("  %s %s - %s\n",
				SColor(ColorGreen, "[✓]"),
				SColor(ColorBWhite, r.TemplateID),
				SColor(ColorDim, r.FilePath))
		} else {
			fmt.Printf("  %s %s - %s\n",
				SColor(ColorBRed, "[✗]"),
				SColor(ColorBWhite, r.TemplateID),
				SColor(ColorDim, r.FilePath))
		}
		for _, w := range r.Warnings {
			fmt.Printf("    %s %s\n", SColor(ColorYellow, "WARN:"), w)
		}
		for _, e := range r.Errors {
			fmt.Printf("    %s %s\n", SColor(ColorRed, "ERR:"), e)
		}
	}
	fmt.Println()
}

func ValidateTmux(templates []*Template) {
	results, valid, invalid := BatchValidate(templates)
	PrintValidationResults(results)
	if noColor {
		fmt.Printf("Summary: %d valid, %d invalid\n", valid, invalid)
	} else {
		fmt.Fprintf(os.Stderr, "\n  %s %s valid, %s invalid\n",
			SColor(ColorGreen, fmt.Sprintf("%d", valid)),
			SColor(ColorBWhite, "valid,"),
			SColor(ColorRed, fmt.Sprintf("%d", invalid)))
	}
}
