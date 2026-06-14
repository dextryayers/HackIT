package main

import (
	"fmt"
	"os"
	"strings"
)

func ValidateTemplate(t *Template) []string {
	var errs []string
	if t.ID == "" {
		errs = append(errs, "missing 'id' field")
	}
	if t.Info.Name == "" {
		errs = append(errs, "missing 'info.name' field")
	}
	if len(t.Requests) == 0 {
		errs = append(errs, "no requests defined")
	}
	for ri, req := range t.Requests {
		if req.Method == "" {
			errs = append(errs, fmt.Sprintf("request[%d]: missing method", ri))
		}
		if len(req.Path) == 0 {
			errs = append(errs, fmt.Sprintf("request[%d]: no paths defined", ri))
		}
		for pi, p := range req.Path {
			if !strings.Contains(p, "{{BaseURL}}") && !strings.Contains(p, "{{URL}}") {
				errs = append(errs, fmt.Sprintf("request[%d].path[%d]: missing {{BaseURL}} placeholder", ri, pi))
			}
		}
	}
	hasMatcher := len(t.Matchers) > 0
	if !hasMatcher {
		for _, req := range t.Requests {
			if len(req.Matchers) > 0 {
				hasMatcher = true
				break
			}
		}
	}
	if !hasMatcher {
		errs = append(errs, "no matchers defined at template or request level")
	}
	return errs
}

func ValidateTemplates(templates []*Template) (valid int, invalid int) {
	for _, t := range templates {
		errs := ValidateTemplate(t)
		if len(errs) > 0 {
			invalid++
			fmt.Fprintf(os.Stderr, "%s Template %s (%s):\n", SColor(ColorYellow, "[!]"), t.ID, t.FilePath)
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorRed, "✗"), e)
			}
		} else {
			valid++
		}
	}
	return
}

func ValidateAll(dir string) {
	templates, err := LoadTemplates(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error loading templates: %v\n", SColor(ColorRed, "[!]"), err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s Loaded %d templates for validation\n", SColor(ColorGreen, "[+]"), len(templates))
	valid, invalid := ValidateTemplates(templates)
	fmt.Fprintf(os.Stderr, "%s Valid: %d, Invalid: %d\n",
		SColor(ColorGreen, "[+]"), valid, invalid)
}
