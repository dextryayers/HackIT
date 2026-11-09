package main

import (
	"fmt"
	"testing"
)

func TestFPLintReport(t *testing.T) {
	templates, err := LoadTemplates("../template")
	if err != nil {
		t.Fatal(err)
	}
	issues := LintFPTemplates(templates)
	total := 0
	for id, list := range issues {
		fmt.Printf("%s\n", id)
		for _, i := range list {
			total++
			fmt.Printf("    - %s\n", i)
		}
	}
	fmt.Printf("TOTAL_FP_RISK: %d templates, %d issues\n", len(issues), total)
}
