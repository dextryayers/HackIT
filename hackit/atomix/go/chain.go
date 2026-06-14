package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

type WorkflowStep struct {
	Template  string            `yaml:"template"`
	Variables map[string]string `yaml:"variables,omitempty"`
	Matchers  []string          `yaml:"matchers,omitempty"`
}

type Workflow struct {
	ID      string         `yaml:"id"`
	Info    TemplateInfo   `yaml:"info"`
	Steps   []WorkflowStep `yaml:"steps"`
}

func LoadWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil { return nil, err }
	return &wf, nil
}

func (s *Scanner) RunWorkflow(wf *Workflow, baseURL string) []Result {
	var allResults []Result
	fmt.Fprintf(os.Stderr, "%s Running workflow: %s (%d steps)\n",
		SColor(ColorBCyan, "►"), wf.ID, len(wf.Steps))
	for i, step := range wf.Steps {
		fmt.Fprintf(os.Stderr, "  %s Step %d: %s\n",
			SColor(ColorCyan, "→"), i+1, step.Template)
		var matched []*Template
		for _, t := range s.Templates {
			if t.ID == step.Template {
				matched = append(matched, t)
			}
		}
		if len(matched) == 0 {
			fmt.Fprintf(os.Stderr, "  %s Template not found: %s\n",
				SColor(ColorRed, "✗"), step.Template)
			continue
		}
		s.Templates = matched
		results := s.Scan(baseURL)
		allResults = append(allResults, results...)
		if len(results) == 0 && len(step.Matchers) > 0 {
			fmt.Fprintf(os.Stderr, "  %s Step %d failed matchers, aborting workflow\n",
				SColor(ColorYellow, "!"), i+1)
			break
		}
	}
	return allResults
}

func LoadAndRunWorkflow(path, baseURL string, scanner *Scanner) []Result {
	wf, err := LoadWorkflow(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error loading workflow: %v\n",
			SColor(ColorRed, "[!]"), err)
		return nil
	}
	return scanner.RunWorkflow(wf, baseURL)
}
