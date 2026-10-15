package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("yaml parse error in %s: %w", path, err)
	}
	t.FilePath = path
	if t.ID == "" {
		return nil, fmt.Errorf("template %s missing 'id' field", path)
	}
	NormalizeTemplate(&t)
	return &t, nil
}

func LoadAllTemplatesFromFile(path string) ([]*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var templates []*Template
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var t Template
		if err := decoder.Decode(&t); err != nil {
			break
		}
		if t.ID == "" {
			continue
		}
		t.FilePath = path
		NormalizeTemplate(&t)
		templates = append(templates, &t)
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no valid templates found in %s", path)
	}
	return templates, nil
}

func LoadTemplates(dir string) ([]*Template, error) {
	var templates []*Template
	seen := make(map[string]bool)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		lower := strings.ToLower(info.Name())
		if info.IsDir() || (!strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml")) {
			return nil
		}
		loaded, err := LoadAllTemplatesFromFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Skipping %s: %v\n", path, err)
			return nil
		}
		for _, t := range loaded {
			if seen[t.ID] {
				fmt.Fprintf(os.Stderr, "[!] Duplicate template id %q in %s skipped\n", t.ID, path)
				continue
			}
			seen[t.ID] = true
			templates = append(templates, t)
		}
		return nil
	})
	return templates, err
}

func matchSeverityList(tplSev string, filter string) bool {
	tplSev = strings.ToLower(strings.TrimSpace(tplSev))
	for _, s := range strings.Split(filter, ",") {
		if strings.ToLower(strings.TrimSpace(s)) == tplSev {
			return true
		}
	}
	return false
}

func matchAnyTag(tplTags string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	set := make(map[string]bool)
	for _, tt := range strings.Split(strings.ToLower(tplTags), ",") {
		set[strings.TrimSpace(tt)] = true
	}
	for _, f := range filters {
		if set[strings.ToLower(strings.TrimSpace(f))] {
			return true
		}
	}
	return false
}

func matchExcluded(tplTags string, excluded []string) bool {
	if len(excluded) == 0 {
		return false
	}
	set := make(map[string]bool)
	for _, tt := range strings.Split(strings.ToLower(tplTags), ",") {
		set[strings.TrimSpace(tt)] = true
	}
	for _, f := range excluded {
		if set[strings.ToLower(strings.TrimSpace(f))] {
			return true
		}
	}
	return false
}

func FilterTemplates(templates []*Template, opts FilterOptions) []*Template {
	var filtered []*Template
	for _, t := range templates {
		if opts.ID != "" {
			hit := false
			for _, id := range strings.Split(opts.ID, ",") {
				if strings.TrimSpace(id) == t.ID {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		if opts.Severity != "" && !matchSeverityList(t.Info.Severity, opts.Severity) {
			continue
		}
		if opts.ExcludeSeverity != "" && matchSeverityList(t.Info.Severity, opts.ExcludeSeverity) {
			continue
		}
		if !matchAnyTag(t.Info.Tags, opts.Tags) {
			continue
		}
		if matchExcluded(t.Info.Tags, opts.ExcludeTags) {
			continue
		}
		if opts.Author != "" && !strings.Contains(strings.ToLower(t.Info.Author), strings.ToLower(opts.Author)) {
			continue
		}
		if len(opts.Types) > 0 {
			tplType := strings.ToLower(strings.TrimSpace(t.Info.Type))
			hit := false
			for _, ty := range opts.Types {
				if strings.ToLower(strings.TrimSpace(ty)) == tplType {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		filtered = append(filtered, t)
	}
	return filtered
}
