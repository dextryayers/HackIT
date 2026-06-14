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
		templates = append(templates, &t)
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no valid templates found in %s", path)
	}
	return templates, nil
}

func LoadTemplates(dir string) ([]*Template, error) {
	var templates []*Template
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".yaml") {
			return nil
		}
		loaded, err := LoadAllTemplatesFromFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Skipping %s: %v\n", path, err)
			return nil
		}
		templates = append(templates, loaded...)
		return nil
	})
	return templates, err
}

func FilterTemplates(templates []*Template, opts FilterOptions) []*Template {
	var filtered []*Template
	for _, t := range templates {
		if opts.ID != "" && t.ID != opts.ID {
			continue
		}
		if opts.Severity != "" {
			sev := strings.ToLower(t.Info.Severity)
			reqSev := strings.ToLower(opts.Severity)
			if sev != reqSev {
				continue
			}
		}
		if len(opts.Tags) > 0 {
			tplTags := strings.Split(t.Info.Tags, ",")
			found := false
			for _, rt := range opts.Tags {
				for _, tt := range tplTags {
					if strings.TrimSpace(rt) == strings.TrimSpace(tt) {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				continue
			}
		}
		filtered = append(filtered, t)
	}
	return filtered
}
