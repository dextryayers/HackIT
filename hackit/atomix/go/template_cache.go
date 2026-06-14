package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type CompiledTemplate struct {
	Template     *Template
	PathRegexps  []*regexp.Regexp
	WordRegexps  []*regexp.Regexp
	RegexMatcher []*regexp.Regexp
	StatusSet    map[int]bool
	SizeSet      map[int]bool
}

type TemplateCache struct {
	mu         sync.RWMutex
	entries    map[string]*CompiledTemplate
	dirHashes  map[string]string
	loadErrors map[string]error
}

func NewTemplateCache() *TemplateCache {
	return &TemplateCache{
		entries:    make(map[string]*CompiledTemplate),
		dirHashes:  make(map[string]string),
		loadErrors: make(map[string]error),
	}
}

func CompileTemplate(t *Template) *CompiledTemplate {
	ct := &CompiledTemplate{
		Template:  t,
		StatusSet: make(map[int]bool),
		SizeSet:   make(map[int]bool),
	}

	for _, req := range t.Requests {
		for _, path := range req.Path {
			reStr := convertPathToRegex(path)
			if re, err := regexp.Compile(reStr); err == nil {
				ct.PathRegexps = append(ct.PathRegexps, re)
			}
		}

		for _, m := range req.Matchers {
			for _, w := range m.Words {
				reStr := regexp.QuoteMeta(w)
				if re, err := regexp.Compile(reStr); err == nil {
					ct.WordRegexps = append(ct.WordRegexps, re)
				}
			}
			for _, r := range m.Regex {
				if re, err := regexp.Compile(r); err == nil {
					ct.RegexMatcher = append(ct.RegexMatcher, re)
				}
			}
			for _, s := range m.Status {
				ct.StatusSet[s] = true
			}
			for _, s := range m.Size {
				ct.SizeSet[s] = true
			}
		}
	}

	for _, m := range t.Matchers {
		for _, w := range m.Words {
			reStr := regexp.QuoteMeta(w)
			if re, err := regexp.Compile(reStr); err == nil {
				ct.WordRegexps = append(ct.WordRegexps, re)
			}
		}
		for _, r := range m.Regex {
			if re, err := regexp.Compile(r); err == nil {
				ct.RegexMatcher = append(ct.RegexMatcher, re)
			}
		}
		for _, s := range m.Status {
			ct.StatusSet[s] = true
		}
		for _, s := range m.Size {
			ct.SizeSet[s] = true
		}
	}

	return ct
}

func convertPathToRegex(path string) string {
	re := regexp.QuoteMeta(path)
	re = strings.ReplaceAll(re, `\{\{BaseURL\}\}`, `.*`)
	re = strings.ReplaceAll(re, `\{\{Port\}\}`, `\d+`)
	re = strings.ReplaceAll(re, `\{\{Random\}\}`, `[a-zA-Z0-9]+`)
	re = strings.ReplaceAll(re, `\{\{.*?\}\}`, `.*?`)
	return "^" + re + "$"
}

func (tc *TemplateCache) Get(id string) *CompiledTemplate {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.entries[id]
}

func (tc *TemplateCache) Set(id string, ct *CompiledTemplate) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.entries[id] = ct
}

func (tc *TemplateCache) PrecompileAll(templates []*Template) int {
	count := 0
	for _, t := range templates {
		if tc.Get(t.ID) != nil {
			continue
		}
		ct := CompileTemplate(t)
		tc.Set(t.ID, ct)
		count++
	}
	return count
}

func (tc *TemplateCache) Clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.entries = make(map[string]*CompiledTemplate)
	tc.dirHashes = make(map[string]string)
	tc.loadErrors = make(map[string]error)
}

type TemplateWatcher struct {
	dir      string
	cache    *TemplateCache
	patterns []string
}

func NewTemplateWatcher(dir string) *TemplateWatcher {
	return &TemplateWatcher{
		dir:      dir,
		cache:    NewTemplateCache(),
		patterns: []string{"*.yaml", "*.yml", "*.custom"},
	}
}

func (tw *TemplateWatcher) LoadAndCache() ([]*Template, error) {
	var templates []*Template
	err := filepath.Walk(tw.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil { return err }
		if info.IsDir() { return nil }
		valid := false
		for _, p := range tw.patterns {
			if matched, _ := filepath.Match(p, info.Name()); matched {
				valid = true
				break
			}
		}
		if !valid { return nil }
		loaded, err := LoadAllTemplatesFromFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Skipping %s: %v\n",
				SColor(ColorYellow, "[!]"), path, err)
			return nil
		}
		templates = append(templates, loaded...)
		return nil
	})
	if err != nil {
		return templates, err
	}
	tw.cache.PrecompileAll(templates)
	return templates, nil
}

func (tw *TemplateWatcher) CacheStats() (int, int) {
	tw.cache.mu.RLock()
	defer tw.cache.mu.RUnlock()
	total := len(tw.cache.entries)
	errors := len(tw.cache.loadErrors)
	return total, errors
}
