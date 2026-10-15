package main

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

type Scope struct {
	BaseHost   string
	BaseDomain string
	MaxDepth   int
	Excludes   []*regexp.Regexp
	IncludeRe  []*regexp.Regexp
	ExcludeRe  []*regexp.Regexp
}

func NewScope(rawURL string, maxDepth int) *Scope {
	u, _ := url.Parse(rawURL)
	host := strings.Split(u.Host, ":")[0]
	base := strings.TrimPrefix(host, "www.")
	if base == host {
		base = host
	}
	return &Scope{
		BaseHost:   host,
		BaseDomain: base,
		MaxDepth:   maxDepth,
		Excludes:   compileExcludes(),
	}
}

func CompileScopeRegexes(include, exclude string) (inc, exc []*regexp.Regexp) {
	for _, p := range strings.Split(include, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if re, err := regexp.Compile(p); err == nil {
				inc = append(inc, re)
			}
		}
	}
	for _, p := range strings.Split(exclude, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if re, err := regexp.Compile(p); err == nil {
				exc = append(exc, re)
			}
		}
	}
	return inc, exc
}

func compileExcludes() []*regexp.Regexp {
	patterns := []string{
		`(?i)\.(png|jpg|jpeg|gif|ico|svg|bmp|webp|woff|woff2|ttf|eot|pdf|zip|tar|gz|mp4|mp3|avi|mov)$`,
		`(?i)(logout|signout|sign-?out|log-?out)`,
		`(?i)(node_modules|bower_components|vendor|\.git|\.svn|__pycache__)`,
		`(?i)(calendar|/ics/|\.ics$)`,
	}
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return compiled
}

func (s *Scope) IsInScope(rawURL string, depth int) bool {
	if depth > s.MaxDepth {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.Split(u.Host, ":")[0]
	if host == "" {
		return true
	}
	if !strings.HasSuffix(host, s.BaseDomain) {
		return false
	}
	for _, ex := range s.Excludes {
		if ex.MatchString(rawURL) {
			return false
		}
	}
	for _, ex := range s.ExcludeRe {
		if ex.MatchString(rawURL) {
			return false
		}
	}
	if len(s.IncludeRe) > 0 {
		matched := false
		for _, in := range s.IncludeRe {
			if in.MatchString(rawURL) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (s *Scope) IsJS(rawURL string) bool {
	ext := strings.ToLower(path.Ext(rawURL))
	_, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	switch ext {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte":
		return true
	}
	return strings.Contains(rawURL, ".js?") || strings.Contains(rawURL, "js/")
}

func (s *Scope) IsCode(rawURL string) bool {
	ext := strings.ToLower(path.Ext(rawURL))
	switch ext {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue",
		".svelte", ".json", ".xml", ".yaml", ".yml", ".conf",
		".config", ".env", ".txt", ".md", ".php", ".asp", ".aspx",
		".jsp", ".py", ".rb", ".go", ".java", ".swift", ".kt",
		".dart", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs", ".fs",
		".css", ".scss", ".less", ".map", ".csv":
		return true
	}
	return false
}

func (s *Scope) Normalize(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	return u.String()
}
