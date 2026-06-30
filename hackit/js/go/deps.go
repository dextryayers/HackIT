package main

import (
	"regexp"
	"strings"
)

var (
	requirePattern  = regexp.MustCompile(`require\(["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\)`)
	dynamicImport   = regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`)
	moduleExports   = regexp.MustCompile(`module\.exports\s*=\s*require\(["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\)`)
	importMapPattern = regexp.MustCompile(`"imports"\s*:\s*\{([^}]+)\}`)
)

func (c *Crawler) extractDependencies(body string, sourceURL string, depth int) {
	patterns := []struct {
		name  string
		re    *regexp.Regexp
		group int
	}{
		{"require", requirePattern, 1},
		{"dynamic_import", dynamicImport, 1},
		{"module_exports", moduleExports, 1},
	}
	seen := make(map[string]bool)
	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) <= p.group {
				continue
			}
			mod := strings.TrimSpace(m[p.group])
			if mod == "" || seen[mod] {
				continue
			}
			seen[mod] = true
			if isBareModule(mod) {
				writeOutput(`{"type":"dependency","source":%q,"module":%q,"resolved":"%s","kind":%q}`+"\n", sourceURL, mod, "npm:"+mod, p.name)
				continue
			}
			absURL := resolveJSImport(mod, sourceURL, p.name)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
				writeOutput(`{"type":"dependency","source":%q,"module":%q,"resolved":%q,"kind":%q}`+"\n", sourceURL, mod, absURL, p.name)
				c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1})
			}
		}
	}
	impMap := importMapPattern.FindStringSubmatch(body)
	if len(impMap) >= 2 {
		pairs := strings.Split(impMap[1], ",")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if !strings.Contains(pair, ":") {
				continue
			}
			parts := strings.SplitN(pair, ":", 2)
			k := strings.Trim(strings.TrimSpace(parts[0]), "\"")
			v := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			if k != "" && v != "" && strings.HasPrefix(v, "http") {
				absURL := resolveURL(v, sourceURL)
				if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
					writeOutput(`{"type":"import_map","source":%q,"module":%q,"resolved":%q}`+"\n", sourceURL, k, absURL)
					c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1})
				}
			}
		}
	}
}

func isBareModule(mod string) bool {
	if strings.HasPrefix(mod, "http") || strings.HasPrefix(mod, "//") || strings.HasPrefix(mod, "/") || strings.HasPrefix(mod, "./") || strings.HasPrefix(mod, "../") {
		return false
	}
	return true
}
