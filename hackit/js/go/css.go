package main

import (
	"regexp"
	"strings"
)

var (
	cssURLFunc    = regexp.MustCompile(`(?i)url\(\s*["']?([^"'()]+?)["']?\s*\)`)
	cssImportRule = regexp.MustCompile(`(?i)@import\s+(?:url\(\s*["']?([^"'()]+?)["']?\s*\)|["']([^"'()]+?)["'])\s*;?`)
	cssImageSet   = regexp.MustCompile(`(?i)image-set\(\s*([^)]+?)\s*\)`)
	cssSrcProp    = regexp.MustCompile(`(?i)(?:^|[;{}])\s*src\s*:\s*([^;{}]+)`)
	cssFontFace   = regexp.MustCompile(`(?i)@font-face\s*\{([^}]+)\}`)
)

// parseCSSResources extracts every referenced asset from a stylesheet:
// url(), @import, image-set(), legacy src:, @font-face blocks.
func (c *Crawler) parseCSSResources(css, pageURL string, depth int) {
	seen := make(map[string]bool)
	emit := func(raw, ctx string) {
		raw = strings.TrimSpace(strings.Trim(raw, `"'`))
		// Unwrap legacy src:url(...) values to the bare path.
		if strings.HasPrefix(strings.ToLower(raw), "url(") {
			if m := cssURLFunc.FindStringSubmatch(raw); len(m) >= 2 {
				raw = strings.TrimSpace(m[1])
			}
		}
		if raw == "" || seen[raw] || strings.HasPrefix(raw, "#") ||
			strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "about:") {
			return
		}
		seen[raw] = true
		absURL := resolveURL(raw, pageURL)
		if absURL == "" {
			return
		}
		writeOutput(`{"type":"css_ref","url":%q,"source":%q,"ctx":%q}`+"\n", absURL, pageURL, ctx)
		if !c.Scope.IsInScope(absURL, depth+1) || c.Filters.HasSeen(absURL) {
			return
		}
		if c.Scope.IsCode(absURL) || c.Scope.IsJS(absURL) {
			c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
		}
	}

	for _, m := range cssImportRule.FindAllStringSubmatch(css, -1) {
		if len(m) >= 2 && m[1] != "" {
			emit(m[1], "css_import")
		} else if len(m) >= 3 && m[2] != "" {
			emit(m[2], "css_import")
		}
	}
	for _, m := range cssURLFunc.FindAllStringSubmatch(css, -1) {
		if len(m) >= 2 {
			emit(m[1], "css_url")
		}
	}
	for _, m := range cssImageSet.FindAllStringSubmatch(css, -1) {
		if len(m) < 2 {
			continue
		}
		for _, part := range strings.Split(m[1], ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) > 0 {
				emit(fields[0], "css_image_set")
			}
		}
	}
	for _, m := range cssSrcProp.FindAllStringSubmatch(css, -1) {
		if len(m) >= 2 {
			emit(m[1], "css_src")
		}
	}
	for _, m := range cssFontFace.FindAllStringSubmatch(css, -1) {
		if len(m) >= 2 {
			for _, u := range cssURLFunc.FindAllStringSubmatch(m[1], -1) {
				if len(u) >= 2 {
					emit(u[1], "css_font")
				}
			}
		}
	}
}
