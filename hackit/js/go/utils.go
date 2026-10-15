package main

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var baseHrefPattern = regexp.MustCompile(`(?i)<base[^>]+href=["']?([^"'\s>]+)["']?`)

func extractBaseHref(body, pageURL string) string {
	m := baseHrefPattern.FindStringSubmatch(body)
	if len(m) >= 2 {
		if abs := resolveURL(strings.TrimSpace(m[1]), pageURL); abs != "" {
			return abs
		}
	}
	return pageURL
}

func parseSrcset(srcset string) []string {
	var out []string
	for _, part := range strings.Split(srcset, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) > 0 && fields[0] != "" {
			out = append(out, fields[0])
		}
	}
	return out
}

func resolveURL(ref, base string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	baseU, err := url.Parse(base)
	if err != nil {
		return ""
	}
	resolved := baseU.ResolveReference(u)
	resolved.Fragment = ""
	// Collapse accidental double slashes in path (keep scheme:// intact).
	for strings.Contains(resolved.Path, "//") {
		resolved.Path = strings.ReplaceAll(resolved.Path, "//", "/")
	}
	return resolved.String()
}

func getExtension(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	ext := path.Ext(u.Path)
	return strings.TrimPrefix(ext, ".")
}

func isInternal(rawURL, host string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Host == "" {
		return true
	}
	targetHost := strings.Split(host, ":")[0]
	currentHost := strings.Split(u.Host, ":")[0]
	return strings.HasSuffix(currentHost, targetHost)
}

func resolveJSImport(imp string, baseURL string, discoveryType string) string {
	if strings.HasPrefix(imp, "http://") || strings.HasPrefix(imp, "https://") {
		return imp
	}
	if strings.HasPrefix(imp, "//") {
		u, _ := url.Parse(baseURL)
		return u.Scheme + ":" + imp
	}
	if strings.HasPrefix(imp, "/") {
		u, _ := url.Parse(baseURL)
		return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, imp)
	}
	if strings.HasPrefix(imp, "./") || strings.HasPrefix(imp, "../") || !strings.Contains(imp, "/") {
		baseDir := baseURL
		if idx := strings.LastIndex(baseURL, "/"); idx > 8 {
			baseDir = baseURL[:idx]
		}
		cleaned := cleanPath(baseDir + "/" + imp)
		return cleaned
	}
	return imp
}

func cleanPath(p string) string {
	parts := strings.Split(p, "/")
	var result []string
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		if part == ".." && len(result) > 0 {
			result = result[:len(result)-1]
		} else {
			result = append(result, part)
		}
	}
	if len(result) < 2 {
		return p
	}
	scheme := result[0] + "//"
	return scheme + strings.Join(result[1:], "/")
}
