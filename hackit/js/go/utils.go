package main

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

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
