package main

import (
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
	
	// Remove fragments and normalize
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
	
	// Handle relative URLs
	if u.Host == "" {
		return true
	}
	
	// Normalize hosts (remove ports)
	targetHost := strings.Split(host, ":")[0]
	currentHost := strings.Split(u.Host, ":")[0]
	
	// Strict root domain check (e.g., allow subdomains)
	return strings.HasSuffix(currentHost, targetHost)
}
