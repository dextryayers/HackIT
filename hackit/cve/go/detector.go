package main

import (
	"net/http"
	"strings"
	"time"
)

type DetectedTech struct {
	Software string
	Version  string
}

// Safely probe the target for HTTP headers to extract software signatures.
func DetectTechnologies(target string) []DetectedTech {
	var techs []DetectedTech

	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	client := http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return techs
	}
	req.Header.Set("User-Agent", "TechHunter-CVE-Detector/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return techs
	}
	defer resp.Body.Close()

	// 1. Check Server Header
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		techs = append(techs, parseHeaderSignature(serverHeader)...)
	}

	// 2. Check X-Powered-By
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		techs = append(techs, parseHeaderSignature(poweredBy)...)
	}

	return techs
}

func parseHeaderSignature(header string) []DetectedTech {
	var results []DetectedTech
	parts := strings.Split(header, " ")
	for _, part := range parts {
		if strings.Contains(part, "/") {
			sub := strings.Split(part, "/")
			if len(sub) == 2 {
				results = append(results, DetectedTech{
					Software: strings.ToLower(sub[0]),
					Version:  sub[1],
				})
			}
		} else {
			results = append(results, DetectedTech{
				Software: strings.ToLower(part),
				Version:  "unknown",
			})
		}
	}
	return results
}
