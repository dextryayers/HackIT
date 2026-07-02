package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func DetectWildcard(target string, client *http.Client) (int, int64) {
	// Test 1: Random path
	randomPath := fmt.Sprintf("hackit_wildcard_%d", time.Now().UnixNano())
	testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), randomPath)
	resp, err := client.Get(testURL)
	if err != nil {
		return 404, -1
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	size := int64(len(body))

	// Test 2: Another random path for verification
	randomPath2 := fmt.Sprintf("hackit_wildcard_verify_%d", time.Now().UnixNano())
	testURL2 := fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), randomPath2)
	resp2, err2 := client.Get(testURL2)
	if err2 == nil {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1024*1024))
		size2 := int64(len(body2))
		if resp2.StatusCode == status && size2 == size {
			return status, size
		}
	}

	return status, size
}

func DetectWAF(target string, client *http.Client) string {
	wafSignatures := map[string][]string{
		"Cloudflare": {"cloudflare", "__cfduid", "cf-ray"},
		"Akamai":     {"akamai", "akamaized"},
		"ModSecurity": {"mod_security", "modsecurity", "No modifications are allowed"},
		"AWS WAF":    {"awselb", "aws-waf", "x-amz-rid"},
		"F5 BIG-IP":  {"big-ip", "f5"},
		"Barracuda":  {"barracuda", "barra"},
		"Sucuri":     {"sucuri", "cloudproxy"},
		"Wordfence":  {"wordfence"},
		"Stackpath":  {"stackpath"},
		"Comodo":     {"comodo"},
	}

	wafPayloads := []string{
		"?id=' OR '1'='1",
		"?id=<script>alert(1)</script>",
		"?id=../../etc/passwd",
		"?id=UNION SELECT NULL--",
		"?id=<svg onload=alert(1)>",
	}

	for _, payload := range wafPayloads {
		testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), payload)
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}

		blockedStatus := resp.StatusCode == 403 || resp.StatusCode == 406 ||
			resp.StatusCode == 429 || resp.StatusCode == 501 ||
			resp.StatusCode == 503

		if blockedStatus {
			serverHeader := resp.Header.Get("Server")
			bodyPreview := ""
			limitedBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			bodyStr := string(limitedBody)
			resp.Body.Close()

			if len(bodyStr) < 4096 {
				bodyPreview = bodyStr
			} else {
				bodyPreview = bodyStr[:4096]
			}

			for wafName, sigs := range wafSignatures {
				for _, sig := range sigs {
					if strings.Contains(strings.ToLower(serverHeader), sig) ||
						strings.Contains(strings.ToLower(bodyPreview), sig) {
						resp.Body.Close()
						return wafName
					}
				}
			}

			if serverHeader != "" {
				resp.Body.Close()
				return fmt.Sprintf("Generic WAF (Server: %s, Blocked: %d)", serverHeader, resp.StatusCode)
			}
			resp.Body.Close()
			return fmt.Sprintf("Generic WAF (Blocked: %d)", resp.StatusCode)
		}
		resp.Body.Close()
	}

	return ""
}

func DetectTechnologies(resp *http.Response) []string {
	var tech []string

	server := resp.Header.Get("Server")
	if server != "" {
		tech = append(tech, server)
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		tech = append(tech, xPoweredBy)
	}

	setCookie := resp.Header.Get("Set-Cookie")
	switch {
	case strings.Contains(setCookie, "PHPSESSID"):
		tech = append(tech, "PHP")
	case strings.Contains(setCookie, "JSESSIONID"):
		tech = append(tech, "Java/JSP")
	case strings.Contains(setCookie, "ASP.NET_SessionId"):
		tech = append(tech, "ASP.NET")
	case strings.Contains(setCookie, "laravel_session"):
		tech = append(tech, "Laravel")
	case strings.Contains(setCookie, "symfony"):
		tech = append(tech, "Symfony")
	case strings.Contains(setCookie, "drupal"):
		tech = append(tech, "Drupal")
	}

	if strings.Contains(server, "nginx") {
		tech = append(tech, "Nginx")
	} else if strings.Contains(server, "apache") {
		tech = append(tech, "Apache")
	} else if strings.Contains(server, "iis") {
		tech = append(tech, "IIS")
	} else if strings.Contains(server, "cloudflare") {
		tech = append(tech, "Cloudflare")
	}

	return tech
}

func LoadSmartAnalysis(path string) ([]string, string) {
	if _, err := os.Stat(path); err != nil {
		return nil, ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ""
	}

	var smart struct {
		Endpoints []string `json:"endpoints"`
		Tech      []string `json:"tech,omitempty"`
		WAF       string   `json:"waf,omitempty"`
	}

	if err := json.Unmarshal(data, &smart); err != nil {
		return nil, ""
	}

	wafInfo := smart.WAF
	if len(smart.Tech) > 0 {
		wafInfo = strings.Join(smart.Tech, ", ")
	}

	return smart.Endpoints, wafInfo
}
