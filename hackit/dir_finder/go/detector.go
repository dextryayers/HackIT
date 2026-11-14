package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

func DetectWildcard(target string, client *http.Client) (int, int64) {
	base, err := url.Parse(target)
	if err != nil {
		return 404, -1
	}

	// Calibrate relative to the target's own directory. For a file base
	// like /DVWA/index.php, the wildcard probe goes next to it
	// (/DVWA/<random>), not at the web root.
	dirPath := base.Path
	if ext := path.Ext(dirPath); ext != "" {
		dirPath = path.Dir(dirPath)
	}
	dirPath = strings.TrimSuffix(dirPath, "/")

	mkProbe := func(tag string) string {
		probe := fmt.Sprintf("hackit_wildcard_%s_%d", tag, time.Now().UnixNano())
		if dirPath == "" {
			return strings.TrimSuffix(base.Scheme+"://"+base.Host, "/") + "/" + probe
		}
		return strings.TrimSuffix(base.Scheme+"://"+base.Host+dirPath, "/") + "/" + probe
	}

	resp, err := client.Get(mkProbe("a"))
	if err != nil {
		return 404, -1
	}
	status, size := followAndRead(resp, client, target)

	resp2, err2 := client.Get(mkProbe("b"))
	if err2 == nil {
		status2, size2 := followAndRead(resp2, client, target)
		if status2 == status && size2 == size {
			return status, size
		}
	}

	return status, size
}

func followAndRead(resp *http.Response, client *http.Client, baseTarget string) (int, int64) {
	finalResp := resp
	// DVWA and other local apps can bounce a missing path back to
	// itself; cap redirect hops so calibration can't loop forever.
	for hops := 0; finalResp.StatusCode >= 300 && finalResp.StatusCode < 400 && hops < 8; hops++ {
		loc := finalResp.Header.Get("Location")
		if loc == "" {
			break
		}
		if !strings.HasPrefix(loc, "http") {
			base := strings.TrimRight(baseTarget, "/")
			if strings.HasPrefix(loc, "/") {
				loc = base + loc
			} else {
				loc = base + "/" + loc
			}
		}
		req, _ := http.NewRequest("GET", loc, nil)
		finalResp.Body.Close()
		nextResp, err := client.Do(req)
		if err != nil || nextResp == nil {
			break
		}
		finalResp = nextResp
	}
	defer finalResp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(finalResp.Body, 1024*1024))
	return finalResp.StatusCode, int64(len(body))
}

func DetectWAF(target string, client *http.Client) string {
	wafSignatures := map[string][]string{
		"Cloudflare":  {"cloudflare", "__cfduid", "cf-ray"},
		"Akamai":      {"akamai", "akamaized"},
		"ModSecurity": {"mod_security", "modsecurity", "No modifications are allowed"},
		"AWS WAF":     {"awselb", "aws-waf", "x-amz-rid"},
		"F5 BIG-IP":   {"big-ip", "f5"},
		"Barracuda":   {"barracuda", "barra"},
		"Sucuri":      {"sucuri", "cloudproxy"},
		"Wordfence":   {"wordfence"},
		"Stackpath":   {"stackpath"},
		"Comodo":      {"comodo"},
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
