package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// Multi-probe wildcard calibration. Four random paths are requested; if they
// all share a status the site is wildcarding. The representative size is the
// median and the body hashes are recorded so soft-404 bodies that drift by a
// few bytes are still recognised as noise instead of "found".
var (
	wildcardHashes = make(map[string]bool)
	wildcardSizes  []int64
)

func DetectWildcard(target string, client *http.Client) (int, int64) {
	base, err := url.Parse(target)
	if err != nil {
		return 404, -1
	}

	dirPath := base.Path
	if ext := path.Ext(dirPath); ext != "" {
		dirPath = path.Dir(dirPath)
	}
	dirPath = strings.TrimSuffix(dirPath, "/")

	mkProbe := func(tag string) string {
		probe := fmt.Sprintf("hackit_wc_%s_%d", tag, time.Now().UnixNano())
		if dirPath == "" {
			return strings.TrimSuffix(base.Scheme+"://"+base.Host, "/") + "/" + probe
		}
		return strings.TrimSuffix(base.Scheme+"://"+base.Host+dirPath, "/") + "/" + probe
	}

	type probe struct {
		status int
		size   int64
		hash   string
	}
	var probes []probe
	for _, tag := range []string{"a", "b", "c", "d"} {
		resp, err := client.Get(mkProbe(tag))
		if err != nil {
			continue
		}
		st, sz, hash := followAndReadHash(resp, client, target)
		probes = append(probes, probe{st, sz, hash})
	}
	if len(probes) == 0 {
		return 404, -1
	}

	wildcardHashes = make(map[string]bool)
	wildcardSizes = nil
	for _, p := range probes {
		if p.hash != "" {
			wildcardHashes[p.hash] = true
		}
		wildcardSizes = append(wildcardSizes, p.size)
	}

	// All probes agree on status → the site returns that for any path.
	sameStatus := true
	for _, p := range probes[1:] {
		if p.status != probes[0].status {
			sameStatus = false
			break
		}
	}
	if !sameStatus {
		// Divergent statuses mean no reliable wildcard; use the first probe.
		return probes[0].status, probes[0].size
	}

	// Representative size = median, robust against a probe that drifted.
	sizes := append([]int64(nil), wildcardSizes...)
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	median := sizes[len(sizes)/2]
	return probes[0].status, median
}

func followAndRead(resp *http.Response, client *http.Client, baseTarget string) (int, int64) {
	st, sz, _ := followAndReadHash(resp, client, baseTarget)
	return st, sz
}

func followAndReadHash(resp *http.Response, client *http.Client, baseTarget string) (int, int64, string) {
	finalResp := resp
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
			return finalResp.StatusCode, -1, ""
		}
		finalResp = nextResp
	}
	defer finalResp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(finalResp.Body, 1024*1024))
	hash := fmt.Sprintf("%x", sha1.Sum(body))[:16]
	return finalResp.StatusCode, int64(len(body)), hash
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
