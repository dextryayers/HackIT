package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

type AnalysisResult struct {
	Server       string   `json:"server,omitempty"`
	Framework    string   `json:"framework,omitempty"`
	CMS          string   `json:"cms,omitempty"`
	Language     string   `json:"language,omitempty"`
	WAF          string   `json:"waf,omitempty"`
	Charset      string   `json:"charset,omitempty"`
	DetectedLang string   `json:"detected_lang,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	Title        string   `json:"title,omitempty"`
	BodyPreview  string   `json:"body_preview,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	Status       int      `json:"status"`
	Size         int64    `json:"size"`
	Headers      map[string]string `json:"headers,omitempty"`
}

type AnalyzeEngine struct{}

var analyzeEngine = &AnalyzeEngine{}

func (ae *AnalyzeEngine) Analyze(target string, client *http.Client) *AnalysisResult {
	result := &AnalysisResult{
		Technologies: []string{},
		Endpoints:    []string{},
		Headers:      make(map[string]string),
	}

	resp, err := client.Get(target)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode
	for k, v := range resp.Header {
		result.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	result.Server = ae.detectServer(resp.Header)
	result.Framework = ae.detectFramework(resp.Header)
	result.CMS = ae.detectCMS(resp.Header)
	result.Language = ae.detectLanguage(resp.Header)
	result.ContentType = resp.Header.Get("Content-Type")

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(body)
	result.Size = int64(len(body))
	result.Title = extractTitle(bodyStr)
	result.BodyPreview = compareEngine.ExtractBodyPreview(bodyStr, 200)
	result.DetectedLang = compareEngine.DetectLanguage(bodyStr)
	result.Charset = compareEngine.DetectCharset(bodyStr, result.ContentType)

	result.Technologies = ae.detectTechnologies(result.Server, result.Framework, result.CMS, result.Language, resp.Header)
	result.Endpoints = ae.extractEndpoints(bodyStr, target)
	result.WAF = ae.detectWAF(resp.Header, bodyStr, target, client)

	return result
}

func (ae *AnalyzeEngine) detectServer(headers http.Header) string {
	server := headers.Get("Server")
	if server != "" {
		return server
	}
	if h := headers.Get("Via"); h != "" {
		return "Via: " + h
	}
	return ""
}

func (ae *AnalyzeEngine) detectFramework(headers http.Header) string {
	xp := headers.Get("X-Powered-By")
	if xp != "" {
		return xp
	}
	xr := headers.Get("X-Runtime")
	if xr != "" {
		return "Ruby on Rails (" + xr + ")"
	}
	sc := headers.Get("Set-Cookie")
	switch {
	case strings.Contains(sc, "laravel_session"):
		return "Laravel"
	case strings.Contains(sc, "symfony"):
		return "Symfony"
	case strings.Contains(sc, "ci_session"):
		return "CodeIgniter"
	case strings.Contains(sc, "YII_CSRF_TOKEN"):
		return "Yii"
	case strings.Contains(sc, "drupal"):
		return "Drupal"
	case strings.Contains(sc, "wordpress_logged_in"):
		return "WordPress"
	}
	return ""
}

func (ae *AnalyzeEngine) detectCMS(headers http.Header) string {
	sc := headers.Get("Set-Cookie")
	server := headers.Get("Server")
	xp := headers.Get("X-Powered-By")

	switch {
	case strings.Contains(sc, "wordpress") || strings.Contains(sc, "wp-"):
		return "WordPress"
	case strings.Contains(sc, "drupal"):
		return "Drupal"
	case strings.Contains(xp, "Joomla"):
		return "Joomla"
	case strings.Contains(server, "Magento"):
		return "Magento"
	case strings.Contains(sc, "shopify"):
		return "Shopify"
	case strings.Contains(sc, "Wix"):
		return "Wix"
	case strings.Contains(sc, "squarespace"):
		return "Squarespace"
	}
	return ""
}

func (ae *AnalyzeEngine) detectLanguage(headers http.Header) string {
	xp := headers.Get("X-Powered-By")
	server := headers.Get("Server")
	sc := headers.Get("Set-Cookie")

	switch {
	case strings.Contains(sc, "PHPSESSID"):
		return "PHP"
	case strings.Contains(sc, "JSESSIONID"):
		return "Java"
	case strings.Contains(sc, "ASP.NET_SessionId"):
		return "ASP.NET"
	case strings.Contains(xp, "PHP"):
		return "PHP"
	case strings.Contains(xp, "ASP.NET"):
		return "ASP.NET"
	case strings.Contains(server, "gunicorn") || strings.Contains(server, "WSGIServer"):
		return "Python"
	case strings.Contains(server, "Node"):
		return "Node.js"
	case strings.Contains(xp, "Express"):
		return "Node.js"
	case strings.Contains(server, "Cowboy"):
		return "Erlang/Elixir"
	case strings.Contains(server, "Jetty"):
		return "Java"
	case strings.Contains(server, "Tomcat"):
		return "Java"
	}
	return ""
}

func (ae *AnalyzeEngine) detectTechnologies(server, framework, cms, lang string, headers http.Header) []string {
	var techs []string
	if server != "" {
		techs = append(techs, "Server: "+server)
	}
	if framework != "" {
		techs = append(techs, "Framework: "+framework)
	}
	if cms != "" {
		techs = append(techs, "CMS: "+cms)
	}
	if lang != "" {
		techs = append(techs, "Language: "+lang)
	}
	return techs
}

func (ae *AnalyzeEngine) detectWAF(headers http.Header, body string, target string, client *http.Client) string {
	server := headers.Get("Server")
	bodyLower := strings.ToLower(body)

	wafSignatures := map[string][]string{
		"Cloudflare":   {"cloudflare", "__cfduid", "cf-ray"},
		"Akamai":       {"akamai", "akamaized"},
		"ModSecurity":  {"mod_security", "modsecurity", "No modifications are allowed"},
		"AWS WAF":      {"awselb", "aws-waf", "x-amz-rid"},
		"F5 BIG-IP":    {"big-ip", "f5"},
		"Barracuda":    {"barracuda", "barra"},
		"Sucuri":       {"sucuri", "cloudproxy"},
		"Wordfence":    {"wordfence"},
		"Stackpath":    {"stackpath"},
		"Comodo":       {"comodo"},
		"Imperva":      {"imperva", "incapsula"},
	}

	headerStr := ""
	for k, v := range headers {
		headerStr += strings.ToLower(k) + "=" + strings.ToLower(strings.Join(v, ",")) + ";"
	}

	for wafName, sigs := range wafSignatures {
		for _, sig := range sigs {
			if strings.Contains(headerStr, sig) || strings.Contains(server, sig) || strings.Contains(bodyLower, sig) {
				return wafName
			}
		}
	}

	// Test with malicious payload
	if client != nil && target != "" {
		payloads := []string{
			"?id=' OR '1'='1",
			"?id=<script>alert(1)</script>",
			"?id=../../etc/passwd",
		}
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), payload)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
				resp.Body.Close()
				return "Generic WAF (blocked: " + fmt.Sprint(resp.StatusCode) + ")"
			}
			resp.Body.Close()
		}
	}

	return ""
}

func (ae *AnalyzeEngine) extractEndpoints(body, baseURL string) []string {
	endpoints := make(map[string]bool)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:href|src|action|data-url)\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`url\(["']?([^"')]+)["']?\)`),
		regexp.MustCompile(`["'](/[a-zA-Z0-9_\-./]+)["']`),
	}

	for _, re := range patterns {
		matches := re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) > 1 {
				ep := strings.TrimSpace(m[1])
				if strings.HasPrefix(ep, "/") && len(ep) > 2 && !strings.ContainsAny(ep, "<>(){}") {
					ep = strings.TrimSuffix(ep, "/")
					if !strings.HasSuffix(ep, ".css") && !strings.HasSuffix(ep, ".ico") &&
						!strings.HasSuffix(ep, ".png") && !strings.HasSuffix(ep, ".jpg") &&
						!strings.HasSuffix(ep, ".svg") && !strings.HasSuffix(ep, ".woff") &&
						!strings.HasSuffix(ep, ".woff2") {
						endpoints[ep] = true
					}
				}
			}
		}
	}

	var unique []string
	for ep := range endpoints {
		unique = append(unique, ep)
	}
	return unique
}

func (ae *AnalyzeEngine) AnalyzeResponse(res *DirResult, body string) map[string]interface{} {
	result := make(map[string]interface{})
	result["status"] = res.Status
	result["size"] = res.Size
	result["content_type"] = res.ContentType
	result["title"] = res.Title
	result["body_hash"] = res.BodyHash
	result["words"] = res.Words
	result["lines"] = res.Lines
	result["language"] = compareEngine.DetectLanguage(body)
	result["charset"] = compareEngine.DetectCharset(body, res.ContentType)
	result["body_preview"] = compareEngine.ExtractBodyPreview(body, 150)
	result["is_soft404"] = compareEngine.IsSoft404(res, body)
	result["is_duplicate"] = compareEngine.IsDuplicate(res)
	result["cluster_size"] = compareEngine.ClusterCount(res)
	return result
}

func (ae *AnalyzeEngine) ExportJSON(results []DirResult) string {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "[]"
	}
	return string(data)
}
