package native

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// TechResult holds the mapped technologies and potential vulnerabilities
type TechResult struct {
	Server          string
	Frameworks      []string
	Vulnerabilities []string
}

// MapTechnologies attempts to identify the stack and potential vulns on an HTTP/S port
func MapTechnologies(ip string, port int, banner string) TechResult {
	result := TechResult{}

	// Analyze Banner First
	bannerLower := strings.ToLower(banner)
	if strings.Contains(bannerLower, "litespeed") {
		result.Server = "LiteSpeed"
		result.Vulnerabilities = append(result.Vulnerabilities, "Check for CVE-2022-0073 (Privilege Escalation)")
	} else if strings.Contains(bannerLower, "nginx") {
		result.Server = "Nginx"
	} else if strings.Contains(bannerLower, "apache") {
		result.Server = "Apache"
	} else if strings.Contains(bannerLower, "pure-ftpd") {
		result.Server = "Pure-FTPd"
	} else if strings.Contains(bannerLower, "mysql") || strings.Contains(bannerLower, "mariadb") {
		result.Server = "MySQL/MariaDB"
	}

	// If it's a web port, do an HTTP probe
	if port == 80 || port == 8080 || port == 443 || port == 8443 || strings.Contains(bannerLower, "http") {
		scheme := "http"
		if port == 443 || port == 8443 || strings.Contains(bannerLower, "ssl") {
			scheme = "https"
		}

		targetURL := fmt.Sprintf("%s://%s:%d", scheme, ip, port)

		// Custom HTTP Client ignoring SSL errors
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}

		req, err := http.NewRequest("GET", targetURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			resp, err := client.Do(req)

			if err == nil {
				defer resp.Body.Close()

				// Extract Server Header
				if srv := resp.Header.Get("Server"); srv != "" && result.Server == "" {
					result.Server = srv
				}

				// Extract X-Powered-By
				if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
					result.Frameworks = append(result.Frameworks, xpb)
					if strings.Contains(strings.ToLower(xpb), "php") {
						result.Vulnerabilities = append(result.Vulnerabilities, "Potential PHP CGI/FPM bypass or deserialization vulns")
					}
				}

				// Check Cookies for hints (e.g. PHPSESSID, JSESSIONID)
				for _, cookie := range resp.Cookies() {
					if strings.Contains(cookie.Name, "PHPSESSID") {
						result.Frameworks = append(result.Frameworks, "PHP")
					} else if strings.Contains(cookie.Name, "JSESSIONID") {
						result.Frameworks = append(result.Frameworks, "Java/Tomcat")
					} else if strings.Contains(cookie.Name, "sessionid") {
						result.Frameworks = append(result.Frameworks, "Django/Python")
					}
				}

				// Read a chunk of body for meta tags
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
				bodyStr := string(bodyBytes)

				if strings.Contains(strings.ToLower(bodyStr), "wp-content") {
					result.Frameworks = append(result.Frameworks, "WordPress")
					result.Vulnerabilities = append(result.Vulnerabilities, "WordPress Detected: Run WPScan for plugin vulns")
				}

				reGenerator := regexp.MustCompile(`(?i)<meta name="generator" content="([^"]+)"`)
				if match := reGenerator.FindStringSubmatch(bodyStr); len(match) > 1 {
					result.Frameworks = append(result.Frameworks, match[1])
				}
			}
		}
	}

	// Basic Deduplication
	result.Frameworks = uniqueStrings(result.Frameworks)
	result.Vulnerabilities = uniqueStrings(result.Vulnerabilities)

	return result
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range input {
		if entry != "" {
			if _, value := keys[entry]; !value {
				keys[entry] = true
				list = append(list, entry)
			}
		}
	}
	return list
}
