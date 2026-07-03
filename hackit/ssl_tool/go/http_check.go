package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type HTTPReport struct {
	Status          int      `json:"status"`
	Server          string   `json:"server"`
	HSTS            string   `json:"hsts"`
	HSTSValid       bool     `json:"hsts_valid"`
	CSP             string   `json:"csp"`
	XFrameOptions   string   `json:"x_frame_options"`
	XContentType    string   `json:"x_content_type_options"`
	XXSSProtection  string   `json:"x_xss_protection"`
	ReferrerPolicy  string   `json:"referrer_policy"`
	PermissionsPolicy string `json:"permissions_policy"`
	CookiesSecure   bool     `json:"cookies_secure"`
	CookiesHttpOnly bool     `json:"cookies_httponly"`
	CORSPolicy      string   `json:"cors_policy"`
	Issues          []string `json:"issues"`
	Score           int      `json:"score"`
}

func scanHTTP(host string, port int, timeout time.Duration) HTTPReport {
	r := HTTPReport{
		Issues: make([]string, 0),
	}

	httpTimeout := timeout
	if httpTimeout > 6*time.Second {
		httpTimeout = 6 * time.Second
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: httpTimeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		r.Issues = append(r.Issues, fmt.Sprintf("TLS connection failed: %v", err))
		return r
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: HackIT-SSL-Scanner/3.0\r\nConnection: close\r\n\r\n", host)
	_, err = conn.Write([]byte(req))
	if err != nil {
		r.Issues = append(r.Issues, fmt.Sprintf("HTTP request failed: %v", err))
		return r
	}

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		r.Issues = append(r.Issues, "No HTTP response received")
		return r
	}

	resp := string(buf[:n])
	lines := strings.Split(resp, "\r\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "HTTP/") {
		parts := strings.SplitN(lines[0], " ", 3)
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &r.Status)
		}
	}

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(k)] = v
		}
	}

	r.Server = headers["server"]
	r.HSTS = headers["strict-transport-security"]
	r.HSTSValid = strings.Contains(strings.ToUpper(r.HSTS), "MAX-AGE") && !strings.Contains(strings.ToUpper(r.HSTS), "MAX-AGE=0")
	r.CSP = headers["content-security-policy"]
	r.XFrameOptions = headers["x-frame-options"]
	r.XContentType = headers["x-content-type-options"]
	r.XXSSProtection = headers["x-xss-protection"]
	r.ReferrerPolicy = headers["referrer-policy"]
	r.PermissionsPolicy = headers["permissions-policy"]

	if acao := headers["access-control-allow-origin"]; acao != "" {
		r.CORSPolicy = acao
	}

	if setCookie := headers["set-cookie"]; setCookie != "" {
		r.CookiesSecure = strings.Contains(strings.ToUpper(setCookie), "SECURE")
		r.CookiesHttpOnly = strings.Contains(strings.ToUpper(setCookie), "HTTPONLY")
	}

	r.Issues = buildHTTPIssues(&r)
	r.Score = calcHTTPSScore(&r)
	return r
}

func buildHTTPIssues(r *HTTPReport) []string {
	var issues []string
	if r.HSTS == "" {
		issues = append(issues, "HTTP Strict-Transport-Security (HSTS) not set")
	} else if !r.HSTSValid {
		issues = append(issues, "HSTS header present but max-age=0 (disabled)")
	}
	if r.CSP == "" {
		issues = append(issues, "Content-Security-Policy (CSP) not set")
	}
	if r.XFrameOptions == "" {
		issues = append(issues, "X-Frame-Options not set (clickjacking risk)")
	}
	if r.XContentType == "" {
		issues = append(issues, "X-Content-Type-Options not set (MIME sniffing risk)")
	}
	if r.ReferrerPolicy == "" {
		issues = append(issues, "Referrer-Policy not set")
	}
	if !r.CookiesSecure {
		issues = append(issues, "Cookies missing Secure flag")
	}
	if !r.CookiesHttpOnly {
		issues = append(issues, "Cookies missing HttpOnly flag")
	}
	if r.CORSPolicy != "" && r.CORSPolicy != "null" && !strings.HasPrefix(r.CORSPolicy, "https://") {
		issues = append(issues, fmt.Sprintf("Permissive CORS policy: %s", r.CORSPolicy))
	}
	return issues
}

func calcHTTPSScore(r *HTTPReport) int {
	s := 100
	if r.HSTS == "" {
		s -= 15
	}
	if r.CSP == "" {
		s -= 15
	}
	if r.XFrameOptions == "" {
		s -= 10
	}
	if r.XContentType == "" {
		s -= 5
	}
	if r.ReferrerPolicy == "" {
		s -= 5
	}
	if !r.CookiesSecure {
		s -= 10
	}
	if !r.CookiesHttpOnly {
		s -= 5
	}
	if r.CORSPolicy != "" && r.CORSPolicy != "null" && !strings.HasPrefix(r.CORSPolicy, "https://") {
		s -= 15
	}
	if s < 0 {
		s = 0
	}
	return s
}

func printHTTPReport(r HTTPReport) {
	fmt.Printf("\n  [+] HTTP Security Headers:")
	fmt.Printf("\n    %-24s : %d", "HTTP Status", r.Status)
	if r.Server != "" {
		fmt.Printf("\n    %-24s : %s", "Server", r.Server)
	}
	fmt.Printf("\n    %-24s : %s", "HSTS", boolYesNo(r.HSTS != ""))
	if r.HSTS != "" {
		fmt.Printf("\n    %-24s : %s", "  HSTS Header", truncateStr(r.HSTS, 60))
	}
	fmt.Printf("\n    %-24s : %s", "CSP", boolYesNo(r.CSP != ""))
	fmt.Printf("\n    %-24s : %s", "X-Frame-Options", boolVal(r.XFrameOptions))
	fmt.Printf("\n    %-24s : %s", "X-Content-Type-Options", boolVal(r.XContentType))
	fmt.Printf("\n    %-24s : %s", "Referrer-Policy", boolVal(r.ReferrerPolicy))
	fmt.Printf("\n    %-24s : HttpOnly=%v Secure=%v", "Cookies", r.CookiesHttpOnly, r.CookiesSecure)
	fmt.Printf("\n    %-24s : %d/100", "HTTP Score", r.Score)
	if len(r.Issues) > 0 {
		fmt.Printf("\n\n    [!] HTTP Issues (%d):", len(r.Issues))
		for _, iss := range r.Issues {
			fmt.Printf("\n      - %s", iss)
		}
	}
	fmt.Println()
}

func boolVal(v string) string {
	if v == "" {
		return "\033[31mNot Set\033[0m"
	}
	return fmt.Sprintf("\033[32m%s\033[0m", v[:min(len(v), 30)])
}

func boolYesNo(v bool) string {
	if v {
		return "\033[32mYes\033[0m"
	}
	return "\033[31mNo\033[0m"
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
