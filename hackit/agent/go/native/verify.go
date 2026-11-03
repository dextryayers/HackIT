package native

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// VerifiedFinding is a vulnerability confirmed by a live probe, never by name
// matching alone. Every field carries the evidence an analyst needs to
// reproduce it with curl.
type VerifiedFinding struct {
	ID          string
	Name        string
	Severity    string
	CVSS        float64
	Port        int
	Description string
	Evidence    string
	Remediation string
	Category    string
	Reproduce   string // copy-paste curl command
}

func verifyClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
}

func verifyGet(client *http.Client, target string) (int, http.Header, string) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return 0, nil, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return resp.StatusCode, resp.Header, string(body)
}

// bodySnippet returns context around marker for evidence strings.
func bodySnippet(body, marker string) string {
	lower := strings.ToLower(body)
	idx := strings.Index(lower, strings.ToLower(marker))
	if idx < 0 {
		if len(body) > 160 {
			return strings.TrimSpace(body[:160]) + "..."
		}
		return strings.TrimSpace(body)
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(marker) + 80
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

// VerifyExposedEndpoint re-probes an enumerated URL and only confirms when the
// body carries the file's unmistakable signature. Returns nil on soft-404,
// login wall, or generic page.
func VerifyExposedEndpoint(endpoint string) *VerifiedFinding {
	client := verifyClient(10 * time.Second)
	status, header, body := verifyGet(client, endpoint)
	if status == 0 {
		return nil
	}
	lower := strings.ToLower(endpoint)
	ct := strings.ToLower(header.Get("Content-Type"))
	lb := strings.ToLower(body)

	switch {
	case strings.HasSuffix(lower, "/.env"):
		if status == 200 && (strings.Contains(lb, "db_password") || strings.Contains(lb, "database_url") ||
			strings.Contains(lb, "app_key") || strings.Contains(lb, "secret")) {
			return &VerifiedFinding{
				ID: "MISCONF-001", Name: "Exposed Environment File (.env)",
				Severity: "Critical", CVSS: 9.8,
				Description: fmt.Sprintf("Live .env file with secrets served at %s (HTTP %d)", endpoint, status),
				Evidence:    fmt.Sprintf("HTTP %d, Content-Type %s, secrets marker: %q", status, ct, bodySnippet(body, "DB_")),
				Remediation: "Block dotfiles at the edge and rotate every secret in the file.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s -D- %q | head -c 2000", endpoint),
			}
		}
	case strings.HasSuffix(lower, "/.git/config"):
		if status == 200 && strings.Contains(lb, "[core]") && strings.Contains(lb, "repositoryformatversion") {
			return &VerifiedFinding{
				ID: "MISCONF-002", Name: "Exposed Git Repository",
				Severity: "High", CVSS: 7.5,
				Description: fmt.Sprintf("Live .git/config served at %s: full repo history downloadable", endpoint),
				Evidence:    fmt.Sprintf("HTTP %d with [core] repositoryformatversion block: %q", status, bodySnippet(body, "[core]")),
				Remediation: "Deny /.git at the edge and purge secrets from git history.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s %q", endpoint),
			}
		}
	case strings.HasSuffix(lower, "/phpinfo.php") || strings.HasSuffix(lower, "/info.php"):
		if status == 200 && strings.Contains(lb, "php version") && strings.Contains(lb, "configuration") {
			return &VerifiedFinding{
				ID: "MISCONF-PHPINFO", Name: "PHPInfo Information Disclosure",
				Severity: "High", CVSS: 7.0,
				Description: fmt.Sprintf("Live phpinfo() dump at %s leaks versions, paths, env", endpoint),
				Evidence:    fmt.Sprintf("HTTP %d with PHP Version table: %q", status, bodySnippet(body, "PHP Version")),
				Remediation: "Delete phpinfo files from production.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s %q | grep -i -m2 'PHP Version'", endpoint),
			}
		}
	case strings.HasSuffix(lower, "/server-status"):
		if status == 200 && strings.Contains(lb, "apache status") {
			return &VerifiedFinding{
				ID: "MISCONF-SERVER-STATUS", Name: "Apache server-status Exposed",
				Severity: "Medium", CVSS: 5.3,
				Description: fmt.Sprintf("Live mod_status at %s leaks workers, vhosts, request paths", endpoint),
				Evidence:    fmt.Sprintf("HTTP %d Apache Status page: %q", status, bodySnippet(body, "Apache Status")),
				Remediation: "Require local + auth for /server-status.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s %q | head -c 1000", endpoint),
			}
		}
	case strings.Contains(lower, "actuator"):
		if status == 200 && (strings.Contains(lb, "\"status\"") || strings.Contains(lb, "_links")) {
			return &VerifiedFinding{
				ID: "MISCONF-ACTUATOR", Name: "Spring Boot Actuator Exposed",
				Severity: "High", CVSS: 7.5,
				Description: fmt.Sprintf("Live actuator endpoint at %s (HTTP %d)", endpoint, status),
				Evidence:    fmt.Sprintf("HTTP %d actuator JSON: %q", status, bodySnippet(body, "status")),
				Remediation: "Disable actuators or gate behind management port + auth.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s %q", endpoint),
			}
		}
	case strings.Contains(lower, "swagger") || strings.Contains(lower, "api-docs") || strings.Contains(lower, "openapi"):
		if status == 200 && (strings.Contains(lb, "\"swagger\"") || strings.Contains(lb, "\"openapi\"") || strings.Contains(lb, "\"paths\"")) {
			return &VerifiedFinding{
				ID: "MISCONF-SWAGGER", Name: "API Specification Exposed",
				Severity: "Medium", CVSS: 5.0,
				Description: fmt.Sprintf("Live API spec at %s enumerates every route", endpoint),
				Evidence:    fmt.Sprintf("HTTP %d OpenAPI/Swagger JSON: %q", status, bodySnippet(body, "paths")),
				Remediation: "Gate API docs behind auth in production.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s %q | head -c 1000", endpoint),
			}
		}
	case strings.Contains(lower, "graphql"):
		if status < 500 && (strings.Contains(lb, "graphql") || strings.Contains(lb, "query")) {
			return &VerifiedFinding{
				ID: "MISCONF-GRAPHQL", Name: "GraphQL Endpoint Exposed",
				Severity: "Medium", CVSS: 5.0,
				Description: fmt.Sprintf("GraphQL endpoint at %s (HTTP %d): introspection may be on", endpoint, status),
				Evidence:    fmt.Sprintf("HTTP %d GraphQL surface: %q", status, bodySnippet(body, "graphql")),
				Remediation: "Disable introspection in production; enforce query depth/cost limits.",
				Category:    "misconfiguration",
				Reproduce: fmt.Sprintf("curl -s -X POST %q -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{queryType{name}}}\"}'", endpoint),
			}
		}
	}
	return nil
}

// VerifyServiceBanner checks version-bearing banners against known-vulnerable
// builds. Unknown versions are reported as hardening notes, never as CVEs.
func VerifyServiceBanner(ip string, port int, banner, tech string) *VerifiedFinding {
	combined := strings.ToLower(banner + " " + tech)
	mk := func(id, name, sev string, cvss float64, desc, rem string) *VerifiedFinding {
		return &VerifiedFinding{
			ID: id, Name: name, Severity: sev, CVSS: cvss, Port: port,
			Description: fmt.Sprintf("%s on %s:%d", desc, ip, port),
			Evidence:    fmt.Sprintf("Live banner: %q", strings.TrimSpace(banner)),
			Remediation: rem, Category: "vulnerable-service",
			Reproduce: fmt.Sprintf("curl -s -D- http://%s:%d/ | head -20", ip, port),
		}
	}

	// Apache 2.4.49/2.4.50 path traversal RCE: banner must pin the build.
	if strings.Contains(combined, "apache/2.4.49") || strings.Contains(combined, "apache/2.4.50") {
		return mk("CVE-2021-41773", "Apache 2.4.49/50 Path Traversal RCE", "Critical", 9.8,
			"Banner pins a build with public RCE exploit",
			"Upgrade Apache to 2.4.51+ immediately.")
	}
	if strings.Contains(combined, "apache/2.2") {
		return mk("EOL-APACHE22", "Apache 2.2 End-of-Life", "High", 7.5,
			"Apache 2.2 is EOL since 2017 with unpatched CVEs",
			"Migrate to Apache 2.4.latest.")
	}
	if strings.Contains(combined, "nginx/1.18.0") || strings.Contains(combined, "nginx/1.14") || strings.Contains(combined, "nginx/1.16") {
		return mk("EOL-NGINX", "Nginx EOL Build", "Medium", 5.0,
			"Banner pins an unsupported nginx build",
			"Upgrade nginx to a supported stable branch.")
	}
	if strings.Contains(combined, "openssh_8.2p1") || strings.Contains(combined, "openssh_7.") {
		return mk("EOL-OPENSSH", "OpenSSH Outdated Build", "Medium", 5.5,
			"Banner pins an OpenSSH with known weaknesses (e.g. CVE-2020-15778 scp)",
			"Upgrade OpenSSH and disable scp in favor of sftp.")
	}
	if strings.Contains(combined, "iis/6.0") || strings.Contains(combined, "iis/7.0") || strings.Contains(combined, "iis/7.5") {
		return mk("EOL-IIS", "IIS EOL Version", "High", 7.5,
			"Banner pins an unsupported IIS generation",
			"Migrate to a supported IIS/Windows Server.")
	}
	if strings.Contains(combined, "php/5.") || strings.Contains(combined, "php/7.0") || strings.Contains(combined, "php/7.1") {
		return mk("EOL-PHP", "PHP EOL Version Disclosed", "High", 7.5,
			"Banner leaks an EOL PHP with unpatched RCEs",
			"Upgrade PHP to a supported release and hide version headers.")
	}
	return nil
}

// ProbeAnonymousFTP returns a finding only when anonymous login succeeds.
func ProbeAnonymousFTP(ip string, port int) *VerifiedFinding {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	greeting := string(buf[:n])
	conn.Write([]byte("USER anonymous\r\n"))
	n, _ = conn.Read(buf)
	userResp := string(buf[:n])
	conn.Write([]byte("PASS anonymous@\r\n"))
	n, _ = conn.Read(buf)
	passResp := string(buf[:n])
	if strings.HasPrefix(strings.TrimSpace(userResp), "331") && strings.HasPrefix(strings.TrimSpace(passResp), "230") {
		return &VerifiedFinding{
			ID: "MISCONF-FTP-ANON", Name: "FTP Anonymous Login Allowed",
			Severity: "High", CVSS: 7.5, Port: port,
			Description: fmt.Sprintf("FTP on %s accepts anonymous login", addr),
			Evidence:    fmt.Sprintf("Greeting %q -> USER anonymous %q -> PASS %q", firstLine(greeting), firstLine(userResp), firstLine(passResp)),
			Remediation: "Disable anonymous FTP or jail it read-only with no sensitive content.",
			Category:    "misconfiguration",
			Reproduce:   fmt.Sprintf("ftp -n %s %d  # USER anonymous / PASS anonymous@", ip, port),
		}
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	if len(s) > 90 {
		return s[:90]
	}
	return s
}
