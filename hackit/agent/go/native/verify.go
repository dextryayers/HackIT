package native

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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

// endpointPort reports the port a finding lives on, defaulting by scheme.
func endpointPort(endpoint string) int {
	if u, err := url.Parse(endpoint); err == nil && u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err == nil {
			return p
		}
	}
	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return 443
	}
	return 80
}

// endpointRule maps a fuzzer path kind to the finding it produces once the
// body carries that kind's unmistakable signature.  Sharing the signature
// function keeps enumeration and verification from disagreeing about what
// counts as evidence.
type endpointRule struct {
	id, name, severity string
	cvss               float64
	description        string // fmt: endpoint, status
	remediation        string
	category           string
}

var endpointRules = map[string]endpointRule{
	"env":         {"MISCONF-001", "Exposed Environment File (.env)", "Critical", 9.8, "Live .env file with secrets served at %q (HTTP %d)", "Block dotfiles at the edge and rotate every secret in the file.", "misconfiguration"},
	"wpconfig":    {"MISCONF-WPCONFIG", "WordPress Config Backup Exposed", "Critical", 9.8, "wp-config backup with DB credentials served at %q (HTTP %d)", "Delete the backup, block dotfile/bak suffixes, and rotate DB and auth keys.", "credential-exposure"},
	"git":         {"MISCONF-002", "Exposed Git Repository", "High", 7.5, "Live .git/config served at %q (HTTP %d): full repo history downloadable", "Deny /.git at the edge and purge secrets from git history.", "misconfiguration"},
	"phpinfo":     {"MISCONF-PHPINFO", "PHPInfo Information Disclosure", "High", 7.0, "Live phpinfo() dump at %q (HTTP %d) leaks versions, paths, env", "Delete phpinfo files from production.", "misconfiguration"},
	"apache":      {"MISCONF-SERVER-STATUS", "Apache server-status Exposed", "Medium", 5.3, "Live mod_status at %q (HTTP %d) leaks workers, vhosts, request paths", "Require local + auth for /server-status.", "misconfiguration"},
	"actuator":    {"MISCONF-ACTUATOR", "Spring Boot Actuator Exposed", "High", 7.5, "Live actuator endpoint at %q (HTTP %d)", "Disable actuators or gate behind management port + auth.", "misconfiguration"},
	"swagger":     {"MISCONF-SWAGGER", "API Specification Exposed", "Medium", 5.0, "Live API spec at %q (HTTP %d) enumerates every route", "Gate API docs behind auth in production.", "misconfiguration"},
	"graphql":     {"MISCONF-GRAPHQL", "GraphQL Endpoint Exposed", "Medium", 5.0, "GraphQL endpoint at %q answers a typed query (HTTP %d)", "Disable introspection in production; enforce query depth/cost limits.", "misconfiguration"},
	"ssh-key":     {"MISCONF-SSH-KEY", "Private SSH Key Exposed", "Critical", 9.8, "Private key material downloadable at %q (HTTP %d)", "Remove the key from the web root and rotate it immediately.", "credential-exposure"},
	"aws":         {"MISCONF-AWS-CREDS", "AWS Credentials File Exposed", "Critical", 9.8, "AWS access keys served at %q (HTTP %d)", "Revoke the keys, remove the file, and use instance roles.", "credential-exposure"},
	"heapdump":    {"MISCONF-HEAPDUMP", "JVM Heap Dump Exposed", "High", 8.2, "Downloadable heap dump at %q (HTTP %d) may contain secrets", "Disable the heapdump actuator and block /actuator at the edge.", "information-disclosure"},
	"htaccess":    {"MISCONF-HTACCESS", "Apache .htaccess Exposed", "Medium", 5.3, "Readable .htaccess at %q (HTTP %d) discloses rewrite/auth rules", "Deny dotfiles at the edge.", "information-disclosure"},
	"webconfig":   {"MISCONF-WEBCONFIG", "IIS web.config Exposed", "Medium", 5.3, "Readable web.config at %q (HTTP %d) discloses app settings", "Deny web.config at the edge and rotate any connection strings.", "information-disclosure"},
	"compose":     {"MISCONF-COMPOSE", "Docker Compose Manifest Exposed", "Medium", 5.3, "docker-compose manifest at %q (HTTP %d) maps the deployment", "Remove deployment manifests from the web root.", "information-disclosure"},
	"dockerfile":  {"MISCONF-DOCKERFILE", "Dockerfile Exposed", "Medium", 5.3, "Dockerfile at %q (HTTP %d) reveals base images and build steps", "Remove build files from the web root.", "information-disclosure"},
	"dsstore":     {"MISCONF-DSSTORE", ".DS_Store Exposed", "Low", 3.7, ".DS_Store at %q (HTTP %d) leaks directory filenames", "Block .DS_Store at the edge and stop deploying Finder metadata.", "information-disclosure"},
	"sql":         {"MISCONF-SQL-DUMP", "SQL Dump Exposed", "High", 7.5, "Database dump at %q (HTTP %d) is downloadable", "Remove dumps from the web root and rotate the DB credentials they contain.", "information-disclosure"},
	"zip":         {"MISCONF-BACKUP", "Backup Archive Exposed", "High", 7.5, "Backup archive at %q (HTTP %d) is downloadable", "Remove backups from the web root and rotate contained secrets.", "information-disclosure"},
	"gzip":        {"MISCONF-BACKUP", "Backup Archive Exposed", "High", 7.5, "Backup archive at %q (HTTP %d) is downloadable", "Remove backups from the web root and rotate contained secrets.", "information-disclosure"},
	"tar":         {"MISCONF-BACKUP", "Backup Archive Exposed", "High", 7.5, "Backup archive at %q (HTTP %d) is downloadable", "Remove backups from the web root and rotate contained secrets.", "information-disclosure"},
	"svn-entries": {"MISCONF-SVN", "Subversion Metadata Exposed", "High", 7.5, "Subversion metadata at %q (HTTP %d) exposes source history", "Deny /.svn at the edge and migrate to git.", "misconfiguration"},
	"svn-db":      {"MISCONF-SVN", "Subversion Metadata Exposed", "High", 7.5, "Subversion metadata at %q (HTTP %d) exposes source history", "Deny /.svn at the edge and migrate to git.", "misconfiguration"},
}

func headSnippet(body string, n int) string {
	body = strings.TrimSpace(body)
	if len(body) > n {
		return body[:n] + "..."
	}
	return body
}

// VerifyExposedEndpoint re-probes an enumerated URL and only confirms when the
// body carries the file's unmistakable signature — the same check the fuzzer
// applied, run again against the live file. Returns nil on soft-404, login
// wall, or a body that merely echoes the requested path.
func VerifyExposedEndpoint(endpoint string) *VerifiedFinding {
	kind := fuzzKind(endpoint)
	rule, ok := endpointRules[kind]
	if !ok {
		return nil
	}
	if kind == "graphql" {
		return probeGraphQL(endpoint, rule)
	}

	client := verifyClient(10 * time.Second)
	status, header, body := verifyGet(client, endpoint)
	if status != 200 {
		return nil
	}
	lower := strings.ToLower(body)
	signature := fuzzSignature(kind, []byte(body), lower, strings.ToLower(header.Get("Content-Type")))
	if signature == "" {
		return nil
	}
	return &VerifiedFinding{
		ID: rule.id, Name: rule.name, Severity: rule.severity, CVSS: rule.cvss,
		Port:        endpointPort(endpoint),
		Description: fmt.Sprintf(rule.description, endpoint, status),
		Evidence:    fmt.Sprintf("HTTP %d — %s — body: %q", status, signature, headSnippet(body, 200)),
		Remediation: rule.remediation, Category: rule.category,
		Reproduce: fmt.Sprintf("curl -s -D- %q | head -c 2000", endpoint),
	}
}

// probeGraphQL proves the endpoint parses GraphQL by asking it to resolve a
// typed field.  The previous check accepted any page containing the word
// "query", so soft-404 pages were reported as GraphQL surfaces.
func probeGraphQL(endpoint string, rule endpointRule) *VerifiedFinding {
	client := verifyClient(10 * time.Second)
	query := `{"query":"{__typename}"}`
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(query))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	lower := strings.ToLower(string(raw))
	if !strings.Contains(lower, `"__typename"`) {
		return nil
	}
	return &VerifiedFinding{
		ID: rule.id, Name: rule.name, Severity: rule.severity, CVSS: rule.cvss,
		Port:        endpointPort(endpoint),
		Description: fmt.Sprintf(rule.description, endpoint, resp.StatusCode),
		Evidence:    fmt.Sprintf("HTTP %d — query {__typename} resolved: %q", resp.StatusCode, headSnippet(string(raw), 200)),
		Remediation: rule.remediation, Category: rule.category,
		Reproduce: fmt.Sprintf("curl -s -X POST %q -H 'Content-Type: application/json' -d '%s'", endpoint, query),
	}
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
