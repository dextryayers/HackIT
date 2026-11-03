package native

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FuzzResult is one sensitive path observation.  Verified is only true when a
// real indicator was found: a file signature, a directory listing, a JSON API
// body, or a response that materially differs from a random baseline path.
// A bare HTTP 200/403 is never enough on its own, because catch-all servers
// and SPA fallbacks answer everything with the same page.
type FuzzResult struct {
	Path           string
	StatusCode     int
	BaselineStatus int
	Verified       bool
	Evidence       string
}

// sensitivePaths are files and endpoints with a recognisable body signature.
// Generic admin/login pages are deliberately excluded: their 200 says nothing
// without authentication-aware testing in a later phase.
var sensitivePaths = []string{
	"/.git/config", "/.git/HEAD",
	"/.env", "/.env.backup", "/.env.dev", "/.env.local",
	"/.env.production", "/.env.staging", "/.env.bak",
	"/.aws/credentials", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/id_rsa",
	"/.htaccess", "/.DS_Store", "/Dockerfile", "/docker-compose.yml",
	"/web.config", "/wp-config.php.bak", "/wp-config.php.save",
	"/config.php.bak", "/backup.zip", "/backup.tar.gz", "/backup.tar",
	"/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
	"/.svn/entries", "/.svn/wc.db",
	"/server-status", "/phpinfo.php", "/info.php",
	"/swagger-ui.html", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
	"/openapi.json", "/graphql",
	"/actuator/env", "/actuator/health", "/actuator/heapdump", "/actuator/mappings",
}

type fuzzTarget struct {
	path string
	kind string
}

func fuzzKind(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "heapdump"):
		return "heapdump"
	case strings.Contains(lower, "wp-config"):
		return "wpconfig"
	case strings.Contains(lower, ".env") || strings.Contains(lower, "config.php"):
		return "env"
	case strings.Contains(lower, ".git"):
		return "git"
	case strings.Contains(lower, ".svn/entries"):
		return "svn-entries"
	case strings.Contains(lower, ".svn"):
		return "svn-db"
	case strings.Contains(lower, ".aws"):
		return "aws"
	case strings.Contains(lower, "id_rsa") || strings.Contains(lower, "id_ed25519"):
		return "ssh-key"
	case strings.Contains(lower, ".htaccess"):
		return "htaccess"
	case strings.Contains(lower, ".ds_store"):
		return "dsstore"
	case strings.Contains(lower, "dockerfile"):
		return "dockerfile"
	case strings.Contains(lower, "docker-compose"):
		return "compose"
	case strings.Contains(lower, "web.config"):
		return "webconfig"
	case strings.HasSuffix(lower, ".sql"):
		return "sql"
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".tar.gz"):
		return "gzip"
	case strings.HasSuffix(lower, ".tar"):
		return "tar"
	case strings.HasSuffix(lower, "phpinfo.php") || strings.HasSuffix(lower, "info.php"):
		return "phpinfo"
	case strings.Contains(lower, "server-status"):
		return "apache"
	case strings.Contains(lower, "swagger") || strings.Contains(lower, "api-docs") || strings.Contains(lower, "openapi"):
		return "swagger"
	case strings.Contains(lower, "graphql"):
		return "graphql"
	case strings.Contains(lower, "actuator"):
		return "actuator"
	default:
		return "generic"
	}
}

// normalizeFuzzBase removes query strings and fragments from a target URL and
// guarantees a trailing slash.  Without this, a target such as
// http://host/?id=1 would produce http://host/?id=1/.git/config instead of
// http://host/.git/config, silently testing the wrong path.
func normalizeFuzzBase(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return baseURL
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	return parsed.String()
}

// FuzzDirectories concurrently checks for sensitive files/directories.
func FuzzDirectories(baseURL string, concurrency int) []FuzzResult {
	baseURL = normalizeFuzzBase(baseURL)
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	if concurrency < 1 {
		concurrency = 1
	}

	client := scanClient(6 * time.Second)
	baseline := fetchBaseline(client, baseURL)

	targets := make(chan fuzzTarget, len(sensitivePaths))
	resultsChan := make(chan FuzzResult, len(sensitivePaths))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go fuzzWorker(client, baseURL, baseline, targets, resultsChan, &wg)
	}

	for _, path := range sensitivePaths {
		targets <- fuzzTarget{path: path, kind: fuzzKind(path)}
	}
	close(targets)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []FuzzResult
	for res := range resultsChan {
		if res.Verified {
			results = append(results, res)
		}
	}
	return results
}

type fuzzBaseline struct {
	status      int
	body        []byte
	location    string
	contentType string
}

func randomPath() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "hackit-nonexistent-000000000000"
	}
	return "hackit-nonexistent-" + hex.EncodeToString(buf)
}

func fetchBaseline(client *http.Client, baseURL string) fuzzBaseline {
	baseline := fuzzBaseline{}
	req, err := http.NewRequest("GET", baseURL+randomPath(), nil)
	if err != nil {
		return baseline
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := client.Do(req)
	if err != nil {
		return baseline
	}
	defer resp.Body.Close()
	baseline.status = resp.StatusCode
	baseline.body = readLimited(resp.Body)
	baseline.location = resp.Header.Get("Location")
	baseline.contentType = strings.ToLower(resp.Header.Get("Content-Type"))
	return baseline
}

func fuzzWorker(client *http.Client, baseURL string, baseline fuzzBaseline,
	targets <-chan fuzzTarget, results chan<- FuzzResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for target := range targets {
		req, err := http.NewRequest("GET", baseURL+strings.TrimPrefix(target.path, "/"), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := readLimited(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 403 {
			continue
		}

		verified, evidence := verifyFuzzHit(target, resp.StatusCode, resp.Header.Get("Location"),
			resp.Header.Get("Content-Type"), body, baseline)
		if !verified {
			continue
		}
		results <- FuzzResult{
			Path:           "/" + strings.TrimPrefix(target.path, "/"),
			StatusCode:     resp.StatusCode,
			BaselineStatus: baseline.status,
			Verified:       true,
			Evidence:       evidence,
		}
	}
}

// verifyFuzzHit decides whether a response is real evidence.  It checks the
// path-specific body signature first, then accepts a response only when its
// status/location/body materially differs from the random catch-all baseline.
func verifyFuzzHit(target fuzzTarget, status int, location, contentType string,
	body []byte, baseline fuzzBaseline) (bool, string) {
	lower := strings.ToLower(string(body))
	contentType = strings.ToLower(contentType)

	if signature := fuzzSignature(target.kind, body, lower, contentType); signature != "" {
		return true, signature
	}

	// A redirect that lands somewhere new is evidence only when the baseline
	// random path does not redirect to the same destination.
	if (status == 301 || status == 302) && target.kind != "generic" {
		if location != "" && location != baseline.location {
			return true, "redirects to " + location
		}
		return false, ""
	}

	// A 403 only means the path exists if the catch-all path is not also 403.
	if status == 403 {
		if baseline.status != 403 {
			return true, "HTTP 403 while a random path returns " + itoa(baseline.status)
		}
		return false, ""
	}

	if status != 200 {
		return false, ""
	}

	// An empty 200 is not evidence of an exposed file.
	if len(body) == 0 {
		return false, ""
	}

	// Catch-all servers answer every path with the same page.  Require a
	// meaningful body difference and a path-specific clue.
	if baseline.status == 200 {
		ratio := responseDiffRatio(body, baseline.body)
		if ratio < 0.35 {
			return false, ""
		}
		// HTML pages need a listing or application marker; an error page that
		// merely echoes the requested path is not evidence.
		if strings.Contains(contentType, "html") || bytes.Contains(body, []byte("<html")) {
			if !containsListingMarker(lower) {
				return false, ""
			}
		}
		return true, "body differs from catch-all baseline by " + pct(ratio)
	}

	return true, "HTTP 200 while a random path returns " + itoa(baseline.status)
}

func fuzzSignature(kind string, body []byte, lower, contentType string) string {
	switch kind {
	case "git":
		if strings.Contains(lower, "[core]") && strings.Contains(lower, "repositoryformatversion") {
			return "valid .git config (repositoryformatversion)"
		}
		if strings.HasPrefix(strings.TrimSpace(lower), "ref: refs/") {
			return "valid .git HEAD reference"
		}
	case "env":
		if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
			return ""
		}
		// Only files that actually carry credentials are Critical.  An env
		// file with just APP_ENV=production is a config leak, not a 9.8.
		secrets := []string{"password", "secret", "token", "credential", "access_key", "private_key", "database_url", "dsn"}
		trimmed := strings.TrimSpace(lower)
		hasKV := len(trimmed) > 8 && !strings.Contains(trimmed, "<") && strings.Count(trimmed, "=") >= 2
		if hasKV {
			for _, marker := range secrets {
				if strings.Contains(trimmed, marker) {
					return "environment file with credential keys (" + marker + ")"
				}
			}
		}
	case "wpconfig":
		if strings.Contains(lower, "<html") {
			return ""
		}
		if strings.Contains(lower, "define(") &&
			(strings.Contains(lower, "db_password") || strings.Contains(lower, "db_user") || strings.Contains(lower, "auth_key")) {
			return "WordPress config with DB credentials"
		}
	case "sql":
		for _, marker := range []string{"insert into", "create table", "mysql dump", "postgresql database dump", "sqlite format 3"} {
			if strings.Contains(lower, marker) {
				return "SQL dump content (" + marker + ")"
			}
		}
	case "zip":
		if bytes.HasPrefix(body, []byte("PK\x03\x04")) {
			return "ZIP archive signature"
		}
	case "gzip":
		if bytes.HasPrefix(body, []byte("\x1f\x8b")) {
			return "gzip archive signature"
		}
	case "phpinfo":
		if strings.Contains(lower, "php version") && strings.Contains(lower, "phpinfo()") {
			return "PHP information page"
		}
	case "svn-entries":
		trimmed := strings.TrimSpace(lower)
		if strings.Contains(lower, "<html") {
			return ""
		}
		if len(trimmed) > 0 && trimmed[0] >= '0' && trimmed[0] <= '9' &&
			(strings.Contains(trimmed, "dir") || strings.Contains(trimmed, "file")) {
			return "Subversion entries file"
		}
	case "svn-db":
		if strings.HasPrefix(strings.TrimSpace(lower), "sqlite format 3") {
			return "Subversion SQLite database"
		}
	case "apache":
		if strings.Contains(lower, "apache server status") {
			return "Apache mod_status output"
		}
	case "swagger":
		if strings.Contains(lower, "swagger") || strings.Contains(lower, "openapi") {
			if strings.Contains(lower, "\"paths\"") || strings.Contains(lower, "swagger ui") {
				return "OpenAPI/Swagger document"
			}
		}
	case "graphql":
		trimmed := strings.TrimSpace(lower)
		jsonLike := strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") ||
			strings.Contains(contentType, "json")
		if jsonLike && (strings.Contains(lower, "\"data\"") || strings.Contains(lower, "\"errors\"") ||
			strings.Contains(lower, "graphql")) {
			return "GraphQL endpoint response"
		}
	case "actuator":
		if strings.Contains(lower, "\"propertysources\"") || strings.Contains(lower, "\"activeprofiles\"") {
			return "Spring Boot actuator environment"
		}
		// Compact Spring health JSON only: a generic page mentioning "up"
		// and "status" separately used to count as evidence.
		if strings.Contains(lower, "\"status\":\"up\"") || strings.Contains(lower, "\"status\": \"up\"") {
			return "Spring Boot actuator health"
		}
	case "ssh-key":
		if strings.Contains(lower, "-----begin ") && strings.Contains(lower, "private key-----") {
			return "private SSH key material"
		}
	case "aws":
		if strings.Contains(lower, "aws_access_key_id") && strings.Contains(lower, "aws_secret_access_key") {
			return "AWS credentials file"
		}
	case "htaccess":
		if !strings.Contains(lower, "<html") &&
			(strings.Contains(lower, "rewriteengine") || strings.Contains(lower, "order deny") ||
				strings.Contains(lower, "options +followsymlinks")) {
			return "Apache .htaccess directives"
		}
	case "dsstore":
		if bytes.HasPrefix(body, []byte("\x00\x00\x00\x01Bud1")) {
			return ".DS_Store metadata"
		}
	case "dockerfile":
		trimmed := strings.TrimSpace(lower)
		if strings.HasPrefix(trimmed, "from ") &&
			(strings.Contains(trimmed, "\nrun ") || strings.Contains(trimmed, "\ncopy ") || strings.Contains(trimmed, "\nenv ")) {
			return "Dockerfile build recipe"
		}
	case "compose":
		if !strings.Contains(lower, "<html") && strings.Contains(lower, "services:") && strings.Contains(lower, "image:") {
			return "docker-compose manifest"
		}
	case "webconfig":
		if strings.Contains(lower, "<configuration") && strings.Contains(lower, "<system.web") {
			return "IIS web.config"
		}
	case "tar":
		if len(body) > 262 && string(body[257:262]) == "ustar" {
			return "TAR archive signature"
		}
	case "heapdump":
		if bytes.HasPrefix(body, []byte("JAVA PROFILE")) {
			return "JVM heap dump (JAVA PROFILE)"
		}
	}
	return ""
}

func containsListingMarker(lower string) bool {
	for _, marker := range []string{
		"index of /", "directory listing for", "parent directory",
		"swagger ui", "<title>phpinfo", "apache server status",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func itoa(value int) string {
	if value == 0 {
		return "no response"
	}
	return strconv.Itoa(value)
}

func pct(ratio float64) string {
	return strconv.Itoa(int(ratio*100)) + "%"
}
