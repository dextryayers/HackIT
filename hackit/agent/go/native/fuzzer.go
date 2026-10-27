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
	"/.git/config", "/.git/HEAD", "/.env", "/.env.backup", "/.env.dev",
	"/.env.local", "/wp-config.php.bak", "/wp-config.php.save",
	"/config.php.bak", "/backup.zip", "/backup.tar.gz", "/backup.sql",
	"/dump.sql", "/database.sql", "/db.sql", "/.svn/entries", "/.svn/wc.db",
	"/server-status", "/phpinfo.php", "/info.php", "/swagger-ui.html",
	"/v2/api-docs", "/openapi.json", "/graphql", "/actuator/env",
	"/actuator/health",
}

type fuzzTarget struct {
	path string
	kind string
}

func fuzzKind(path string) string {
	switch {
	case strings.Contains(path, ".env") || strings.Contains(path, "wp-config") || strings.Contains(path, "config.php"):
		return "env"
	case strings.Contains(path, ".git"):
		return "git"
	case strings.Contains(path, ".svn/entries"):
		return "svn-entries"
	case strings.Contains(path, ".svn"):
		return "svn-db"
	case strings.HasSuffix(path, ".sql"):
		return "sql"
	case strings.HasSuffix(path, ".zip"):
		return "zip"
	case strings.HasSuffix(path, ".tar.gz"):
		return "gzip"
	case strings.HasSuffix(path, "phpinfo.php") || strings.HasSuffix(path, "info.php"):
		return "phpinfo"
	case strings.Contains(path, "server-status"):
		return "apache"
	case strings.Contains(path, "swagger") || strings.Contains(path, "api-docs") || strings.Contains(path, "openapi"):
		return "swagger"
	case strings.Contains(path, "graphql"):
		return "graphql"
	case strings.Contains(path, "actuator"):
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
		for _, marker := range []string{"app_key=", "app_env=", "db_password=", "db_host=", "secret_key=", "aws_access_key", "api_key=", "mysql_password"} {
			if strings.Contains(lower, marker) {
				return "environment file content (" + marker + ")"
			}
		}
		trimmed := strings.TrimSpace(lower)
		if len(trimmed) > 8 && !strings.Contains(trimmed, "<") && strings.Count(trimmed, "=") >= 2 {
			return "environment-style KEY=VALUE content"
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
		if strings.Contains(lower, "\"status\"") && strings.Contains(lower, "\"up\"") {
			return "Spring Boot actuator health"
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
