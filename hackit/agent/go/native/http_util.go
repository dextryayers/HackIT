package native

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxScanBody = 64 * 1024

// scanClient returns a client that never follows redirects and has a sane
// timeout.  Redirect-following hides Location headers needed by open-redirect
// checks and can turn SSRF probes into loops.
func scanClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// readLimited drains at most maxScanBody bytes so a hostile or huge response
// cannot exhaust memory.
func readLimited(body io.Reader) []byte {
	data, _ := io.ReadAll(io.LimitReader(body, maxScanBody))
	return data
}

// paramRequest applies params to baseURL and overrides one parameter with
// override.  The returned body is the raw response body (capped).
func paramRequest(client *http.Client, baseURL string, params map[string]string,
	param, override string) (int, []byte, time.Duration, error) {
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return 0, nil, 0, err
	}
	query := req.URL.Query()
	for key, value := range params {
		if key == param {
			query.Set(key, override)
			continue
		}
		query.Set(key, value)
	}
	req.URL.RawQuery = query.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	start := time.Now()
	body := readLimited(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, body, time.Since(start), nil
}

func newParamRequest(client *http.Client, baseURL string, params map[string]string,
	param, override string) (int, []byte, error) {
	status, body, _, err := paramRequest(client, baseURL, params, param, override)
	return status, body, err
}

// paramResponse exposes response headers as well, for redirect analysis.
func paramResponse(client *http.Client, baseURL string, params map[string]string,
	param, override string) (int, http.Header, []byte, error) {
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	query := req.URL.Query()
	for key, value := range params {
		if key == param {
			query.Set(key, override)
			continue
		}
		query.Set(key, value)
	}
	req.URL.RawQuery = query.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	body := readLimited(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header, body, nil
}

// responseDiffRatio reports how different two bodies are by length.  It is a
// cheap proxy that avoids storing full response fingerprints while still
// catching the large content shifts caused by injected conditions.
func responseDiffRatio(a, b []byte) float64 {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 0
	}
	diff := len(a) - len(b)
	if diff < 0 {
		diff = -diff
	}
	return float64(diff) / float64(maxLen)
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// sqlErrorSignatures are database-specific error strings.  Generic words such
// as "sql" or "driver" are deliberately excluded: they appear on countless
// legitimate pages and caused the previous scanner to flag every login form.
var sqlErrorSignatures = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"microsoft ole db provider for sql server",
	"odbc sql server driver",
	"ora-00933",
	"ora-01756",
	"ora-06512",
	"oracle error",
	"postgresql error",
	"pg_query",
	"pg::syntaxerror",
	"sqlite error",
	"sqlite3::",
	"sqliteexception",
	"sqlstate[",
	"syntax error at or near",
	"unknown column",
	"unexpected end of sql",
	"division by zero",
}

var nosqlErrorSignatures = []string{
	"mongoerror",
	"mongoservererror",
	"e11000 duplicate key",
	"bsontypeerror",
	"bsonerror",
	"cast to objectid failed",
	"cannot apply $",
	"unknown operator: $",
	"bad value: $",
	"nosql injection",
}

// newSignature returns the first signature present in body but absent from the
// baseline.  Baseline comparison prevents a page that always prints a database
// error from being reported as injectable.
func newSignature(body, baseline []byte, signatures []string) string {
	lowerBody := strings.ToLower(string(body))
	lowerBaseline := strings.ToLower(string(baseline))
	for _, signature := range signatures {
		if strings.Contains(lowerBody, signature) && !strings.Contains(lowerBaseline, signature) {
			return signature
		}
	}
	return ""
}

// isExternalAttackerHost checks whether a Location/ACAO host belongs to the
// canary domain used by the scanners.  A simple substring test is not enough:
// "https://good.com/?next=//evil.com" contains "evil.com" but is not an open
// redirect.
func isExternalAttackerHost(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false
	}
	return host == "evil.com" ||
		host == "evil.com.evildomain.com" ||
		host == "good.com.evil.com" ||
		strings.HasSuffix(host, ".evil.com")
}
