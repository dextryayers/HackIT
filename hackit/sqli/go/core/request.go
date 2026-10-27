package core

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
}

// Request keeps the historical signature used by the older modules. It
// resolves the parameter to a discovered injection point and delegates to
// RequestAt.
func (e *Engine) Request(payload string, param string) (string, int, http.Header, error) {
	point := e.resolvePoint(param)
	return e.RequestAt(point, payload)
}

func (e *Engine) resolvePoint(param string) InjectionPoint {
	if param != "" {
		for _, p := range e.Points {
			if strings.EqualFold(p.Name, param) {
				return p
			}
		}
		return InjectionPoint{
			Location: LocationQuery,
			Name:     param,
			Original: "",
			Method:   strings.ToUpper(e.Opts.Method),
		}
	}
	if len(e.Points) > 0 {
		return e.Points[0]
	}
	return InjectionPoint{
		Location: LocationQuery,
		Name:     "",
		Method:   strings.ToUpper(e.Opts.Method),
	}
}

// RequestAt sends one request with the payload placed at the given injection
// point. The original value is preserved and the payload is appended, which is
// the same contract used by classic SQL injection scanners.
func (e *Engine) RequestAt(point InjectionPoint, payload string) (string, int, http.Header, error) {
	adaptiveDelay := e.rateLimiter.GetDelay()
	if adaptiveDelay > 0 {
		time.Sleep(adaptiveDelay)
	}

	if e.Opts.Stealth {
		jitter := rand.Intn(1000)
		time.Sleep(time.Duration(e.Opts.Delay+jitter) * time.Millisecond)
	} else if e.Opts.Delay > 0 {
		time.Sleep(time.Duration(e.Opts.Delay) * time.Millisecond)
	}

	maxRetries := e.Opts.Retry
	if maxRetries <= 0 {
		maxRetries = 2
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*400) * time.Millisecond)
		}
		body, length, headers, err := e.doRequestAt(point, payload)
		if err == nil {
			return body, length, headers, nil
		}
		lastErr = err
		if isFatalError(err) {
			break
		}
	}
	return "", 0, nil, lastErr
}

func isFatalError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid URL") ||
		strings.Contains(msg, "unsupported protocol") ||
		strings.Contains(msg, "no Host")
}

func (e *Engine) doRequestAt(point InjectionPoint, payload string) (string, int, http.Header, error) {
	u, err := url.Parse(e.Opts.URL)
	if err != nil {
		return "", 0, nil, err
	}

	method := strings.ToUpper(strings.TrimSpace(point.Method))
	if method == "" {
		method = strings.ToUpper(strings.TrimSpace(e.Opts.Method))
	}
	if method == "" {
		method = http.MethodGet
	}

	var body io.Reader
	contentType := ""

	switch point.Location {
	case LocationQuery:
		q := u.Query()
		q.Set(point.Name, point.Original+payload)
		u.RawQuery = q.Encode()
	case LocationBody:
		form, err := url.ParseQuery(e.Opts.Data)
		if err != nil {
			return "", 0, nil, err
		}
		form.Set(point.Name, point.Original+payload)
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
		method = http.MethodPost
	case LocationJSON:
		updated, err := setJSONPath(e.Opts.Data, point.Path, point.Original+payload)
		if err != nil {
			return "", 0, nil, err
		}
		body = strings.NewReader(updated)
		contentType = "application/json"
		method = http.MethodPost
	case LocationCookie:
		cookie := replaceCookieValue(e.Opts.Cookie, point.Name, point.Original+payload)
		e.setCookieHeader(cookie)
	case LocationHeader:
		// Applied after the base headers below.
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return "", 0, nil, err
	}

	for _, raw := range e.Opts.Header {
		pair := strings.SplitN(raw, ":", 2)
		if len(pair) != 2 {
			continue
		}
		name := strings.TrimSpace(pair[0])
		value := strings.TrimSpace(pair[1])
		if point.Location == LocationHeader && strings.EqualFold(name, point.Name) {
			value = point.Original + payload
		}
		req.Header.Set(name, value)
	}

	if point.Location == LocationHeader {
		req.Header.Set(point.Name, point.Original+payload)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else if e.Opts.Data != "" && (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if e.Opts.Agent != "" {
		req.Header.Set("User-Agent", e.Opts.Agent)
	} else if e.Opts.Stealth {
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}

	if point.Location != LocationCookie && e.Opts.Cookie != "" {
		req.Header.Set("Cookie", e.Opts.Cookie)
	}
	if point.Location == LocationCookie {
		req.Header.Set("Cookie", e.currentCookie())
	}
	if e.Opts.Referer != "" {
		req.Header.Set("Referer", e.Opts.Referer)
	}

	startTime := time.Now()
	resp, err := e.Client.Do(req)
	elapsed := time.Since(startTime)
	if err != nil {
		e.Log.Warning(fmt.Sprintf("connection error: %v", err))
		return "", 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, nil, err
	}

	e.LastResponseHeaders = resp.Header
	e.LastResponseBody = string(respBody)
	e.LastResponseTime = elapsed
	e.LastStatusCode = resp.StatusCode
	e.rateLimiter.RecordResponseTime(elapsed)

	return string(respBody), len(respBody), resp.Header, nil
}

func replaceCookieValue(raw, name, value string) string {
	parts := strings.Split(raw, ";")
	found := false
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		pair := strings.SplitN(trimmed, "=", 2)
		if len(pair) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(pair[0]), name) {
			parts[i] = fmt.Sprintf(" %s=%s", strings.TrimSpace(pair[0]), value)
			found = true
		}
	}
	if !found {
		parts = append(parts, fmt.Sprintf(" %s=%s", name, value))
	}
	return strings.TrimSpace(strings.Join(parts, ";"))
}

// Cookie injection needs a per-request cookie value without mutating the
// shared options. This small field keeps the value for the current request.
func (e *Engine) setCookieHeader(value string) {
	e.lastCookieValue = value
}

func (e *Engine) currentCookie() string {
	if e.lastCookieValue != "" {
		return e.lastCookieValue
	}
	return e.Opts.Cookie
}
