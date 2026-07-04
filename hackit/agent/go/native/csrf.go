package native

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CSRFResult struct {
	Endpoint     string `json:"endpoint"`
	Method       string `json:"method"`
	HasToken     bool   `json:"has_token"`
	TokenName    string `json:"token_name,omitempty"`
	FormAction   string `json:"form_action,omitempty"`
	Vulnerable   bool   `json:"vulnerable"`
	Evidence     string `json:"evidence"`
}

func TestCSRF(baseURL string) []CSRFResult {
	client := &http.Client{Timeout: 10 * time.Second}
	var results []CSRFResult

	resp, err := client.Get(baseURL)
	if err != nil {
		return []CSRFResult{{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   fmt.Sprintf("Failed to fetch page: %v", err),
		}}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return []CSRFResult{{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   fmt.Sprintf("Failed to read body: %v", err),
		}}
	}

	pageContent := string(body)
	csrfTokenPatterns := []string{
		"csrf", "CSRF", "_token", "authenticity_token",
		"csrf_token", "csrf-token", "csrfmiddlewaretoken",
		"__RequestVerificationToken", "xsrf-token", "xsrf",
		"nonce", "csrfKey",
	}

	idx := 0
	for idx < len(pageContent) {
		si := strings.Index(strings.ToLower(pageContent[idx:]), "<form")
		if si == -1 {
			break
		}
		si += idx
		ei := strings.Index(pageContent[si:], "</form>")
		if ei == -1 {
			break
		}
		formHTML := pageContent[si : si+ei+7]
		idx = si + ei + 7

		action := ""
		actionStart := strings.Index(strings.ToLower(formHTML), "action=")
		if actionStart != -1 {
			actionStart += 7
			if actionStart < len(formHTML) {
				quote := formHTML[actionStart]
				if quote == '"' || quote == '\'' {
					actionStart++
					actionEnd := strings.Index(formHTML[actionStart:], string(quote))
					if actionEnd != -1 {
						action = formHTML[actionStart : actionStart+actionEnd]
					}
				}
			}
		}

		method := "GET"
		methodStart := strings.Index(strings.ToLower(formHTML), "method=")
		if methodStart != -1 {
			methodStart += 7
			if methodStart < len(formHTML) {
				quote := formHTML[methodStart]
				if quote == '"' || quote == '\'' {
					methodStart++
					methodEnd := strings.Index(formHTML[methodStart:], string(quote))
					if methodEnd != -1 {
						method = strings.ToUpper(formHTML[methodStart : methodStart+methodEnd])
					}
				}
			}
		}

		hasToken := false
		foundTokenName := ""
		for _, pattern := range csrfTokenPatterns {
			if strings.Contains(strings.ToLower(formHTML), strings.ToLower(pattern)) {
				hasToken = true
				foundTokenName = pattern
				break
			}
		}

		if method == "POST" && !hasToken {
			results = append(results, CSRFResult{
				Endpoint:   baseURL,
				Method:     method,
				HasToken:   false,
				FormAction: action,
				Vulnerable: true,
				Evidence:   fmt.Sprintf("POST form to '%s' has no CSRF token", action),
			})
		} else if method == "POST" && hasToken {
			results = append(results, CSRFResult{
				Endpoint:   baseURL,
				Method:     method,
				HasToken:   true,
				TokenName:  foundTokenName,
				FormAction: action,
				Vulnerable: false,
				Evidence:   fmt.Sprintf("POST form to '%s' has CSRF token (%s)", action, foundTokenName),
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CSRFResult{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   "No forms found or all forms have CSRF protection",
		})
	}

	return results
}
