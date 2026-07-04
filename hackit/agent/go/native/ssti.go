package native

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type SSTIResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Engine     string `json:"engine,omitempty"`
	Evidence   string `json:"evidence"`
}

func TestSSTI(baseURL string, params map[string]string) []SSTIResult {
	smokeTests := []struct {
		payload string
		engine  string
		check   string
	}{
		{"{{7*7}}", "Jinja2/Twig", "49"},
		{"{{7*'7'}}", "Jinja2", "7777777"},
		{"<%= 7*7 %>", "ERB", "49"},
		{"${7*7}", "Freemarker", "49"},
		{"${{7*7}}", "Velocity", "49"},
		{"#{(7*7)}", "Razor", "49"},
		{"{{7*7}}", "Generic", "49"},
		{"{{7*'7'}}", "Generic", "7777777"},
		{"{{config}}", "Jinja2", "config"},
		{"${7+7}", "Freemarker", "14"},
		{"*{7*7}", "Freemarker", "49"},
		{"{{_self.env.registerUndefinedFilterCallback('exec')}}", "Twig", "registerUndefinedFilterCallback"},
		{"{{''.__class__.__mro__[2].__subclasses__()}}", "Jinja2", "__mro__"},
		{"${7*7}", "Generic", "49"},
		{"#set($x=7*7)$x", "Velocity", "49"},
	}

	errorPatterns := []string{
		"TemplateSyntaxError", "TemplateNotFound", "TemplateError",
		"UndefinedError", "jinja2.exceptions", "Template compilation error",
		"Freemarker", "FreeMarker", "template error",
		"__class__", "__mro__", "__subclasses__",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []SSTIResult

	for param := range params {
		for _, st := range smokeTests {
			req, _ := http.NewRequest("GET", baseURL, nil)
			q := req.URL.Query()
			for k, v := range params {
				if k == param {
					q.Set(k, st.payload)
				} else {
					q.Set(k, v)
				}
			}
			req.URL.RawQuery = q.Encode()

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			var bodyStr string
			if resp.StatusCode == 200 {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
				if err == nil {
					bodyStr = string(body)
				}
			}
			resp.Body.Close()

			if strings.Contains(bodyStr, st.check) {
				results = append(results, SSTIResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    st.payload,
					Vulnerable: true,
					Engine:     st.engine,
					Evidence:   fmt.Sprintf("Template expression '%s' evaluated to '%s' in response", st.payload, st.check),
				})
				continue
			}

			for _, pat := range errorPatterns {
				if strings.Contains(bodyStr, pat) {
					results = append(results, SSTIResult{
						Endpoint:   baseURL,
						Parameter:  param,
						Payload:    st.payload,
						Vulnerable: true,
						Engine:     st.engine,
						Evidence:   fmt.Sprintf("Template engine error '%s' suggests SSTI on param %s", pat, param),
					})
					break
				}
			}
		}
	}

	if len(results) == 0 {
		results = append(results, SSTIResult{
			Endpoint: baseURL,
			Evidence: fmt.Sprintf("No SSTI detected across %d test payloads on %d parameters", len(smokeTests), len(params)),
		})
	}

	return results
}
