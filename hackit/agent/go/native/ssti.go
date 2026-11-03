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
	// A product of two 6-digit numbers produces a 12-13 digit result that cannot
	// appear in ordinary page furniture. Each payload has a control with
	// different operands: a real engine evaluates both, static content neither.
	a, b, c, d := 193457, 7919, 204361, 8009
	pos := func(x, y int) string { return fmt.Sprintf("%d", x*y) }
	smokeTests := []struct {
		payload string
		engine  string
		check   string
		control string
		ctrlRes string
	}{
		{fmt.Sprintf("{{%d*%d}}", a, b), "Jinja2/Twig", pos(a, b), fmt.Sprintf("{{%d*%d}}", c, d), pos(c, d)},
		{fmt.Sprintf("<%%= %d*%d %%>", a, b), "ERB", pos(a, b), fmt.Sprintf("<%%= %d*%d %%>", c, d), pos(c, d)},
		{fmt.Sprintf("${%d*%d}", a, b), "Freemarker/Velocity", pos(a, b), fmt.Sprintf("${%d*%d}", c, d), pos(c, d)},
		{fmt.Sprintf("${{%d*%d}}", a, b), "Velocity", pos(a, b), fmt.Sprintf("${{%d*%d}}", c, d), pos(c, d)},
		{fmt.Sprintf("#{(%d*%d)}", a, b), "Razor", pos(a, b), fmt.Sprintf("#{(%d*%d)}", c, d), pos(c, d)},
		{fmt.Sprintf("*{%d*%d}", a, b), "Freemarker", pos(a, b), fmt.Sprintf("*{%d*%d}", c, d), pos(c, d)},
		{fmt.Sprintf("#set($x=%d*%d)$x", a, b), "Velocity", pos(a, b), fmt.Sprintf("#set($x=%d*%d)$x", c, d), pos(c, d)},
		{"{{'hackit'.upper()}}", "Jinja2", "HACKIT", "{{'control'.upper()}}", "CONTROL"},
	}

	// Engine-error markers only: names that also appear inside payloads were
	// matching reflected input rather than a template failure.
	errorPatterns := []string{
		"TemplateSyntaxError", "TemplateNotFound", "TemplateError",
		"UndefinedError", "jinja2.exceptions", "Template compilation error",
		"FreeMarker template error", "freemarker.core",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []SSTIResult

	// Baseline: a reflected payload must not count as evaluation, so the
	// marker has to be absent before injection.
	baselineBody := ""
	if breq, berr := http.NewRequest("GET", baseURL, nil); berr == nil {
		q := breq.URL.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		breq.URL.RawQuery = q.Encode()
		if bresp, err := client.Do(breq); err == nil {
			if raw, rerr := io.ReadAll(io.LimitReader(bresp.Body, 4096)); rerr == nil {
				baselineBody = string(raw)
			}
			bresp.Body.Close()
		}
	}

	// fetch injects one value into one parameter and returns the response body.
	fetch := func(param, value string) string {
		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			return ""
		}
		q := req.URL.Query()
		for k, v := range params {
			if k == param {
				q.Set(k, value)
			} else {
				q.Set(k, v)
			}
		}
		req.URL.RawQuery = q.Encode()
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return string(raw)
	}

	for param := range params {
		for _, st := range smokeTests {
			bodyStr := fetch(param, st.payload)

			// Evidence of evaluation: the arithmetic result is present, was not
			// present in the baseline, and is not merely the payload echoed back.
			if strings.Contains(bodyStr, st.check) &&
				!strings.Contains(baselineBody, st.check) &&
				!strings.Contains(st.payload, st.check) {
				// Control expression must not yield its own result: numbers that
				// are page furniture appear for both payloads.
				ctrlBody := fetch(param, st.control)
				if strings.Contains(ctrlBody, st.ctrlRes) {
					continue
				}
				results = append(results, SSTIResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    st.payload,
					Vulnerable: true,
					Engine:     st.engine,
					Evidence:   fmt.Sprintf("Payload %q produced %q while control %q did not produce %q", st.payload, st.check, st.control, st.ctrlRes),
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
