package main

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reUUID        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reJWT         = regexp.MustCompile(`^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`)
	reEmail       = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	reURL         = regexp.MustCompile(`^https?://`)
	reHash        = regexp.MustCompile(`^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{128}$`)
	reBase64      = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	reNumeric     = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	reDate        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reTS          = regexp.MustCompile(`^\d{10,13}$`)
	reBoolean     = regexp.MustCompile(`^(true|false|1|0)$`)
	rePath        = regexp.MustCompile(`^/|^\.\./|^\./`)
	reGraphQL     = regexp.MustCompile(`(?i)(query|mutation|subscription)\s*[{(]`)
	reArray       = regexp.MustCompile(`^\[.*\]$`)
	reObject      = regexp.MustCompile(`^\{.*\}$`)
	reSensitive   = regexp.MustCompile(`(?i)(token|secret|key|auth|password|cred|jwt|bearer|session|cert)`)
	reOAuthParam  = regexp.MustCompile(`(?i)^(code_challenge|code_challenge_method|state|nonce|redirect_uri|redirect_url|callback_url|response_type|response_mode|scope|audience|client_id|client_secret|grant_type|assertion|id_token_hint|login_hint|acr_values|claims|resource|access_type|prompt|include_granted_scopes|request|request_uri|registration)$`)
	reAPIParam    = regexp.MustCompile(`(?i)^(api_key|apikey|api[_-]?secret|api[_-]?version|endpoint|format|callback|jsonp|method|action|command|op|operation|func|function|page|limit|offset|sort|order|filter|q|query|search|debug|env|environment)$`)
	reURLEncoded  = regexp.MustCompile(`(?i)%[0-9a-f]{2}|-[0-9a-f][0-9a-f]`)
	reSuspicious  = regexp.MustCompile(`(?i)(password|secret|token|key|sid|session|csrf|xsrf|auth|cert|private|jwt|bearer)`)
)

func analyzeParamValue(name, value string) ParamType {
	if value == "" {
		return TypeEmpty
	}
	if len(value) > 5000 {
		return TypeString
	}

	// Check for sensitive names first
	if isSensitiveParam(name) {
		return TypeSensitive
	}

	// GraphQL queries/mutations
	if reGraphQL.MatchString(value) && (strings.Contains(value, "{") && strings.Contains(value, "}")) {
		return TypeGraphQL
	}

	if reBoolean.MatchString(value) {
		return TypeBoolean
	}
	if reUUID.MatchString(strings.ToLower(value)) {
		return TypeUUID
	}
	if reJWT.MatchString(value) {
		// Verify it has 3 parts
		parts := strings.Split(value, ".")
		if len(parts) == 3 {
			return TypeJWT
		}
	}
	if reEmail.MatchString(strings.ToLower(value)) {
		return TypeEmail
	}
	if reURL.MatchString(strings.ToLower(value)) {
		return TypeURL
	}
	if reNumeric.MatchString(value) {
		f, _ := strconv.ParseFloat(value, 64)
		if f > 0 && value[0] != '0' {
			return TypeNumeric
		}
	}
	if reHash.MatchString(strings.ToLower(value)) {
		return TypeHash
	}
	if reTS.MatchString(value) {
		ts, _ := strconv.ParseInt(value, 10, 64)
		if ts > 1_000_000_000 && ts < 2_000_000_000_000 {
			return TypeTimestamp
		}
	}
	if reDate.MatchString(value) {
		if _, err := time.Parse("2006-01-02", value); err == nil {
			return TypeDate
		}
	}
	if rePath.MatchString(value) {
		return TypePath
	}
	if reArray.MatchString(value) && len(value) < 1000 {
		var arr []interface{}
		if json.Unmarshal([]byte(value), &arr) == nil {
			return TypeArray
		}
	}
	if reObject.MatchString(value) && len(value) < 2000 {
		var obj map[string]interface{}
		if json.Unmarshal([]byte(value), &obj) == nil {
			return TypeObject
		}
	}
	// Base64 detection (must be reasonable length and valid chars)
	if len(value) > 10 && len(value)%4 == 0 {
		if reBase64.MatchString(value) {
			if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) > 0 {
				_ = decoded
				return TypeBase64
			}
			if decoded, err := base64.URLEncoding.DecodeString(value); err == nil && len(decoded) > 0 {
				_ = decoded
				return TypeBase64
			}
		}
	}

	return TypeString
}

func analyzeParamsAcrossURLs(results []DiscoResult) []ParamDetail {
	paramData := make(map[string]*ParamDetail)

	for _, r := range results {
		for name, val := range r.Params {
			if _, exists := paramData[name]; !exists {
				pt := analyzeParamValue(name, val)
				isSens := pt == TypeSensitive || isSensitiveParam(name) || reOAuthParam.MatchString(name)
				paramData[name] = &ParamDetail{
					Name:      name,
					Type:      pt,
					HasValue:  val != "",
					IsEmpty:   val == "",
					Sensitive: isSens,
				}
			}
			pd := paramData[name]
			pd.URLCount++
			pd.Sources = append(pd.Sources, r.URL)
			if pd.Sample == "" && val != "" {
				pd.Sample = val
			}
			// Refine type if we get more data
			if val != "" {
				pt := analyzeParamValue(name, val)
				if pt != TypeString && pd.Type == TypeString {
					pd.Type = pt
				}
				if pt == TypeSensitive {
					pd.Sensitive = true
				}
				if reOAuthParam.MatchString(name) {
					pd.Sensitive = true
				}
			}
		}
	}

	var details []ParamDetail
	for _, pd := range paramData {
		details = append(details, *pd)
	}
	// Sort by URL count desc
	for i := 0; i < len(details); i++ {
		for j := i + 1; j < len(details); j++ {
			if details[j].URLCount > details[i].URLCount {
				details[i], details[j] = details[j], details[i]
			}
		}
	}
	return details
}

func urlDecodeDeep(s string) string {
	if !strings.Contains(s, "-2") && !strings.Contains(s, "%") {
		return ""
	}
	// Try to URL decode
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return ""
	}
	if decoded == s {
		return ""
	}
	// If decoded looks like base64, try that too
	b64url := regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)
	if b64url.MatchString(decoded) && len(decoded) > 10 {
		if b, err := base64.StdEncoding.DecodeString(decoded); err == nil && len(b) > 3 {
			text := string(b)
			if len(text) > 40 {
				text = text[:40] + "..."
			}
			printable := make([]byte, 0, len(text))
			for _, c := range []byte(text) {
				if c >= 32 && c < 127 {
					printable = append(printable, c)
				}
			}
			maxLen := 30
	if len(decoded) < maxLen {
		maxLen = len(decoded)
	}
	return "urlDecoded→" + decoded[:maxLen] + "→b64:" + string(printable)
		}
	}
	maxLen := 40
	if len(decoded) < maxLen {
		maxLen = len(decoded)
	}
	return "urlDecoded→" + decoded[:maxLen]
}

func decodeJWTPreview(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return ""
	}
	// Try to pad and decode the payload (2nd part)
	payload := parts[1]
	switch len(payload) % 4 {
	case 0:
	case 1:
		return ""
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	// Pretty-print as compact JSON
	var obj interface{}
	if json.Unmarshal(decoded, &obj) == nil {
		pretty, _ := json.Marshal(obj)
		if len(pretty) > 120 {
			return string(pretty[:120]) + "..."
		}
		return string(pretty)
	}
	return string(decoded)
}

func decodeBase64Preview(s string) string {
	if len(s) < 10 {
		return ""
	}
	// Try standard
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try URL-safe
		decoded, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return ""
		}
	}
	// Check if decoded looks like JSON
	if json.Valid(decoded) {
		var obj interface{}
		if json.Unmarshal(decoded, &obj) == nil {
			pretty, _ := json.Marshal(obj)
			if len(pretty) > 100 {
				return string(pretty[:100]) + "..."
			}
			return string(pretty)
		}
	}
	text := string(decoded)
	if len(text) > 60 {
		text = text[:60] + "..."
	}
	// Only show printable
	printable := make([]byte, 0, len(text))
	for _, b := range []byte(text) {
		if b >= 32 && b < 127 {
			printable = append(printable, b)
		}
	}
	return string(printable)
}

func urlContainsParams(s string) string {
	parsed, err := url.Parse(s)
	if err != nil {
		return ""
	}
	if len(parsed.Query()) > 0 {
		var keys []string
		for k := range parsed.Query() {
			keys = append(keys, k)
		}
		return strings.Join(keys, ", ")
	}
	return ""
}

func findInterestingParams(details []ParamDetail) []Finding {
	var findings []Finding
	for _, d := range details {
		if d.Sensitive {
			severity := SeverityHigh
			cat := "Sensitive Parameter"
			if reOAuthParam.MatchString(d.Name) {
				severity = SeverityMedium
				cat = "OAuth2 Parameter"
			}
			findings = append(findings, Finding{
				Type:        "sensitive_param",
				Category:    cat,
				Param:       d.Name,
				Description: "Sensitive parameter detected: " + d.Name + " (type: " + string(d.Type) + ")",
				Severity:    severity,
			})
		}
		if d.Type == TypeJWT {
			desc := "JWT token found in parameter: " + d.Name
			if decoded := decodeJWTPreview(d.Sample); decoded != "" {
				desc += " | payload: " + decoded
			}
			findings = append(findings, Finding{
				Type:        "jwt_param",
				Category:    "JWT Token",
				Param:       d.Name,
				Description: desc,
				Severity:    SeverityHigh,
			})
		}
		if d.Type == TypeBase64 {
			desc := "Base64 encoded value in parameter: " + d.Name
			if decoded := decodeBase64Preview(d.Sample); decoded != "" {
				desc += " | decoded: " + decoded
			}
			findings = append(findings, Finding{
				Type:        "base64_param",
				Category:    "Base64 Encoded",
				Param:       d.Name,
				Description: desc,
				Severity:    SeverityMedium,
			})
		}
		if d.Type == TypeHash {
			findings = append(findings, Finding{
				Type:        "hash_param",
				Category:    "Hash Value",
				Param:       d.Name,
				Description: "Hash-like value in parameter: " + d.Name,
				Severity:    SeverityMedium,
			})
		}
		if d.Type == TypeGraphQL {
			findings = append(findings, Finding{
				Type:        "graphql_param",
				Category:    "GraphQL Query",
				Param:       d.Name,
				Description: "GraphQL query found in parameter: " + d.Name,
				Severity:    SeverityInfo,
			})
		}
		if d.Type == TypePath {
			findings = append(findings, Finding{
				Type:        "path_param",
				Category:    "Path Traversal Potential",
				Param:       d.Name,
				Description: "Path-like value in parameter: " + d.Name,
				Severity:    SeverityMedium,
			})
		}
		if d.Type == TypeURL {
			desc := "URL value in parameter: " + d.Name + " - possible SSRF/redirect target"
			if nested := urlContainsParams(d.Sample); nested != "" {
				desc += " | contains nested params: " + nested
			}
			findings = append(findings, Finding{
				Type:        "url_param",
				Category:    "URL Redirect Potential",
				Param:       d.Name,
				Description: desc,
				Severity:    SeverityMedium,
			})
		}
		// API-related params are interesting
		if reAPIParam.MatchString(d.Name) && !d.Sensitive {
			findings = append(findings, Finding{
				Type:        "api_param",
				Category:    "API Parameter",
				Param:       d.Name,
				Description: "API-related parameter: " + d.Name,
				Severity:    SeverityLow,
			})
		}
		// Deep URL-decoded analysis for suspicious encoded values
		if d.HasValue && d.Sample != "" && (reSuspicious.MatchString(d.Name) || reURLEncoded.MatchString(d.Sample)) {
			if decoded := urlDecodeDeep(d.Sample); decoded != "" {
				findings = append(findings, Finding{
					Type:        "deep_encoded",
					Category:    "Deep Encoded Value",
					Param:       d.Name,
					Description: "Deep decoded: " + d.Name + " " + decoded,
					Severity:    SeverityLow,
				})
			}
		}
	}
	return findings
}
