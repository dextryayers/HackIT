package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

type layerType int

const (
	layerNone  layerType = iota
	layerURL
	layerBase64Std
	layerBase64URL
	layerHex
	layerDoubleURL
	layerHTML
)

var (
	reAllHex    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reHasURLEnc = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	reHasHTML   = regexp.MustCompile(`&[a-z]+;|&#[0-9]+;|&#x[0-9a-f]+;`)
	rePlaintext = regexp.MustCompile(`^[\x20-\x7e\s]+$`)
)

func detectLayer(s string) layerType {
	if len(s) < 3 {
		return layerNone
	}
	if reHasURLEnc.MatchString(s) &&
		(strings.Count(s, "%") > 1 || (strings.Count(s, "%") == 1 && len(s) < 30)) {
		return layerURL
	}
	if strings.Contains(s, "&amp;") || strings.Contains(s, "&lt;") ||
		strings.Contains(s, "&gt;") || strings.Contains(s, "&#") {
		return layerHTML
	}
	if reAllHex.MatchString(s) && len(s) >= 10 && (len(s)%2 == 0) {
		if decoded, err := hex.DecodeString(s); err == nil && len(decoded) > 0 && !reAllHex.MatchString(string(decoded)) {
			return layerHex
		}
	}
	if len(s) >= 8 && len(s)%4 == 0 {
		if _, err := base64.StdEncoding.DecodeString(s); err == nil {
			return layerBase64Std
		}
		if _, err := base64.URLEncoding.DecodeString(s); err == nil {
			return layerBase64URL
		}
	}
	return layerNone
}

func deepDecode(s string) DecodeResult {
	if s == "" || len(s) < 3 {
		return DecodeResult{Original: s, Decoded: s, Layers: 0, Types: "none"}
	}

	current := s
	history := []string{s}
	types := []string{}
	maxLayers := 10

	for layer := 0; layer < maxLayers; layer++ {
		lt := detectLayer(current)
		if lt == layerNone {
			break
		}

		decoded := ""
		switch lt {
		case layerURL:
			d, err := urlDecodeSafe(current)
			if err == nil && d != current {
				decoded = d
				types = append(types, "url")
			}
		case layerHTML:
			d := htmlDecode(current)
			if d != current {
				decoded = d
				types = append(types, "html")
			}
		case layerHex:
			d, err := hex.DecodeString(current)
			if err == nil {
				decoded = string(d)
				types = append(types, "hex")
			}
		case layerBase64Std:
			d, err := base64.StdEncoding.DecodeString(current)
			if err == nil {
				decoded = string(d)
				types = append(types, "b64std")
			}
		case layerBase64URL:
			d, err := base64.URLEncoding.DecodeString(current)
			if err == nil {
				decoded = string(d)
				types = append(types, "b64url")
			}
		case layerDoubleURL:
			d, err := urlDecodeSafe(current)
			if err == nil && d != current {
				decoded = d
				types = append(types, "url2x")
			}
		}

		if decoded == "" || decoded == current {
			break
		}

		current = decoded
		history = append(history, current)

		// If decoded content is readable plaintext, stop
		if rePlaintext.MatchString(current) && len(current) > 5 {
			break
		}
		// If decoded contains JSON with params, stop (we'll analyze it separately)
		if strings.Contains(current, "\"") && (strings.Contains(current, ":") || strings.Contains(current, "=")) {
			break
		}
		// If decoded is URL-friendly and contains = or & (query string inside)
		if strings.Contains(current, "=") && strings.Contains(current, "&") {
			break
		}
	}

	if len(history) <= 1 {
		return DecodeResult{
			Original: s,
			Decoded:  s,
			Layers:   0,
			Types:    "none",
			IOC:      false,
		}
	}

	typesJoined := strings.Join(types, "→")

	// Check if decoded value looks interesting (contains sensitive data)
	ioc := containsIOC(current)

	return DecodeResult{
		Original: s,
		Decoded:  current,
		Layers:   len(history) - 1,
		Types:    typesJoined,
		IOC:      ioc,
	}
}

func urlDecodeSafe(s string) (string, error) {
	decoded, err := decodeURIComponent(s)
	if err != nil {
		return s, err
	}
	return decoded, nil
}

func decodeURIComponent(s string) (string, error) {
	var result strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hexStr := s[i+1 : i+3]
			val := 0
			for _, h := range hexStr {
				val *= 16
				switch {
				case h >= '0' && h <= '9':
					val += int(h - '0')
				case h >= 'a' && h <= 'f':
					val += int(h - 'a' + 10)
				case h >= 'A' && h <= 'F':
					val += int(h - 'A' + 10)
				default:
					return s, &strError{"invalid hex"}
				}
			}
			result.WriteByte(byte(val))
			i += 3
		} else if c == '+' {
			result.WriteByte(' ')
			i++
		} else {
			result.WriteByte(c)
			i++
		}
	}
	return result.String(), nil
}

type strError struct{ msg string }

func (e *strError) Error() string { return e.msg }

// decodeURIComponent is defined above

func htmlDecode(s string) string {
	r := strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">",
		"&quot;", "\"", "&#39;", "'", "&#x27;", "'",
		"&#x2F;", "/", "&#60;", "<", "&#62;", ">",
		"&nbsp;", " ", "&apos;", "'",
	)
	return r.Replace(s)
}

func containsIOC(s string) bool {
	lower := strings.ToLower(s)
	// JWT token pattern
	if strings.Count(s, ".") == 2 && len(s) > 40 {
		return true
	}
	// API key patterns
	keywords := []string{"sk-", "pk-", "api_key", "apikey", "secret", "token=",
		"bearer", "password", "AKIA", "eyJ", "ghp_", "gho_", "ghu_"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// DecodeParamsInResults runs deep decode on all param values in results
// and returns findings for multi-layer encoded values
func findDeepDecodeFindings(allResults []DiscoResult) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, r := range allResults {
		for name, val := range r.Params {
			if val == "" || seen[name+":"+val] {
				continue
			}
			seen[name+":"+val] = true

			dr := deepDecode(val)
			if dr.Layers >= 2 {
				severity := SeverityMedium
				if dr.IOC {
					severity = SeverityHigh
				}
				desc := "Multi-layer encoded: " + name + " decoded " + dr.Types
				if len(dr.Decoded) > 60 {
					desc += " → " + dr.Decoded[:60] + "..."
				} else {
					desc += " → " + dr.Decoded
				}
				if dr.IOC {
					desc += " [IOC!]"
				}
				findings = append(findings, Finding{
					Type:        "deep_decode",
					Category:    "Deep Encoded",
					Param:       name,
					URL:         r.URL,
					Description: desc,
					Severity:    severity,
				})
			}

			// Also check if decoded content contains JSON with embedded params
			if dr.Layers >= 1 {
				decoded := dr.Decoded
				// Check if decoded looks like JSON with query-able data
				if strings.HasPrefix(decoded, "{") || strings.HasPrefix(decoded, "[") {
					var js interface{}
					if json.Unmarshal([]byte(decoded), &js) == nil {
						findings = append(findings, Finding{
							Type:        "decoded_json",
							Category:    "Decoded JSON",
							Param:       name,
							URL:         r.URL,
							Description: "Decoded JSON in param: " + name + " (" + dr.Types + ")",
							Severity:    SeverityInfo,
						})
					}
				}
			}
		}
	}
	return findings
}
