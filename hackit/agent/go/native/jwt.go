package native

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JWTResult struct {
	Endpoint     string `json:"endpoint"`
	Token        string `json:"token"`
	HeaderAlg    string `json:"header_alg"`
	Vulnerable   bool   `json:"vulnerable"`
	VulnType     string `json:"vuln_type,omitempty"`
	Evidence     string `json:"evidence"`
}

func TestJWT(token string) []JWTResult {
	var results []JWTResult

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		results = append(results, JWTResult{
			Token:      token[:min(len(token), 50)] + "...",
			Vulnerable: false,
			Evidence:   "Not a valid JWT (expected 3 parts)",
		})
		return results
	}

	headerStr := decodeBase64URL(parts[0])
	var header map[string]interface{}
	if err := json.Unmarshal([]byte(headerStr), &header); err != nil {
		results = append(results, JWTResult{
			Token:      token[:min(len(token), 50)] + "...",
			Vulnerable: false,
			Evidence:   fmt.Sprintf("Invalid header: %v", err),
		})
		return results
	}

	alg, _ := header["alg"].(string)

	if strings.EqualFold(alg, "none") {
		results = append(results, JWTResult{
			Token:      token[:min(len(token), 50)] + "...",
			HeaderAlg:  alg,
			Vulnerable: true,
			VulnType:   "alg=none",
			Evidence:   "JWT uses alg=none — attacker can forge arbitrary tokens without signature",
		})
	}

	payloadStr := decodeBase64URL(parts[1])
	var payload map[string]interface{}
	json.Unmarshal([]byte(payloadStr), &payload)

	if len(parts[2]) == 0 || parts[2] == "" {
		results = append(results, JWTResult{
			Token:      token[:min(len(token), 50)] + "...",
			HeaderAlg:  alg,
			Vulnerable: true,
			VulnType:   "Empty Signature",
			Evidence:   "JWT signature is empty",
		})
	}

	if len(results) == 0 {
		results = append(results, JWTResult{
			Token:      token[:min(len(token), 50)] + "...",
			HeaderAlg:  alg,
			Vulnerable: false,
			Evidence:   fmt.Sprintf("JWT with alg=%s appears standard", alg),
		})
	}

	return results
}

func decodeBase64URL(s string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		if d2, e2 := base64.RawStdEncoding.DecodeString(s); e2 == nil {
			return string(d2)
		}
		if d3, e3 := base64.StdEncoding.DecodeString(s); e3 == nil {
			return string(d3)
		}
		return ""
	}
	return string(decoded)
}
