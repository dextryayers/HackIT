package core

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

func (e *Engine) ApplyTamper(payload string) string {
	if len(e.Opts.Tamper) == 0 {
		return payload
	}

	result := payload
	for _, t := range e.Opts.Tamper {
		switch strings.ToLower(t) {
		case "space2comment":
			result = strings.ReplaceAll(result, " ", "/**/")
		case "randomcase":
			result = randomCase(result)
		case "base64encode":
			result = base64.StdEncoding.EncodeToString([]byte(result))
		case "hexencode":
			result = hexEncode(result)
		case "double_hex":
			result = hexEncode(hexEncode(result))
		case "nested_base64":
			result = base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(result))))
		case "poly_comment":
			result = "/*!" + result + "*/"
		case "urlencode":
			result = url.QueryEscape(result)
		case "commentinjection":
			result = strings.ReplaceAll(result, " ", "/**/OR/**/1=1/**/")
		case "nullbyte":
			result = result + "%00"
		}
	}
	return result
}

func hexEncode(s string) string {
	var res strings.Builder
	for _, r := range s {
		res.WriteString(fmt.Sprintf("%%%02x", r))
	}
	return res.String()
}

func randomCase(s string) string {
	var result strings.Builder
	for _, r := range s {
		if rand.Intn(2) == 0 {
			result.WriteString(strings.ToLower(string(r)))
		} else {
			result.WriteString(strings.ToUpper(string(r)))
		}
	}
	return result.String()
}
