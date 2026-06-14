package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

type TemplateVars struct {
	BaseURL    string
	URL        string
	Hostname   string
	Port       string
	Scheme     string
	Path       string
	Random     string
	RandomInt  int
	Timestamp  string
	UnixTime   int64
	EncodeURL  func(string) string
	Base64Encode func(string) string
	Base64Decode func(string) string
}

func NewTemplateVars(baseURL string) *TemplateVars {
	u, err := url.Parse(baseURL)
	if err != nil {
		u = &url.URL{Scheme: "https", Host: baseURL}
	}
	hostname := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return &TemplateVars{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		URL:         baseURL,
		Hostname:    hostname,
		Port:        port,
		Scheme:      u.Scheme,
		Path:        u.Path,
		Random:      randomString(8),
		RandomInt:   int(randomInt(1, 99999)),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		UnixTime:    time.Now().Unix(),
		EncodeURL:   url.QueryEscape,
		Base64Encode: base64Encode,
		Base64Decode: base64Decode,
	}
}

func (v *TemplateVars) Resolve(tmpl string) string {
	result := tmpl
	result = strings.ReplaceAll(result, "{{BaseURL}}", v.BaseURL)
	result = strings.ReplaceAll(result, "{{URL}}", v.URL)
	result = strings.ReplaceAll(result, "{{Hostname}}", v.Hostname)
	result = strings.ReplaceAll(result, "{{Port}}", v.Port)
	result = strings.ReplaceAll(result, "{{Scheme}}", v.Scheme)
	result = strings.ReplaceAll(result, "{{Path}}", v.Path)
	result = strings.ReplaceAll(result, "{{Random}}", v.Random)
	result = strings.ReplaceAll(result, "{{Timestamp}}", v.Timestamp)
	result = strings.ReplaceAll(result, "{{UnixTime}}", fmt.Sprintf("%d", v.UnixTime))
	result = strings.ReplaceAll(result, "{{RandomInt}}", fmt.Sprintf("%d", v.RandomInt))
	result = strings.ReplaceAll(result, "{{newline}}", "\n")
	result = strings.ReplaceAll(result, "{{tab}}", "\t")
	result = strings.ReplaceAll(result, "{{space}}", " ")
	result = strings.ReplaceAll(result, "{{pipe}}", "|")
	result = strings.ReplaceAll(result, "{{quote}}", "\"")
	result = strings.ReplaceAll(result, "{{apos}}", "'")
	result = strings.ReplaceAll(result, "{{dollar}}", "$")
	result = strings.ReplaceAll(result, "{{amp}}", "&")
	result = strings.ReplaceAll(result, "{{lt}}", "<")
	result = strings.ReplaceAll(result, "{{gt}}", ">")
	return result
}

func ResolvePayload(tmpl string, payload string, vars *TemplateVars) string {
	result := vars.Resolve(tmpl)
	if payload != "" {
		result = strings.ReplaceAll(result, "{{payload}}", payload)
		result = strings.ReplaceAll(result, "{{url_encode}}", url.QueryEscape(payload))
		result = strings.ReplaceAll(result, "{{base64}}", base64Encode(payload))
		result = strings.ReplaceAll(result, "{{hex}}", hexEncode(payload))
	}
	return result
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}

func randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func base64Decode(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(b)
}

func hexEncode(s string) string {
	hex := ""
	for _, c := range []byte(s) {
		hex += fmt.Sprintf("%%%02x", c)
	}
	return hex
}
