package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

var (
	loginKeywords = []string{
		"login", "signin", "sign-in", "log-in", "auth", "authenticate",
		"admin", "dashboard", "wp-admin", "wp-login", "administrator",
		"user", "password", "forgot", "reset", "register", "signup",
		"cpanel", "webmail", "panel", "manager",
	}

	apiKeywords = []string{
		"api", "v1", "v2", "v3", "rest", "graphql", "swagger",
		"openapi", "endpoint", "service", "rpc", "soap", "wsdl",
	}

	loginFormPattern = regexp.MustCompile(`(?i)<form[^>]*(?:login|signin|auth|password)[^>]*>`)
	loginInputPattern = regexp.MustCompile(`(?i)<input[^>]*(?:password|type=["']password["'])[^>]*>`)
	apiPattern = regexp.MustCompile(`(?i)(?:api|endpoint|swagger|graphql)`)
)

type DetectionResult struct {
	IsLogin      bool
	IsAPI        bool
	LoginType    string
	APIType      string
	Confidence   int
}

func DetectLoginPage(result *DirResult, body string) DetectionResult {
	dr := DetectionResult{}

	// Check by path
	pathLower := strings.ToLower(result.Path)
	for _, kw := range loginKeywords {
		if strings.Contains(pathLower, kw) {
			dr.IsLogin = true
			dr.LoginType = "path:" + kw
			dr.Confidence += 20
			break
		}
	}

	// Check by body
	bodyLower := strings.ToLower(body)
	if loginFormPattern.MatchString(body) {
		dr.IsLogin = true
		dr.LoginType = "form"
		dr.Confidence += 40
	}
	if loginInputPattern.MatchString(body) {
		dr.IsLogin = true
		dr.LoginType = "password-input"
		dr.Confidence += 30
	}
	if strings.Contains(bodyLower, "login") && strings.Contains(bodyLower, "password") {
		dr.Confidence += 25
	}

	return dr
}

func DetectAPIEndpoint(result *DirResult, body string) DetectionResult {
	dr := DetectionResult{}

	pathLower := strings.ToLower(result.Path)
	for _, kw := range apiKeywords {
		if strings.Contains(pathLower, kw) {
			dr.IsAPI = true
			dr.APIType = "path:" + kw
			dr.Confidence += 25
			break
		}
	}

	if apiPattern.MatchString(body) {
		dr.IsAPI = true
		if dr.APIType == "" {
			dr.APIType = "body"
		}
		dr.Confidence += 20
	}

	contentType := strings.ToLower(result.ContentType)
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") {
		dr.Confidence += 15
	}

	return dr
}

func ClassifyResponse(result *DirResult, body string) {
	loginResult := DetectLoginPage(result, body)
	apiResult := DetectAPIEndpoint(result, body)

	result.IsLogin = loginResult.IsLogin
	result.IsAPI = apiResult.IsAPI
}

func PrintDetectionSummary(logins, apis int) {
	if logins > 0 {
		fmt.Fprintf(color.Output, "%s Login pages found: %d\n", color.YellowString("[!]"), logins)
	}
	if apis > 0 {
		fmt.Fprintf(color.Output, "%s API endpoints found: %d\n", color.CyanString("[*]"), apis)
	}
}
