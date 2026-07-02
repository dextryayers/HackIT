package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

var swaggerPaths = []string{
	"/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
	"/api-docs", "/v1/api-docs", "/v2/api-docs",
	"/openapi.json", "/openapi.yaml", "/openapi.yml",
	"/swagger", "/swagger-ui", "/swagger/index.html",
	"/api/swagger.json", "/api/openapi.json",
	"/docs", "/api/docs",
}

func DetectSwagger(target string, client *http.Client) (string, bool) {
	for _, sp := range swaggerPaths {
		fullURL := buildFullURL(target, sp)
		resp, err := client.Get(fullURL)
		if err != nil || resp == nil {
			continue
		}
		body := make([]byte, 64*1024)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()

		content := strings.ToLower(string(body[:n]))
		if strings.Contains(content, "swagger") || strings.Contains(content, "openapi") {
			return sp, true
		}
		if strings.Contains(content, `"paths"`) || strings.Contains(content, `"definitions"`) {
			return sp, true
		}
	}
	return "", false
}

func SetupAPIMode(config *ScanConfig) {
	if len(config.Extensions) == 0 {
		config.Extensions = []string{"json", "xml", "php"}
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	if config.Headers["Accept"] == "" {
		config.Headers["Accept"] = "application/json, text/plain, */*"
	}
	config.DetectTech = true
	config.DetectWAF = true
}

func PrepareRequestBody(config *ScanConfig) string {
	body := config.Data

	if config.JSONBody && body == "" {
		body = "{}"
	}

	if config.GraphQL && body != "" {
		escaped := strings.ReplaceAll(body, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		body = `{"query":"` + escaped + `"}`
	}

	if config.DataFile != "" && body == "" {
		dataBytes, err := os.ReadFile(config.DataFile)
		if err == nil {
			body = string(dataBytes)
			if config.GraphQL {
				escaped := strings.ReplaceAll(body, `\`, `\\`)
				escaped = strings.ReplaceAll(escaped, `"`, `\"`)
				body = `{"query":"` + escaped + `"}`
			}
		}
	}

	return body
}

func PrintSwaggerResult(path string, found bool) {
	if found {
		fmt.Fprintf(color.Output, "%s Swagger/OpenAPI found: %s\n", color.GreenString("[+]"), path)
	} else {
		fmt.Fprintf(color.Output, "%s No Swagger/OpenAPI detected\n", color.CyanString("[*]"))
	}
}
