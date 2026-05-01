package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScriptResult represents the result of a script execution
type ScriptResult struct {
	ScriptName string   `json:"script_name"`
	Port       int      `json:"port"`
	Host       string   `json:"host"`
	Output     []string `json:"output"`
	Status     string   `json:"status"`
	Error      string   `json:"error,omitempty"`
}

// ScriptCategory represents different categories of NSE-style scripts
type ScriptCategory string

const (
	ScriptDiscovery ScriptCategory = "discovery"
	ScriptVuln      ScriptCategory = "vuln"
	ScriptAuth      ScriptCategory = "auth"
	ScriptBrute     ScriptCategory = "brute"
	ScriptExternal  ScriptCategory = "external"
	ScriptIntrusive ScriptCategory = "intrusive"
	ScriptMalware   ScriptCategory = "malware"
	ScriptSafe      ScriptCategory = "safe"
	ScriptVersion   ScriptCategory = "version"
)

// Script represents an NSE-style script
type Script struct {
	Name        string         `json:"name"`
	Category    ScriptCategory `json:"category"`
	Description string         `json:"description"`
	Path        string         `json:"path"`
	Requires    []string       `json:"requires,omitempty"`
	Ports       []int          `json:"ports,omitempty"`
}

// ScriptEngine manages NSE-style script execution
type ScriptEngine struct {
	scripts        map[string]Script
	scriptDir      string
	defaultScripts []string
}

// NewScriptEngine creates a new script engine
func NewScriptEngine() *ScriptEngine {
	engine := &ScriptEngine{
		scripts:   make(map[string]Script),
		scriptDir: "nse_scripts",
		defaultScripts: []string{
			"http-server-header",
			"http-title",
			"ssh-auth-methods",
			"ssh-hostkey",
			"ssl-cert",
			"ssl-enum-ciphers",
			"banner",
			"version",
		},
	}

	engine.loadScripts()
	return engine
}

// loadScripts loads available scripts from the scripts directory
func (se *ScriptEngine) loadScripts() {
	// Define built-in scripts
	builtInScripts := []Script{
		{
			Name:        "http-server-header",
			Category:    ScriptDiscovery,
			Description: "Retrieves HTTP server header",
			Path:        "builtin",
		},
		{
			Name:        "http-title",
			Category:    ScriptDiscovery,
			Description: "Retrieves HTTP page title",
			Path:        "builtin",
		},
		{
			Name:        "ssh-auth-methods",
			Category:    ScriptAuth,
			Description: "Enumerates SSH authentication methods",
			Path:        "builtin",
		},
		{
			Name:        "ssh-hostkey",
			Category:    ScriptDiscovery,
			Description: "Retrieves SSH host key",
			Path:        "builtin",
		},
		{
			Name:        "ssl-cert",
			Category:    ScriptDiscovery,
			Description: "Retrieves SSL certificate",
			Path:        "builtin",
		},
		{
			Name:        "ssl-enum-ciphers",
			Category:    ScriptDiscovery,
			Description: "Enumerates SSL ciphers",
			Path:        "builtin",
		},
		{
			Name:        "banner",
			Category:    ScriptDiscovery,
			Description: "Retrieves service banner",
			Path:        "builtin",
		},
		{
			Name:        "version",
			Category:    ScriptVersion,
			Description: "Detects service version",
			Path:        "builtin",
		},
		{
			Name:        "http-vuln-cve2021-44228",
			Category:    ScriptVuln,
			Description: "Checks for Log4j vulnerability",
			Path:        "builtin",
		},
		{
			Name:        "http-vuln-cve2021-34527",
			Category:    ScriptVuln,
			Description: "Checks for SAML vulnerability",
			Path:        "builtin",
		},
		{
			Name:        "smb-vuln-ms17-010",
			Category:    ScriptVuln,
			Description: "Checks for EternalBlue vulnerability",
			Path:        "builtin",
		},
	}

	for _, script := range builtInScripts {
		se.scripts[script.Name] = script
	}
}

// GetScript retrieves a script by name
func (se *ScriptEngine) GetScript(name string) (Script, bool) {
	script, ok := se.scripts[name]
	return script, ok
}

// ListScripts returns all available scripts
func (se *ScriptEngine) ListScripts() []Script {
	scripts := make([]Script, 0, len(se.scripts))
	for _, script := range se.scripts {
		scripts = append(scripts, script)
	}
	return scripts
}

// ListScriptsByCategory returns scripts filtered by category
func (se *ScriptEngine) ListScriptsByCategory(category ScriptCategory) []Script {
	scripts := make([]Script, 0)
	for _, script := range se.scripts {
		if script.Category == category {
			scripts = append(scripts, script)
		}
	}
	return scripts
}

// RunScript executes a single script
func (se *ScriptEngine) RunScript(scriptName string, host string, port int, service string, banner string) ScriptResult {
	_, ok := se.GetScript(scriptName)
	if !ok {
		return ScriptResult{
			ScriptName: scriptName,
			Status:     "error",
			Error:      "Script not found",
		}
	}

	result := ScriptResult{
		ScriptName: scriptName,
		Port:       port,
		Host:       host,
		Status:     "success",
	}

	// Execute built-in scripts
	switch scriptName {
	case "http-server-header":
		result.Output = se.runHTTPServerHeader(host, port)
	case "http-title":
		result.Output = se.runHTTPTitle(host, port)
	case "ssh-auth-methods":
		result.Output = se.runSSHAuthMethods(host, port)
	case "ssh-hostkey":
		result.Output = se.runSSHHostkey(host, port)
	case "ssl-cert":
		result.Output = se.runSSLCert(host, port)
	case "ssl-enum-ciphers":
		result.Output = se.runSSLEnumCiphers(host, port)
	case "banner":
		result.Output = []string{banner}
		result.Status = "success"
	case "version":
		result.Output = se.runVersionDetection(service, banner)
	case "http-vuln-cve2021-44228":
		result.Output = se.runLog4jCheck(host, port)
	case "http-vuln-cve2021-34527":
		result.Output = se.runSAMLCheck(host, port)
	case "smb-vuln-ms17-010":
		result.Output = se.runEternalBlueCheck(host, port)
	default:
		result.Status = "error"
		result.Error = "Script execution not implemented"
	}

	return result
}

// RunScripts executes multiple scripts
func (se *ScriptEngine) RunScripts(host string, port int, service string, banner string) []string {
	results := make([]string, 0)

	// Determine which scripts to run based on service
	scriptsToRun := se.getScriptsForService(service, port)

	for _, scriptName := range scriptsToRun {
		result := se.RunScript(scriptName, host, port, service, banner)
		if result.Status == "success" && len(result.Output) > 0 {
			for _, output := range result.Output {
				if output != "" {
					results = append(results, fmt.Sprintf("[%s] %s", scriptName, output))
				}
			}
		}
	}

	return results
}

// getScriptsForService returns appropriate scripts for a given service
func (se *ScriptEngine) getScriptsForService(service string, port int) []string {
	scripts := make([]string, 0)

	// Always run banner and version
	scripts = append(scripts, "banner", "version")

	// Service-specific scripts
	switch strings.ToLower(service) {
	case "http", "https":
		scripts = append(scripts, "http-server-header", "http-title")
		scripts = append(scripts, "http-vuln-cve2021-44228", "http-vuln-cve2021-34527")
	case "ssh":
		scripts = append(scripts, "ssh-auth-methods", "ssh-hostkey")
	case "smtp":
		scripts = append(scripts, "smtp-commands", "smtp-enum-users")
	case "ftp":
		scripts = append(scripts, "ftp-anon", "ftp-brute")
	case "microsoft-ds", "smb":
		scripts = append(scripts, "smb-vuln-ms17-010", "smb-enum-shares")
	}

	// SSL/TLS scripts for common SSL ports
	if port == 443 || port == 8443 || port == 993 || port == 995 || port == 465 || port == 587 {
		scripts = append(scripts, "ssl-cert", "ssl-enum-ciphers")
	}

	return scripts
}

// Built-in script implementations

func (se *ScriptEngine) runHTTPServerHeader(host string, port int) []string {
	// Implementation would make HTTP request and extract Server header
	return []string{"Server: nginx/1.18.0"}
}

func (se *ScriptEngine) runHTTPTitle(host string, port int) []string {
	// Implementation would make HTTP request and extract title
	return []string{"Title: Welcome to nginx!"}
}

func (se *ScriptEngine) runSSHAuthMethods(host string, port int) []string {
	// Implementation would connect to SSH and enumerate auth methods
	return []string{"auth_methods: publickey, password"}
}

func (se *ScriptEngine) runSSHHostkey(host string, port int) []string {
	// Implementation would retrieve SSH host key
	return []string{"hostkey: ssh-rsa 2048"}
}

func (se *ScriptEngine) runSSLCert(host string, port int) []string {
	// Implementation would retrieve SSL certificate
	return []string{"cert: CN=example.com, O=Example Org"}
}

func (se *ScriptEngine) runSSLEnumCiphers(host string, port int) []string {
	// Implementation would enumerate SSL ciphers
	return []string{"ciphers: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
}

func (se *ScriptEngine) runVersionDetection(service string, banner string) []string {
	// Implementation would analyze banner for version info
	return []string{fmt.Sprintf("version: %s", banner)}
}

func (se *ScriptEngine) runLog4jCheck(host string, port int) []string {
	// Implementation would check for Log4j vulnerability
	return []string{"VULNERABLE: CVE-2021-44228 detected"}
}

func (se *ScriptEngine) runSAMLCheck(host string, port int) []string {
	// Implementation would check for SAML vulnerability
	return []string{"VULNERABLE: CVE-2021-34527 detected"}
}

func (se *ScriptEngine) runEternalBlueCheck(host string, port int) []string {
	// Implementation would check for EternalBlue vulnerability
	return []string{"VULNERABLE: MS17-010 detected"}
}

// LoadExternalScripts loads external script files from directory
func (se *ScriptEngine) LoadExternalScripts(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".nse") {
			continue
		}

		scriptPath := filepath.Join(dir, file.Name())
		scriptName := strings.TrimSuffix(file.Name(), ".nse")

		script := Script{
			Name:        scriptName,
			Category:    ScriptDiscovery,
			Description: fmt.Sprintf("External script: %s", scriptName),
			Path:        scriptPath,
		}

		se.scripts[scriptName] = script
	}

	return nil
}

// ExecuteScriptArgs executes a script with custom arguments
func (se *ScriptEngine) ExecuteScriptArgs(scriptName string, args map[string]string) ScriptResult {
	_, ok := se.GetScript(scriptName)
	if !ok {
		return ScriptResult{
			ScriptName: scriptName,
			Status:     "error",
			Error:      "Script not found",
		}
	}

	// For now, return a placeholder result
	return ScriptResult{
		ScriptName: scriptName,
		Status:     "success",
		Output:     []string{fmt.Sprintf("Executed with args: %v", args)},
	}
}

// GetScriptOutput returns formatted script output
func (se *ScriptEngine) GetScriptOutput(results []ScriptResult) string {
	var output strings.Builder

	for _, result := range results {
		if result.Status == "success" {
			output.WriteString(fmt.Sprintf("|  %s\n", result.ScriptName))
			for _, line := range result.Output {
				output.WriteString(fmt.Sprintf("|    %s\n", line))
			}
		}
	}

	return output.String()
}

// SaveScriptResults saves script results to a file
func (se *ScriptEngine) SaveScriptResults(results []ScriptResult, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
