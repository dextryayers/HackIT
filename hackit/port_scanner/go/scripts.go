package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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

// ScriptEngine manages the built-in Go probes.
//
// Every built-in here talks to the target. Vulnerability coverage lives in the
// NSE layer (hackit/port_scanner/nse.py), which runs nmap's own script engine;
// this file deliberately does not guess at vulnerabilities, because a guess
// dressed as a finding is worse than no finding.
type ScriptEngine struct {
	scripts        map[string]Script
	scriptDir      string
	defaultScripts []string
	httpTimeout    time.Duration
}

// NewScriptEngine creates a new script engine
func NewScriptEngine() *ScriptEngine {
	engine := &ScriptEngine{
		scripts:     make(map[string]Script),
		scriptDir:   "nse_scripts",
		httpTimeout: 6 * time.Second,
		defaultScripts: []string{
			"http-server-header",
			"http-title",
			"ssh-banner",
			"ssl-cert",
			"ssl-enum-ciphers",
			"banner",
			"version",
		},
	}

	engine.loadScripts()
	return engine
}

// loadScripts registers the built-in probes.
func (se *ScriptEngine) loadScripts() {
	builtInScripts := []Script{
		{
			Name:        "http-server-header",
			Category:    ScriptDiscovery,
			Description: "Reads the Server header from a real HTTP response",
			Path:        "builtin",
			Ports:       []int{80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443},
		},
		{
			Name:        "http-title",
			Category:    ScriptDiscovery,
			Description: "Extracts the <title> element from a real HTTP response",
			Path:        "builtin",
			Ports:       []int{80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443},
		},
		{
			Name:        "ssh-banner",
			Category:    ScriptDiscovery,
			Description: "Reads the SSH identification string",
			Path:        "builtin",
			Ports:       []int{22, 2222},
		},
		{
			Name:        "ssl-cert",
			Category:    ScriptDiscovery,
			Description: "Performs a TLS handshake and reports the peer certificate",
			Path:        "builtin",
			Ports:       []int{443, 465, 636, 853, 993, 995, 8443, 9443},
		},
		{
			Name:        "ssl-enum-ciphers",
			Category:    ScriptDiscovery,
			Description: "Tests which TLS cipher suites the endpoint completes a handshake with",
			Path:        "builtin",
			Ports:       []int{443, 465, 636, 853, 993, 995, 8443, 9443},
		},
		{
			Name:        "banner",
			Category:    ScriptDiscovery,
			Description: "Returns the banner already captured by the scanner",
			Path:        "builtin",
		},
		{
			Name:        "version",
			Category:    ScriptVersion,
			Description: "Derives a version string from the captured banner",
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

// RunScript executes a single script against the target.
func (se *ScriptEngine) RunScript(scriptName string, host string, port int, service string, banner string) ScriptResult {
	if _, ok := se.GetScript(scriptName); !ok {
		return ScriptResult{
			ScriptName: scriptName,
			Port:       port,
			Host:       host,
			Status:     "error",
			Error:      "script not registered",
		}
	}

	result := ScriptResult{
		ScriptName: scriptName,
		Port:       port,
		Host:       host,
		Status:     "success",
	}

	var output []string
	var err error

	switch scriptName {
	case "http-server-header":
		output, err = se.httpServerHeader(host, port)
	case "http-title":
		output, err = se.httpTitle(host, port)
	case "ssh-banner":
		output, err = se.sshBanner(host, port)
	case "ssl-cert":
		output, err = se.tlsCertificate(host, port)
	case "ssl-enum-ciphers":
		output, err = se.tlsCipherSuites(host, port)
	case "banner":
		if strings.TrimSpace(banner) == "" {
			err = fmt.Errorf("no banner captured")
		} else {
			output = []string{strings.TrimSpace(banner)}
		}
	case "version":
		output, err = deriveVersion(service, banner)
	default:
		err = fmt.Errorf("script %q has no implementation", scriptName)
	}

	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result
	}
	result.Output = output
	return result
}

// RunScripts executes the default probes that fit the detected service.
func (se *ScriptEngine) RunScripts(host string, port int, service string, banner string) []string {
	results := make([]string, 0)

	for _, scriptName := range se.getScriptsForService(service, port) {
		result := se.RunScript(scriptName, host, port, service, banner)
		if result.Status != "success" {
			continue
		}
		for _, line := range result.Output {
			if strings.TrimSpace(line) != "" {
				results = append(results, fmt.Sprintf("[%s] %s", scriptName, line))
			}
		}
	}

	return results
}

// getScriptsForService returns the probes worth running for a service.
func (se *ScriptEngine) getScriptsForService(service string, port int) []string {
	scripts := make([]string, 0)

	switch strings.ToLower(service) {
	case "http", "https", "http-proxy", "http-alt":
		scripts = append(scripts, "http-server-header", "http-title")
	case "ssh":
		scripts = append(scripts, "ssh-banner")
	}

	if port == 443 || port == 8443 || port == 993 || port == 995 || port == 465 || port == 636 {
		scripts = append(scripts, "ssl-cert")
	}

	return scripts
}

// ── real probes ─────────────────────────────────────────────────

func (se *ScriptEngine) httpClient(host string, port int) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: se.httpTimeout,
		}).DialContext,
	}
	return &http.Client{
		Timeout:   se.httpTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (se *ScriptEngine) fetch(host string, port int) (*http.Response, string, error) {
	scheme := "http"
	if port == 443 || port == 8443 || port == 9443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	resp, err := se.httpClient(host, port).Get(url)
	if err != nil {
		return nil, url, err
	}
	return resp, url, nil
}

func (se *ScriptEngine) httpServerHeader(host string, port int) ([]string, error) {
	resp, url, err := se.fetch(host, port)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	lines := []string{fmt.Sprintf("status: %s", resp.Status)}
	if server := resp.Header.Get("Server"); server != "" {
		lines = append(lines, "server: "+server)
	} else {
		lines = append(lines, "server: (not advertised)")
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		lines = append(lines, "x-powered-by: "+powered)
	}
	lines = append(lines, "url: "+url)
	return lines, nil
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (se *ScriptEngine) httpTitle(host string, port int) ([]string, error) {
	resp, _, err := se.fetch(host, port)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buffer := make([]byte, 256*1024)
	read, _ := resp.Body.Read(buffer)
	body := string(buffer[:read])

	match := titlePattern.FindStringSubmatch(body)
	if match == nil {
		return []string{"title: (none)"}, nil
	}
	title := strings.Join(strings.Fields(match[1]), " ")
	if len(title) > 200 {
		title = title[:200]
	}
	return []string{"title: " + title}, nil
}

func (se *ScriptEngine) sshBanner(host string, port int) ([]string, error) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, se.httpTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(se.httpTimeout))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "SSH-") {
		return nil, fmt.Errorf("peer did not send an SSH identification string")
	}
	parts := strings.SplitN(line, "-", 3)
	output := []string{"banner: " + line}
	if len(parts) == 3 {
		output = append(output, "protocol: "+parts[1])
		output = append(output, "software: "+parts[2])
	}
	return output, nil
}

func (se *ScriptEngine) tlsCertificate(host string, port int) ([]string, error) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: se.httpTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address,
		&tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("handshake completed without a peer certificate")
	}
	cert := state.PeerCertificates[0]

	output := []string{
		"subject: " + cert.Subject.String(),
		"issuer: " + cert.Issuer.String(),
		"serial: " + cert.SerialNumber.String(),
		"not_before: " + cert.NotBefore.UTC().Format(time.RFC3339),
		"not_after: " + cert.NotAfter.UTC().Format(time.RFC3339),
		"tls_version: " + tlsVersionName(state.Version),
		"cipher: " + tls.CipherSuiteName(state.CipherSuite),
	}
	if len(cert.DNSNames) > 0 {
		output = append(output, "san_dns: "+strings.Join(cert.DNSNames, ", "))
	}
	return output, nil
}

func (se *ScriptEngine) tlsCipherSuites(host string, port int) ([]string, error) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	candidates := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	supported := make([]string, 0, len(candidates))
	for _, suite := range candidates {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{suite},
		})
		if err != nil {
			continue
		}
		negotiated := conn.ConnectionState().CipherSuite
		conn.Close()
		supported = append(supported, tls.CipherSuiteName(negotiated))
	}

	if len(supported) == 0 {
		return nil, fmt.Errorf("no TLS handshake completed")
	}
	return []string{"supported: " + strings.Join(supported, ", ")}, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

var versionPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9_.+-]*)[/\s]v?(\d+(?:\.\d+){1,3})`)

// deriveVersion reads a product/version pair out of a captured banner.
func deriveVersion(service string, banner string) ([]string, error) {
	trimmed := strings.TrimSpace(banner)
	if trimmed == "" {
		return nil, fmt.Errorf("no banner to parse")
	}
	match := versionPattern.FindStringSubmatch(trimmed)
	if match == nil {
		return []string{"service: " + service, "version: (not advertised)"}, nil
	}
	return []string{
		"service: " + service,
		"product: " + match[1],
		"version: " + match[2],
	}, nil
}

// LoadExternalScripts indexes .nse files for the Python/NSE layer.
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

		se.scripts[scriptName] = Script{
			Name:        scriptName,
			Category:    ScriptDiscovery,
			Description: "External NSE script (executed by the nmap NSE layer)",
			Path:        scriptPath,
		}
	}

	return nil
}

// ExecuteScriptArgs runs a registered script with the given arguments.
// The built-in probes take no arguments; unknown keys are reported back rather
// than silently ignored.
func (se *ScriptEngine) ExecuteScriptArgs(scriptName string, args map[string]string) ScriptResult {
	if _, ok := se.GetScript(scriptName); !ok {
		return ScriptResult{
			ScriptName: scriptName,
			Status:     "error",
			Error:      "script not registered",
		}
	}

	result := ScriptResult{ScriptName: scriptName, Status: "error"}
	if len(args) > 0 {
		keys := make([]string, 0, len(args))
		for key := range args {
			keys = append(keys, key)
		}
		result.Error = fmt.Sprintf("built-in probe takes no arguments (got %s); use --script with an NSE script",
			strings.Join(keys, ", "))
		return result
	}
	result.Status = "error"
	result.Error = "ExecuteScriptArgs needs host and port; call RunScript instead"
	return result
}

// GetScriptOutput returns formatted script output
func (se *ScriptEngine) GetScriptOutput(results []ScriptResult) string {
	var output strings.Builder

	for _, result := range results {
		if result.Status != "success" {
			continue
		}
		output.WriteString(fmt.Sprintf("|  %s\n", result.ScriptName))
		for _, line := range result.Output {
			output.WriteString(fmt.Sprintf("|    %s\n", line))
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
