package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CppBridge struct {
	mu          sync.Mutex
	binaryCache map[string]string
	baseDir     string
}

func NewCppBridge() *CppBridge {
	return &CppBridge{
		binaryCache: make(map[string]string),
		baseDir:     findCppBinDir(),
	}
}

func findCppBinDir() string {
	exe, _ := os.Executable()
	base := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(base, "..", "bin"),
		filepath.Join(base, "bin"),
		filepath.Join(base, "..", "cpp"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return filepath.Join(base, "..", "bin")
}

func (cb *CppBridge) findBinary(name string) string {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cached, ok := cb.binaryCache[name]; ok {
		if _, err := os.Stat(cached); err == nil {
			return cached
		}
	}

	candidates := []string{
		filepath.Join(cb.baseDir, name),
		filepath.Join(cb.baseDir, name+".exe"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			cb.binaryCache[name] = c
			return c
		}
	}
	return name
}

func (cb *CppBridge) execBinary(binary string, timeoutSec int, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func (cb *CppBridge) parseRESULT(output string) []PortResult {
	var results []PortResult
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "RESULT:") {
			continue
		}
		var pr PortResult
		if err := json.Unmarshal([]byte(line[7:]), &pr); err != nil {
			continue
		}
		results = append(results, pr)
	}
	return results
}

func (cb *CppBridge) parseFINAL(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FINAL:") {
			return line[6:]
		}
	}
	return ""
}

func (cb *CppBridge) DeepAnalyze(host string, port int, banner string) string {
	binary := cb.findBinary("deep_analyzer")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := cb.execBinary(binary, 30, host, fmt.Sprintf("%d", port), banner)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RESULT:") {
			var raw map[string]interface{}
			if json.Unmarshal([]byte(line[7:]), &raw) == nil {
				if d, ok := raw["deep_analysis"].(string); ok && d != "" {
					return d
				}
			}
		}
	}
	finalRaw := cb.parseFINAL(output)
	if finalRaw != "" {
		var raw map[string]interface{}
		if json.Unmarshal([]byte(finalRaw), &raw) == nil {
			if d, ok := raw["deep_analysis"].(string); ok {
				return d
			}
		}
	}
	return strings.TrimSpace(output)
}

func (cb *CppBridge) VulnMatch(host string, port int, service string, banner string) []string {
	binary := cb.findBinary("vuln_matcher")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		binary = cb.findBinary("vuln_matcher_v2")
	}
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return nil
	}
	output, err := cb.execBinary(binary, 30, host, fmt.Sprintf("%d", port), service, banner)
	if err != nil {
		return nil
	}
	var vulns []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "VULN:") {
			vulns = append(vulns, strings.TrimSpace(line[5:]))
			continue
		}
		if strings.HasPrefix(line, "RESULT:") {
			var raw map[string]interface{}
			if json.Unmarshal([]byte(line[7:]), &raw) == nil {
				if v, ok := raw["vulnerabilities"].([]interface{}); ok {
					for _, vi := range v {
						if vs, ok := vi.(string); ok {
							vulns = append(vulns, vs)
						}
					}
				}
			}
		}
	}
	return vulns
}

func (cb *CppBridge) TLSAnalyze(host string, port int, timeoutMs int) string {
	binary := cb.findBinary("tls_analyzer_v2")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := cb.execBinary(binary, 30, host, fmt.Sprintf("%d", port), fmt.Sprintf("%d", timeoutMs))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RESULT:") {
			var raw map[string]interface{}
			if json.Unmarshal([]byte(line[7:]), &raw) == nil {
				if t, ok := raw["tls"].(string); ok && t != "" {
					return t
				}
				if d, ok := raw["deep_analysis"].(string); ok && d != "" {
					return d
				}
			}
		}
	}
	finalRaw := cb.parseFINAL(output)
	if finalRaw != "" {
		var raw map[string]interface{}
		if json.Unmarshal([]byte(finalRaw), &raw) == nil {
			if d, ok := raw["deep_analysis"].(string); ok {
				return d
			}
		}
	}
	return strings.TrimSpace(output)
}

func (cb *CppBridge) ResponseParse(host string, port int, data string) string {
	binary := cb.findBinary("response_parser")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := cb.execBinary(binary, 15, host, fmt.Sprintf("%d", port), data)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func (cb *CppBridge) Correlate(host string, results []PortResult) string {
	binary := cb.findBinary("results_correlator")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	jsonInput, _ := json.Marshal(results)
	output, err := cb.execBinary(binary, 30, host, string(jsonInput))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CORR:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return strings.TrimSpace(output)
}

var defaultCppBridge *CppBridge
var cppBridgeOnce sync.Once

func GetCppBridge() *CppBridge {
	cppBridgeOnce.Do(func() {
		defaultCppBridge = NewCppBridge()
	})
	return defaultCppBridge
}
