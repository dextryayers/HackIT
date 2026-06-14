//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func findBinary(name string) string {
	exe, _ := os.Executable()
	base := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(base, "bin", name),
		filepath.Join(base, "..", "c", name),
		filepath.Join(base, "..", "cpp", name),
		filepath.Join(base, "..", "rust", "target", "release", name),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return name
}

func runBinary(binary string, args ...string) (string, error) {
	cmd := exec.Command(binary, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func parseRESULTLine(line string) (port int, state string) {
	if !strings.HasPrefix(line, "RESULT:") {
		return 0, ""
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line[7:]), &raw); err != nil {
		return 0, ""
	}
	p, _ := raw["port"].(float64)
	s, _ := raw["state"].(string)
	if s == "" {
		if st, ok := raw["status"].(string); ok {
			s = st
		}
	}
	return int(p), s
}

func parseRESULTLineFromMap(raw map[string]interface{}) (port int, state string) {
	p, _ := raw["port"].(float64)
	s, _ := raw["state"].(string)
	if s == "" {
		if st, ok := raw["status"].(string); ok {
			s = st
		}
	}
	return int(p), s
}

func RustFastScan(host string, port int, timeoutMs int, stealth bool) PortResult {
	binary := findBinary("hyper_scan")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		binary = findBinary("syn_scanner")
	}
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return PortResult{Port: port, State: "error"}
	}
	output, err := runBinary(binary, host, fmt.Sprintf("%d", port), fmt.Sprintf("%d", timeoutMs))
	if err != nil {
		return PortResult{Port: port, State: "error"}
	}
	for _, line := range strings.Split(output, "\n") {
		p, s := parseRESULTLine(line)
		if p == port && s != "" {
			return PortResult{Port: port, State: s}
		}
	}
	return PortResult{Port: port, State: "error"}
}

func RustMassScan(host string, ports []int, threads int, timeoutMs int, stealth bool) []PortResult {
	binary := findBinary("hyper_scan")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return nil
	}
	portStr := make([]string, len(ports))
	for i, p := range ports {
		portStr[i] = strconv.Itoa(p)
	}
	minP, maxP := ports[0], ports[0]
	for _, p := range ports {
		if p < minP {
			minP = p
		}
		if p > maxP {
			maxP = p
		}
	}
	output, err := runBinary(binary, host, fmt.Sprintf("%d-%d", minP, maxP), fmt.Sprintf("%d", timeoutMs), fmt.Sprintf("%d", threads))
	if err != nil {
		return nil
	}
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}
	seen := make(map[int]bool)
	var results []PortResult
	for _, line := range strings.Split(output, "\n") {
		p, s := parseRESULTLine(line)
		if p > 0 && portSet[p] && !seen[p] {
			seen[p] = true
			results = append(results, PortResult{Port: p, State: s, Protocol: "tcp"})
		}
	}
	return results
}

func RustFingerprintService(banner string) string {
	return ""
}

func RustExtractVersion(banner string, service string) string {
	return ""
}

func RustDetectOS(host string) OSInfo {
	binary := findBinary("os_detect")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return OSInfo{Name: "Unknown", Accuracy: 0}
	}
	output, err := runBinary(binary, host)
	if err != nil {
		return OSInfo{Name: "Unknown", Accuracy: 0}
	}
	os := OSInfo{Name: "Unknown", Accuracy: 0}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "RESULT:") {
			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(line[7:]), &raw); err != nil {
				continue
			}
			if n, ok := raw["name"].(string); ok {
				os.Name = n
			}
			if v, ok := raw["version"].(string); ok {
				os.Version = v
			}
			if f, ok := raw["family"].(string); ok {
				os.Family = f
			}
			if a, ok := raw["accuracy"].(float64); ok {
				os.Accuracy = int(a)
			}
			if t, ok := raw["ttl"].(float64); ok {
				os.TTL = int(t)
			}
			if w, ok := raw["window"].(float64); ok {
				os.Window = int(w)
			}
			if c, ok := raw["confidence"].(float64); ok {
				os.Confidence = c
			}
			if fp, ok := raw["fingerprint"].(string); ok {
				os.Fingerprint = fp
			}
		}
	}
	return os
}

func RustCheckVulnerabilities(host string, port int, service string, banner string) []string {
	binary := findBinary("vuln_matcher")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return nil
	}
	output, err := runBinary(binary, service, banner)
	if err != nil {
		return nil
	}
	var vulns []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "RESULT:") {
			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(line[7:]), &raw); err != nil {
				continue
			}
			if cve, ok := raw["cve"].(string); ok {
				vulns = append(vulns, cve)
			} else if desc, ok := raw["description"].(string); ok {
				vulns = append(vulns, desc)
			}
		}
	}
	return vulns
}

func RustPerformDeepScan(host string, port int, banner string) string {
	return ""
}

func RustBatchScan(host string, startPort int, endPort int, timeout int, concurrency int) string {
	binary := findBinary("hyper_scan")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := runBinary(binary, host, fmt.Sprintf("%d-%d", startPort, endPort), fmt.Sprintf("%d", timeout), fmt.Sprintf("%d", concurrency))
	if err != nil {
		return ""
	}
	var openPorts []string
	seen := make(map[int]bool)
	for _, line := range strings.Split(output, "\n") {
		p, s := parseRESULTLine(line)
		if p > 0 && s == "open" && !seen[p] {
			seen[p] = true
			openPorts = append(openPorts, strconv.Itoa(p))
		}
	}
	return strings.Join(openPorts, ",")
}

func CExpertDetectOs(host string, openPorts string, ttl int, window int) string {
	binary := findBinary("os_fingerprint")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := runBinary(binary, host, openPorts, fmt.Sprintf("%d", ttl), fmt.Sprintf("%d", window))
	if err != nil {
		return ""
	}
	return output
}

func CppScanService(host string, port int, timeoutMs int) PortResult {
	binary := findBinary("tls_scanner")
	if _, err := os.Stat(binary); err != nil {
		return PortResult{Port: port, State: "error"}
	}
	output, err := runBinary(binary, host, fmt.Sprintf("%d", port))
	if err != nil {
		return PortResult{Port: port, State: "error"}
	}
	res := PortResult{Port: port, State: "error"}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "RESULT:") {
			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(line[7:]), &raw); err != nil {
				continue
			}
			if s, ok := raw["state"].(string); ok {
				res.State = s
			}
			if svc, ok := raw["service"].(string); ok {
				res.Service = svc
			}
			if b, ok := raw["banner"].(string); ok {
				res.Banner = b
			}
			if v, ok := raw["version"].(string); ok {
				res.Version = v
			}
		}
	}
	return res
}

func RustFirewallBypass(host string, port int) (string, int) {
	return "None", 0
}

func RustGetNetworkIntelAdvanced(host string) IntelInfo {
	return IntelInfo{}
}

func RustDetectOsDetailed(host string, openPorts string, guess bool, limit bool) string {
	return ""
}

func RustGatherIpInfo(host string) string {
	return ""
}

func RustKernelDetect(host string, ports string) string {
	binary := findBinary("kernel_detect")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := runBinary(binary, host, ports)
	if err != nil {
		return ""
	}
	return output
}

func RustDnsDetect(host string, dnsServer string) string {
	binary := findBinary("dns_detect")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := runBinary(binary, host, dnsServer)
	if err != nil {
		return ""
	}
	return output
}

func RustWebFingerprint(host string, port int) string {
	binary := findBinary("web_fingerprint")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := runBinary(binary, host, fmt.Sprintf("%d", port))
	if err != nil {
		return ""
	}
	return output
}

func RustDeepScan(host string, port int, banner string) string {
	binary := findBinary("hyper_scan")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := runBinary(binary, host, fmt.Sprintf("%d", port), "5000")
	if err != nil {
		return ""
	}
	return output
}
