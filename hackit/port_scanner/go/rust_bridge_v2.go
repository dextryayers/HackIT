package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

type RustBridge struct {
	mu          sync.Mutex
	binaryCache map[string]string
}

func NewRustBridge() *RustBridge {
	return &RustBridge{
		binaryCache: make(map[string]string),
	}
}

func (rb *RustBridge) findBinary(name string) string {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if cached, ok := rb.binaryCache[name]; ok {
		if _, err := os.Stat(cached); err == nil {
			return cached
		}
	}

	path := findBinary(name)
	if path != name {
		rb.binaryCache[name] = path
	}
	return path
}

func (rb *RustBridge) runBinary(binary string, args ...string) (string, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return runBinary(binary, args...)
}

func (rb *RustBridge) parseRESULT(output string) []PortResult {
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

func (rb *RustBridge) parseFINAL(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FINAL:") {
			return line[6:]
		}
	}
	return ""
}

func (rb *RustBridge) BinaryExists(name string) bool {
	path := rb.findBinary(name)
	_, err := os.Stat(path)
	return err == nil
}

type DNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Name  string `json:"name"`
	TTL   int    `json:"ttl"`
}

func (rb *RustBridge) RunDNSEnum(host string) []DNSRecord {
	binary := rb.findBinary("dns_enum")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return nil
	}
	output, err := rb.runBinary(binary, "--target", host)
	if err != nil {
		return nil
	}
	var records []DNSRecord
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "RESULT:") {
			continue
		}
		var raw struct {
			Type  string `json:"type"`
			Value string `json:"value"`
			Name  string `json:"name"`
			TTL   int    `json:"ttl"`
		}
		if err := json.Unmarshal([]byte(line[7:]), &raw); err == nil {
			records = append(records, DNSRecord{
				Type: raw.Type, Value: raw.Value,
				Name: raw.Name, TTL: raw.TTL,
			})
		}
	}
	return records
}

func (rb *RustBridge) TCPScan(host string, port int, timeoutMs int) PortResult {
	binary := rb.findBinary("hyper_scan")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		binary = rb.findBinary("rust_syn_scanner")
	}
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return PortResult{Port: port, State: "error", Reason: "no rust tcp binary"}
	}
	output, err := rb.runBinary(binary, host, fmt.Sprintf("%d", port), fmt.Sprintf("%d", timeoutMs))
	if err != nil {
		return PortResult{Port: port, State: "error", Reason: err.Error()}
	}
	results := rb.parseRESULT(output)
	for _, r := range results {
		if r.Port == port {
			return r
		}
	}
	finalRaw := rb.parseFINAL(output)
	if finalRaw != "" {
		var pr PortResult
		if json.Unmarshal([]byte(finalRaw), &pr) == nil && pr.Port == port {
			return pr
		}
	}
	return PortResult{Port: port, State: "filtered", Reason: "no result"}
}

func (rb *RustBridge) UDPScan(host string, port int, timeoutMs int) PortResult {
	binary := rb.findBinary("udp_scanner")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return PortResult{Port: port, State: "error", Reason: "no rust udp binary"}
	}
	output, err := rb.runBinary(binary, host, fmt.Sprintf("%d", port), fmt.Sprintf("%d", timeoutMs))
	if err != nil {
		return PortResult{Port: port, State: "error", Reason: err.Error()}
	}
	results := rb.parseRESULT(output)
	for _, r := range results {
		if r.Port == port {
			return r
		}
	}
	return PortResult{Port: port, State: "open|filtered", Protocol: "udp"}
}

func (rb *RustBridge) ServiceDetect(host string, port int, banner string) string {
	binary := rb.findBinary("web_fingerprint")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	output, err := rb.runBinary(binary, host, fmt.Sprintf("%d", port))
	if err != nil {
		return ""
	}
	results := rb.parseRESULT(output)
	for _, r := range results {
		if r.Port == port && r.Service != "" {
			return r.Service
		}
	}
	finalRaw := rb.parseFINAL(output)
	if finalRaw != "" {
		var pr PortResult
		if json.Unmarshal([]byte(finalRaw), &pr) == nil && pr.Service != "" {
			return pr.Service
		}
	}
	return ""
}

func (rb *RustBridge) OSDetect(host string) OSInfo {
	binary := rb.findBinary("os_detect")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return OSInfo{Name: "Unknown", Accuracy: 0}
	}
	output, err := rb.runBinary(binary, host, "", "64", "29200")
	if err != nil {
		return OSInfo{Name: "Unknown", Accuracy: 0}
	}
	info := OSInfo{Name: strings.TrimSpace(output), Accuracy: 80}
	if info.Name == "" {
		info.Name = "Unknown"
	}
	return info
}

func (rb *RustBridge) DNSEnum(host string, dnsServer string) string {
	binary := rb.findBinary("dns_detect")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	args := []string{host}
	if dnsServer != "" {
		args = append(args, dnsServer)
	}
	output, err := rb.runBinary(binary, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func (rb *RustBridge) VulnScan(host string, port int, service string, banner string) []string {
	var vulns []string

	if service != "" || banner != "" {
		rustVulns := RustCheckVulnerabilities(host, port, service, banner)
		vulns = append(vulns, rustVulns...)
	}

	binary := rb.findBinary("vuln_matcher_v2")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return vulns
	}
	output, err := rb.runBinary(binary, host, fmt.Sprintf("%d", port), service, banner)
	if err != nil {
		return vulns
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "VULN:") {
			vulns = append(vulns, strings.TrimSpace(line[5:]))
		}
	}
	return vulns
}

var defaultRustBridge *RustBridge
var rustBridgeOnce sync.Once

func GetRustBridge() *RustBridge {
	rustBridgeOnce.Do(func() {
		defaultRustBridge = NewRustBridge()
	})
	return defaultRustBridge
}
