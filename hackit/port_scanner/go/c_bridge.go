package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cacheEntry struct {
	result    interface{}
	expiresAt time.Time
}

type CBridge struct {
	mu          sync.Mutex
	binaryCache map[string]string
	baseDir     string
	resultCache sync.Map
}

func (cb *CBridge) cacheGet(key string) (interface{}, bool) {
	if val, ok := cb.resultCache.Load(key); ok {
		entry := val.(*cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.result, true
		}
		cb.resultCache.Delete(key)
	}
	return nil, false
}

func (cb *CBridge) cacheSet(key string, val interface{}, ttl time.Duration) {
	cb.resultCache.Store(key, &cacheEntry{result: val, expiresAt: time.Now().Add(ttl)})
}

func (cb *CBridge) cacheClear() {
	cb.resultCache.Range(func(key, _ interface{}) bool {
		cb.resultCache.Delete(key)
		return true
	})
}

func NewCBridge() *CBridge {
	return &CBridge{
		binaryCache: make(map[string]string),
		baseDir:     findCBinDir(),
	}
}

func findCBinDir() string {
	exe, _ := os.Executable()
	base := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(base, "..", "bin"),
		filepath.Join(base, "bin"),
		filepath.Join(base, "..", "c"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return filepath.Join(base, "..", "bin")
}

func (cb *CBridge) findBinary(name string) string {
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

func (cb *CBridge) execBinary(binary string, timeoutSec int, args ...string) (string, error) {
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

func (cb *CBridge) parseJSONLine(line string) map[string]interface{} {
	var raw map[string]interface{}
	if !strings.HasPrefix(line, "RESULT:") {
		return nil
	}
	if err := json.Unmarshal([]byte(line[7:]), &raw); err != nil {
		return nil
	}
	return raw
}

func (cb *CBridge) SYCScan(host string, port int, timeoutMs int) PortResult {
	cacheKey := "syn:" + host + ":" + strconv.Itoa(port)
	if val, ok := cb.cacheGet(cacheKey); ok {
		return val.(PortResult)
	}

	// Prefer cgo direct call over subprocess
	if cgo := GetCgoEngine(); cgo.IsCAvailable() {
		args := []string{host, strconv.Itoa(port), strconv.Itoa(timeoutMs), "1", "1", "0", "0", "none", "0", "0"}
		ret := cgo.CallCScanner("syn_scanner", args)
		if ret == 0 {
			result := PortResult{Port: port, State: "open"}
			cb.cacheSet(cacheKey, result, 30*time.Second)
			return result
		}
		if ret == 1 {
			result := PortResult{Port: port, State: "closed"}
			cb.cacheSet(cacheKey, result, 30*time.Second)
			return result
		}
	}

	// Fallback to subprocess
	binary := cb.findBinary("syn_scanner")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return PortResult{Port: port, State: "error", Reason: "c syn_scanner not found"}
	}
	timeoutSec := timeoutMs / 1000
	if timeoutSec < 3 {
		timeoutSec = 3
	}
	output, err := cb.execBinary(binary, timeoutSec+5,
		host, strconv.Itoa(port), strconv.Itoa(timeoutMs), "1", "1", "0", "0", "none", "0", "0")
	if err != nil {
		return PortResult{Port: port, State: "error", Reason: err.Error()}
	}
	var result PortResult
	for _, line := range strings.Split(output, "\n") {
		raw := cb.parseJSONLine(line)
		if raw == nil {
			continue
		}
		p, _ := raw["port"].(float64)
		if int(p) != port {
			continue
		}
		pr := PortResult{Port: port}
		if s, ok := raw["state"].(string); ok {
			pr.State = s
		} else if st, ok := raw["state"].(float64); ok {
			switch int(st) {
			case 0:
				pr.State = "closed"
			case 1:
				pr.State = "open"
			case 2:
				pr.State = "filtered"
			default:
				pr.State = "open|filtered"
			}
		}
		result = pr
		break
	}
	if result.State == "" {
		result = PortResult{Port: port, State: "filtered", Reason: "c syn_scanner no result"}
	}
	cb.cacheSet(cacheKey, result, 30*time.Second)
	return result
}

func (cb *CBridge) TCPProbe(host string, port int, timeoutMs int) PortResult {
	cacheKey := "tcp:" + host + ":" + strconv.Itoa(port)
	if val, ok := cb.cacheGet(cacheKey); ok {
		return val.(PortResult)
	}

	// Prefer cgo direct call over subprocess
	if cgo := GetCgoEngine(); cgo.IsCAvailable() {
		args := []string{host, strconv.Itoa(port), strconv.Itoa(timeoutMs), "1"}
		ret := cgo.CallCScanner("scanner", args)
		if ret == 0 {
			result := PortResult{Port: port, State: "open"}
			cb.cacheSet(cacheKey, result, 30*time.Second)
			return result
		}
	}

	// Fallback to subprocess
	binary := cb.findBinary("scanner")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return PortResult{Port: port, State: "error", Reason: "c scanner not found"}
	}
	timeoutSec := timeoutMs / 1000
	if timeoutSec < 3 {
		timeoutSec = 3
	}
	output, err := cb.execBinary(binary, timeoutSec+5,
		host, strconv.Itoa(port), strconv.Itoa(timeoutMs), "1")
	if err != nil {
		return PortResult{Port: port, State: "error", Reason: err.Error()}
	}
	var result PortResult
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[SCAN]") {
			continue
		}
		var p int
		var state, service, banner, version string
		fmt.Sscanf(line, "[SCAN] PORT=%d STATE=%s SERVICE=%s", &p, &state, &service)
		if p != port {
			continue
		}
		if parts := strings.Split(line, " PRODUCT="); len(parts) > 1 {
			product := strings.Split(parts[1], " VERSION=")[0]
			product = strings.Trim(product, "\"")
			if service == "" || service == "unknown" {
				service = product
			}
		}
		if parts := strings.Split(line, " VERSION="); len(parts) > 1 {
			version = strings.Split(parts[1], " BANNER=")[0]
			version = strings.Trim(version, "\"")
		}
		if parts := strings.Split(line, " BANNER=\""); len(parts) > 1 {
			banner = strings.TrimRight(parts[1], "\"")
		}
		goState := "closed"
		if state == "open" {
			goState = "open"
		}
		result = PortResult{Port: p, State: goState, Service: service, Banner: banner, Version: version}
		break
	}
	if result.State == "" {
		result = PortResult{Port: port, State: "filtered"}
	}
	cb.cacheSet(cacheKey, result, 60*time.Second)
	return result
}

func (cb *CBridge) UDPProbe(host string, port int, timeoutMs int) PortResult {
	binary := cb.findBinary("udp_scanner")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return PortResult{Port: port, State: "error", Reason: "c udp_scanner not found"}
	}
	timeoutSec := timeoutMs / 1000
	if timeoutSec < 3 {
		timeoutSec = 3
	}
	output, err := cb.execBinary(binary, timeoutSec+5,
		host, strconv.Itoa(port), strconv.Itoa(timeoutMs))
	if err != nil {
		return PortResult{Port: port, State: "error", Reason: err.Error()}
	}
	results := cb.parseRESULT(output)
	for _, r := range results {
		if r.Port == port {
			return r
		}
	}
	return PortResult{Port: port, State: "open|filtered", Protocol: "udp"}
}

func (cb *CBridge) parseRESULT(output string) []PortResult {
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

func (cb *CBridge) OSFingerprint(host string, ports []int, ttl int, window int) string {
	binary := cb.findBinary("os_detect")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	portStr := ""
	if len(ports) > 0 {
		ps := make([]string, len(ports))
		for i, p := range ports {
			ps[i] = strconv.Itoa(p)
		}
		portStr = strings.Join(ps, ",")
	}
	output, err := cb.execBinary(binary, 15,
		host, portStr, strconv.Itoa(ttl), strconv.Itoa(window))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func (cb *CBridge) BannerGrab(host string, port int, timeoutMs int) string {
	binary := cb.findBinary("syn_scanner")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return ""
	}
	timeoutSec := timeoutMs / 1000
	if timeoutSec < 3 {
		timeoutSec = 3
	}
	output, err := cb.execBinary(binary, timeoutSec+5,
		host, strconv.Itoa(port), strconv.Itoa(timeoutMs), "1", "6", "0", "0", "none", "0", "0")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(output, "\n") {
		raw := cb.parseJSONLine(line)
		if raw == nil {
			continue
		}
		if b, ok := raw["banner"].(string); ok && b != "" {
			return b
		}
	}
	return ""
}

func (cb *CBridge) ICMPDiscover(host string) bool {
	binary := cb.findBinary("os_detect")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return false
	}
	output, err := cb.execBinary(binary, 10, host, "", "64", "29200")
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) != ""
}

var defaultCBridge *CBridge
var cBridgeOnce sync.Once

func GetCBridge() *CBridge {
	cBridgeOnce.Do(func() {
		defaultCBridge = NewCBridge()
	})
	return defaultCBridge
}
