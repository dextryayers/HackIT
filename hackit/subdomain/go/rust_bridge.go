package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var rustBinDir string

func init() {
	if runtime.GOOS == "linux" {
		rustBinDir = filepath.Join("rust_engine", "target", "release")
	}
}

func getRustBinPath(binName string) string {
	if rustBinDir == "" {
		return ""
	}
	return filepath.Join(rustBinDir, binName)
}

func callRustBinary(binName string, args ...string) ([]string, error) {
	binPath := getRustBinPath(binName)
	if binPath == "" {
		return nil, fmt.Errorf("Rust bridge not available on %s", runtime.GOOS)
	}

	cmd := exec.Command(binPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var results []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "RESULT:") {
			results = append(results, strings.TrimPrefix(line, "RESULT:"))
		}
	}

	if err := cmd.Wait(); err != nil {
		return results, err
	}
	return results, nil
}

func linuxRustResolveDNS(domain string) []string {
	results, err := callRustBinary("subdomain_resolver", domain)
	if err != nil || len(results) == 0 {
		return nil
	}
	var ips []string
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(results[0]), &parsed); err == nil {
		if ipList, ok := parsed["ips"].([]interface{}); ok {
			for _, ip := range ipList {
				ips = append(ips, fmt.Sprintf("%v", ip))
			}
		}
	}
	return ips
}

func linuxRustResolveDNSBatch(domains []string) map[string][]string {
	result := make(map[string][]string)
	joined := strings.Join(domains, ",")
	rawResults, err := callRustBinary("subdomain_resolver", joined)
	if err != nil {
		return result
	}
	for _, raw := range rawResults {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			continue
		}
		sub, _ := parsed["subdomain"].(string)
		if sub == "" {
			continue
		}
		if ipList, ok := parsed["ips"].([]interface{}); ok {
			for _, ip := range ipList {
				result[sub] = append(result[sub], fmt.Sprintf("%v", ip))
			}
		}
	}
	return result
}

func linuxRustGetCname(domain string) string {
	results, err := callRustBinary("subdomain_resolver", domain)
	if err != nil || len(results) == 0 {
		return ""
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(results[0]), &parsed); err != nil {
		return ""
	}
	cname, _ := parsed["cname"].(string)
	return cname
}

func linuxRustOSINTScan(domain string) []string {
	results, err := callRustBinary("subdomain_osint", domain)
	if err != nil {
		return nil
	}
	var subs []string
	for _, raw := range results {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			continue
		}
		sub, _ := parsed["subdomain"].(string)
		if sub != "" {
			subs = append(subs, sub)
		}
	}
	return subs
}

func linuxRustGetTitle(url string) string {
	client := defaultClient
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	m := titleRegex.FindStringSubmatch(string(body))
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func linuxRustCheckSubTakeover(domains []string) map[string]string {
	results := make(map[string]string)
	joined := strings.Join(domains, ",")
	rawResults, err := callRustBinary("subdomain_takeover", joined)
	if err != nil {
		return results
	}
	for _, raw := range rawResults {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			continue
		}
		sub, _ := parsed["subdomain"].(string)
		if sub == "" {
			continue
		}
		status, _ := parsed["status"].(string)
		if status == "vulnerable" {
			detail, _ := parsed["detail"].(string)
			platform, _ := parsed["platform"].(string)
			results[sub] = fmt.Sprintf("%s: %s", platform, detail)
		}
	}
	return results
}

var (
	linuxBridgeOnce sync.Once
	linuxBridgeErr  error
)

func ensureRustBinaries() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("not Linux")
	}
	linuxBridgeOnce.Do(func() {
		bins := []string{"subdomain_resolver", "subdomain_osint", "subdomain_takeover"}
		for _, b := range bins {
			p := getRustBinPath(b)
			if p == "" {
				linuxBridgeErr = fmt.Errorf("empty path for %s", b)
				return
			}
		}
	})
	return linuxBridgeErr
}
