package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
	"strings"
	"syscall"
	"unsafe"
)

var (
	cLib   = syscall.NewLazyDLL("os_detect.dll")
	cDetectOsDetailed = cLib.NewProc("c_get_detailed_os_ip_info")
	
	cppLib = syscall.NewLazyDLL("advanced_scanner.dll")
	cppScanService = cppLib.NewProc("cpp_scan_service")
	cppFreeResult  = cppLib.NewProc("cpp_free_service_result")
)

type CppServiceResult struct {
	Banner  *byte
	Service *byte
	Version *byte
	Port    int32
}

// CExpertDetectOs calls the C engine for deep OS fingerprinting
func CExpertDetectOs(host string, openPorts string, ttl int, window int) string {
	cHost := []byte(host + "\x00")
	cPorts := []byte(openPorts + "\x00")

	ret, _, _ := cDetectOsDetailed.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
		uintptr(unsafe.Pointer(&cPorts[0])),
		uintptr(ttl),
		uintptr(window),
	)

	if ret == 0 {
		return ""
	}

	return goString((*byte)(unsafe.Pointer(ret)))
}

// CppScanService calls the C++ engine for deep service auditing
func CppScanService(host string, port int, timeoutMs int) PortResult {
	cHost := []byte(host + "\x00")
	
	ret, _, _ := cppScanService.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
		uintptr(port),
		uintptr(timeoutMs),
	)

	if ret == 0 {
		return PortResult{Port: port, State: "error"}
	}

	res := (*CppServiceResult)(unsafe.Pointer(ret))
	defer cppFreeResult.Call(ret)

	return PortResult{
		Port:    int(res.Port),
		State:   "open",
		Service: goString(res.Service),
		Banner:  goString(res.Banner),
		Version: goString(res.Version),
	}
}

// RubyScanPorts calls the Ruby engine for scripted reconnaissance with a strict timeout
func RubyScanPorts(host string, ports []int, mode string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	portsStr := ""
	for i, p := range ports {
		if i > 0 { portsStr += "," }
		portsStr += fmt.Sprintf("%d", p)
	}

	// Determine which script to run based on mode
	script := "engine.rb"
	if mode == "vhost" {
		script = "vhost_discovery.rb"
	} else if mode == "api" {
		script = "api_endpoint_finder.rb"
	}

	cmd := exec.CommandContext(ctx, "ruby", "../ruby/"+script, host, portsStr, mode)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "Error: Tactical timeout exceeded"
		}
		return fmt.Sprintf("Error: %v", err)
	}

	return string(out)
}

// MultiEngineOrchestrator coordinates all engines for maximum precision
func (e *ScanEngine) MultiEngineOrchestrator(port int) PortResult {
	var res PortResult
	
	// Default to Rust for high-speed initial discovery
	res = RustFastScan(e.Host, port, e.TimeoutMs, e.Stealth)
	
	if res.State == "open" {
		// Use C++ for deep service auditing if initial engines were unsure
		if res.Service == "UNKNOWN" || res.Banner == "" || strings.Contains(res.Service, "unassigned") {
			cppRes := CppScanService(e.Host, port, 500) // Fast audit
			if cppRes.Service != "" && cppRes.Service != "UNKNOWN" {
				res.Service = cppRes.Service
				res.Banner = cppRes.Banner
				res.Version = cppRes.Version
			}
		}

		// INTEGRATION: Use Rust Probe Adapter for extremely detailed banners (Aggressive Timeout)
		if res.Banner == "" || res.Service == "UNKNOWN" || strings.Contains(res.Service, "unassigned") {
			reports, err := ProbeWithRust(e.Host, []uint16{uint16(port)}, 500)
			if err == nil && len(reports) > 0 {
				report := reports[0]
				if len(report.Hits) > 0 {
					res.Service = report.Hits[0].Label
					// Try to find a banner in observations
					for _, obs := range report.Observations {
						if obs.ResponseSampleB64 != "" {
							res.Banner = "[RUST-PROBE]: " + obs.ResponseSampleB64
							break
						}
					}
				}
			}
		}
		
		// Use Ruby for specific protocol scripts if needed
		if port == 80 || port == 443 || port == 8080 {
			// Ruby has great HTTP/SSL handling
			rubyData := RubyScanPorts(e.Host, []int{port}, "vhost")
			if !strings.Contains(rubyData, "Error") {
				res.DeepAnalysis += "\n[RUBY-VHOST]: " + rubyData
			}
			
			sslData := RubyScanPorts(e.Host, []int{port}, "ssl")
			if !strings.Contains(sslData, "Error") {
				res.DeepAnalysis += "\n[RUBY-SSL]: " + sslData
			}
		}
	}
	
	return res
}
