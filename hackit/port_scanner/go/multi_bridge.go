//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	cLib             = syscall.NewLazyDLL("os_detect.dll")
	cDetectOsDetailed = cLib.NewProc("c_get_detailed_os_ip_info")

	cppLib        = syscall.NewLazyDLL("advanced_scanner.dll")
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

// RubyScanPorts calls the Ruby engine for scripted reconnaissance
func RubyScanPorts(host string, ports []int, mode string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	portsStr := ""
	for i, p := range ports {
		if i > 0 { portsStr += "," }
		portsStr += fmt.Sprintf("%d", p)
	}

	script := "engine.rb"
	if mode == "vhost" {
		script = "vhost_discovery.rb"
	} else if mode == "api" {
		script = "api_endpoint_finder.rb"
	} else if mode == "ssl" {
		script = "ssl_analyzer.rb"
	}

	cmd := exec.CommandContext(ctx, "ruby", "../ruby/"+script, host, portsStr, mode)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "Error: Tactical timeout exceeded"
		}
		return fmt.Sprintf("Error: %v", err)
	}

	return strings.TrimSpace(string(out))
}

// MultiEngineOrchestrator is now defined in engine.go — removed from here to avoid redeclaration.
