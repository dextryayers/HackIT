package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	rustLib                    = syscall.NewLazyDLL("rust_port_scanner.dll")
	rustUltimateMassScan       = rustLib.NewProc("rust_ultimate_mass_scan")
	rustFreeMassScanReport     = rustLib.NewProc("rust_free_mass_scan_report")
	rustFastScan               = rustLib.NewProc("rust_fast_scan")
	rustFreeScanResult         = rustLib.NewProc("rust_free_scan_result")
	rustDetectOS               = rustLib.NewProc("rust_detect_os")
	rustFreeOSInfo             = rustLib.NewProc("rust_free_os_info")
	rustFirewallBypassCheck    = rustLib.NewProc("rust_firewall_bypass_check")
	rustFreeFirewallResult     = rustLib.NewProc("rust_free_firewall_result")
	rustGetNetworkIntel        = rustLib.NewProc("rust_get_network_intel")
	rustFreeNetworkIntel       = rustLib.NewProc("rust_free_network_intel")
	procRustFingerprintService = rustLib.NewProc("rust_fingerprint_service")
	procRustExtractVersion     = rustLib.NewProc("rust_extract_version")
	rustDetectOsDetailed       = rustLib.NewProc("rust_os_detect")
	rustGatherIpInfo           = rustLib.NewProc("rust_gather_ip_info")
	procRustCheckVulnerabilities = rustLib.NewProc("rust_check_vulnerabilities")
	rustPerformDeepScan         = rustLib.NewProc("rust_perform_deep_scan")
)

type RustOSResult struct {
	Name     *byte
	Version  *byte
	Family   *byte
	Accuracy int32
	TTL      int32
	Window   int32
	Evidence *byte
}

type RustMassScanReport struct {
	Results      *RustScanResult
	Count        uintptr
	TotalScanned uintptr
}

func RustMassScan(host string, ports []int, threads int, timeoutMs int, stealth bool) []PortResult {
	cHost := []byte(host + "\x00")
	cPorts := make([]int32, len(ports))
	for i, p := range ports {
		cPorts[i] = int32(p)
	}

	isStealth := 0
	if stealth {
		isStealth = 1
	}

	ret, _, _ := rustUltimateMassScan.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
		uintptr(unsafe.Pointer(&cPorts[0])),
		uintptr(len(ports)),
		uintptr(threads),
		uintptr(timeoutMs),
		uintptr(isStealth),
	)

	if ret == 0 {
		return nil
	}

	report := (*RustMassScanReport)(unsafe.Pointer(ret))
	defer rustFreeMassScanReport.Call(ret)

	var results []PortResult
	if report.Count > 0 {
		// Convert C array to Go slice
		resSlice := (*[1 << 30]RustScanResult)(unsafe.Pointer(report.Results))[:report.Count:report.Count]

		for _, r := range resSlice {
			results = append(results, PortResult{
				Port:    int(r.Port),
				State:   goString(r.State),
				Service: strings.ToUpper(goString(r.Service)),
				Banner:  goString(r.Banner),
				Version: goString(r.Version),
			})
		}
	}

	return results
}

type RustScanResult struct {
	Port    int32
	State   *byte
	Service *byte
	Banner  *byte
	Version *byte
}

type RustFirewallResult struct {
	IsFiltered   bool
	BypassMethod *byte
	Confidence   int32
}

type RustNetworkIntelResult struct {
	DNSResolved *byte
	WhoisInfo   *byte
	GeoLocation *byte
	ASNInfo     *byte
}

func RustFastScan(host string, port int, timeoutMs int, stealth bool) PortResult {
	cHost := []byte(host + "\x00")
	isStealth := 0
	if stealth {
		isStealth = 1
	}

	ret, _, _ := rustFastScan.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
		uintptr(port),
		uintptr(timeoutMs),
		uintptr(isStealth),
	)

	if ret == 0 {
		return PortResult{Port: port, State: "error"}
	}

	res := (*RustScanResult)(unsafe.Pointer(ret))
	defer rustFreeScanResult.Call(ret)

	return PortResult{
		Port:    int(res.Port),
		State:   goString(res.State),
		Service: strings.ToUpper(goString(res.Service)),
		Banner:  goString(res.Banner),
		Version: goString(res.Version),
	}
}

func RustDetectOS(host string) OSInfo {
	cHost := []byte(host + "\x00")
	ret, _, _ := rustDetectOS.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
	)

	if ret == 0 {
		return OSInfo{Name: "Unknown", Accuracy: 0}
	}

	res := (*RustOSResult)(unsafe.Pointer(ret))
	defer rustFreeOSInfo.Call(ret)

	os := OSInfo{
		Name:     goString(res.Name),
		Version:  goString(res.Version),
		Family:   goString(res.Family),
		Accuracy: int(res.Accuracy),
	}
	// Extended fields
	os.TTL = int(res.TTL)
	os.Window = int(res.Window)
	if ev := goString(res.Evidence); ev != "" {
		os.Fingerprint = ev
	}
	return os
}

func RustFirewallBypass(host string, port int) (string, int) {
	cHost := []byte(host + "\x00")
	ret, _, _ := rustFirewallBypassCheck.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
		uintptr(port),
	)

	if ret == 0 {
		return "None", 0
	}

	res := (*RustFirewallResult)(unsafe.Pointer(ret))
	defer rustFreeFirewallResult.Call(ret)

	return goString(res.BypassMethod), int(res.Confidence)
}

func RustFingerprintService(banner string) string {
	cBanner := []byte(banner + "\x00")
	ret, _, _ := procRustFingerprintService.Call(
		uintptr(unsafe.Pointer(&cBanner[0])),
	)
	if ret == 0 {
		return "UNKNOWN"
	}
	// Note: We should ideally free the string from Rust, but for simplicity here:
	return goString((*byte)(unsafe.Pointer(ret)))
}

func RustExtractVersion(banner string, service string) string {
	cBanner := []byte(banner + "\x00")
	cService := []byte(service + "\x00")
	ret, _, _ := procRustExtractVersion.Call(
		uintptr(unsafe.Pointer(&cBanner[0])),
		uintptr(unsafe.Pointer(&cService[0])),
	)
	if ret == 0 {
		return ""
	}
	return goString((*byte)(unsafe.Pointer(ret)))
}

func RustGetNetworkIntelAdvanced(host string) IntelInfo {
	cHost := []byte(host + "\x00")
	ret, _, _ := rustGetNetworkIntel.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
	)

	if ret == 0 {
		return IntelInfo{}
	}

	res := (*RustNetworkIntelResult)(unsafe.Pointer(ret))
	defer rustFreeNetworkIntel.Call(ret)

	return IntelInfo{
		DNS:     []string{goString(res.DNSResolved)},
		Reverse: goString(res.DNSResolved),
		WHOIS:   goString(res.WhoisInfo),
		Geo:     goString(res.GeoLocation),
		ASN:     goString(res.ASNInfo),
	}
}

func goString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var s []byte
	for {
		b := *ptr
		if b == 0 {
			break
		}
		s = append(s, b)
		ptr = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1))
	}
	return string(s)
}

// RustDetectOsDetailed calls the Rust engine for detailed OS detection with IP information
func RustDetectOsDetailed(host string, openPorts string) string {
	cHost := []byte(host + "\x00")
	cPorts := []byte(openPorts + "\x00")

	ret, _, _ := rustDetectOsDetailed.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
		uintptr(unsafe.Pointer(&cPorts[0])),
	)

	if ret == 0 {
		return ""
	}

	resultPtr := (*byte)(unsafe.Pointer(ret))
	result := goString(resultPtr)

	return result
}

// RustGatherIpInfo calls the Rust engine to gather IP information
func RustGatherIpInfo(host string) string {
	cHost := []byte(host + "\x00")

	ret, _, _ := rustGatherIpInfo.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
	)

	if ret == 0 {
		return ""
	}

	resultPtr := (*byte)(unsafe.Pointer(ret))
	result := goString(resultPtr)

	return result
}
// RustCheckVulnerabilities calls the Rust engine to check for potential vulnerabilities
func RustCheckVulnerabilities(host string, port int, service string, banner string) []string {
	var vulns []string

	// 1. Check explicit vulnerability signatures via Rust FFI
	cBanner := []byte(banner + "\x00")
	ret, _, _ := procRustCheckVulnerabilities.Call(uintptr(unsafe.Pointer(&cBanner[0])))
	if ret != 0 {
		rustVulnsRaw := goString((*byte)(unsafe.Pointer(ret)))
		if rustVulnsRaw != "" {
			parts := strings.Split(rustVulnsRaw, "|")
			vulns = append(vulns, parts...)
		}
	}

	// 2. Secondary check via detailed OS detection context
	openPortsStr := fmt.Sprintf("%d", port)
	detailedInfo := RustDetectOsDetailed(host, openPortsStr)
	
	if detailedInfo != "" {
		if strings.Contains(strings.ToLower(detailedInfo), "outdated") || 
		   strings.Contains(strings.ToLower(detailedInfo), "vulnerable") {
			vulns = append(vulns, "RUST_CONTEXT: Intelligence suggests infrastructure risk")
		}
	}

	return vulns
}

// RustPerformDeepScan calls the Rust engine for extremely deep vulnerability analysis
func RustPerformDeepScan(host string, port int, banner string) string {
	cHost := []byte(host + "\x00")
	cBanner := []byte(banner + "\x00")

	ret, _, _ := rustPerformDeepScan.Call(
		uintptr(unsafe.Pointer(&cHost[0])),
		uintptr(port),
		uintptr(unsafe.Pointer(&cBanner[0])),
	)

	if ret == 0 {
		return ""
	}

	resultPtr := (*byte)(unsafe.Pointer(ret))
	result := goString(resultPtr)

	return result
}
