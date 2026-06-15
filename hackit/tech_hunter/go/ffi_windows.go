//go:build windows

package main

import (
	"path/filepath"
	"syscall"
)

var (
	techHunterHome = getTechHunterRoot()
	cppPath        = filepath.Join(techHunterHome, "cpp")
	cPath          = filepath.Join(techHunterHome, "c")
	rubyPath       = filepath.Join(techHunterHome, "ruby")
	luaPath        = filepath.Join(techHunterHome, "lua")
	libExt         = ".dll"

	rustDLL       = syscall.NewLazyDLL(filepath.Join(techHunterHome, "rust_engine/target/release/tech_hunter_rust.dll"))
	fetchUrl      procCaller = rustDLL.NewProc("rust_fetch_url")
	freeStr       procCaller = rustDLL.NewProc("free_rust_string")
	fetchDNSHist  procCaller = rustDLL.NewProc("fetch_dns_history")
	freeDNSHistStr procCaller = rustDLL.NewProc("free_dns_history_string")
	detectWAFProc procCaller = rustDLL.NewProc("detect_waf")
	freeWAFStr    procCaller = rustDLL.NewProc("free_waf_string")
	fingerprintApp  procCaller = rustDLL.NewProc("fingerprint_web_app")
	freeFingerStr   procCaller = rustDLL.NewProc("free_fingerprint_string")
	scanTechStack   procCaller = rustDLL.NewProc("scan_tech_stack")
	freeTechStr     procCaller = rustDLL.NewProc("free_tech_string")

	cppDLL        = syscall.NewLazyDLL(filepath.Join(cppPath, "forensics.dll"))
	analyzeSec    procCaller = cppDLL.NewProc("analyze_security_forensics")
	freeForensics procCaller = cppDLL.NewProc("free_forensics_string")

	deepScannerDLL  = syscall.NewLazyDLL(filepath.Join(cppPath, "deep_scanner.dll"))
	deepScanProc   procCaller = deepScannerDLL.NewProc("deep_payload_scan")

	lowLevelDLL = syscall.NewLazyDLL(filepath.Join(cPath, "low_level.dll"))
	checkAnom   procCaller = lowLevelDLL.NewProc("check_header_anomalies")

	entropyDLL  = syscall.NewLazyDLL(filepath.Join(cPath, "entropy.dll"))
	calcEntropy procCaller = entropyDLL.NewProc("calculate_payload_entropy")

	vulnMatchDLL = syscall.NewLazyDLL(filepath.Join(cppPath, "vulnerability_matcher.dll"))
	matchVuln    procCaller = vulnMatchDLL.NewProc("match_vulnerabilities")

	sslVulnDLL    = syscall.NewLazyDLL(filepath.Join(cppPath, "ssl_vulns.dll"))
	checkSSLVulns procCaller = sslVulnDLL.NewProc("check_ssl_vulnerabilities")
	freeSSLVulns  procCaller = sslVulnDLL.NewProc("free_ssl_vulns_string")

	protoCheckDLL  = syscall.NewLazyDLL(filepath.Join(cPath, "proto_check.dll"))
	auditProtocols procCaller = protoCheckDLL.NewProc("audit_tls_protocols")
	freeProtoStr   procCaller = protoCheckDLL.NewProc("free_proto_string")

	infraDLL      = syscall.NewLazyDLL(filepath.Join(cppPath, "infra_forensics.dll"))
	runTraceroute procCaller = infraDLL.NewProc("run_traceroute")
	freeInfraStr  procCaller = infraDLL.NewProc("free_infra_string")

	tcpDLL      = syscall.NewLazyDLL(filepath.Join(cPath, "tcp_forensics.dll"))
	analyzeTCP  procCaller = tcpDLL.NewProc("analyze_tcp_sequence")
	freeTCPStr  procCaller = tcpDLL.NewProc("free_tcp_string")

	serviceDLL  = syscall.NewLazyDLL(filepath.Join(cppPath, "service_fingerprinter.dll"))
	identifySvc procCaller = serviceDLL.NewProc("identify_service")
	freeSvcStr  procCaller = serviceDLL.NewProc("free_service_string")

	endpointDLL   = syscall.NewLazyDLL(filepath.Join(cppPath, "endpoint_forensics.dll"))
	scanEndpoints procCaller = endpointDLL.NewProc("scan_endpoints")
	freeEndStr    procCaller = endpointDLL.NewProc("free_endpoint_string")

	tpDLL       = syscall.NewLazyDLL(filepath.Join(cPath, "third_party_mapper.dll"))
	checkTPProc procCaller = tpDLL.NewProc("check_third_party")
	freeTPStr   procCaller = tpDLL.NewProc("free_tp_string")

	sessionDLL      = syscall.NewLazyDLL(filepath.Join(cPath, "session_analyzer.dll"))
	analyzeSessProc procCaller = sessionDLL.NewProc("analyze_session")
	freeSessStr     procCaller = sessionDLL.NewProc("free_session_string")
)
