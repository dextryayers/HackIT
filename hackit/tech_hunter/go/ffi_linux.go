//go:build linux

package main

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>

typedef void* (*fn0_t)(void);
typedef void* (*fn1_t)(uintptr_t);
typedef void* (*fn2_t)(uintptr_t, uintptr_t);
typedef void* (*fn3_t)(uintptr_t, uintptr_t, uintptr_t);

uintptr_t call_fn_0(void* fn) {
	if (!fn) return 0;
	return (uintptr_t)((fn0_t)fn)();
}
uintptr_t call_fn_1(void* fn, uintptr_t a1) {
	if (!fn) return 0;
	return (uintptr_t)((fn1_t)fn)(a1);
}
uintptr_t call_fn_2(void* fn, uintptr_t a1, uintptr_t a2) {
	if (!fn) return 0;
	return (uintptr_t)((fn2_t)fn)(a1, a2);
}
uintptr_t call_fn_3(void* fn, uintptr_t a1, uintptr_t a2, uintptr_t a3) {
	if (!fn) return 0;
	return (uintptr_t)((fn3_t)fn)(a1, a2, a3);
}

double call_fn_1_double(void* fn, uintptr_t a1) {
	if (!fn) return 0.0;
	return ((double (*)(uintptr_t))fn)(a1);
}
*/
import "C"
import (
	"path/filepath"
	"sync"
	"unsafe"
)

type ffiProc struct {
	addr unsafe.Pointer
}

func (p ffiProc) Call(args ...uintptr) (uintptr, uintptr, error) {
	if p.addr == nil {
		return 0, 0, nil
	}
	var ret uintptr
	switch len(args) {
	case 0:
		ret = uintptr(C.call_fn_0(p.addr))
	case 1:
		ret = uintptr(C.call_fn_1(p.addr, C.uintptr_t(args[0])))
	case 2:
		ret = uintptr(C.call_fn_2(p.addr, C.uintptr_t(args[0]), C.uintptr_t(args[1])))
	case 3:
		ret = uintptr(C.call_fn_3(p.addr, C.uintptr_t(args[0]), C.uintptr_t(args[1]), C.uintptr_t(args[2])))
	default:
		return 0, 0, nil
	}
	return ret, 0, nil
}

type entropyProc struct {
	addr unsafe.Pointer
}

func (e entropyProc) Call(args ...uintptr) (uintptr, uintptr, error) {
	if e.addr == nil || len(args) != 1 {
		return 0, 0, nil
	}
	ret := C.call_fn_1_double(e.addr, C.uintptr_t(args[0]))
	return *(*uintptr)(unsafe.Pointer(&ret)), 0, nil
}

func dlopen(path string) unsafe.Pointer {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	return C.dlopen(cpath, C.RTLD_LAZY|C.RTLD_GLOBAL)
}

func dlsym(handle unsafe.Pointer, name string) unsafe.Pointer {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return C.dlsym(handle, cname)
}

func rustSym(symbol string) ffiProc {
	path := filepath.Join(techHunterHome, "rust_engine/target/release/libtech_hunter_rust.so")
	h := dlopen(path)
	if h == nil {
		return ffiProc{nil}
	}
	return ffiProc{dlsym(h, symbol)}
}

func cppSym(libname, symbol string) ffiProc {
	path := filepath.Join(cppPath, libname+".so")
	h := dlopen(path)
	if h == nil {
		return ffiProc{nil}
	}
	return ffiProc{dlsym(h, symbol)}
}

func cSym(libname, symbol string) ffiProc {
	path := filepath.Join(cPath, libname+".so")
	h := dlopen(path)
	if h == nil {
		return ffiProc{nil}
	}
	return ffiProc{dlsym(h, symbol)}
}

var (
	ffiOnce sync.Once

	techHunterHome string
	cppPath        string
	cPath          string
	rubyPath       string
	luaPath        string
	libExt         string

	fetchUrl       procCaller
	freeStr        procCaller
	fetchDNSHist   procCaller
	freeDNSHistStr procCaller
	detectWAFProc  procCaller
	freeWAFStr     procCaller
	fingerprintApp procCaller
	freeFingerStr  procCaller
	scanTechStack  procCaller
	freeTechStr    procCaller

	analyzeSec    procCaller
	freeForensics procCaller
	deepScanProc  procCaller
	freeDeepStr   procCaller
	matchVuln     procCaller
	runTraceroute procCaller
	freeInfraStr  procCaller
	identifySvc   procCaller
	freeSvcStr    procCaller
	scanEndpoints procCaller
	freeEndStr    procCaller
	checkSSLVulns procCaller
	freeSSLVulns  procCaller

	checkAnom       procCaller
	freeAnomStr     procCaller
	calcEntropy     procCaller
	auditProtocols  procCaller
	freeProtoStr    procCaller
	analyzeTCP      procCaller
	freeTCPStr      procCaller
	checkTPProc     procCaller
	freeTPStr       procCaller
	analyzeSessProc procCaller
	freeSessStr     procCaller
)

func initFFI() {
	techHunterHome = getTechHunterRoot()
	cppPath = filepath.Join(techHunterHome, "cpp")
	cPath = filepath.Join(techHunterHome, "c")
	rubyPath = filepath.Join(techHunterHome, "ruby")
	luaPath = filepath.Join(techHunterHome, "lua")
	libExt = ".so"

	fetchUrl = rustSym("rust_fetch_url")
	freeStr = rustSym("free_rust_string")
	fetchDNSHist = rustSym("fetch_dns_history")
	freeDNSHistStr = rustSym("free_dns_history_string")
	detectWAFProc = rustSym("detect_waf")
	freeWAFStr = rustSym("free_waf_string")
	fingerprintApp = rustSym("fingerprint_web_app")
	freeFingerStr = rustSym("free_fingerprint_string")
	scanTechStack = rustSym("scan_tech_stack")
	freeTechStr = rustSym("free_tech_string")

	analyzeSec = cppSym("forensics", "analyze_security_forensics")
	freeForensics = cppSym("forensics", "free_forensics_string")
	deepScanProc = cppSym("deep_scanner", "deep_payload_scan")
	freeDeepStr = cppSym("deep_scanner", "free_deep_scan_string")
	matchVuln = cppSym("vulnerability_matcher", "match_vulnerabilities")
	runTraceroute = cppSym("infra_forensics", "run_traceroute")
	freeInfraStr = cppSym("infra_forensics", "free_infra_string")
	identifySvc = cppSym("service_fingerprinter", "identify_service")
	freeSvcStr = cppSym("service_fingerprinter", "free_service_string")
	scanEndpoints = cppSym("endpoint_forensics", "scan_endpoints")
	freeEndStr = cppSym("endpoint_forensics", "free_endpoint_string")
	checkSSLVulns = cppSym("ssl_vulns", "check_ssl_vulnerabilities")
	freeSSLVulns = cppSym("ssl_vulns", "free_ssl_vulns_string")

	checkAnom = cSym("low_level", "check_header_anomalies")
	freeAnomStr = cSym("low_level", "free_low_level_string")
	calcEntropy = entropyProc{cSym("entropy", "calculate_payload_entropy").addr}
	auditProtocols = cSym("proto_check", "audit_tls_protocols")
	freeProtoStr = cSym("proto_check", "free_proto_string")
	analyzeTCP = cSym("tcp_forensics", "analyze_tcp_sequence")
	freeTCPStr = cSym("tcp_forensics", "free_tcp_string")
	checkTPProc = cSym("third_party_mapper", "check_third_party")
	freeTPStr = cSym("third_party_mapper", "free_tp_string")
	analyzeSessProc = cSym("session_analyzer", "analyze_session")
	freeSessStr = cSym("session_analyzer", "free_session_string")
}

func ensureFFI() {
	ffiOnce.Do(initFFI)
}
