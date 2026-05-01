package main

/*
#cgo LDFLAGS: -L./rust_engine/target/release -lrust_port_scanner
#cgo CFLAGS: -I./rust_engine/target/release
#include <stdlib.h>

typedef void* ProbesHandle;

extern ProbesHandle rust_load_probes_dir(const char* path);
extern void rust_free_probes_handle(ProbesHandle handle);
extern char* rust_probe_port_json(const char* host, unsigned short port, ProbesHandle handle, unsigned long timeout_ms);
extern char* rust_probe_ports_json(const char* host, const unsigned short* ports, size_t ports_count, ProbesHandle handle, unsigned long timeout_ms);
extern void rust_free_cstring(char* s);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

type ProbeObservation struct {
	ProbeID           string `json:"probe_id"`
	Port              uint16 `json:"port"`
	Protocol          string `json:"protocol"`
	Success           bool   `json:"success"`
	RttMs             uint64 `json:"rtt_ms"`
	ResponseSampleB64 string `json:"response_sample_b64"`
}

type FingerprintHit struct {
	Label      string            `json:"label"`
	Score      float64           `json:"score"`
	Confidence float64           `json:"confidence"`
	Metadata   map[string]string `json:"metadata"`
}

type PortProbeReport struct {
	Port         uint16             `json:"port"`
	Observations []ProbeObservation `json:"observations"`
	Hits         []FingerprintHit   `json:"hits"`
}

type RustProbeAdapter struct {
	handle C.ProbesHandle
}

func NewRustProbeAdapter(probePath string) (*RustProbeAdapter, error) {
	cPath := C.CString(probePath)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.rust_load_probes_dir(cPath)
	if handle == nil {
		return nil, fmt.Errorf("failed to load probes from %s", probePath)
	}

	return &RustProbeAdapter{handle: handle}, nil
}

func (a *RustProbeAdapter) Close() {
	if a.handle != nil {
		C.rust_free_probes_handle(a.handle)
		a.handle = nil
	}
}

func (a *RustProbeAdapter) ProbePort(host string, port uint16, timeoutMs uint64) (*PortProbeReport, error) {
	if a.handle == nil {
		return nil, fmt.Errorf("adapter not initialized")
	}

	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	result := C.rust_probe_port_json(cHost, C.ushort(port), a.handle, C.ulong(timeoutMs))
	if result == nil {
		return nil, fmt.Errorf("probe failed")
	}
	defer C.rust_free_cstring(result)

	jsonStr := C.GoString(result)
	var report PortProbeReport
	if err := json.Unmarshal([]byte(jsonStr), &report); err != nil {
		return nil, fmt.Errorf("failed to parse result: %v", err)
	}

	return &report, nil
}

func (a *RustProbeAdapter) ProbePorts(host string, ports []uint16, timeoutMs uint64) ([]PortProbeReport, error) {
	if a.handle == nil {
		return nil, fmt.Errorf("adapter not initialized")
	}

	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	cPorts := (*C.ushort)(unsafe.Pointer(&ports[0]))
	result := C.rust_probe_ports_json(cHost, cPorts, C.size_t(len(ports)), a.handle, C.ulong(timeoutMs))
	if result == nil {
		return nil, fmt.Errorf("probe failed")
	}
	defer C.rust_free_cstring(result)

	jsonStr := C.GoString(result)
	var reports []PortProbeReport
	if err := json.Unmarshal([]byte(jsonStr), &reports); err != nil {
		return nil, fmt.Errorf("failed to parse result: %v", err)
	}

	return reports, nil
}

func FindProbesDir() string {
	searchPaths := []string{
		"rust_engine/probes",
		"../rust_engine/probes",
		"../go/rust_engine/probes",
		"probes",
	}

	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}

	return ""
}

func ProbeWithRust(host string, ports []uint16, timeoutMs uint64) ([]PortProbeReport, error) {
	probesDir := FindProbesDir()
	if probesDir == "" {
		return nil, fmt.Errorf("probes directory not found")
	}

	adapter, err := NewRustProbeAdapter(probesDir)
	if err != nil {
		return nil, err
	}
	defer adapter.Close()

	if len(ports) == 1 {
		report, err := adapter.ProbePort(host, ports[0], timeoutMs)
		if err != nil {
			return nil, err
		}
		return []PortProbeReport{*report}, nil
	}

	return adapter.ProbePorts(host, ports, timeoutMs)
}
