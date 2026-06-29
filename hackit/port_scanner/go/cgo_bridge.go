package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

typedef int (*dispatch_fn)(const char*, int, char**);

static dispatch_fn load_dispatch(const char* lib_path, const char* fn_name) {
    void* handle = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return NULL;
    dispatch_fn fn = (dispatch_fn)dlsym(handle, fn_name);
    return fn;
}

static int call_dispatch(dispatch_fn fn, const char* scanner_name, int argc, char** argv) {
    if (!fn) return -1;
    return fn(scanner_name, argc, argv);
}
*/
import "C"
import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"
)

type CgoEngine struct {
	mu       sync.Mutex
	cLib     unsafe.Pointer
	cppLib   unsafe.Pointer
	cDisp    C.dispatch_fn
	cppDisp  C.dispatch_fn
	loaded   bool
}

var globalCgo *CgoEngine

func GetCgoEngine() *CgoEngine {
	if globalCgo == nil {
		globalCgo = &CgoEngine{}
		globalCgo.load()
	}
	return globalCgo
}

func (e *CgoEngine) load() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.loaded {
		return
	}

	baseDir := findSoDir()
	cPath := filepath.Join(baseDir, "libportstorm_c.so")
	cppPath := filepath.Join(baseDir, "libportstorm_cpp.so")

	if _, err := os.Stat(cPath); err == nil {
		cStr := C.CString(cPath)
		dispStr := C.CString("portstorm_c_dispatch")
		e.cDisp = C.load_dispatch(cStr, dispStr)
		C.free(unsafe.Pointer(cStr))
		C.free(unsafe.Pointer(dispStr))
		if e.cDisp != nil {
			fmt.Fprintf(os.Stderr, "[cgo] Loaded libportstorm_c.so\n")
		}
	}

	if _, err := os.Stat(cppPath); err == nil {
		cStr := C.CString(cppPath)
		dispStr := C.CString("portstorm_cpp_dispatch")
		e.cppDisp = C.load_dispatch(cStr, dispStr)
		C.free(unsafe.Pointer(cStr))
		C.free(unsafe.Pointer(dispStr))
		if e.cppDisp != nil {
			fmt.Fprintf(os.Stderr, "[cgo] Loaded libportstorm_cpp.so\n")
		}
	}

	e.loaded = true
}

func findSoDir() string {
	exe, _ := os.Executable()
	base := filepath.Dir(exe)
	candidates := []string{
		base,
		filepath.Join(base, ".."),
		filepath.Join(base, "..", "c"),
		".",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return base
}

func (e *CgoEngine) CallCScanner(scannerName string, args []string) int {
	e.mu.Lock()
	fn := e.cDisp
	e.mu.Unlock()
	if fn == nil {
		return -1
	}
	return e.call(fn, scannerName, args)
}

func (e *CgoEngine) CallCppScanner(scannerName string, args []string) int {
	e.mu.Lock()
	fn := e.cppDisp
	e.mu.Unlock()
	if fn == nil {
		return -1
	}
	return e.call(fn, scannerName, args)
}

func (e *CgoEngine) call(fn C.dispatch_fn, name string, args []string) int {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	argc := len(args) + 1
	argv := make([]*C.char, argc)
	argv[0] = C.CString(name)
	for i, a := range args {
		argv[i+1] = C.CString(a)
	}
	defer func() {
		for _, p := range argv {
			C.free(unsafe.Pointer(p))
		}
	}()

	return int(C.call_dispatch(fn, cname, C.int(argc), &argv[0]))
}

func (e *CgoEngine) IsCAvailable() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cDisp != nil
}

func (e *CgoEngine) IsCppAvailable() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cppDisp != nil
}
