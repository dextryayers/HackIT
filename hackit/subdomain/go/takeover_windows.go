//go:build windows

package main

import "syscall"

func init() {
	rustLib := syscall.NewLazyDLL("rust_engine/target/release/subdomain_rust_engine.dll")
	rustCheckSubTakeover = rustLib.NewProc("rust_check_subdomain_takeover")
	rustResolveDNS = rustLib.NewProc("rust_resolve_dns")
	rustResolveDNSBatch = rustLib.NewProc("rust_resolve_dns_batch")
	rustOSINTScan = rustLib.NewProc("rust_osint_scan")
	rustGetTitle = rustLib.NewProc("rust_get_title")
	rustGetCname = rustLib.NewProc("rust_get_cname")
}
