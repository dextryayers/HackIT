# AGENTS.md — HackIT Wireless Session

## Goal
Full evil twin attack suite: real AF_PACKET beacon injection + captive portal with fake login page. 12 new eviltwin engine files (3×C, 3×C++, 3×C#, 3×Rust) + Go + Python coordinator, all built 0 errors.

## Build Status
| Engine | Status |
|--------|--------|
| C/C++ `.so` + `.a` | ✅ 0 errors |
| C static binary `eviltwin-inject` | ✅ 0 errors |
| Rust `cargo check` | ✅ 0 errors |
| C# `dotnet build` | ✅ 0 errors 0 warnings |
| Go `go build` | ✅ 0 errors |
| Python coordinator + captive portal | ✅ Imports OK |

## Files Created/Modified — Eviltwin Session

### New engine files (12 + Go + Python)
| Engine | File(s) | Purpose |
|--------|---------|---------|
| C v1 | `src/eviltwin_v1.c/h` | Single-SSID beacon flood, `sendmmsg()` batched |
| C v2 | `src/eviltwin_v2.c/h` | Multi-SSID round-robin (BSSID generated from SSID hash) |
| C v3 | `src/eviltwin_v3.c/h` | Full eviltwin + shared memory stats for coordinator |
| C++ v1 | `src/eviltwin_cpp_v1.cpp/h` | Class `EviltwinBeaconV1`, OOP beacon flood |
| C++ v2 | `src/eviltwin_cpp_v2.cpp/h` | Class `EviltwinBeaconV2`, multi-SSID |
| C++ v3 | `src/eviltwin_cpp_v3.cpp/h` | Class `EviltwinFull`, writes config to `/tmp/eviltwin.json` |
| C# v1 | `EviltwinEngineV1.cs` | Thread-based beacon flood, raw AF_PACKET |
| C# v2 | `EviltwinEngineV2.cs` | Multi-SSID round-robin |
| C# v3 | `EviltwinEngineV3.cs` | Task-based async, writes JSON stats |
| Rust v1 | `src/eviltwin_v1.rs` | Single-SSID via `raw_injector::RawSocket` |
| Rust v2 | `src/eviltwin_v2.rs` | Multi-AP pair round-robin |
| Rust v3 | `src/eviltwin_v3.rs` | Same + writes `/tmp/eviltwin_v3.json` via serde |
| Go v1 | `eviltwin_v1.go` | AF_PACKET raw socket beacon flood |
| Go v2 | `eviltwin_v2.go` | Multi-SSID round-robin |
| Go v3 | `eviltwin_v3.go` | Same + JSON stats to `/tmp/eviltwin_go.json` |

### Infrastructure files
| File | Purpose |
|------|---------|
| `c_core/eviltwin-inject` | **Static C binary** for eviltwin beacon flood (called via sudo) |
| `captive_portal.py` | Full captive portal: DHCP server (UDP 67), DNS server (UDP 53), HTTP server (TCP 80), fake login page |
| `eviltwin_coordinator.py` | Python coordinator: launches injector binary + captive portal, monitors status, displays captured credentials |

### Modified files
| File | Change |
|------|--------|
| `console.py` | eviltwin: added `--sum` flag, updated help text, updated table entry |
| `executor.py` | `do_eviltwin`: uses `num_fake` param, launches `EviltwinCoordinator`, `do_eviltwin_multi` for `--sum` |
| `c_core/Makefile` | Added 6 new C/C++ source files + `eviltwin-inject` target |
| `rust_engine/src/main.rs` | Added `eviltwin_v1/2/3` modules + `Eviltwin` CLI command |
| `go_workers/main.go` | Added `eviltwin` subcommand (v1/v2/v3) |

### CLI Usage
```
eviltwin <iface> <ssid> [--channel 6] [--sum 3] [--captive]
```
- `--sum N` : create N fake SSIDs with auto-generated BSSIDs
- `--captive` : start DHCP + DNS + HTTP fake login portal
- Captured passwords saved to `/tmp/eviltwin_creds.txt`

## Key Architecture
- **EviltwinInjector** (`c_core/eviltwin-inject`): standalone static C binary, called via sudo from Python
- **CaptivePortal** (`captive_portal.py`): DHCP assigns IPs, DNS redirects all to our IP, HTTP serves fake login
- **EviltwinCoordinator** (`eviltwin_coordinator.py`): orchestrates injector + portal, monitors credentials
- **Engine files**: each language implements the beacon frame building + raw socket injection; used via Python bridge

## Pre-existing Limitations
- Raw AF_PACKET sockets need `CAP_NET_RAW` or root — `eviltwin-inject` binary must run with sudo
- Rust binary link: `libpcap-dev` not installed — use `cargo check` for verification
