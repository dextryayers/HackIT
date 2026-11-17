# HackIT Wireless - WiFi audit console

Interactive console for authorized wireless assessments of networks you own
or may test in writing. Not a background service; it is an operator shell
(`start_wireless_console()`) with explicit per-command invocation.

## Command entry

```bash
hackit wireless        # interactive console
```

The console is a `cmd.Cmd` shell (`console.py`) with banner, interface
detection and a command grammar (`_parse_flags`). It orchestrates native
engines and Python coordinators.

## Components

- `engine_bridge.py` - build/lookup of native engines with clear errors
  (`EngineBuildError`) if toolchains are missing
- `c_core/`, `cpp_core/`, `csharp_core/`, `rust_engine/`, `go_workers/` -
  candidate native engines for capture, injection and analysis
- `deauth_coordinator.py`, `eviltwin_coordinator.py`, `captive_portal.py` -
  scripted attack flows for authorized lab use
- `data_parser.py`, `oui_db.py` - packet/ oui lookups and parsing helpers
- `ui_renderer.py`, `ui_renderer` - Rich-based rendering
- `weblocal/` - local web surface (if built)
- `hackit_wireless.log` - runtime log
- `plugins/` - pluggable checks

## What it is for

Authorized wireless testing on equipment you control: verifying encryption
posture (WPA2/3), captive portal behaviour, handshake capture and verification (lab use),
client isolation, rogue AP detection, and reporting.

It is not a tool for testing networks you do not own. The console exists to
make wireless assessment deliberate, not automatic: every action is invoked
explicitly and logged.

Authorized testing only. Wireless attacks against networks you do not own are
illegal in most jurisdictions.

## Verified crypto engines (v2)

All native engines build with **0 errors / 0 warnings** (C core, C++ core,
Rust, Go, C#). The cryptographic primitives are verified against published
test vectors, not just round-tripped:

- **AES-128/192/256** — FIPS-197 block vectors (CPU-independent paths checked)
- **AES key wrap/unwrap** — RFC 3394 §4.1 vector (`1fa68b0a8112b447...`)
- **WPA PBKDF2-SHA1 (4096 iters)** — canonical WPA reference vector
  (`password`/`IEEE` → `f42c6fc52df0ebef9ebb4b90b38a5f90...`) in both Rust
  and Go
- **WPS Pixie Dust** — native DH → DHKey → KDK → RFC 3394 unwrap → PSK
  (`wps_engine.py` + C++ `wps_aes_unwrap`); PIN derivation consistent across
  Python / C++ / Rust (first-5-bytes big-endian + ×3 check digit)
- **WEP** — real FMS / PTW / Korek (RC4 KSA, weak-IV classes, keystream
  recovery); 44 Rust unit tests pass
- **WPA3 → WPA2 downgrade** — RSN-IE forge (WPA2-PSK/CCMP, PMF-required
  cleared) + AF_PACKET injector, byte-identical across C++ / Go / Rust / C#

### New / changed commands

```
wpa3-detect   <iface>                          # find WPA3/SAE APs via RSN IE
wpa3-downgrade <iface> <bssid> <ssid> [opts]   # force WPA2 transition for capture
wep-crack     -f <capture> [-a auto|fms|ptw|korek]
wep-replay    -i <iface> -b <bssid>            # IV harvesting guidance
wps pixie     <iface> <bssid> [--es1 --es2 --pke --pkr ...]  # native derivation
```

### Build

```bash
make -C c_core -j                 # libhackit_wireless_c.so (includes C++ wpa3 + AES)
cargo build --release             # rust_engine/target/release/hackit_wireless_engine
go build -o hackit-worker .       # go_workers/
dotnet build -c Release           # csharp_core/  (needs /opt/dotnet)
```

`engine_bridge.py` reports `engine_health()` for all five backends and loads
the C library via `ctypes` (ABI-stable C API; C++ symbols are `extern "C"`).
