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
