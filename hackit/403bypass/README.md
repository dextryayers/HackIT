# 403bypass - HTTP 403 authorization fuzzer

Industrial-grade 403/authorization bypass engine for authorized web assessments.
The click command is a thin wrapper that compiles and runs the Go engine in
this folder (`go_engine/bypass_engine`); all real logic lives in Go.

## Usage

```bash
hackit web 403bypass --help
```

CLI passes target URL plus an optional verbose/only-success flag to the Go
binary with `-url <target>`. Results print to stdout as JSON parsed by the
python wrapper; on engine failure the wrapper prints the error and returns.

## What it tests

- HTTP method overrides (PUT/POST/PATCH/etc.)
- Header injection (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, ...)
- Path normalization tricks (double slashes, `..;/`, encoded separators, case)
- Query string pollution
- User-Agent / role spoofing

Exact technique inventory is defined in `go_engine/`. The tool is pure active
testing; it does not silently mutate state. Read the code before pointing it
at anything you do not control.

Authorized testing only.

## Implementation

- `__init__.py` - click command `403bypass` registered under `hackit web`
- `go_engine/bypass_engine[.exe]` - prebuilt Go binary; source in `go_engine/`
- `403.txt` - bypass payload reference list (human reference; engine source is authoritative)
- `run_403bypass.sh` - convenience wrapper, same delegation pattern as other tools
