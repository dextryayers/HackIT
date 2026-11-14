# rce_modul - command injection detection and exploitation

Multi-technique RCE detection with a Go correlation engine. Banner reads
"RCE NUCLEAR". Exposed as `hackit vuln rce`.

## Usage

```bash
hackit vuln rce -u https://example.com/ping?host=127.0.0.1
hackit vuln rce -u https://example.com/task?q=1 --detect
hackit vuln rce -u https://example.com/ -p id --exploit -c "id"
hackit vuln rce -u https://example.com/ --find
hackit vuln rce -u https://example.com/ -m POST -d host=x --blind
```

## Options

- `-u/--url` (required)
- `-p/--param` - parameter(s) to test (comma separated)
- `--detect` - detection only
- `--exploit` - active exploitation
- `-c/--cmd` - command for exploitation
- `-m/--method` - `GET` or `POST`
- `-d/--data` - POST body data
- `--timeout 15`, `--proxy`, `--cookie`, `--ua`, `--threads 20`
- `--all-params` - test all parameters on the page
- `--find` - discover page parameters plus common names, test each
- `--blind` - blind/boolean/time-based checks
- `--output <file>` - save JSON
- `--verbose`
- `--engines go` - engine selection (Go only; other values are silently dropped)

## Engine

Go `detector.go`: baseline body/time/status capture, then differential analysis.
Payload database (`payloads.go`) covers output (semicolon, pipe, backtick,
`$()`, quote escape, comment, windows cmd), error-based (sql-style markers),
and blind (time/DNS, when callback infra is configured).

SSTI and OOB callbacks require an external callback server for true OOB
detection; blind mode without OOB degrades to bypass detection.

## Output

Rich tables and panels to terminal. `--output` writes JSON to the given path;
no default report file. `--find` spawns one subprocess per param (slow).

Authorized testing only. This module submits live payloads; do not point it at
systems you do not own or lack permission to test.
