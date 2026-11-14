# network_scanner - CIDR alive-host detection

Scans an IP range for alive hosts with TCP probes. Dual engine: Go worker
preferred, threaded python fallback (`--no-go`).

## Usage

```bash
hackit recon ips 192.0.2.0/24
hackit recon ips 10.0.0.0/24 -o alive.json -p 22,80,443 -t 2 -w 200
hackit recon ips 192.168.1.0/24 --resolve --json-only
```

## Options

- `-o/--output` - write live hosts to JSON
- `-p/--ports` - probe list (default ~22 common ports: 21,22,23,25,53,80,110,135,
  139,143,443,445,587,993,995,1433,3306,3389,5432,5900,8080,8443)
- `-t/--timeout` - per-host timeout in seconds
- `-w/--threads 100` - python fallback workers
- `--no-go` - force python engine
- `--resolve` - reverse-lookup hostnames for live hosts
- `--json-only` - machine output only
- `-v/--verbose`

## Engines

- **Go worker** (`go/`) - TCP dial with semaphore concurrency, emits
  `{target, alive_count, hosts[]}` JSON; compiled on demand by `go_bridge.py`
- **Python fallback** (`__init__.py`) - `scan_host` TCP-connects to the default
  set, assigns confidence (0.95 when >=2 ports open, else 0.65), verdicts
  `host_up` / `host_likely_up`, optional reverse DNS

## Output

Stdout summary plus per-host listing. `-o` writes structured JSON:
`{cidr, alive_count, total_scanned, hosts[], scan_time}`. Each host entry
carries open ports, hostname (when resolved), confidence and verdict.

Authorized testing only. TCP probing of networks you do not own is still scanning.
