# hackit ddos — authorized resilience testing

Measures how systems you own (or may assess under written permission) behave
under load. It is a measurement instrument, not an attack kit:

- **Confirmation-gated** — loopback targets run immediately; remote targets
  require typing `yes` to confirm ownership or written permission in
  interactive mode, or a signed scope file (`--scope` + `--approval`) for
  scripted runs.
- **Capped** — interactive: 1000 rps / 64 workers / 300 s. Lab: 500 rps /
  16 workers / 60 s. Scripted: hard ceilings 10000 rps / 256 workers /
  600 s, and the scope file can only lower them.
- **Audited** — every run appends a JSON record to
  `~/.hackit/ddos/audit.log`; the run aborts if the audit log is not
  writable.
- **No spoofing, no amplification, no evasion, no persistence.** TLS is
  verified for HTTPS targets.

## Engines

| Engine | Language | Role |
|--------|----------|------|
| `go/stresslab` | Go (stdlib) | HTTP(S) load: latency p50/p90/p99/max, error rate, achieved rps |
| `c/stress_engine` | C11 + pthreads | TCP connect rate and plain-HTTP GET latency, tight thread caps |

The Python layer (`ddos.py`) is the bridge into the HackIt CLI and the
gatekeeper: it validates scope, enforces caps, launches the engines and
renders one report schema.

## Layout

```
hackit/ddos/
├── __init__.py          # exposes the `ddos` command to the main CLI
├── ddos.py              # CLI: interactive console + run / lab / check / build
├── scope.py             # fail-closed scope validation
├── engines.py           # engine discovery, build and execution
├── scope.example.json   # template for the signed scope file
├── go/                  # Go HTTP(S) engine
└── c/                   # C11 TCP/HTTP engine
```

## Usage

Bare `hackit ddos` prints the console help. For the interactive console
(remote targets need a typed `yes`):

```bash
hackit ddos console
# target domain/IP: 127.0.0.1:8080   → runs immediately
# target domain/IP: staging.example.internal   → asks for authorization first
```

Method profiles: `get post put patch delete head options mixed`
(`mixed` rotates verbs per request). Extras: `--body` (JSON auto-detected),
`--ramp N` (linearly ramp 1 → --rps over N seconds), `--close`
(Connection: close), `-v/--verbose` (resolved target, caps, audit path),
`http-raw` profile (C engine plain-HTTP GET against a raw socket path).

Scripted — signed scope file required for remote targets:

```bash
# compile engines
hackit ddos build

# validate a scope file without generating load
hackit ddos check --scope scope.json --target https://staging.example.internal/health --approval CHG-1234

# authorized HTTP load test
hackit ddos run --target https://staging.example.internal/health \
    --scope scope.json --approval CHG-1234 --profile http \
    --rps 100 --workers 16 --duration 30 --output report.json

# authorized TCP handshake resilience test
hackit ddos run --target db.internal --port 5432 \
    --scope scope.json --approval CHG-1234 --profile tcp

# loopback-only smoke test, no scope file
hackit ddos lab --target http://127.0.0.1:8080 --duration 5 --rps 20

# POST with a JSON body, verbose
hackit ddos run --target https://staging.example.internal/api \
    --scope scope.json --approval CHG-1234 --method post \
    --body '{"probe":true}' -v
```

## Scope file

See `scope.example.json`. Rules enforced at load time:

- `authorized` must be the boolean `true`
- `approval_ref` non-empty, `--approval` must equal it exactly
- `targets`: hosts (exact), IPs/CIDRs, or `*.suffix` wildcards — nothing else passes
- `expires` in the future, ISO 8601
- caps are clamped to `min(requested, scope, hard ceiling)`

## Exit codes

- `0` — test completed (check its error rate; 5xx counts as error)
- `1` — engine failure
- `2` — scope/approval refusal (fail-closed)
