# hackit stresslab — authorized resilience testing

Measures how systems you own (or may assess under written permission) behave
under load. It is a measurement instrument, not an attack kit:

- **Scope-gated** — every non-lab run needs a signed scope file (JSON) with an
  explicit target allowlist, an expiry date and an approval reference; the
  `--approval` flag must match `approval_ref` or nothing runs.
- **Capped** — hard ceilings: 10000 rps, 256 workers, 600 s. The scope file
  can only lower them.
- **Audited** — every run appends a JSON record to
  `~/.hackit/stresslab/audit.log`; the run aborts if the audit log is not
  writable.
- **No spoofing, no amplification, no evasion, no persistence.** TLS is
  verified for HTTPS targets.

## Engines

| Engine | Language | Role |
|--------|----------|------|
| `go/stresslab` | Go (stdlib) | HTTP(S) load: latency p50/p90/p99/max, error rate, achieved rps |
| `c/stress_engine` | C11 + pthreads | TCP connect rate and plain-HTTP GET latency, tight thread caps |

The Python layer (`stress.py`) is the bridge and the gatekeeper: it validates
scope, enforces caps, launches the engines and renders one report schema.

## Layout

```
hackit/stresslab/
├── __init__.py          # exposes the `stress` click group to the main CLI
├── stress.py            # CLI: run / lab / check / build
├── scope.py             # fail-closed scope validation
├── engines.py           # engine discovery, build and execution
├── scope.example.json   # template for the signed scope file
├── go/                  # Go HTTP(S) engine
└── c/                   # C11 TCP/HTTP engine
```

## Usage

```bash
# compile both engines
hackit stress build

# validate a scope file without generating load
hackit stress check --scope scope.json --target https://staging.example.internal/health --approval CHG-1234

# authorized HTTP load test
hackit stress run --target https://staging.example.internal/health \
    --scope scope.json --approval CHG-1234 --profile http \
    --rps 100 --workers 16 --duration 30 --output report.json

# authorized TCP handshake resilience test
hackit stress run --target db.internal --port 5432 \
    --scope scope.json --approval CHG-1234 --profile tcp

# loopback-only smoke test, no scope file needed
hackit stress lab --target http://127.0.0.1:8080 --duration 5 --rps 20
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
