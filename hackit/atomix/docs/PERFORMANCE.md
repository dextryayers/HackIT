# Atomix — Performance Part 2 (V2.1)

Baseline: pre-upgrade (the 2.2.0 line, `Atomix v2.2.0`) binary. Changes are behavior-preserving; E2E
finding set verified identical before/after (46/46 tuples match). Measured on
the same host, same 310-template library, same local fixture target
(`http://127.0.0.1:8077`, Python `ThreadingHTTPServer`, single-process).

## Changes

| Area | Change | Why it matters |
|---|---|---|
| HTTP/2 | `ForceAttemptHTTP2` now default ON in both clients (was opt-in via `-http2`); Go skips ALPN h2 when `TLSClientConfig` is set on the transport | Multiplexed streams on h2 targets; previously atomix silently spoke HTTP/1.1 |
| Body read | Response body read via `sync.Pool` byte buffers + `buf.String()` (one copy) instead of `io.ReadAll(LimitReader)` + `string()` (two copies + no pooling) | ~3.1× faster body ingestion, 4× fewer allocs (see numbers) |
| Header render | Raw `strings.Builder` writes instead of `fmt.Sprintf` per header line | One less reflection-heavy formatting path per response |
| `-H` parsing | `ParseCustomHeaders` memoized once per scan (was re-parsed per request) | Removes O(#headers) parse from the hot path of every request |
| Auth headers | `AuthProvider` memoized per `*ScanConfig` (was rebuilt per request; OAuth2 fetched a token **per request**) | Correctness + huge latency win for OAuth2 targets |
| Host bookkeeping | URL host computed once per probe and passed into the goroutine (was `url.Parse` × 3–4 per request) | 3–4 fewer URL parses per request |
| Case-insensitive word matchers | Body/headers lowered **once per response** and reused across matchers | 83µs → 107ns per CI matcher call (~770×) |
| Explicit headers | Dropped explicit `Connection: keep-alive` | Avoids h2-illegal connection header; Go manages this itself |
| `-scan-all-ips` / circuit breaker / resume | Unchanged semantics from Part 1 | — |

## Benchmark numbers (`go test -bench . -benchtime=100ms -benchmem`)

```
BenchmarkMatchWords-16                             25.17 ns/op       0 B/op    0 allocs/op
BenchmarkMatchWordsCaseInsensitivePreLogged-16     107.4 ns/op       16 B/op    1 allocs/op
BenchmarkMatchWordsCaseInsensitivePerCall-16     83088 ns/op      49168 B/op    2 allocs/op   ← pre-upgrade behavior
BenchmarkMatchRegexFast-16                         387.2 ns/op        0 B/op    0 allocs/op
BenchmarkMatchTemplateAndMatchers-16               584.2 ns/op       64 B/op    1 allocs/op
BenchmarkDSLBool-16                               4822 ns/op      3309 B/op   32 allocs/op
BenchmarkNormalizeDSLExpr-16                      2572 ns/op       556 B/op   19 allocs/op
BenchmarkExtractJSON-16                           7710 ns/op      3119 B/op   55 allocs/op
BenchmarkReadBodyPooled-16                        51925 ns/op    168369 B/op    3 allocs/op
BenchmarkReadBodyPooledLimit-16                  163007 ns/op    686423 B/op   21 allocs/op   ← pre-upgrade behavior
BenchmarkJoinRequestURL-16                         60.98 ns/op       48 B/op    1 allocs/op
BenchmarkExpandAttackClusterbomb-16              12126 ns/op      7048 B/op  114 allocs/op
```

## E2E (full library, 310 templates, 1 host, fixture target)

| Version | Wall time | Findings | stderr |
|---|---|---|---|
| pre-upgrade (v2.2.0) | 4.226s | 46 | 0 B |
| V2.1 (run 1) | 3.60s | 46 | 0 B |
| V2.1 (run 2) | 3.47s | 46 | 0 B |
| V2.1 (run 3) | 3.83s | 46 | 0 B |

~15% wall-clock on a localhost, mostly-I/O-bound target. CPU-bound paths
(matcher, body ingestion) improved far more; see benchmarks above. Against
real network targets with TLS and bigger bodies, the HTTP/2 default and
pooled body reads compound further.

## Known remaining hot spots (out of this pass)

- `buildDSLEnv` allocates ~30 entries + ~22 closures per DSL evaluation
  (4822 ns/op, ~3.3 KB/op). A compile-time DSL constant-folding pass or a
  pooled env would cut this; deferred until the DSL function library grows.
- `MatchTemplate` JSON marshaling of findings is fine at expected volumes;
  streaming JSONL direct-to-file remains Part 3 material.
- DNS lookups rely on the system resolver; a TTL cache in the custom
  dialer would help multi-target sweeps heavily and is tracked for Part 3
  (deliberately deferred: wrong-stale-IP risk needs a careful TTL/cap design).

## Verify

```
cd hackit/atomix/go
go build -o bin/atomix .
go test -run '^$' -bench . -benchmem .
go test ./...        # 34/34 green
go vet ./...
```
