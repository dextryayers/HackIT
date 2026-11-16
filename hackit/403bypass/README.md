# 403bypass — 403 / WAF authorization bypass engine

Industrial-grade 403/401 authorization fuzzer for authorized web assessments.
The click command is a thin wrapper around the Go engine; all request logic,
scoring and classification lives in Go.

## Usage

```bash
# single URL, full sweep
hackit web 403bypass --url https://target.example/admin

# tune concurrency / per-request timeout, also dump the raw JSON report
hackit web 403bypass --url https://target.example/admin -t 100 --timeout 8 -o report.json

# only show techniques that reached the application
hackit web 403bypass --url https://target.example/admin --only-success

# every payload, including the rejected ones
hackit web 403bypass --url https://target.example/admin --verbose
```

Run directly without the CLI wrapper:

```bash
python3 hackit/403bypass/__init__.py --url https://target.example/admin
```

## Engine v3 — accuracy upgrades

- **Multi-baseline capture** — one original probe, three random paths, one deep
  404. Any of them that returns a 4xx becomes a reference deny page, so sites
  that rotate their 403 body are still scored correctly.
- **Trigram similarity (Jaccard)** — every response is normalised
  (whitespace collapsed) into trigram shingles and compared against every deny
  page. A 2xx whose body is >= 85% similar to the deny page is classified
  `soft-200` instead of `bypass`, killing the most common false positive on
  SPA fallbacks and CDN error pages.
- **Per-candidate verification** — every 2xx/3xx that survives classification is
  re-issued once. Flapping servers no longer inflate the result set; the code
  prints `✓` for stable and `?` for unstable.
- **Payload corpus 1493** — adds absolute-URI request targets, Host header
  twists, header whitespace/duplication tricks, matrix params, extension
  whitelisting, J2EE/Symfony dot-segment variants, unicode dot, rewrite
  encodings, query injection, smuggling probes and verb casing.

## Engine v3 - accuracy upgrades

- **Multi-baseline capture** - one original probe, three random paths, one deep
  404. Any that returns a 4xx becomes a reference deny page, so sites that
  rotate their 403 body are still scored correctly.
- **Trigram similarity (Jaccard)** - every response is normalized into trigram
  shingles and compared against every deny page. A 2xx body >= 0.85 similar to
  the deny page is classified `soft-200` instead of `bypass`.
- **Per-candidate verification** - every 2xx/3xx is re-issued once. Flapping
  servers no longer inflate the result set; `+` stable, `?` unstable.
- **Payload corpus 1493** - absolute-URI targets, Host twists, header
  whitespace/duplication, matrix params, extension whitelisting, dot-segment
  variants, unicode dot, rewrite encodings, query injection, smuggling probes,
  verb casing.

## How it works

1. **Baseline probe** — the engine requests a random path (`/<random>`) and
   records the status, body length and SHA-256 of the default response. That
   gives a reference for "what a denied request looks like" on this specific
   deployment, independent of the real 403 page.
2. **Payload sweep** — 1493 techniques fire concurrently against the target:
   - IP header spoofing across ~35 proxy/CDN/origin headers and ~26 values
   - Path rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, …) against `/`
   - Protocol and port spoofing (`X-Forwarded-Proto`, `X-Forwarded-Port`, …)
   - WAF vendor headers (Cloudflare, Akamai, AWS, Sucuri, Imperva, F5, Cisco, …)
   - Authentication header / cookie injection
   - CORS / origin bypass
   - HTTP verb tampering (RFI methods, WebDAV, HTTP/2 prior knowledge)
   - Method override headers
   - Path suffix and prefix fuzzing (encoded traversal, `..;/`, `%2f`, `%3b`, …)
   - Content-Type / Accept manipulation, User-Agent spoofing, Range, cache
3. **Classification** — each response is scored against the baseline:
   - `bypass` — 2xx with a body that differs from the default deny page
   - `soft-200` — 2xx carrying the *same* body as the deny page (a WAF that
     renders its block as HTTP 200, or a SPA fallback returning 200 for
     everything)
   - `redirect` — 3xx (Location header captured for follow-up)
   - `blocked` — 403/401 identical to the baseline
   - `error` / `error5xx` — network error or server fault
4. **Report** — verdict summary, open responses table, blocked-technique
   spread, response clusters and a final verdict banner.

## Output shape

The Go engine emits a single JSON object:

```json
{
  "target": "https://example.com/admin",
  "waf": "Cloudflare",
  "baseline": {"url": "...", "status_code": 403, "length": 1234, "body_hash": "..."},
  "requested_status": "403",
  "results": [
    {"payload": "Path Rewrite Header [X-Original-URL: /admin] [path: /]",
     "type": "Path Rewrite Header", "method": "GET", "status_code": 200,
     "length": 4521, "body_hash": "...", "title": "Admin", "verdict": "bypass",
     "same_as_baseline": false, "duration_ms": 42.1}
  ],
  "clusters": ["200 09b4ba49 len=4521 x3 title=Admin"],
  "duration_ms": 2315,
  "version": "2.0.0"
}
```

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--url`, `-u` | required | Target URL returning 403/401 |
| `--threads`, `-t` | 60 | Concurrent workers (1–200) |
| `--timeout` | 12 | Per-request timeout in seconds (1–60) |
| `--verbose`, `-v` | off | Print every payload, not only open responses |
| `--only-success` | off | Suppress the blocked/noise and cluster sections |
| `--json-out`, `-o` | off | Also write the raw JSON report to a file |

## Building the engine

The prebuilt binary in `go_engine/bypass_engine` targets Linux amd64. To rebuild:

```bash
cd go_engine
go build -o bypass_engine -ldflags="-s -w" .
```

The engine has no third-party dependencies (Go stdlib only).

## Files

- `__init__.py` — click command `403bypass` registered under `hackit web`;
  banner, verdict tables, JSON export
- `go_engine/main.go` — HTTP client, baseline probe, classification, clustering
- `go_engine/payloads.go` — the 1300+ technique corpus
- `go_engine/bypass_engine` — prebuilt Go binary
- `403.txt` — original reference list (kept as documentation; the engine
  corpus is authoritative)

## Notes

- A response that returns 200 with the deny page's body is **not** a bypass.
  It is reported as `soft-200`. This eliminates the most common false positive
  when scanning CDN-fronted sites and SPA fallbacks.
- Redirects are followed up to 5 hops before classification, so an
  intermediary that 301s `/admin` to a login page shows as `redirect`,
  not `bypass`.
- Baseline is captured once per run. If the deployment rotates error pages
  per request, re-run and compare reports.

Authorized testing only.
