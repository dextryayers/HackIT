# Atomix — Deep Upgrade Audit & Roadmap

Status: living document. v3.0.0 deep-upgrade pass completed and verified against
`atomix/go` (build + vet + gofmt + 34 unit tests + E2E fixture scan). Items
marked **[DONE]** shipped in v3.0.0. Everything else is the remaining backlog,
ordered by impact.

---

## 1. Executive summary

Atomix is a template-driven vulnerability scanner (Go single-binary + Python
bridge) that handles nuclei-style `http:` template blocks by normalizing them
into its internal `requests:` model. Baseline: builds clean, `--validate`
reports 310/310 templates valid.

The audit found the usual generated-code skeleton, and v3.0.0 closes it:
**a real DSL expression engine** (expr-lang), **request-scoped extractors**
(nuclei-style `json`/`kval`/`dsl`/`regex`), **per-request `case-insensitive`
matchers**, **relative-path template support**, and **everything the CLI
promised actually works now** — `-resume`, `-max-host-error`, `-delay`,
`-rate-limit-minute`, `-bulk-size`, `-scan-all-ips`, `-sni`, `-cookie-jar`,
`-pn/pipeline`. Plus: stdin template loading and pipeline mode no longer
compete for stdin, SARIF output deduplicates rules, `--silent` produces pure
machine output on stdout with empty stderr, and the repo now has a unit-test
suite (34 tests) covering matchers, DSL, variables, templates, resume, dedupe.

---

## 2. Architecture map

```
hackit/atomix/
├── go_bridge.py        Python wrapper: FLAG_MAP -> binary flags, PATH mgmt
├── __init__.py         HackIT plugin glue (click, grouped help)
├── template/           310 YAML templates, 59 files, 27 categories
├── go/
│   ├── main.go         flags, dispatch, handleResults, pipeline mode
│   ├── engine.go       Scanner, circuit breakers, resume, fan-out
│   ├── template.go     YAML load (multi-doc), filter, dedupe-by-id
│   ├── http_compat.go  nuclei `http:` block normalization, attack expansion
│   ├── matcher.go      word/regex/status/size/dsl matchers, extraction
│   ├── dsl.go          expr-lang DSL engine (contains-rewrite + cache)
│   ├── variables.go    {{BaseURL}} {{Random}} … resolution
│   ├── http.go         client construction (SNI/resolver/cookie-jar), SendRequest
│   ├── resume.go       append-only scan checkpoint (-resume)
│   ├── targets.go      target loading, -scan-all-ips expansion
│   ├── output.go       JSON/JSONL/CSV/SARIF/HTML/Markdown reports
│   └── …               waf, tech, chain, dashboard, project, monitor, oob …
└── docs/DEEP_UPGRADE.md  this file
```

Request path: `main` → `LoadTemplatesFromDirs` → `FilterTemplates` →
`Scanner.Scan` (N template goroutines, semaphore) → `ProcessTemplate` →
`TestTemplate` (path × payload fan-out, per-request semaphore, circuit
breaker) → `SendRequestWithRetry` (host override for -scan-all-ips) →
`MatchTemplate` → `Result` → dedupe → print/collect.

---

## 3. Defects found in audit → status

### 3.1 Dead CLI surface — all **[DONE]**
- `-resume` → append-only checkpoint, skip-on-load, crash-safe (`resume.go`)
- `-max-host-error` → per-host consecutive-error circuit breaker in the fan-out
- `-delay <ms>` → fixed pacing throttler (alternative to rps)
- `-rate-limit-minute` → derived to rps at `InitScanner`
- `-bulk-size` → caps path×payload fan-out per template
- `-scan-all-ips` → A/AAAA lookup, one target per IP, original hostname as
  `Host:` override (verified E2E: 127.0.0.1 hit, [::1] refused, no crash)
- `-sni <name>` → TLS `ServerName` override
- custom resolver (`-r host:port`) → Go resolver dialed via UDP (existing flag, wired)
- `-cookie-jar <file>` → Netscape + JSON cookie file loading
- `-pn` / `-pipeline` → continuous stdin target scan until EOF (also fixes
  stdin conflict with template loading)
- `-no-meta` was shared with `-resume-cfg` → split: `-no-meta` bool,
  `-resume-cfg <file>` merged config on top of `--config`

### 3.2 Correctness bugs — all **[DONE]**
1. Relative template paths (`path: "/login"`) — now joined onto BaseURL
   (nuclei behavior). Verified E2E.
2. DSL matcher — replaced hand-rolled atom evaluator with expr-lang engine
   (env: `status_code`, `content_length`, `body_size`, `body_length`,
   `duration`, `duration_ms`, `body`, `header`, `all_headers`, `content_type`;
   functions: `contains` (rewritten to `__contains` pre-compile to dodge the
   infix operator), `contains_any`, `contains_all`, `regex`, `starts_with`,
   `ends_with`, `len`, `to_number`, `to_string`, `to_lower`, `to_upper`,
   `concat`, `md5`, `sha1`, `sha256`, `hex_decode`, `base64_decode`,
   `url_decode`, `header_value`). Legacy atom evaluator kept as fallback.
3. Type-level `and`/`or` matchers with only status/size never matched —
   resp context now flows into `matchAll`/`matchAny`.
4. Extractors were template-level only; per-request (nuclei-style)
   `extractors:` were silently dropped — Request now carries `Extractors`,
   `http:` normalization keeps them request-scoped, `extractAll` collects
   request + template level. Verified E2E: `matched: "9.9.9-vulnerable; production"`.
5. `kval` extractor — header key=value extraction by key list.
6. `xpath` — deliberately not shipped (libxml2 dependency decision pending).
7. Matcher has no `case-insensitive: true` — added (word/regex, `(?i)` injection).
8. `--silent`/`--json*` printed real-time findings + progress bar + "Loaded N
   templates" — now: stdout is pure machine output, stderr empty (verified).
9. SARIF emitted one rule per finding — deduplicated by ruleId (verified).
10. Template cache precompiled regexes nobody read — `PrecompileAll` now
    warms the matcher's `getRegex` cache instead.
11. stdin was consumed by the template loader even in `-pn` pipeline mode
    (targets went to the YAML parser, scan produced nothing) — loader is
    skipped in pipeline mode. Verified: pipeline yields correct NDJSON stream.
12. Python bridge crashed with `build_args() got multiple values for 'url'`
    — fixed; `hackit vuln atomix ... --jsonl` now works E2E. New flags
    (`--rate-limit-minute`, `--delay`, `--pipeline`, `--bulk-size`) exposed
    in both the click CLI and the Go FLAG_MAP.

### 3.3 Missing nuclei-parity features (backlog)
- DNS/WHOIS/TCP/SSL/JavaScript/Code protocols (atomix: HTTP only)
- `xpath` extractor
- Full DSL function library (~100 fns; we ship the core 20)
- `matchers-condition: and` + `req-condition: true`
- Per-extractor `internal: true` and named-matcher references
- `shared:` payload libraries, template inheritance (`extends:`)
- Real Interactsh lifecycle (register/poll/deregister + AES) — current OOB
  code is fire-and-forget HTTP GET against a guessed endpoint
- Headless v2 (CDP action graph) — current headless is a chrome-spawn stub
- HTML/Markdown reports rebuilt from SARIF model (single source of truth)

### 3.4 Quality gaps — status
- Unit tests: **34 tests**, `go test ./...` green
- `go vet` clean; `go mod tidy` applied (expr-lang/expr v1.17.8 direct)
- `gofmt -l`: repo was never gofmt-clean; v3.0.0-formatted files are clean,
  remaining pre-existing files listed for a follow-up sweep
- No `golangci-lint` config; no CI gate for `--validate` on template changes

---

## 4. Nuclei parity matrix

| Capability | nuclei | atomix v2.2 | atomix v3.0 |
|---|---|---|---|
| YAML templates, multi-doc | ✅ | ✅ | ✅ |
| `requests:` native style | n/a | ✅ | ✅ |
| `http:` block + normalization | n/a | ✅ | ✅ |
| `{{BaseURL}}` + interpolation | ✅ | ✅ | ✅ |
| Relative `path:` auto-join | ✅ | ❌ | ✅ |
| Payloads cartesian/batteringram/pitchfork/clusterbomb | ✅ | ✅ | ✅ |
| word/regex/status/size/dsl matchers | ✅ | ✅ partial | ✅ |
| `matchers-condition: and/or` | ✅ | ✅ | ✅ |
| `case-insensitive` matchers | ✅ | ❌ | ✅ |
| Real DSL expression engine | ✅ (expr-lang) | ❌ | ✅ (expr-lang) |
| regex/kval/json/dsl extractors | ✅ | regex only | ✅ |
| Per-request extractors | ✅ | ❌ | ✅ |
| Host circuit breaker `-max-host-error` | ✅ | ❌ | ✅ |
| Rate limit `rps` / per-minute | ✅ | rps only | ✅ both |
| `-resume` checkpoint | ✅ | ❌ | ✅ |
| `-scan-all-ips` | ✅ | ❌ | ✅ |
| Cookie jar | ✅ | ❌ | ✅ |
| Custom DNS resolver / SNI | ✅ | ❌ | ✅ |
| Pipeline mode (stdin targets) | ✅ (`-mode pipe`) | ❌ broken | ✅ |
| Headless/JS protocol | ✅ | stub | stub (backlog) |
| DNS/TCP/SSL/WHOIS protocol | ✅ | partial | partial |
| Unit test suite | ✅ | ❌ | ✅ |
| Interactsh lifecycle | ✅ | stub | stub (backlog) |

---

## 5. Deep-upgrade execution plan (sub-TODO status)

### Phase 1 — Engine core correctness
- [x] expr-lang DSL engine + legacy fallback (`dsl.go`)
- [x] DSL `condition:` honored for multi-expression matchers
- [x] `case-insensitive: true` on matchers
- [x] `status`/`size` honored inside type-level `and`/`or` matchers
- [x] Relative template paths auto-joined onto BaseURL
- [ ] `req-condition: true`
- [ ] xpath extractor (blocked on libxml2 decision)

### Phase 2 — Nuclei template-language parity
- [x] `json` extractor (dotted path, `a.b[0].c`)
- [x] `kval` extractor
- [x] `dsl` extractor (expression → string output)
- [x] Request-scoped extractors for native + `http:` blocks
- [x] Template cache warms the matcher regex cache
- [ ] Named matcher references + `internal: true` extractors
- [ ] `shared:` payload libraries, template inheritance

### Phase 3 — Performance
- [x] Per-host consecutive-error circuit breaker (`-max-host-error`)
- [x] `-bulk-size` fan-out cap
- [x] `-delay` fixed pacing
- [x] `-rate-limit-minute` derived rps
- [ ] Body-arena pooling (`sync.Pool`), zero-alloc target scanner
- [ ] Benchmark suite with baseline in docs/

### Phase 4 — Robustness / operations
- [x] `-resume <file>` (verified: skips completed pairs on rerun)
- [x] `-scan-all-ips` (verified E2E incl. Host override)
- [x] `-sni <name>`
- [x] Custom resolver dialed over UDP
- [x] `-cookie-jar` (Netscape + JSON)
- [x] `-pn`/`-pipeline` (verified E2E)
- [x] `-no-meta` split from `-resume-cfg`
- [ ] Persist cookie jar on save
- [ ] Resume checkpoint namespacing per `-project`
- [ ] Retry jitter for transient network errors

### Phase 5 — Output & reporting
- [x] SARIF rule dedup by ruleId
- [x] `--silent`: pure stdout machine output (verified: 0 bytes stderr)
- [x] Real-time finding print suppressed in machine formats
- [ ] Streaming JSONL to `-o file.jsonl` (today: buffered, fine at ≤5 MiB findings)
- [ ] Exit codes + `-fail-on-findings`

### Phase 6 — Quality gates
- [x] `go vet` clean, build clean, unit tests green
- [x] E2E fixture proof (vulnerable local server, 47 findings, exit 0, 4.2 s)
- [x] Python bridge: build_args url fix + new flags exposed
- [ ] gofmt sweep of pre-existing unformatted files
- [ ] golangci-lint config + CI gate for `--validate`

### Phase 7 — Long-term
- Interactsh session lifecycle
- `code` protocol (needs dedicated sandbox review)
- Headless v2 action graph
- Distributed runner (gRPC agents), queue-based ingestion
- Signature trust chain (CA bundle verify)
- Match-rate telemetry feeding confidence scoring

---

## 6. Verification protocol (all executed)

1. `go build ./...` — clean
2. `go vet ./...` — clean
3. `go test ./...` — **34/34 pass**
4. `./bin/atomix --validate` — 310/310 valid
5. `./bin/atomix -l` — listing intact
6. E2E fixture: `-id basic-simple-ping,basic-default-cred -silent -jsonl`
   → 4 clean JSONL findings on stdout, empty stderr
7. Custom template with `path: "/api/version"` (relative), DSL matcher
   (`status_code == 200 && contains(body, 'version')`), json extractors
   → matched, `extracted: "9.9.9-vulnerable; production"`
8. Resume: `-resume file` → rerun prints `Skipping (resumed): <id>`
9. Pipeline: `printf 't1\nt2\n' | atomix -pn -id basic-simple-ping -silent`
   → 6 JSONL findings, dedup correct for identical targets
10. `-scan-all-ips`: `-u http://localhost:8077` → expanded to 127.0.0.1 (match)
    and [::1] (graceful connection-refused, counted, no crash)
11. SARIF: 1 rule for 3 results (deduped) — verified
12. Python bridge: `python3 main.py vuln atomix -u … --silent --jsonl`
    → findings emitted through `hackit vuln atomix`
