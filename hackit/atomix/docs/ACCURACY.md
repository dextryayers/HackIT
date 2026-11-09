# Atomix — Accuracy / Precision Part (V2.1)

Baseline: atomix v2.2.0 line. Goal: eliminate false criticals on benign
targets while keeping true positives. Everything below is verified on a
local fixture (`atomix-e2e/fixture.py`) serving benign + deliberately
vulnerable endpoints.

## Root causes found (and fixed)

### 1. The engine sent invalid request lines — every `?q=1' UNION …` payload 400'd, and the 400 page reflected the payload back
Go's transport writes `RequestURI` verbatim. Spaces/quotes from template
payloads produced `GET /?q=1' UNION SELECT NULL-- HTTP/1.1` → strict servers
answer `400 Bad request syntax` → the error page **contains the request line**
→ matchers firing on payload tokens ("NULL", "SLEEP", "ORDER BY", "1.*2.*3",
"$ne", "SELECT"…) matched everything. **The majority of "SQLi detected"
results on benign apps were 400-page artifacts.**
Fix: `sanitizeRequestURL` in `http.go` (percent-encode illegal raw chars in
path/query, preserve valid `%XX` triplets) applied at send-time and at
URL-composition time. URLs in results are now canonical (`?q=1'%20UNION…`).

### 2. Template matchers that cannot work (payload-reflection class)
`words: ["SLEEP"]`, `words: ["OR '1'='1"]`, `regex: ["1.*2.*3"]` — the matched
text is the payload itself; the only evidence is the echo. Systematic fix:
engine-level **payload-reflection detection** — any firing matcher whose
word/regex also appears in the request is demoted to `confidence: low`
(new `MatchResult.Reflection`), plus `-suppress-reflection-match` flag to
drop such findings entirely (exposed in the Python bridge as well).

### 3. Status-only matchers at severity critical/high
`type: status, status: [200]` with no other anchor = every 2xx is a critical.
Fix per-template (see below): delete, or convert to `matchers-condition: and`
with a content anchor.

### 4. No differential detection primitive
Time-based blind SQLi had no way to express "the response is slower than the
baseline". Engine now supports per-request `baseline: true`: one benign
counterpart request (all query values rewritten to `1`) is issued once
(cached) and DSL gains `baseline_duration`, `baseline_body_length`,
`baseline_status_code`. Time-based detection is now:
`duration > 4 && baseline_duration > 0 && duration > baseline_duration * 2`.
`baseline_duration > 0` (requires a successful baseline) keeps slow-but-uniform
apps from tripping it.

### 5. Confidence inflation
Reflection-penalized findings → `low` regardless of other rules. `--min-confidence
medium` is now meaningful for filtering heuristic finding classes.

## Template-library fixes

**Deleted (unverifiable by any unauthenticated means):**
`cve-sprint4shell` (2xx POST ≠ RCE; the webshell is unreadable), 
`rce-curl-wget` (blind SSRF with no OOB/interaction proof).

**Rewritten matchers (error-based / marker-based / directory-marker):**
- SQLi family (error-based, boolean-blind, union, sqli-waf-bypass,
  sqli-data-exfil, sqli-json-injection, sqli-order-by, sqli-like-clause,
  sqli-insert/update/having/comment-injection, second-order, nosql-injection):
  regex sets of DBMS error formats ("You have an error in your SQL",
  "Incorrect syntax near", "ERROR:  syntax error", "ORA-009xx", "PG::Error",…)
  — none of these strings appears in the payload, so no echo match is possible.
- `time-based-sqli`: `baseline: true` + DSL above.
- `postgres-sqli` / `mssql-sqli`: DBMS-specific error regexes (no "pg_sleep"
  / "xp_cmdshell" reflection matchers).
- `generic-info-endpoints`: quoted JSON markers (`"UP"`, `"status"`, …).
- `generic-admin-panels`: strong form-marker words (no bare `admin`/`login`).
- `default-creds-accepted`: app-state markers only (`Welcome`, `Dashboard`,
  `Logged in`, …) — request body no longer feeds the matcher.
- `jwt-alg-confusion`/`jwt-kid-byte-array`/`jwt-jku-injection`/`jwt-iat-future`:
  `matchers-condition: and` — status 200 **and** body containing an
  authenticated-user marker (`"user"`, `"email"`, `"role"`, …).
- `api-nosqli` additions: `and`-mode status 200 + token-bearing regex.
- `nosqli-mongodb-injection`, `nosqli-dynamodb-injection`,
  `nosqli-couchdb-injection`: DBMS/driver error regexes and/or `and`-mode
  with response-key anchors.
- `deser-python-pickle`, `deser-java-rmi`: error/marker regexes, `and`-mode
  for the status gated request.
- `cve-php-cgi-args-inject`: now POSTs a real `<?php system('id') ?>` body and
  matches `uid=[0-9]+(` — actual proof of code execution, impossible to echo.
- `cve-text4shell`: dropped weak `oob` word, keeps `uid=`/`gid=`/`groups=`.
- `ldap-blind-injection`: directory-marker matchers only (`cn=`, `dn=`, `ou=`, `dc=`).
- `generic-trace-method`: status 200 AND `Max-Forwards`.
- `generic-http-methods`/`generic-http-verbs`/`generic-common-files`/`jwt*`:
  status-line-as-word → `type: status` matchers.

**FP-RISK linter** (`--validate-deep`): advisory report —
classification per matcher (payload-reflection / high-frequency token /
status-as-word), 127 templates, 242 issues (was 155/313). All remaining hits
are the reflection class demoted by the engine, i.e. noise-filterable with
`-suppress-reflection-match` or `--min-confidence medium`.

## Verification matrix (fixture: benign + vulnerable endpoints)

| Check | Before | After |
|---|---|---|
| Full library on benign fixture | 47 findings, ~25 of them critical FP | **11 findings: 0 false criticals** (2 TP criticals — `.env` exposure, default creds accepted — both genuine, fixture is deliberately vulnerable) |
| `union-based-sqli` / `time-based-sqli` / `boolean-blind-sqli` / `mssql` / `postgres` / `waf-bypass` on benign | fired | **silent** |
| Payload-reflection matchers | high/medium critical confidence | demoted to `low`, e.g. `ping-reflected` |
| REQ with spaces (`?q=1' UNION SELECT NULL--`) | `400 Bad request syntax` reflection → matched | canonical `%20` request line; no echo artifact |
| TP proof: `/search?q=1'` (500 + MySQL error text) | matched (as FP) | matched (real, `medium`) |
| TP proof: `/slow` + `SLEEP(5)` (6s vs ~1ms baseline) | n/a (no baseline) | matched via baseline DSL, `high` |
| Negative control (`/search?q=justaboutright`, `/slow?q=normal-param`) | fired | **silent** |
| `hackit vuln atomix -u … --jsonl` | works | works (confidence visible through bridge) |

## Known residual FP classes (documented, not hidden)

- Reflected-XSS matchers (`alert(1)` in URL/body) — reflection can never prove
  execution context; demoted to `low`. `--min-confidence medium` drops them.
- Path-probe/discovery templates (`swagger-ui`, `wp-json`, `docker-socket`) —
  the matcher token is the probe; `low` confidence now attached.
- `generic-common-files custom-404` — presence-detection semantics, `info`.
- 155→127 flagged-by-lint templates remain; all in the reflection class —
  `-suppress-reflection-match` drops them wholesale.

## Verify
```
./bin/atomix --validate-deep      # Valid: 308, 0 FP-critical classes remain
./bin/atomix -u <benign> -silent -jsonl
./bin/atomix -u <benign> -suppress-reflection-match -silent -jsonl
go test ./...                     # lint + matcher + dsl suites green
```
