# redirect - open redirect finder

Interactive dual-engine open-redirect scanner (Go + Python) for authorized
web assessments. Finds open redirects in query parameters, POST bodies,
headers, path segments, DOM/client redirects and blind cases; includes
encoding-matrix and WAF-bypass-oriented variants.

## Usage

```bash
hackit vuln redirect <url>
hackit vuln redirect -u https://example.com/next -o report.json
```

CLI is interactive when no URL is passed: mode selector banner (query param,
BODY POST, header inject, path inject, DOM/client, WAF bypass, blind redirect,
deep payload, cookie inject, encoding matrix).

## Engines

- **Go engine** (`go/` via `go_bridge.go`) - primary probe engine, high concurrency
- **Python fallback** - slower pure-python path when Go binary missing/out of date

Cross-engine correlation boosts confidence when both engines flag the same
`(url, param)` pair: +0.05 per extra agreeing engine, capped at 0.98.

## What it tests

- Query parameter redirect (`?next=`, `?url=`, `?redirect=`)
- POST body redirects
- HTTP header redirects (`Location`, `X-Forwarded-For` proxies)
- Path-based redirects (`/redirect/https://...`)
- DOM/client redirects (`location`, `location.assign`, `document.write`)
- Blind/out-of-band cases (time/DNS callback style, when Burp Collaborator-like
  infrastructure is configured)
- Encoded payloads and shallow-WAF bypass variants

## Output

Stdout per finding: url, parameter, payload, severity, confidence, engine
that flagged it, correlation marker. `-o` writes JSON.

Authorized testing only. Open redirect alone is low severity; the exploit is
phishing and token leakage chains, so findings should be validated end to end.
