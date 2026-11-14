# xss - reflected XSS scanner (Go + Python)

Multi-engine reflected XSS detection with cross-engine correlation to reduce
false positives. Exposed as `hackit vuln xss`.

## Usage

```bash
hackit vuln xss -u https://example.com/search?q=test
hackit vuln xss -u https://example.com/search?q=test -o results.json --threads 20
```

## Options

- `-u/--url` (required)
- `-o/--output` - save JSON findings
- `--timeout 10`
- `--threads 10`
- `--engines go,python` - comma separated engine selection

## Engines

- `python/payloads.py` - 150+ payloads in 7 classes (script injection, event
  handlers, attribute breakout, tag breakout, javascript: URIs, etc.)
- `python/scanner.py` - GET parameter injection, ThreadPoolExecutor, context
  detection (script/attr/tag), SSL verification disabled, severity/confidence
- `go/` - Go scanner with payload.txt (715 lines, includes exfil-oriented payloads for validation flows)
- `python_bridge.py` - confidence normalization and cross-engine merge

Cross-engine correlation: confidences normalized to 0-1 (high=0.9, med=0.7,
low=0.4), bonus +0.05 for two agreeing engines, sorted descending.

## Output

Stdout banner with severity/confidence/impact/engine per finding, or "No XSS
vulnerabilities found". JSON via `-o`. Per-finding fields: url, parameter,
payload, severity, confidence, impact, correlation_count.

Authorized testing only.
