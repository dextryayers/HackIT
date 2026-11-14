# HackIT OSINT - public footprint intelligence

Handles username, email, phone and domain reconnaissance against public
platforms and keyless APIs. Ships with roughly 790 social/developer/community
sources (`sources.py`), 91 search engines and profile lookup leads
(`SEARCH_LEADS`), 51 keyless "live" collectors (`live_sources.py`), handle
mutation logic for deep modes (`mutations.py`), and a Rust sweep engine when
`hackit/osint/go` is built (forced python fallback via `--no-rust`).

## Usage

```bash
hackit osint                       # interactive mode
hackit osint <handle>             # single-shot scan
hackit osint alice --deep          # handle variant expansion (separators, years, affixes)
hackit osint alice --category Developer   # probe only one category
hackit osint alice --json -o out.json
hackit osint alice --html -o report.html
hackit osint alice --proxy socks5://127.0.0.1:9050
hackit osint alice --phone --domain --all
```

Interactive: enter target, optionally deep-variant expansion, results print
live during the sweep (`print_live_finding`), auto report saved, history
appended.

## Output

- Live console stream of hits/possible/miss findings with confidence.
- HTML report (`--html -o file.html`) or JSON (`--json`).
- `hackit/osint/history.py` keeps a running history of scans (`load_history`).
- `reporter.py` generates the standalone HTML dashboard with confidence badges
  and verification notes (throttled/blocked probes).

## Internals

- `core.py` - probe loop, heuristics, content evidence, veto gate
  (aggregator/shell/not-found titles suppressed), retry with backoff and
  `Retry-After` honor.
- `analyzer.py` - confidence score 0-100 from hit count, quality of hits,
  media diversity, live intel, persona clusters.
- `formatter.py` - terminal rendering, `--quiet`, `--show`, `--only-live`,
  `--show-misses`, pagination.
- `go`/`go_bridge.py` - optional Rust/native sweep engine; falls back to
  python `scan_usernames` automatically.
- `validators.py`, `progress.py`, `identity.py`, `domain_intel.py`,
  `breach.py` - supporting checks (PGP, Gravatar, DNS MX, reputation feeds).

Authorized testing only. Use on systems/accounts you own or may assess.
