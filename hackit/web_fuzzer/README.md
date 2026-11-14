# web_fuzzer - passive parameter discovery

ParamSpider-grade parameter harvesting from public web archives. Passive only:
never invents URLs, never probes targets beyond metadata sources. Exposed as
`hackit web fuzz`.

## Usage

```bash
hackit web fuzz example.com
hackit web fuzz https://sub.example.com
hackit web fuzz 203.0.113.10          # bare IP: archive sources skipped
```

Positional target is optional; prompts if omitted.

## Options

- `-v/--verbose` (default on) - progress chatter
- `-q/--quiet` - no progress output

That is the entire flag surface; the pipeline is deliberately one-button.

## Pipeline (5 phases)

1. Subdomain discovery - crt.sh, RapidDNS, HackerTarget, DNS brute (72 common
   prefixes, 32 workers), wildcard DNS detection disables liveness labeling
2. Parameter mining - Wayback CDX (2018-2020) + `go/cdxfan` (2021+, Go,
   concurrent, server-side filter), CommonCrawl (latest indexes), AlienVault
   OTX, urlscan.io; skipped for bare IPs
3. Normalize/collapse - scheme check, extension blacklist, Wayback-garbage
   path rejection, parameter-bearing only, `(netloc, path, sorted params)`
   collapse, scope filter
4. Liveness - DNS resolve (48 workers); wildcard DNS disables the label
5. Results - green = live, DIM = stale; host summary; top-20 parameter inventory

## Output

Writes `results/<host>.txt` (cwd-relative) with one URL per line plus a header.
Stdout carries the summary only; no JSON. `-v/--verbose` defaults on; dimmed
entries are stale (unresolved) hosts.

## Notes

- Bare IP targets skip both archive sources and liveness.
- CommonCrawl hardcodes fallback index IDs that age out over time.
- Obscure targets may yield nothing from passive sources; that is expected.
- Stale hosts are still printed, labeled.

Authorized testing only.
