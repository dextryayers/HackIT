# hackit cve — vulnerability intelligence scanner

Fingerprints the technologies advertised by a target (headers + body + port
probe), then matches them against NVD, CISA KEV, EPSS and OSV. Findings carry
CVE id, CVSS score/vector, CWE, OWASP mapping, attack type, severity, EPSS
probability and source-confidence metadata.

This is an automated assessment tool for systems you own or are authorized to
evaluate.

## One-shot usage

```bash
hackit util cve example.com                  # scan, briefing on stdout
hackit util cve example.com --deep           # + subdomains, enhanced probing
hackit util cve example.com --json-out r.json --refs
hackit util cve example.com --nvd-concurrency 5 --api-key <NVD_KEY>
```

Interactive mode (`hackit util cve` with no target) shows a small menu.

## How it works

1. **Tech detection** — response headers, HTML body fingerprinting and a
   bounded port probe; feeds `DetectedTech` (software + version).
2. **NVD matching** — per-tech keyword/CPE queries run with bounded parallelism
   (`--nvd-concurrency`, default 3) under the NVD rate limiter; results are
   deduplicated and capped by `--max-results`.
3. **Enrichment** — CISA Known Exploited Vulnerabilities cross-match, EPSS
   probability (FIRST.org), CWE/OWASP mapping.
4. **Report** — human briefing (default), `--json-out` for JSON, `--refs` to
   include advisory URLs.

## Caching

- NVD responses: `~/…/nvd_cache.json` next to the worker binary (created on first use).
- EPSS scores: `$XDG_CACHE_HOME/hackit/cve/epss_cache.json` (or `~/.cache/...`),
  24 h TTL — repeat scans over the same finding set skip the EPSS API entirely.
- CISA KEV: 1 h in-memory + on-disk cache.

## Rate limits

Without an NVD API key the worker honours the public tier (~1 req/s globally,
Semaphore 2). With `--api-key`, throughput rises (0.6 s spacing, Semaphore 4)
and `--nvd-concurrency` may be raised up to 10.

## Exit / output

`hackit util cve <target>` prints the briefing and, on `--json-out` / `--output`,
writes a structured JSON report with per-finding source metadata
(`match_type`, `confidence`) so you can tell engine-confirmed matches from
heuristic ones.
