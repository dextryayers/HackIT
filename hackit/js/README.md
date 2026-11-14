# hackit web js - Katana-style JavaScript & asset hunter

Crawls a target the way Katana does: pages, JS bundles, CSS, source maps,
WASM, framework templates and data/config files - from the main domain, its
subdomains and archive snapshots - then hunts secrets, endpoints and comments.

Usage:

```bash
hackit web js https://example.com
hackit web js -u https://example.com -o results.json   # older flag form still works via engine
```

## What it does

1. **Crawl** - starts at the URL, fetches pages (depth 10, concurrency 100),
   follows in-scope links, parses HTML/CSS/JS for asset references
   (script src, `import()`, webpack chunks, sourcemaps, workers, JSONP
   callbacks, GraphQL URLs, SSR/hydration data, import maps, WASM).
2. **Archive pass** - Wayback Machine + latest Common Crawl index for URLs
   the target is known to have served historically.
3. **Subdomains** - reads the subdomain phase for every reachable subdomain
   and crawls each with the same profile.
4. **Verification** - every `filemap` entry is a real HTTP 200. Nothing is
   invented; sizes (`length`) come from the live response.
5. **Hunting** - secrets (API keys, tokens, passwords in JS), notable
   comments, DOM sinks, endpoint candidates with confidence markers.

## Output

- Console: live crawl heartbeats, per-file verified 200 with sizes, subdomain
  progress, then a summary (fetched / verified 200 / JS / CSS / code files by
  extension / JS by host / files by host / sensitive findings).
- `js_<host>_<timestamp>.json` - full findings stream next to your CWD.
- `js_artifacts_<host>_<timestamp>.txt` - every verified-200 file grouped by
  extension and bucket (JS/TS, styles, source maps, WASM, data/config,
  framework templates, other), with lengths and referrer (`via <source>`).

Both artifact patterns are gitignored.

## Scope behavior

Out-of-scope media and logged-out routes are never fetched (they are only
reported as `[OUT-OF-SCOPE]`). Bare `vendor`-style bundles **are** crawled;
they are frequent sources of leaked endpoints and tokens. `node_modules`,
VCS paths and media files stay excluded. Depth/page caps still apply;
a crawl of a large site will hit `max-pages` rather than run unbounded.

Authorized use only: point this at systems you own or are allowed to assess.
