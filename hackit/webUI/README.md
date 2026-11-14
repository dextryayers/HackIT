# HackIT Web UI - unified web dashboard

Astro + Python dashboard launched by `hackit run`. Serves a single-page UI
for orchestrating HackIT modules from the browser.

## Layout

- `src/`, `public/`, `dist/` - Astro frontend (components.json, astro.config.mjs)
- `main.py` - Python launcher/build manager: rebuilds the Astro bundle when
  sources change, then serves `dist/` and wires the API
- `python/orchestrator.py` - module orchestration hub: enumerates feature
  modules and routes API calls to them
- `python/modules/` - feature modules (threat intel, network mapping,
  CVE/malware analysis, OSINT lookups, firewall detection, cloud hunting,
  phishing/ransomware trackers, DNS/geo/ASN, etc.)
- `python/modules/rust_engine/`, `python/modules/go/` - native engines for
  the heavy lookups
- `data/` - cached lookup data; `package.json`/`package-lock.json` -
  frontend dependencies

## Usage

```bash
hackit run            # launch dashboard (browser)
hackit run --dev      # dev mode with live reload
```

The launcher rebuilds automatically if `src/` is newer than `dist/index.html`.

## API surface

The orchestrator exposes job endpoints consumed by the frontend. Modules
follow a common contract (`module_base.py`, `module_loader.py`): request in,
structured result out (JSON-serializable dict), streamed or polled by the UI.

Authorized testing only.
