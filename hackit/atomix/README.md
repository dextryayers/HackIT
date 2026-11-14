# atomix - template scanner (YAML/HTTP)

Nuclei-style YAML HTTP template scanner. Python bridge feeds flags to a
prebuilt Go binary (`go/atomix` or `go/bin/atomix`); the 310-template claim
in docs predates current state, the working pack is `template/` (59 YAML
files in 21 categories).

## Usage

```bash
hackit vuln atomix -u https://example.com
hackit vuln atomix -u https://example.com --severity high,critical
hackit vuln atomix --target-file targets.txt --json -o findings.json
hackit vuln atomix --list
hackit vuln atomix --stats
hackit vuln atomix --health
hackit vuln atomix --version
```

## Surface

`atomix` exposes ~120 options in grouped help sections:

- BASIC: `-u/--url`, `--target-file`, `--timeout`, `-c/--threads`, `--severity`,
  `--tags`, `--id`, `-m/--method`, `-p/--proxy`, `-r/--resolver`, `--silent`, `-v/--verbose`
- OUTPUT: `-o/--output`, `--json`, `--jsonl`, `--csv`, `--html`, `--md`, `--sarif`,
  `--stats`, `--metrics`, `--analytics`, `--no-color`, `--debug`, `--trace`
- TEMPLATE FILTER: `--author`, `--type`, `--exclude-tags`, `--exclude-severity`,
  `--exclude-pat`, `--scope-file`, `--exclude-file`
- PERFORMANCE: `--concurrency`, `--retries`, `--rate-limit`, `--rate-limit-minute`,
  `--delay`, `--pipeline`, `--bulk-size`, `--follow-redirects`, `--priority`,
  `--no-cache`, `--adaptive-rate`, `--keep-alive`, `--http2`, `--http2-downgrade`
- ADVANCED: `--custom-dir`, `--load`, `--from-git`, `--smart`, `--passive`,
  `--min-confidence`, `-w/--chain`, `--multi`, `--fuzz`, `--fuzz-recursive`,
  `--payloads`, `--detect-tech`, `--waf-skip`, `--waf-bypass`, `--api-discovery`,
  `--auth`, `--auth-token`, `--api-key`, `--custom-agent`, `--rand-agent`,
  `--cookie`, `--cookie-jar`, `-H/--header`, `--scan-all-ips`, `--exclude-ports`,
  `--interactsh`, `--oob-server`, `--monitor`, `--diff`, `--replay`, `--resume`
- HEADLESS: `--headless`, `--no-sandbox`, `--show-browser`, `--system-chrome`,
  `--headless-page-timeout`, `--headless-action-timeout`
- PROTOCOLS: `--proto dns|tcp|tls|all`, `--tls-impersonate`, `--dns-resolver`
- DISCOVERY/NOTIFY: `--uncover`, `--uncover-engine`, `--uncover-query`,
  `--push`, `--slack`, `--telegram`, `--dashboard` (`--dashboard-port`, `--dashboard-auth`)
- UTILITY: `--health`, `--update`, `--probe`, `--validate`, `--validate-deep`,
  `-l/--list`, `--list-sources`, `--completion`, `--config`, `--project`,
  `--allow-local-access`, `--version`, `--license`

## Engine

Go `Scanner` (engine.go): differential detection via baseline URL, DSL
expressions, request-scoped extractors (json/kval/dsl/regex),
case-insensitive matchers, deduplicator, resume tracker, host-error circuit
breaker, prioritized queue for critical/high templates, baseline cache.

Templates follow nuclei-style HTTP semantics converted to internal requests.

## Output

Stdout table by default; `-o` writes output sniffed by extension
(`.json/.jsonl/.csv/.sarif/.md/.html`). Machine mode: `--silent --jsonl`.
SARIF dedupes rules; `--html` with no `-o` writes `./report.html`.

## Notes

- The Go binary is not auto-built; if missing the bridge errors loudly.
- Template path is relative to the `go/` directory (`../template`).
- YAML template counts in docs have historically drifted from `template/` contents.
- TLS verification is relaxed in many paths by design.

Authorized testing only. YAML templates may submit real requests.
