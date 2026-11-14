# tech_hunter - technology fingerprinting

Defensive asset mapping and technology fingerprinting. Exposed as `hackit
web tech` and `hackit recon tech-hunter` (same underlying command).

## Usage

```bash
hackit web tech -t example.com
hackit recon tech-hunter -t example.com
hackit web tech banner       # banner only
hackit web tech scan -t example.com
```

## What it does

- HTTP response fingerprinting: headers, body markers, cookies, error pages,
  generator meta tags
- CMS/framework/server/language detection (WordPress, Drupal, Joomla, nginx,
  Apache, IIS, Django, Rails, Express, Spring, .NET, PHP, etc.)
- Version extraction where advertised
- Technology plus associated attack-surface notes

## Engine

Go engine (`go/` + `go_bridge.py`) compiles on demand; python fallback paths
exist in older code but the Go engine is the supported path.

## Output

Colored structured findings to stdout; JSON where `-o/--output` is supported
by the invoked subcommand. Results are fingerprints, not proof of
exploitability; validate before acting on them.

`-t/--target` is optional; the command runs interactively when omitted.

Authorized testing only. Fingerprinting leaves traces in server logs.
