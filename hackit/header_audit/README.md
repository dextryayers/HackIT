# header_audit - security header auditor

Go-powered + Rust analysis of HTTP security headers, CORS, cookies, TLS,
caching, cache policy, and technology fingerprinting. Python orchestrates the
Go engine and optional Rust tools.

## Usage

```bash
hackit web headers -u https://example.com
hackit web headers -u https://example.com -o report.json
hackit web headers -u https://example.com --no-rust
```

## Checks

- Security headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
  Permissions-Policy, Strict-Transport-Security, COOP/COEP/CORP-style policies
- Cookies: Secure, HttpOnly, SameSite attributes
- CORS: origin reflection, wildcard, credentials with wildcard
- CORS preflight behavior where applicable
- TLS: protocol/cipher posture (via Go engine)
- Caching: Cache-Control/Pragma consistency and unsafe defaults
- Technology fingerprinting: common response-header signals

## Engines

- **Go engine** (`go/`) - primary auditor; compiles on demand via `get_engine()`
- **Rust tools** (`rust/`) - optional deep-analysis companion (`--rust`, default on)

`get_rust_engine().available()` probes availability; missing Rust tools print a
notice rather than aborting the run.

## Output

Console sections per category with colored findings and a summary count per
class (missing, dangerous, cookies, cors, tech, subdomains, csp, policy, coop).
`-o` writes JSON. `--no-rust` skips the optional Rust stage.

## Notes

- Requires Go; `ensure_compiled()` builds the engine if missing.
- Rust is optional and degrades gracefully.
- Findings are advisory; treat CSP findings as risk signals, not ground truth.
