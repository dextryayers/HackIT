# ssl_tool - SSL/TLS suite (Rust + Go + Python)

Interactive SSL/TLS analyzer. Enter a host and it probes the service on 443
(default) and merges results from three engines (Go primary, Rust, Python)
into one report.

## Usage

```bash
hackit ssl check
```

The command is interactive: it prints the banner and prompts for `Input Target`.
Accepts `host` or `host:port`. Type nothing, or `q`/`quit`/`exit`, to leave.

## What it reports

## Certificate

- Subject/issuer, expiry, days remaining
- Chain validity and ordering
- Signature algorithm and key size
- SAN/hostnames and wildcard scope
- Self-signed detection

## Protocols and ciphers

- TLS 1.0 through 1.3 support
- Weak cipher detection (RC4, 3DES/DES, NULL, export, anonymous)
- Key exchange and forward secrecy assessment
- CBC/HMAC combinations flagged where applicable
- RSA key size < 2048

## Vulnerabilities and features

- Known TLS implementation weaknesses surfaced by the engines
- Resumption/session tickets where reportable
- OCSP stapling presence (engine-dependent)
- TLS feature probing (SNI, ALPN, etc.)

## Output

Merged human-readable report; the Go engine performs the primary analysis,
Rust covers the deep path, and the Python path covers the remainder so the
report is complete even if one engine is unavailable.

## Layout

- `__init__.py` - interactive click command `check` under `hackit ssl`
- `core.py` - Python analyzer invoked when needed
- `go_bridge.py`, `rust/` - native engines when built

Authorized testing only. If used against a service you do not operate, confirm
scope in writing.
