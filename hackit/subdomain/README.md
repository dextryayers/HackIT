# subdomain - enumeration and attack-surface mapping (Go-powered)

Passive and active subdomain discovery with a Go engine and rich terminal UI.
Exposed as `hackit recon subdomains`.

## Usage

```bash
hackit recon subdomains -d example.com
hackit recon subdomains -d example.com --common -o out.json --output-format json
hackit recon subdomains -d example.com --passive-only
hackit recon subdomains -d example.com --active-only -w names.txt
hackit recon subdomains -d example.com --all --probe --tech-detect
```

## Main options

- `-d/--domain` - required, target domain
- `-w/--wordlist` - wordlist for active brute force (one name per line)
- `--common` - use built-in common wordlist (~350 entries)
- `--passive-only` - fast passive sources only
- `--active-only` - active brute force only
- `--hyper` - Hyper-Crawler (API-less massive scraping)
- `--permutations` - deep permutation scanning
- `--takeover` - high-precision subdomain takeover checks
- `--recursive` / `--deep` - adaptive depth recursive scanning
- `--stealth` - random UA, resolver rotation
- `--fast` - higher concurrency profile
- `--all` - max depth: common + permutations + takeover + probe
- `--doh` - DNS-over-HTTPS resolvers
- `--no-wildcard` - disable wildcard DNS filtering
- `--no-resolve` - skip DNS resolution of passive findings

## Display flags

`--sc` status codes, `--ip` addresses, `--title` page titles, `--server` server headers,
`--tech-detect`/`--tech` technology detection, `--asn` ASN data, `--probe` alive/dead status,
`-fc/--filter-codes` filter by status.

## Output

`-o/--output` file; `--output-format text|json|csv` (default text). Rich terminal
table for live feedback. `-t/--threads 100` (Go routines).

Authorized testing only. Active brute force against third-party DNS is loud; run it where you have scope.
