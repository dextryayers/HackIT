# NSE scripts - Nmap-ish scripting pack for HackIT

Collection of ~305 `.nse` scripts executed by `hackit/nse_engine.py` ("HackIT
NSE-like Scripting Engine v2"). The engine categorizes scripts (discovery,
vuln, brute, exploit, dos, auth, default, intrusive, malware, safe), scores
severity, resolves dependencies and runs them in parallel.

## Layout

Scripts follow Nmap naming: `<verb>-<subject>.nse`

- `http-*.nse` (~69) - web audits, default credentials, exposed panels
- `ssl-*.nse` (~22) - TLS certificate/protocol checks
- `dns-*.nse` (~22) - name service audits and info disclosure
- `network-*.nse` (~20) - broadcast/service discovery
- `brute-*.nse` (~15) - credential brute against common services
- `cloud-*.nse` (~13) - cloud metadata/misconfiguration checks
- `malware-*.nse` (~10) - known malware port/service indicators
- `audit-*.nse` (~10) - anonymous access, default creds, weak config
- `cve-*.nse` (~8) - version-matched vulnerability probes
- `info-*.nse`, `auth-*.nse`, `exploit-*.nse`, `dos-*.nse` - remainders

## Usage

Scripts are not run directly. They are loaded by:

```bash
hackit analys          # deep-scan pipeline incl. NSE stage
hackit vuln ...        # via engine integration where wired
```

`nse_engine.py` validates Lua `.nse` files via subprocess, parses categories
from `description`/`categories` blocks, applies severity scoring, and
aggregates results into scan output. Malformed or slow scripts are quarantined
rather than executed blindly.

Authorized testing only. Many audit-* scripts perform intrusive checks and
must never point at systems you do not own or lack permission to test.
