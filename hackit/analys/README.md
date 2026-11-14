# analys - zero-flag deep analysis

One-command, no-long-flag deep scanner. Pass a file target for native malware
triage, or a host target for a 7-stage host deep scan. Always writes a JSON
report to `hackit/reports/analys/`.

## Usage

```bash
hackit analys [TARGET]          # prompts for target if omitted
hackit analys /path/to/sample   # file mode: malware triage
hackit analys https://host      # host mode: total deep scan
hackit analys https://host --pure   # host mode, skip AI assessment
```

## File mode

Runs the native malware pipeline:

- `hackit.malware.engine` - Rust `malwscan` + C `fastscan` for PE/ELF/Mach-O
- Hidden-malware detection: embedded PE, packers, NOP sleds, W+X sections
- IOC mining and verdicts (FP/entropy/API/capability profile)
- Exit code 1 when verdict is suspicious or malicious

## Host mode (7 stages)

1. Recon aggregation (`hackit.agent.external_tools`) - subdomains, endpoints, tech
2. Top-1000 port sweep, Go engine, tcp/service detection
3. Security headers audit (7 headers, graded A-D)
4. JS and secrets hunt (regex over up to 8 script srcs + main page)
5. Vuln probes - `hackit.agent.payloads` catalog: sqli/xss/ssrf/lfi/ssti/cmdi
   against common parameters (q,id,url,page,search), first 4 params, GET only
6. Webshell/dropper sweep of ~13 hardcoded paths with marker strings
   (eval(base64_decode, c99shell, FilesMan, ...))
7. AI assessment via `hackit.agent.brain.AIHyperBrain` (native engine)

## Output

Always written to `hackit/reports/analys/analys_<mode>_<slug>_<timestamp>.json`.
`--pure` skips the AI stage; AI failures degrade quietly to an unavailable note.
TLS verification is disabled by design in host mode; report contains raw probe output.

Authorized testing only. The vuln probe stage submits actual payloads.

## Notes

- No subcommands; target is positional, prompts if omitted.
- Host mode assumes https when scheme is missing; falls back to port probes 443/80.
- Exit code is always 0 on host mode, even with findings.
