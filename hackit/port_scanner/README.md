# HackIT PortStorm — port scanner

Four independent engines, one probe model. Every engine runs the same
per-port plan, so a banner, a protocol and a confidence score always belong
to the port that produced them.

## Usage

```bash
# default engine set (Go)
python3 main.py ports scan -t 10.0.0.5 -p top100

# explicit port specs
python3 main.py ports scan -t 10.0.0.5 -p 22,80,443,8000-8100
python3 main.py ports scan -t 10.0.0.5 -p all

# live dashboard
python3 main.py ports scan -t 10.0.0.5 -p top1000 --dashboard

# profile that runs every available engine and correlates the results
python3 main.py ports scan -t 10.0.0.5 -p top100 --profile comprehensive
```

Port specs accepted everywhere: `topN`, `top`, `default`, `all`/`full`,
comma lists and `lo-hi` ranges.

## Engines

| Engine | Entry point | Notes |
|---|---|---|
| Go | `go/` (`probe_engine.go`) | Reference implementation; runs Lua NSE scripts when `-script` is set. |
| Rust | `go/rustsrc/` (`banner.rs`) | Async scanner, same decoders, `--json` output. |
| Python | `banner_engine.py` | No build step; used by `--single-engine` paths and the `comprehensive` profile. |
| Lua | `lua/banner_probe.lua`, `scripts/probe_runner.lua` | Sandboxed `connect`/`send`/`receive`/`close`; also runs inside the Go engine. |

Build:

```bash
cd hackit/port_scanner/go && go build -o port_scanner .
cd hackit/port_scanner/go/rustsrc && cargo build --release
```

The Python orchestrator prefers `go/rustsrc/target/release/portstorm-rust`
over the prebuilt binaries in `bin/`, because those can lag the source tree.

## How probing works

For each open port the engine walks an ordered probe plan (protocol-specific
payloads, TLS handshake, HTTP request, MySQL greeting, Redis `INFO`, …),
reads until the socket goes quiet, and feeds the accumulated bytes through
protocol decoders. The first decode that reaches confidence ≥ 0.80 stops the
plan — the remaining probes would only add noise.

Each record carries:

| Field | Meaning |
|---|---|
| `banner` | Decoded, whitespace-collapsed evidence, capped at 260 chars. |
| `banner_protocol` | `ftp`, `ssh`, `smtp`, `mysql`, `redis`, `vnc`, `http`, `tls`, `unknown`. |
| `product` / `version` | Split from the banner (`nginx` + `1.25.3`). Empty when nothing was decoded — raw text is never turned into a version. |
| `banner_confidence` | 0.0–1.0. Decoders report their own certainty; `unknown` stays at 0.30. |
| `banner_evidence` | Which decode produced the result (`greeting`, `http`, …). |
| `banner_mismatch` | The service is real but sits on a port it does not normally use. |

### Mismatch is informational

`expectedPortsFor` / `expected_ports` / `EXPECTED_PORTS` list the ports each
protocol normally binds to, including the usual alternates (`2222`, `8080`,
`16379`, `5901`, …). A hit outside that list sets `banner_mismatch=true` and
subtracts 0.05 from confidence — the banner is still the evidence, so the
service is never downgraded or relabelled. `http`, `https` and `tls` are
expected anywhere and never mismatch.

The port penalty is applied exactly once, in `finalize` — text classifiers
report raw decoder confidence.

## Output

The CLI table is ANSI-safe and pads on visible width:

```
╭─────────────────────────────────────────────────────────────────────────────────────────╮
│ PORT SCAN RESULTS — 127.0.0.1                                                           │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ PORT         STATE      SERVICE          PROTOCOL      CONF   BANNER / VERSION         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 3306/tcp     OPEN       MySQL            mysql          98%   MySQL 11.8.6-MariaDB-0+… │
│ 18021/tcp    OPEN       FTP              ⚠ ftp          87%   ⚠ 220 (vsFTPd 3.0.5)     │
│ 18080/tcp    OPEN       —                unknown        30%   hello from an unidentif… │
╰─────────────────────────────────────────────────────────────────────────────────────────╯
```

`⚠` marks a protocol/port mismatch. `--dashboard` renders the same fields
live: progress, throughput, per-engine rows and a service table.

## JSON probe definitions

`probes/probes/*.json` holds protocol payloads and match rules. Validate them:

```bash
cd hackit/port_scanner && python3 python_probes.py validate probes/probes
```
