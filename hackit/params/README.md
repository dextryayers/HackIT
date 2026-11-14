# params - parameter discovery via public archives

ParamSpider-style parameter harvesting from public web archives, then optional
reflection/error fuzzing. Go engine does the heavy lifting; Python orchestrates.

## Usage

```bash
hackit web params -d example.com
hackit web params -u https://site.com/page?foo=bar
hackit web params -l domains.txt -o params.json
hackit web params -d example.com --fuzz --params q,id -s
```

## Modes

**Discovery (default)**

- `-d/--domain` - crawl public archives for the domain
- `-u/--url` - seed a single parameterized URL
- `-l/--list` - domains from file
- `-s/--stream` - stream discoveries live
- `--sources` - `wayback,otx,urlscan,commoncrawl` (comma separated)
- `-p/--placeholder FUZZ` - value placeholder used downstream by other tools
- `-o/--output` - JSON with parameter-bearing URLs

**Fuzz mode (`--fuzz`)**

- `--params q,id` - explicit parameter list to test
- `--payloads file` - custom payload file
- `--method` - `GET` or `POST`
- `--threads`, `--timeout`, `--proxy` for pacing/routing

Fuzz mode probes for parameter reflection and error signatures
(sql/error pages). Treat hits as candidates; validate manually.

## Engines

- Go engine (`go/`) - archive mining, URL collapse by parameter signature, DNS/liveness
- Python bridge (`go_bridge.py`) - spawn/bridge to the Go binary

Bare IP targets skip archive sources and liveness labeling (sources do not
index them). Wildcard DNS disables liveness labeling (labels unreliable).
Wildcard hosts are flagged, not silently dropped.

## Output

Parameter inventory by host and parameter name; `-o` JSON with collapsed
`(host, path, sorted params)` signatures and URLs.

Authorized testing only.
