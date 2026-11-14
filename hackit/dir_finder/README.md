# hackit dirfinder — HackIT expert directory & file finder

Directory/file discovery engine with a **sniper marker** (`DIR` or `FUZZ`): everything in the URL stays fixed,
the marker slot is substituted with each wordlist entry.

## One-shot (no flags)

```bash
dirfinder
```

prints the banner + examples, then reads a free-form line:

```
input : https://example.com/DIR threads 25 sc 200,404 verbose on
```

`https://example.com/DIR` with `common.txt` is the default. Examples:

| input | what it fuzzes |
|---|---|
| `https://example.com/DIR threads 25 sc 200,404 verbose on` | path entries from `common.txt` |
| `https://example.com/DIR full threads 50` | same, but `dicc.txt` (deep) |
| `https://example.com/file.DIR sc 200` | extension fuzz from `wordlists/extensions.txt` |
| `https://FUZZ.example.com/ threads 30 sc 403,200` | virtual host fuzz from `wordlists/subdomains.txt` |
| `https://example.com/DIR exclude 404 recursive on` | path fuzz, 404s hidden, recursion on |
| `https://example.com/DIR wordlists /home/user/WD.txt` | external wordlist file (any path) |
| `https://example.com/DIR wordlists /home/user/lists/` | external folder — every `.txt/.lst/.list/.csv/.dic/.words` (or extension-less) inside, recursively |
| `https://example.com/DIR wordlists a.txt,/opt/lists` | mix of files and folders, comma-separated |

Keys (case-insensitive, anywhere on the line):
`threads/t N` (1-200, default 30) · `sc 200,403` · `exclude 404` · `ext php,bak` ·
`full` (db/dicc.txt, 9680 lines) · `subdomains` (subdomains.txt) · `method GET|POST|HEAD` ·
`verbose on|off` (bare = on) · `quiet` · `recursive on|off` ·
`delay N` · `timeout N` · `rate N` ·
`wordlists /path/to/list.txt[,/other/folder]` · `help` · empty input quits.

External lists are resolved at parse time: files must exist and be readable;
missing paths or folders without list files abort before any request is sent.
Custom lists are de-duplicated after merging.

Everything is streamed live: `[HH:MM:SS] <status> <size> <path>` with the
status colored (2xx green, 3xx yellow, 4xx orange, 5xx red), then a summary
`Requests | Found | Filtered | Errors`.

## Flag form (hackit dirfinder ...)

All original functionality remains as flags — see `hackit dirfinder --help`:
`-t` threads (default 5), `-e` extensions, `-w` wordlists, `-r` recursion,
`--api-mode`, `--detect-waf/--detect-tech`, `--json-body`, `--graphql`,
`--adaptive-rate`, sessions, wildcard calibration, smart-filter on by default.

Internal lists live in `hackit/dir_finder/db/` — path sniper defaults to
`db/categories/common.txt`, ext sniper to `db/extensions.txt`, `full` uses
`db/dicc.txt`, host sniper falls back to `hackit/wordlists/subdomains.txt`
(there is no subdomain list in db/). With no `-w`, the engine loads **every**
list under db/ recursively (dict + categories + cms + LFI + blacklists).

Sniper marker works in flag form too:

```bash
hackit dirfinder -u "https://example.com/DIR"           # marker auto-detected
hackit dirfinder -u "https://example.com/file.DIR"      # ext position auto-detected
hackit dirfinder -u "https://FUZZ.example.com/"         # host position auto-detected
```

When the marker is detected the engine substitutes in place, picks the right
default wordlist (`wordlists/common.txt` / `extensions.txt` / `subdomains.txt`;
override with `-w`), disables recursion, and displays the substituted path
(e.g. `/file.php`) instead of the bare payload.

## Output & filtering

- `-O` formats: `simple,plain,json,xml,md,csv,html`; `-o` output file; `--report` JSON report.
- Live SC badges; wildcard/soft-404 calibration suppresses fake hits automatically
  (plus `--smart-filter`).
- Response size/word/line/regex/header match & filter flags for precision control.

## Performance notes

Threads scale via `-t` (HTTP engine is keep-alive with per-host connection
caps ~`5×threads` capped at 100, 32 KB buffers, TCP_NODELAY on dial, TLS 1.2+,
HTTP/2 attempted automatically, redirects not followed by default). Wordlist
parsing skips `#` comments and blank lines; merged custom lists are de-duplicated. For sniper runs, `threads 30` is the
interactive default; the Go engine does not fall back to sequential requests.
