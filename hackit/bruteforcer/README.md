# bruteforcer - KeyStrike multi-protocol brute force

Python front end around a Rust engine (`rust_engine/`). The CLI is a thin
launcher: collect target/candidates, hand to Rust, render the NDJSON stream
live. Fails loudly if the Rust binary is missing.

## Usage

```bash
hackit bruter                     # interactive console
hackit bruter list-protocols      # protocols + default ports
hackit bruter wordlists           # built-in wordlist counts
hackit bruter build               # cargo build --release
hackit bruter detect -t 10.0.0.5 -p 22 -p 2222
hackit bruter scan -P ssh -t 10.0.0.5 -u root -W passwords.txt
hackit bruter scan -P all -t 10.0.0.5 --userlist users.txt -W pass.txt -f -T 64
```

## Subcommands

- `list-protocols` - 23 entries with default ports (ssh 22, ftp 21, telnet 23,
  smtp 25, pop3 110, imap 143, http 80/443, ldap 389/636, mysql 3306,
  postgres 5432, mssql 1433, redis 6379, mqtt 1883, vnc 5900, smb 445,
  snmp 161, rdp 3389); vnc/snmp are userless
- `wordlists` - built-in wordlist statistics
- `build` - compile the Rust engine (`rust_engine/target/release/keystrike`)
- `detect` (`-t/--target`, `-p/--port` repeatable, `--timeout`) - banner-grab service ID
- `scan` (`-P/--protocol`, `-t/--target`) - actual brute force

## `scan` keys

- `-P/--protocol` - protocol name; `all` for auto-detect across default ports
- `-t/--target` - host or IP
- `-p/--port` - override default (0 = use default)
- `-u/--user`, `-U/--userlist`, `-w/--pass`, `-W/--passlist`, `-C/--combo-file user:pass`
- `-e/--extra` - `n` null, `s` same-as-user, `r` reversed
- `-T/--threads 32`, `--timeout 10`, `-f/--stop-on-first`, `--retries 1`
- `--rate`, `--wait` - pacing knobs (sleep-based)
- `--resume <cursor file>` - resume a previous run
- `--check` - verify only mode
- HTTP knobs: `--http-path`, `--http-method GET`, `--http-body` with `^USER^`/`^PASS^`,
  `--http-fail`, `--http-success`, `--http-header` (repeatable), `--http-tls`, `--http-force-basic`
- `-v/--verbose` (default on), `-q/--quiet`

## Engine

Rust worker pool, fixed-size, atomic cursor over the combo space, O(threads)
memory, bounded loops. The Rust binary emits NDJSON: `progress` (4 Hz throttled),
`found` (instant), `complete`, `error`. The Python layer streams lines and prints
credential findings as they land.

`detect_service` connects, reads banners, and applies protocol-aware probes
(FTP greeting, SSH banner, HTTP 401, SMB, LDAP bind, Redis PING).

## Output

Stdout only: live attempts or credentials + summary. The CLI writes no report
files (resume cursor is a temp artifact only). No brute output persists to disk
unless the caller redirects stdout.

Authorized testing only. Do not aim this at networks you do not own.

## Notes

- Rust toolchain required; `build` fails loudly without it.
- Interactive mode implies stop-on-first.
- `rate`/`wait` are sleeps, not token buckets.
- HTTP form detection is text matching, not parser-based.
- `target/release/` contains a prebuilt binary checked in.
