# KeyStrike v3 — Hydra-Class Brute Forcer

Status: in progress

Goal: a brute forcer that matches Hydra on throughput and beats it on
usability, with **real** protocol authentication on every lane, in both the
Rust engine and the Python CLI. No stubs, no fake success detection, no
"requires external tool" holes.

---

## 1. What is broken today (audit)

| Area | Problem | Severity |
|------|---------|----------|
| `rust_engine/target/` | **Not built.** Every Rust call returns "engine not built". | blocker |
| `main.rs` scheduler | One `tokio::spawn` **per combo**. 1M combos = 1M tasks + 1M `Semaphore` waiters. Memory blows up, throughput collapses. | blocker |
| `main.rs` progress | Progress printed by whichever worker happens to hit the modulo. Unordered, lossy, no ETA. | high |
| `main.rs` stop | No `-f` stop-on-first-hit. A hit still runs the whole matrix. | high |
| `main.rs` resume | None. A 4-hour run that dies at hour 3 starts over. | high |
| `http.rs` | Any status other than 401/403 counts as success — 404, 500, 302 all "found". | critical |
| `http.rs` | Only tries `GET /` with Basic auth. No form POST, no login-path, no failure-string matching. | critical |
| `redis.rs` | `get_connection()` is **blocking** and called inside async. Stalls the whole runtime. | critical |
| `ldap.rs` | Blocking `LdapConn` inside async. Same stall. | critical |
| `vnc.rs` | `des_feistel()` is a hash-like toy — **not DES**. VNC auth can never succeed. | critical |
| `smb.rs` | Handshake is hand-rolled and wrong (missing NTLM negotiate, wrong offsets, accepts `0xC0000022` as success). | critical |
| `telnet.rs` | Success = "response contains `$` or `#` or `>`". Any banner matches. | critical |
| `rdp.rs` | `Err("RDP requires external tool (Hydra)")`. | critical |
| `postgres.rs` / `mysql.rs` | Builds a whole sqlx pool per attempt (TLS setup, background tasks, teardown). ~50× slower than a raw handshake. | high |
| `smtp.rs` / `pop3.rs` / `imap.rs` | No TLS variants (465/993/995). Timeouts ignored. | high |
| `snmp.rs` | Success detection is `buf[0]==0x30 && last==0x00` → inverted. | high |
| `ftp.rs` | `suppaftp` blocking per attempt — fine, but no PASV/quit hygiene on failure. | medium |
| `engine.py` | `subprocess.run(capture_output=True)` — nothing streams. No live creds, no live progress. | high |
| `engine.py` | `run_hydra` path is dead (hydra not installed). Silent fallback to nothing. | high |
| `__init__.py` | Only one protocol per run. No `--all`, no service detection, no built-in wordlists. | high |
| `__init__.py` | Password list defaults to 5 entries. Not usable. | medium |

---

## 2. Subtasks

### ST-1 — Scheduler rewrite (Rust `main.rs`)  ← **current**

- Fixed-size worker pool (N async workers pulling from an atomic cursor).
  No task-per-combo. Memory is O(threads), not O(combos).
- `-f/--stop-on-first` — hydra's `-f`. Atomic stop flag, workers drain.
- `-C user:pass` colon file.
- `-e nsr` — null / same-as-login / reversed password generation.
- `--resume FILE` / `--checkpoint FILE` — atomic cursor persisted every 5 s,
  restart picks up at the last un-attempted combo.
- `--retries N` — per-combo retry on transport error (not on auth failure).
- Progress emitted from **one** reporter task at 4 Hz: attempted, total,
  found, speed (EMA), ETA, elapsed.
- `--max-blocking` runtime tuning so SSH/FTP blocking work scales past 512.
- NDJSON contract unchanged (`progress` / `found` / `complete` / `error`),
  plus new fields `eta`, `found_credentials`.

### ST-2 — Protocol correctness

- `http.rs`: failure-string matching, form POST, Basic fallback, redirect
  handling, per-target login path, explicit 2xx/3xx success rule.
- `redis.rs`: async `redis::aio::MultiplexedConnection` / `get_async_connection`.
- `ldap.rs`: `spawn_blocking` around `LdapConn` (ldap3 sync is the correct API).
- `vnc.rs`: real DES (add `des` crate or implement properly), correct key
  bit-reversal, VNC 3.3/3.7/3.8 negotiation.
- `smb.rs`: replace hand-rolled SMB2 with `pavao`/`smb` crate **or** correct
  NTLMSSP negotiate+challenge+authenticate (NTLMv2 response).
- `rdp.rs`: real CredSSP/NLA-less RDP auth via `rdp` crate or raw TPKT +
  X.224 + MCS + security exchange.
- `telnet.rs`: expect-style login prompt matching (`login:`, `Username:`,
  `Password:`), failure strings, success = prompt after password.
- `postgres.rs` / `mysql.rs`: raw startup/auth packet or a reused connection
  attempt, no pool construction.
- `smtp/pop3/imap`: implicit TLS variants, real timeouts.
- `snmp.rs`: correct ASN.1 response validation.
- `ftp.rs`: clean teardown, PASV not required for auth.

### ST-3 — Python engine + CLI

- `engine.py`: streaming `subprocess.Popen`, NDJSON line reader, callback per
  event. Live progress bar + live credential lines.
- Delete the dead hydra fallback (or keep it strictly as `--engine hydra`).
- `__init__.py`: `-P all` (probe every protocol), `--service-detect` (nmap-style
  banner grab to pick protocol from the port), built-in wordlists shipped in
  `hackit/bruteforcer/wordlists/`, `--combo-file`, `-e nsr`, `-f`.
- Rich result rendering: protocol, target, port, user:pass, elapsed, speed.

### ST-4 — Verification against live services

- Spin up local containers: OpenSSH, vsftpd, telnetd (busybox), Postfix,
  Redis (requirepass), MariaDB, PostgreSQL, VNC (x11vnc), Samba.
- Each protocol: wrong creds → no hit; right creds → exactly one hit.
- Measure attempts/sec on SSH with 1000 combos at 16/64/256 threads.

### ST-5 — Docs + integration

- `docs/BRUTEFORCER_V3_PLAN.md` status table.
- CLI help text, `bruter --help`, `bruter list-protocols` reflects reality.
- Regression: `hackit osint`, `hackit ports` untouched.

---

## 3. Acceptance criteria

- `cargo build --release` succeeds with no warnings on the new scheduler.
- 10k-combo SSH run at 256 threads: memory flat (< 100 MB), no task storm.
- Every protocol returns `found` only for a genuinely valid credential.
- `-f` stops within one in-flight window of the first hit.
- `--resume` restarts at the right combo index.
- Python CLI streams progress and prints `user:password` the moment it lands.
- Zero reliance on `hydra` being installed.
