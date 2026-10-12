# HackIT Engine Upgrade Plan v2.1 Pro Part 2: Powerful, Akurat, Real Time

Lokasi: `D:\koding\HackIT`
Versi target: tetap `2.1` (bukan naik versi). Part 2 ini adalah hardening internal menuju `2.1 Pro`.
Tanggal revisi: 2026-10-12
Ruang lingkup: semua modul tools di `hackit/` KECUALI `hackit/agent/` dan `hackit/webUI/`
Batas keras yang tetap berlaku:
- Tidak tambah command baru, subcommand baru, flag baru (`-` / `--`), atau ubah tampilan/banner/format output yang sudah ada.
- Hanya upgrade internal engine: logika deteksi, scoring, pipeline data, konkurensi, streaming, validasi, dan korelasi.
- JSON output boleh tambah field opsional baru, tidak boleh hapus atau rename field lama.
- Nomor versi di `hackit/__init__.py`, `setup.py`, dan `main.py` tetap `2.1`. Bukti peningkatan dicatat di `docs/ENGINE_CHANGELOG_v2_1_PRO.md`, bukan lewat bump versi.

## 0. Standar Pro Part 2

### 0.1 Definisi selesai part 2
Part 2 selesai bila tiap modul memenuhi tiga SLO sekaligus di lab tetap:
- SLO akurasi: precision dan recall di atas ambang di bagiannya masing masing, FP dan FN tercatat nol atau di bawah batas.
- SLO presisi: tiap temuan punya confidence plus alasan plus bukti yang bisa diaudit ulang dalam 60 detik oleh reviewer tanpa replay penuh.
- SLO real time: temuan pertama keluar cepat, progress tidak pernah diam lebih dari 500ms saat kerja besar, cancel bersih di bawah 2 detik.

Skala severity tetap: critical, high, medium, low, info, candidate.
Aturan confidence tetap:
- 0.90 sampai 1.00: confirmed, butuh dua bukti independen atau eksekusi tervalidasi 2x.
- 0.70 sampai 0.89: strong, butuh differential stabil 3x.
- 0.60 sampai 0.69: moderate, wajib `needs_review=true`.
- Di bawah 0.60: candidate saja.

### 0.2 Anggaran waktu real time global
- First finding: modul jaringan lokal di bawah 1000ms, modul web lokal di bawah 3000ms, modul brute/sqli blind di bawah 8000ms.
- Progress tick: max 500ms diam saat antrean tidak kosong.
- Cancel: SIGTERM ditangani, socket ditutup, worker berhenti, event done dengan `cancelled=true` keluar max 2000ms setelah sinyal.
- Stat tick: tiap 1000ms berisi rps, queue_depth, active_workers, timeouts, retries, p50_ms, p95_ms.

### 0.3 Prinsip anti FP part 2
- Satu sinyal tidak boleh jadi vuln. Minimal dua sinyal beda teknik atau satu bukti eksekusi plus satu bukti diferensial.
- Baseline per target wajib diambil sebelum klaim. Threshold global dilarang untuk konten dinamis.
- Token unik per probe. Tanpa token, refleksi tidak dihitung.
- Redaction wajib sebelum simpan finding atau log. Secret mentah tidak boleh masuk disk.

## FASE 0. Lab Tetap v2.1 dan Baseline Pro

### 0.A Lab yang dipakai
Pakai folder `tests/lab/` yang sama dengan part 1:
- `lab_http.py`: XSS 6 konteks, SQLi error/boolean/time/safe, redirect 5 kasus, header 4 profil, 403 dengan 5 rule, param 6 kasus, soft 404, JS bundle 3 secret asli plus 5 decoy.
- `lab_tcp.py`: 10 open acak, 5 filtered, 1 banner terpotong, 1 banner kosong, 1 service salah port.
- `lab_dns.py`: 5 valid, 1 wildcard, 1 CNAME chain, 1 NXDOMAIN.
- `lab_tls.py`: modern, legacy, expired, mischain.
- Tiap lab punya `expected.json`. Tidak ada nilai lolos tanpa cocok ke file ini.

### 0.B File baseline versi 2.1 Pro
- Simpan di `docs/baseline_v2_1_pro.json`. Isi per modul: precision, recall, F1, FP, FN, p50, p95, peak RAM, total request, rps, timeout rate, retry rate, commit git, versi Python/Go/Rust.
- Tanpa file ini, Fase 1 sampai 7 tidak boleh mulai. Ini mencegah klaim meningkat tanpa angka awal.

### 0.C Env tetap 2.1
- Venv dan `requirements.txt` 20 pin tetap. Tambah `requirements.lock` dari `pip freeze` untuk repro.
- Cek: `python -c "import click, rich, aiohttp, scapy"`, `python main.py --help`, `go version`, `cargo --version`, `lua -v`.
- Versi paket tidak boleh bump di part 2. Fokus ke logika, bukan dependency.

## FASE 1. Bus Real Time v2 dan Mesin Akurasi Shared

Dipakai semua `go_bridge.py` (16 file), `rust_bridge.py`, `cpp_bridge.py`, `python_bridge.py`.

### 1.A Protokol event JSONL v2
- Sub 1.A.1: Tiap baris stdout adalah satu event: `finding`, `finding_update`, `progress`, `stat`, `error`, `done`. Akhiri dengan newline dan flush langsung. Dilarang buffer lebih dari 1 event.
- Sub 1.A.2: Field wajib finding: `module`, `target_hash` (sha256 8 char), `vuln_class`, `severity`, `confidence`, `title`, `evidence_ref`, `elapsed_ms`, `run_id`. Field opsional: `needs_review`, `sources`, `remediation_id`.
- Sub 1.A.3: `finding_update` dipakai untuk pola partial lalu final (tech_hunter, header_audit, port service). Konsumen update by `finding_key`, bukan tambah duplikat.
- Sub 1.A.4: Python reader memakai thread baca baris non blocking dengan antrean max 5000. Bila penuh, tulis overflow ke file `run_overflow.jsonl` dan naikkan counter `dropped_to_disk`, bukan drop diam. Tidak ada event hilang tanpa catat.
- Sub 1.A.5: Exit code map tetap: 0 sukses, 2 input invalid, 3 network fail, 4 timeout, 5 internal. Stderr hanya untuk log engine, bukan untuk finding.

### 1.B Backpressure dan konkurensi adaptif
- Sub 1.B.1: Token bucket per modul. Default awal: web 50, port lokal 200, DNS brute 200 qps, brute login 10, sqli blind 4 pararel per param. Naik turun otomatis berdasar timeout rate.
- Sub 1.B.2: Aturan adaptif: bila timeout rate di atas 10 persen dalam jendela 5 detik, potong concurrency 50 persen dan tambah jitter 100 sampai 400ms. Bila di bawah 2 persen selama 10 detik, naikkan 25 persen sampai batas max. Catat tiap perubahan di stat event.
- Sub 1.B.3: Antrean prioritas: kandidat high value (param sink, port top 100, subdomain pendek) dikerjakan dulu agar first finding cepat. Sisa dikerjakan sesudahnya. Tidak ada starvation karena tiap 20 item prioritas diseling 5 item biasa.
- Sub 1.B.4: Batas resource: max 50000 record di memori, selebihnya streaming ke temp JSONL. Max stdout 20 MB per proses native, selebihnya rotasi ke file. Peak RAM target di bawah 500 MB untuk run standar.

### 1.C Kalibrasi dan comparator v2
- Sub 1.C.1: Kalibrasi HTTP 5 request acak per host plus per parent path untuk app dengan 404 beda section. Simpan `status_mode`, `len_median`, `struct_hash_mode`, `p50_ms`, `stddev_ms`.
- Sub 1.C.2: Fungsi `compare_resp` terpusat output `same`, `soft_diff`, `hard_diff` plus skor dan alasan. Bobot: struktur body 0.50, panjang ternormalisasi 0.20, header kunci 0.20, status makna 0.10. Token CSRF, timestamp, nonce diabaikan via normalisasi sebelum hash.
- Sub 1.C.3: Kalibrasi waktu: ambil 5 sampel normal, hitung p50 dan stddev. Threshold sleep = p50 + 4000ms. Bila stddev di atas 800ms, kunci confidence max 0.69 dan flag `unstable_network=true`.
- Sub 1.C.4: Kalibrasi DNS wildcard 2 token acak. Bila resolve, simpan IP wildcard dan filter semua hasil brute yang sama IP plus catat `filtered_wildcard` di stat.

### 1.D Merger, dedup, redact
- Sub 1.D.1: Dedup key = `module + target_hash + vuln_class + param + proof_hash`. Duplikat digabung ke `sources`. Tidak ada dua baris untuk bukti sama.
- Sub 1.D.2: Voting lintas engine: Go 0.50, Python 0.30, Rust/C 0.20. Naik 0.05 bila teknik beda dan bukti independen, max 0.98. Turun 0.15 bila hanya satu teknik lemah.
- Sub 1.D.3: Redact sebelum tulis: Authorization, Cookie session, token query, password form diganti `***` plus hash 8 char untuk korelasi. Validasi dengan grep otomatis bahwa output lab tidak berisi secret mentah.

Kriteria terima Fase 1:
- First finding lab kecil sesuai anggaran 0.2.
- Tidak ada jeda progress lebih dari 500ms saat antrean ada isi.
- Cancel 10x uji selalu bersih di bawah 2000ms di Windows.
- Tidak ada secret mentah di finding, log, atau JSONL lab.

## FASE 2. Grup Recon v2.1 Pro Max

### 2.1 `port_scanner` (inti, 531 file)
Fokus: `hackit/port_scanner/__init__.py`, `core.py`, `go/` 40 file, `c/`, `cpp/`, `rust/`, `lua/`, `ruby/`, `probes/`, `bin/`.

Pipeline real time:
- Tahap A top 100 dulu, pancarkan tiap port selesai. Tahap B sisa 900. Tahap C UDP spesifik. Tahap D rescan ragu max 1x. Progress tiap 200ms.
- Worker async dengan slot terpisah untuk connect, banner, probe agar banner lambat tidak blokir connect cepat.
- First open target di bawah 1000ms di lab lokal. Total 1000 TCP p50 di bawah 15000ms.

Akurasi state:
- TCP: SYN-ACK valid cek seq/ack, RST valid cek flag. Retransmit 2x dengan timeout 1200ms lalu 2000ms sebelum label filtered. Cek ICMP unreachable type 3 code 1/2/3 untuk bedakan filtered vs closed.
- UDP: payload spesifik per port: 53 DNS version.bind, 123 NTP, 161 SNMP public, 137 NetBIOS, 1900 SSDP M-SEARCH. Tunggu 2500ms, kirim 2x. Tanpa respons tetap `open|filtered` confidence max 0.55, bukan filtered pasti.
- Banner: baca max 4096 byte, timeout 3000ms. Simpan `banner_status=full|truncated|empty|timeout`. Service tidak boleh ditebak dari empty/timeout di atas 0.45.

Presisi service:
- Skor: banner exact 0.95, probe spesifik 0.85, handshake perilaku 0.70, port default saja 0.45 plus `needs_review`. Tulis `reason` berisi rule id yang cocok.
- 20 service prioritas sampai F1 min 0.90 di lab sebelum tambah signature baru. Service salah port di lab harus tetap terdeteksi benar, bukan ikut nomor port.
- OS: fitur TTL minus hop estimasi, window, DF, TOS, options order. Toleransi 1 hop. Output `os_family` plus `os_confidence`. Di bawah 0.70 tulis `unknown` dan jangan paksa.

Anti FP list:
- Banner HTTP palsu berisi kata SSH tidak boleh jadi SSH bila handshake SSH gagal.
- RST dari middlebox tanpa banner tidak boleh jadi closed pasti bila retry menunjukkan inkonsistensi. Tandai `flaky` dan rescan 1x.
- UDP tanpa payload spesifik tidak boleh label open.

SLO dan uji:
- Recall open 1.00 untuk 10 open, filtered tepat 5/5, service precision min 0.90, FP service 0 untuk banner kosong/potong.
- Peak RAM di bawah 300 MB untuk 1000 port. Log memuat per port elapsed dan stage.

### 2.2 `network_scanner`
Fokus: `go_bridge.py`, `go/main.go`, scanner, utils.

Pipeline real time:
- Chunk /24 per 254 host. Host up dipancarkan saat 2 bukti terkumpul, tidak tunggu chunk selesai. Progress per chunk plus ETA.
- Slot ICMP/ARP/TCP terpisah agar fallback Windows tetap jalan paralel.

Akurasi:
- Capability detect di awal: tulis `cap_arp`, `cap_icmp`, `cap_tcp`, `npcap_present`. Pilih path terbaik yang tersedia dan catat `method_used` per host.
- Host up butuh 2 bukti: ARP+TCP, ICMP+TCP, TCP 2 port beda, atau ARP+reverse DNS konsisten. Satu bukti max 0.65 `likely_up`.
- OUI offline lokal. Unknown MAC tulis `vendor_unknown`, bukan tebak.

SLO dan uji:
- /30 lab recall 1.00, FP 0, selesai di bawah 15000ms, first host di bawah 2000ms.

### 2.3 `subdomain`
Fokus: `__init__.py`, `go_bridge.py`, `hyper_crawler.py`, worker 6.8 MB.

Pipeline real time:
- Pasif dulu, pancarkan tiap nama valid. Lalu brute dengan qps adaptif. Stat tiap 500ms: `qps`, `queue`, `cache_hits`, `filtered_wildcard`.
- Resolver pool dengan 2 resolver sistem plus 1 DoH fallback bila dikonfigurasi. Timeout 3000ms, retry 1x hanya untuk SERVFAIL/timeout, bukan NXDOMAIN.

Akurasi:
- Normalisasi RFC 1034, lowercase, punycode konsisten, buang `*.`, tolak label kosong atau 64+ char.
- Wildcard 2 token. Bila aktif, filter IP wildcard dan simpan bukti query token di debug.
- CNAME max 3 hop. Takeover hanya `candidate` bila CNAME ke layanan known dangling plus HTTP NXDOMAIN/service not found. Tanpa bukti HTTP, tidak boleh confirmed.
- Pisah field: `dns_exists`, `dns_ips`, `http_live`, `https_live`, `http_status`, `title_hash`, `cert_cn`.

SLO dan uji:
- 5 valid recall 1.00, wildcard FP 0, CNAME chain tercatat lengkap, 5000 kandidat lokal di bawah 20000ms.

### 2.4 `osint`
Fokus: `core.py`, `sources.py`, `breach.py`, `domain_intel.py`, `reporter.py`, `history.py`.

Pipeline real time:
- Fan-out per sumber paralel dengan timeout per sumber 12000ms. Hasil per sumber dipancarkan saat selesai. Cache hit dipancarkan di bawah 200ms.
- Progress `sources_done/total/throttled/failed`. Sumber 429 masuk backoff, bukan gagal total.

Akurasi:
- Normalisasi query dan simpan `query_norm` plus `query_hash` untuk dedup.
- Bobot: primer 1.0, agregator 0.6, cache lama 0.4. Tanpa URL bukti max 0.40.
- Identitas butuh 2 independen atau 1 primer plus 1 atribut cocok (avatar hash, bio exact, URL silang). Selain itu candidate.
- Phone E.164, email lowercase trim, username strip URL. Query duplikat untuk varian sama dilarang.

SLO dan uji:
- 10 query uji tanpa duplikat, tanpa secret di log, precision min 0.85 pada lab yang punya expected.

### 2.5 `tech_hunter`
Fokus: `brain.py`, `go_bridge.py`, Go 20 file, perbaiki `patch.py` path absolut.

Pipeline real time:
- Partial dalam 2000ms dari header plus HTML. Final setelah JS, favicon hash, TLS. Pakai `finding_update` dengan key sama agar tidak duplikat.
- Favicon hash dihitung async. JS bundle max 5 file pertama untuk partial, sisa untuk final.

Akurasi:
- Bobot: Server/X-Powered-By 0.25, meta/generator 0.30, bundle path 0.20, cookie khas 0.10, favicon 0.10, TLS CN/O 0.05. Hanya jumlahkan sinyal cocok.
- Versi butuh 2 lokasi konsisten untuk confidence min 0.70. Satu lokasi max 0.60 dan `version_unknown` bila ragu.
- Perbaiki `patch.py`: path relatif, cek ada, dry run, backup sebelum tulis. Hapus path `d:\web\...`.

SLO dan uji:
- 5 lab (wordpress, laravel, react, nginx only, custom) precision min 0.80, tidak ada map CVE bila versi di bawah 0.60.

## FASE 3. Grup Web Discovery v2.1 Pro Max

### 3.1 `web_fuzzer`
Fokus: `go_bridge.py`, `rust_bridge.py`, `cpp_bridge.py`, engine Go/Rust/C++.

Pipeline real time:
- Kalibrasi 404 dulu max 3000ms, lalu fuzz. Temuan verified langsung pancar. Stat rps dan queue tiap 500ms. Heartbeat tiap 2000ms saat worker tunggu respons lambat.
- Frontier queue prioritas: path admin/api/backup dulu, lalu wordlist urut, lalu ekstensi varian.

Akurasi:
- Baseline per parent path: 3 sampel acak. Similarity di atas 0.92 ke baseline = `soft_404`. Hard diff plus header makna beda = verified.
- Encode varian tercatat: plain, URL encode, double encode, unicode. Jangan campur skor lintas encode.
- Scope lock same host plus prefix awal. `out_of_scope_skipped` dicatat, bukan diam.
- Batas: max URL 10000, depth 5, file 2 MB. Lebih dicatat `truncated`.

SLO dan uji:
- 8 hidden recall 1.00, 2 soft 404 tepat terfilter, FP max 1. 2000 path di bawah 60000ms lab.

### 3.2 `dir_finder`
Fokus: `analyzer.py`, Go smart/session, `dir_finder.rb`, `sessions/`.

Pipeline real time:
- Checkpoint tiap 100 request dengan fsync. Resume lanjut offset, bukan ulang. Kalibrasi ulang bila `wordlist_sha256` berubah.
- WAF terdeteksi turunkan concurrency 50 persen otomatis dan aktifkan jitter. Catat `waf_detected` dan `throttled` di stat.

Akurasi:
- Ganti dummy `smart_analysis.json` dengan deteksi nyata: header WAF, body block page, tech hint dari tech_hunter bila ada di run gabungan, pola backup dengan cek content type dan magic bytes.
- 404 dinamis per parent. Backup `.bak .old .backup ~ .zip .tar.gz .swp` hanya verified bila magic cocok.

SLO dan uji:
- Kill di 50 persen lalu resume hasil identik 100 persen. FP max 2 persen.

### 3.3 `js`
Fokus: Go extractor, secrets, sourcemap, archive (20 file).

Pipeline real time:
- Parse streaming 256 KB per chunk. Secret candidate per file selesai langsung pancar. Progress `files_done/total/bytes/truncated`.
- Sourcemap hanya same origin, max 5 map per run awal agar cepat, sisa di final pass.

Akurasi secret plus validator ketat:
- AKIA 20 char prefix benar plus secret 40 char dekat max 500 char plus entropy min 4.2.
- Google AIza 39 char plus charset plus tolak string contoh docs.
- Slack `xox` plus panjang dan charset plus tolak `example/dummy`.
- JWT 3 segmen decode valid plus header JSON plus cek alg. Exp dicatat bila ada.
- Private key header footer cocok plus panjang min 200 char.
- Konteks exclude: file `example, test, mock, snapshot, docs` plus komentar `dummy/testkey`. Tandai `context_excluded` agar audit jelas.

Akurasi endpoint:
- Sumber: regex path, fetch/axios/XHR, OpenAPI JSON, string JS. Normalisasi hapus cache buster dan trailing slash. Klasifikasi api/static/external/sourcemap.

SLO dan uji:
- 3 asli recall 1.00, 5 decoy FP 0, api recall min 0.90.

### 3.4 `header_audit`
Fokus: Go 13 file, Rust 3 crate.

Pipeline real time:
- Kategori bertahap: hsts, csp, cors, cookie, tls_header. Tiap kategori pancar saat selesai. CORS 4 request update progress per request.

Akurasi:
- HSTS: HTTPS tanpa HSTS = high. max-age di bawah 15552000 = medium. Cek includeSubDomains dan preload. Tulis `max_age` angka.
- CSP: parse directive. `script-src` dengan `unsafe-inline/unsafe-eval/*` = high bila ada input reflektif, medium bila tidak. `frame-ancestors` menang atas X-Frame-Options. `object-src none` dicatat positif.
- CORS: Origin acak, null, subdomain, kosong. Kritikal hanya pantulan attacker plus `Allow-Credentials true`. Wildcard tanpa credentials = medium. Simpan `preflight_status`.
- Cookie: Secure/HttpOnly/SameSite, prefix `__Host-` wajib Secure plus Path=/ tanpa Domain, `__Secure-` wajib Secure. Session vs persistent dicatat plus `expiry_days`.

SLO dan uji:
- 4 profil lab tepat 100 persen. Tidak ada high tanpa bukti header value.

### 3.5 `403bypass`
Fokus: bypass_engine Go, `403.txt`, Bypass403Pro.

Pipeline real time:
- Baseline 403 dulu, lalu tiap teknik pancar bila confirmed. Gagal hanya progress. Urutan cepat dulu: normalize, slash/case, encode, header, verb.

Akurasi:
- Comparator `compare_resp` ke baseline plus kontrol 404. Confirmed butuh hard_diff plus marker konten asli. 200 dengan body sama baseline = `not_bypassed`.
- Simpan `technique`, `variant_hash`, `diff_score`, `proof_snippet_redacted`.
- Rate ketat agar tidak banjir header sensitif di luar lab.

SLO dan uji:
- 3 bypassable vs 2 tidak tepat 100 persen.

### 3.6 `params`
Fokus: `core.py`, scanner 6.6 MB.

Pipeline real time:
- Crawl form/link dulu pancar cepat, lalu brute 50 kandidat per tick. Tiap param confirmed langsung pancar dengan sink.

Akurasi:
- Token unik 12 char per kandidat. Aktif hanya bila token kembali (reflected) atau ubah Location/file/include.
- Klasifikasi: reflected, redirect_sink, file_sink, stored_candidate (muncul di fetch kedua). Tulis `sink_hint` untuk rantai internal ke sqli/xss/redirect.

SLO dan uji:
- 6 param lab tepat sink, FP 0.

## FASE 4. Grup Injection Kritis v2.1 Pro Max

Aturan grup: token unik wajib. Tanpa token, tidak ada klaim. Semua blind ukur jitter dulu.

### 4.1 `sqli`
Fokus: `__init__.py`, `advanced_scan.py`, `bypass.py`, `report.py`, worker 7.1 MB.

Pipeline real time:
- Urutan: error 1x cepat, boolean 3x, time 2x. Candidate dipancarkan per tahap. Time blind kirim heartbeat 2000ms.
- Pararel max 4 per param agar tidak campur timing. Pisah koneksi per percobaan agar keep alive tidak menipu latency.

Akurasi:
- Error per DB: MySQL, Postgres `PG::`, MSSQL `Unclosed quotation`, Oracle `ORA-`, SQLite `near`. Generik max 0.45.
- Boolean: pasangan true/false 3x token beda. 3/3 hard_diff baru strong. 2/3 max candidate.
- Time: p50 dari 5 normal. Threshold p50 + 4000ms. `SLEEP/pg_sleep` sesuai DB guess. 2x validasi. Stddev di atas 800ms kunci max 0.69 plus `unstable_network`.
- WAF: deteksi 403/406 plus body. Coba varian yang sudah ada: comment, whitespace `%09 %0a /**/`, case. Catat blocked vs passed.

Presisi dan safety:
- Bukti: payload hash, snippet 500 char redact, latency tiap coba, baseline. Dump lab max 1 baris bukti.
- Severity: error confirmed 0.95, boolean 0.85, time stabil 0.80.

SLO dan uji:
- 4 tipe lab tepat, FP 0. Blind per param di bawah 90000ms di lokal stabil.

### 4.2 `xss`
Fokus: bridges Go/Python, worker 6.1 MB, `payload.txt`.

Pipeline real time:
- Refleksi per param langsung pancar. Stored check async max 3 fetch dalam 10000ms tanpa blokir param lain.

Akurasi konteks:
- Deteksi: html text, attr double/single/unquoted, js single/double, js block, url param, html comment. Payload dipilih per konteks, bukan semua ke semua.
- Breakout valid wajib: quote/tag/kurung tutup benar. Rusak max candidate.
- CSP: ambil dari header bila ada. `script-src 'self'` ketat tanpa unsafe turun 1 severity plus `csp_may_block=true`. Ada unsafe/wildcard pertahankan.
- Stored: token submit lalu fetch ulang. Langsung = reflected_confirmed. Fetch ulang muncul = stored_candidate. Reload kedua session beda muncul = stored_confirmed.

SLO dan uji:
- 5 konteks tepat, 0 FP di endpoint encode benar.

### 4.3 `rce_modul`
Fokus: `rce_super.py`, Go detector/exploit/payloads, `rce.sh`.

Pipeline real time:
- Klasifikasi teknologi dulu, lalu canary per jenis. Tiap canary pancar hasil. Tidak ada batch buta 100 payload.

Akurasi:
- SSTI `{{7*7}}` jadi 49, EL `${7*7}`, command `;echo token` dan `|echo token`, deserial marker error, template path probe. Tiap jenis validator beda.
- Canary: echo token, sleep 2 dengan kalibrasi, DNS callback hanya lab. Dilarang rm/reboot/fork/wget luar di deteksi.
- Guard default tolak public IP untuk exploit aktif. Audit tiap coba: target_hash, technique, payload_hash, result.

SLO dan uji:
- 3 vuln vs 2 safe tepat, 0 aksi destruktif, critical hanya canary 2x valid.

### 4.4 `redirect`
Fokus: Go 6 file, binary 6.5 MB, 25 param existing.

Pipeline real time:
- Tiap param confirmed langsung pancar dengan chain lengkap.

Akurasi:
- 4 vektor: query, body, header, path. Follow max 2 hop. Confirmed hanya host akhir beda dan terkontrol.
- Bypass parser: `//evil`, `https:evil`, `/\/evil`, `%2f%2fevil`, `?next=//evil%2f`. Reflection only tanpa redirect = bukan confirmed.
- Cek Location plus meta refresh plus JS location sebagai sink kedua.

SLO dan uji:
- 3 vuln vs 2 safe tepat.

## FASE 5. Grup Vuln Intel dan Crypto v2.1 Pro Max

### 5.1 `cve`
Fokus: worker 6.3 MB, NVD.

Pipeline real time:
- Per tech pancar saat NVD selesai untuk tech itu. Cache hit instan. Stat cache hit vs miss.

Akurasi:
- Normalisasi: buang `-ubuntu1 -el8 -deb11`, pisah `-p1`, samakan CPE. Versi unknown tidak boleh match mayor. Max candidate.
- Cache 24 jam keyed CPE. 429 antre ulang max 3x dengan jeda. Simpan `nvd_fetched_at`.
- Prioritas: KEV true dulu, EPSS di atas 0.5, lalu CVSS. Tulis `remediation` versi fix bila ada.

SLO dan uji:
- 10 kasus FP max 1. Tidak ada critical tanpa versi jelas min 0.60.

### 5.2 `atomix`
Fokus: `go_bridge.py`, `go/`, `template/` 61 yaml.

Pipeline real time:
- Load 61 template dengan progress. Tiap match langsung pancar dengan template_id dan part.

Akurasi:
- Validasi: YAML, field wajib, regex compile, DSL and/or/not. Rusak tolak dengan file:line, batch lanjut.
- Regex timeout 1000ms anti ReDoS. Extractor versi untuk chaining cve internal.
- High risk hanya bila guard lab lolos. Default safe dulu.

SLO dan uji:
- 61 load sukses atau karantina jelas. 10 uji deterministik 100 persen sama.

### 5.3 `nse_scripts` dan `nse_engine.py`
Fokus: 298 `.nse`, runner, category_map, timeout_protect, optimizer.

Pipeline real time:
- Hasil per script streaming. Stat scripts_done/total/failed/timed_out tiap 1000ms.

Akurasi:
- Kategori ulang dari isi: categories, portrule/hostrule, string vuln. Perbaiki map salah label.
- Timeout 30000ms per script. Gagal tidak gugurkan batch. Simpan elapsed per script.
- Validasi `lua -e loadfile` 298 file. Gagal parse ke `quarantine/` plus laporan.

SLO dan uji:
- 50 script lab tanpa hang atau crash.

### 5.4 `ssl_tool`
Fokus: `core.py`, Go, Rust.

Pipeline real time:
- Tahap tcp, handshake, cert, cipher enum update progress. Cipher enum yang lama kirim heartbeat.

Akurasi:
- SSLv2/v3, TLS 1.0/1.1 = fail. TLS 1.2 cek cipher lemah. TLS 1.3 prefer.
- Tolak RC4, DES, 3DES, NULL, anon DH, export 40/56. Cek FS ECDHE/DHE dan AEAD plus server order.
- Cert: chain lengkap, SAN/CN wildcard benar, warn H-30/H-7, SHA1 fail, key 1024 fail, OCSP/SCT dicatat.
- Beda Python vs Go vs Rust ambil paling konservatif plus catat diff debug.

SLO dan uji:
- 4 profil tepat 100 persen.

## FASE 6. Grup Brute, Pressure, Wireless, Stub v2.1 Pro Max

### 6.1 `bruteforcer`
Fokus: `engine.py`, Rust 18 protokol.

Pipeline real time:
- Success instan pancar plus stop user itu saja. Stat attempts/rps/throttles tiap 1000ms.

Akurasi:
- Sequence per protokol benar termasuk CSRF fetch untuk HTTP form dan NTLM challenge untuk SMB. Timeout 5000ms. Retry hanya conn_fail max 2x.
- Klasifikasi auth_fail, conn_fail, rate_limited, locked, success. Success wajib verifikasi koneksi baru 1x.
- Anti lockout: throttle terdeteksi naikkan jeda 2x, lockout 2x stop otomatis. Max 10 concurrent.

SLO dan uji:
- 1 kredensial di 100 kandidat ketemu, tanpa ban lab. Tidak ada password di log.

### 6.2 `ddos` (lab measure only)
Fokus: `c/`, `go/`, `masking.py`, `engine_ddos`.

Pipeline real time:
- Stat 500ms: rps aktual, p50/p95 latency target, timeout rate, error rate, CPU pengirim.

Akurasi metric:
- Preflight tolak non RFC1918/non localhost. Tulis target_class.
- Auto stop: target diam 10000ms atau CPU pengirim di atas 90 persen 5 detik.
- Masking pakai `anonymity.py` existing. Tidak ada duplikat Tor logic.

SLO dan uji:
- Hanya lolos ke 127.0.0.1 dan 192.168.0.0/16 di uji.

### 6.3 `wireless`
Fokus: executor, engine_bridge, captive_portal, c_core, cpp_core, csharp_core, go_workers, rust_engine, plugins.

Pipeline real time:
- Stat tiap 1000ms: packets, clients, handshakes, deauth, bssid count. Handshake valid langsung pancar.

Akurasi:
- Capability detect: monitor, injection, driver, chipset. Unsupported tulis jelas plus saran adapter.
- Handshake wajib 4 way lengkap plus MIC valid plus replay naik. Parsial buang dengan alasan.
- Evil twin isolasi interface lab. Tidak bridge internet host. Lease dan DNS dicatat dengan MAC hash.
- Build: pindah `target_custom/` ke `target/` ignore. Dokumen cargo dan gcc flags.

SLO dan uji:
- Tanpa hardware tetap tidak crash, capability结论 jelas. Dengan lab adapter, handshake valid recall 1.00 untuk capture lengkap.

### 6.4 `sosialengineer` (stub)
- Putuskan arsip ke `docs/deprecated.md` atau minimal aman localhost dengan template lokal plus tracker token.
- Tidak ada kirim massal. Tidak ada import mati apa pun pilihan.
- Verifikasi: tidak ada referensi mati di `cli.py` dan docs.

## FASE 7. Korelasi Live dan Gate Rilis v2.1

### 7.A Korelasi tanpa command baru
- Struct final: `module, target_hash, vuln_class, severity, confidence, evidence_ref, sources, first_seen_ms, remediation_id, needs_review, finding_key`.
- Aturan:
  - tech versi plus cve plus atomix sama = satu finding 3 sources, severity max, confidence plus 0.05 max 0.98.
  - subdomain plus port plus tech = satu asset host, bukan 3 lepas.
  - params sink_hint plus sqli/xss/redirect confirmed = naikkan priority tambal.
- Schema check tiap handoff. Tidak valid ditolak dengan error jelas, bukan data korup lanjut.

### 7.B Benchmark v2.1 Pro dan gate blokir
Tulis `docs/benchmark_v2_1_pro.md` sebelum vs sesudah per modul. Ambang pro part 2:
- port: 1000 port p50 di bawah 15000ms, recall open 1.00, service precision min 0.90, first di bawah 1000ms.
- network: /30 recall 1.00 FP 0 di bawah 15000ms.
- subdomain: recall 1.00 FP 0, 5000 kandidat di bawah 20000ms.
- web_fuzzer/dir_finder: recall min 0.95 FP max 2 persen, resume identik.
- js: secret recall 1.00 FP max 5 persen, api recall min 0.90.
- header: 4 profil 100 persen, CORS kritikal tidak lolos.
- 403: 5 rule 100 persen.
- params: 6 param tepat FP 0.
- sqli: 4 tipe tepat FP 0, blind di bawah 90000ms.
- xss: 5 konteks tepat FP 0.
- rce/redirect: tepat 100 persen lab, 0 destruktif.
- cve: 10 kasus FP max 1.
- atomix: 61 load jelas, 10 uji deterministik.
- nse: 298 parse atau karantina, 50 run tanpa hang.
- ssl: 4 profil 100 persen.
- brute: 1 di 100 ketemu tanpa ban.
- ddos/wireless: guard lolos, stat live, tidak crash.
Gate: satu merah blokir rilis. RAM web di bawah 500 MB atau wajib streaming.

### 7.C Docs rilis tetap 2.1
- Isi atau hapus 18 README 0 byte dengan ringkasan engine plus cara rebuild. Pilih satu LICENSE (rekomendasi MIT sesuai setup.py) dan catat alasan di changelog.
- Tulis `docs/ENGINE_CHANGELOG_v2_1_PRO.md`: file diubah, logika baru, metric sebelum vs sesudah, cara rebuild native, risiko sisa.
- Tahap: alpha lab, beta staging terkontrol, stabil. Lampirkan JSONL mentah tiap tahap.
- Dilarang bump ke 2.2 di part 2. Bump hanya bila gate 7.B hijau semua dan disetujui terpisah.

## Lampiran A. Urutan Eksekusi Part 2

1. Fase 0 dan 1 sampai hijau. Tanpa stream dan kalibrasi, angka part 2 tidak sah.
2. Inti: port_scanner, sqli, xss.
3. Lalu: web_fuzzer, dir_finder, subdomain, tech_hunter, params, redirect.
4. Lalu: js, header_audit, 403bypass, cve, atomix, nse, ssl.
5. Lalu: network_scanner, osint, bruteforcer, rce_modul, ddos, wireless, sosialengineer.
6. Terakhir Fase 7 gate v2.1.

## Lampiran B. Risiko dan Mitigasi Part 2

- Build Go 434 dan Rust 219 gagal di Windows: kunci toolchain, sediakan `build_all.ps1`, fallback Python dengan confidence turun dan flag `engine_fallback`.
- Jitter tinggi: utamakan boolean/diferensial, kunci time blind max 0.69, flag unstable.
- WAF blokir: deteksi dulu, turunkan concurrency, catat blocked rate.
- OOM: streaming JSONL, batas 50000 memory, checkpoint 100.
- ReDoS regex: timeout 1000ms per match plus karantina pola lambat.
- Penyalahgunaan agresif: guard RFC1918/localhost, audit hash target, redact.

## Lampiran C. Checklist Selesai Part 2 Per Modul

- port: state tepat, F1 min 0.90, live per port, first di bawah 1000ms.
- network: 2 bukti per host, live instan, /30 hijau.
- subdomain: wildcard filter, dns vs http pisah, live per nama.
- osint: tanpa duplikat, evidence ada, cache cepat.
- tech: partial 2000ms lalu final, versi jujur.
- web_fuzzer/dir_finder: soft 404 filter, resume identik, live verified.
- js: validator ketat, endpoint klasifikasi, streaming chunk.
- header: severity beralasan, CORS 4 origin, live per kategori.
- 403: hard_diff, tolak error custom.
- params: token unik, sink tepat.
- sqli/xss/rce/redirect: bukti ganda, severity turun bila CSP/jitter buruk.
- cve/atomix/nse/ssl: versi bersih, template valid, parse 298, profil tepat.
- brute/ddos/wireless: klasifikasi tepat, guard lab, stat live.
- sosialengineer: arsip atau minimal aman, tanpa import mati.

Akhir dokumen part 2. Versi tetap 2.1. Setiap PR modul wajib lampirkan expected.json, hasil lab, diff metric sebelum vs sesudah, dan contoh event JSONL real time.
