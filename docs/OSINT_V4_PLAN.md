# OSINT v4 — Real-Source Expansion + CLI Rebuild

Status: in progress
Scope: `hackit/osint/*` — collectors, verdict engine, CLI presentation, JSON contract.
Constraint: **no API keys, no simulation**. Every finding must come from a live public
endpoint that answers without credentials.

---

## 1. Problems being fixed

| # | Symptom | Root cause |
|---|---------|-----------|
| 1 | `POSSIBLE` on Google Fonts / Google Groups / Google Patents for `torvalds` | Generic `200 OK` treated as evidence; no soft-404 detection |
| 2 | Only 6 verified live profile sources | `live_sources.py` covers GitHub, GitLab, Reddit, Keybase, Gravatar, Mastodon only |
| 3 | Only 3 domain sources | crt.sh + dns.google + ip-api |
| 4 | Table truncated at 80 rows, `… 756 more` | `print_results` hard-caps and dumps one flat table |
| 5 | `--json` output is not parseable | Global banner writes to stdout before JSON |
| 6 | No signal separation | Hits, guesses, dead ends, live API data all rendered at the same weight |
| 7 | No pagination / grouping in live intel | Single `VERIFIED PUBLIC PROFILES` table |

---

## 2. Source matrix (target)

### 2.1 Identity / profile collectors — keyless JSON APIs

| Source | Endpoint | Kind | Yields |
|--------|----------|------|--------|
| GitHub | `api.github.com/users/{u}` + `/repos` | JSON | name, bio, company, location, blog, email, followers, repos, created |
| GitLab | `gitlab.com/api/v4/users?username=` | JSON | name, bio, location, created |
| Reddit | `reddit.com/user/{u}/about.json` | JSON | karma, bio, created, avatar |
| Keybase | `keybase.io/_/api/1.0/user/lookup.json` | JSON | full name, bio, location, **proofs** (cross-platform links) |
| Gravatar | `gravatar.com/{md5}.json` | JSON | name, bio, location, **linked accounts** |
| Mastodon (multi-instance) | `{inst}/api/v1/accounts/lookup?acct=` | JSON | display name, bio, followers, created — try 5 instances |
| HackerNews | `hn.algolia.com/api/v1/users/{u}` | JSON | karma, about, created |
| StackExchange | `api.stackexchange.com/2.3/users?inname=` | JSON | reputation, badges, location, website |
| Dev.to | `dev.to/api/users/by_username` | JSON | name, bio, location, github/twitter handles |
| Hashnode | `gql.hashnode.com` (public GraphQL) | JSON | name, bio, social |
| Codeberg | `codeberg.org/api/v1/users/{u}` | JSON | Gitea profile |
| npm | `registry.npmjs.org/-/user/org.couchdb.user:{u}` | JSON | name, email (if public) |
| PyPI | `pypi.org/pypi/{u}/json` (package name probe) | JSON | package owner signal |
| Docker Hub | `hub.docker.com/v2/users/{u}/` | JSON | name, company, location, created |
| Chess.com | `api.chess.com/pub/player/{u}` | JSON | name, location, joined, followers |
| Lichess | `lichess.org/api/user/{u}` | JSON | name, bio, created, playtime |
| Roblox | `users.roblox.com/v1/usernames/users` | JSON (POST) | id, display name, created |
| Steam | `steamcommunity.com/id/{u}/?xml=1` | XML | steamID64, avatar, created |
| Twitch | `decapi.me/twitch/…` or public GQL | JSON | exists signal |
| VK | `vk.com/{u}` scrape | HTML | name, city (public pages) |
| Telegram | `t.me/{u}` scrape | HTML | title, bio, member count |
| YouTube | `youtube.com/@{u}` scrape | HTML | channel name, subscriber text |
| Pinterest | `pinterest.com/{u}/` scrape | HTML | display name, follower count |
| Tumblr | `{u}.tumblr.com/api/read/json` | JSON | blog title, posts |
| Medium | `medium.com/@{u}` scrape | HTML | name, bio |
| Bluesky | `public.api.bsky.app/xrpc/app.bsky.actor.getProfile` | JSON | handle, display name, bio, followers |
| HackerOne | `hackerone.com/{u}.json` | JSON | reputation, signal |
| Bugcrowd | `bugcrowd.com/{u}` scrape | HTML | researcher handle |
| TryHackMe | `tryhackme.com/api/user/username/{u}` | JSON | rank, rooms |
| HackTheBox | `labs.hackthebox.com/api/v4/user/profile/basic/{id}` (public) | JSON | rank |
| CTFtime | `ctftime.org/api/v1/users/{id}/` | JSON | team |
| SoundCloud | `soundcloud.com/{u}` scrape | HTML | name, followers |
| Spotify | `open.spotify.com/user/{u}` scrape | HTML | display name |
| Flickr | `flickr.com/people/{u}/` scrape | HTML | name |
| Letterboxd | `letterboxd.com/{u}/` scrape | HTML | name, films |
| Goodreads | `goodreads.com/{u}` scrape | HTML | name, books |
| Wattpad | `wattpad.com/user/{u}` scrape | HTML | name, followers |
| About.me | `about.me/{u}` scrape | HTML | name, bio |
| Linktree | `linktr.ee/{u}` scrape | HTML | links |
| Beacons | `beacons.ai/{u}` scrape | HTML | links |
| Kaggle | `kaggle.com/api/v1/users/{u}` | JSON | name, bio, tier |
| Replit | `replit.com/api/v0/users/{u}` | JSON | name, bio |
| CodePen | `codepen.io/{u}` scrape | HTML | name |
| Product Hunt | `producthunt.com/@{u}` scrape | HTML | name, bio |
| Odysee | `odysee.com/$/api/proxy?…` (public) | JSON | channel |
| Rumble | `rumble.com/user/{u}` scrape | HTML | name |
| Kick | `kick.com/api/v2/channels/{u}` | JSON | bio, followers |
| Dailymotion | `dailymotion.com/api/user/{u}` | JSON | name |
| Vimeo | `vimeo.com/api/v2/{u}/info.json` | JSON | name, bio, location |
| Behance | `behance.net/{u}` scrape | HTML | name, city |
| Dribbble | `dribbble.com/{u}` scrape | HTML | name, bio |
| Gitea/Codeberg | `codeberg.org/api/v1/users/{u}` | JSON | profile |

### 2.2 Domain / digital footprint — keyless

| Source | Endpoint | Yields |
|--------|----------|--------|
| crt.sh | `crt.sh/?q=%25.{d}&output=json` | certificate subdomains |
| HackerTarget | `api.hackertarget.com/hostsearch/?q={d}` | subdomains + IPs |
| RapidDNS | `rapiddns.io/subdomain/{d}?full=1` | subdomains |
| dns.google | `dns.google/resolve` (A/MX/NS/TXT/CNAME/SOA/CAA) | DNS records |
| RDAP | `rdap.org/domain/{d}` | registrar, dates, status, nameservers |
| Wayback CDX | `web.archive.org/cdx/search/cdx?url=…&output=json` | snapshot count, first/last |
| Common Crawl index | `index.commoncrawl.org/CC-MAIN-2024-10-index?url=…&output=json` | crawl presence |
| urlscan.io | `urlscan.io/api/v1/search/?q=domain:{d}` | recent scans, IPs, ASNs |
| AlienVault OTX | `otx.alienvault.com/api/v1/indicators/domain/{d}/general` | pulse count, passive DNS |
| InternetDB (Shodan keyless) | `internetdb.shodan.io/{ip}` | open ports, hostnames, CVEs, tags |
| ip-api | `ip-api.com/json/{ip}` | geo + ASN |
| ipinfo.io | `ipinfo.io/{ip}/json` | geo fallback |
| Team Cymru whois | `whois.cymru.com:43` | ASN |
| crt.sh org | `crt.sh/?O=…` | sibling domains (optional) |
| HSTS preload | `hstspreload.org/api/v2/status?domain=` | preload status |
| SSL Labs | `api.ssllabs.com/api/v3/analyze?host=` (rate-limited) | grade |
| Mozilla Observatory | `httpobs-api.todaysai.com/analyze?host=` | score |

### 2.3 Email / breach / credential — keyless

| Source | Endpoint | Yields |
|--------|----------|--------|
| Gravatar (hash) | `gravatar.com/{md5}.json` | profile + linked accounts |
| PGP keyservers | `keyserver.ubuntu.com`, `keys.openpgp.org` | key presence, UIDs |
| HIBP (public, no key) | **not available** — replaced with: | |
| Breach directory dumps | `psbdmp.ws/api/search/{q}` | pastebin dumps mentioning the address |
| DeHashed public? | no | — |
| EmailRep | `emailrep.io/{email}` (public, rate-limited, no key) | reputation, profiles, breaches flag |
| Have I Been Pwned (unauthenticated page scrape) | `haveibeenpwned.com/account/{email}` | breach names in HTML |
| Hunter.io public? | no | — |
| MX / SPF / DMARC | dns.google TXT | mail posture |
| Disposable check | local list | throwaway domain |
| GitHub commit email search | `api.github.com/search/commits?q=author-email:` (unauth, 10/min) | repo activity |

### 2.4 Username pivot / archive / leak — keyless

| Source | Endpoint | Yields |
|--------|----------|--------|
| Wayback CDX per-platform | `web.archive.org/cdx/search/cdx?url={profile}` | archived snapshots |
| psbdmp | `psbdmp.ws/api/search/{u}` | paste hits |
| Rentry search | `rentry.co` (site search via Google dork only) | link |
| GitHub code search | `api.github.com/search/code?q=` (needs auth) → fallback: `grep.app/api/search?q=` | code mentions |
| grep.app | `grep.app/api/search?q={u}` | code mentions across GitHub |
| Common Crawl | index lookup | page presence |
| HackerNews Algolia | `hn.algolia.com/api/v1/search?query={u}` | mentions |
| Reddit search | `reddit.com/search.json?q=` | mentions |
| StackExchange search | `api.stackexchange.com/2.3/search/excerpts?q=` | mentions |
| Mastodon search (public tag) | `mastodon.social/api/v2/search?q=` | mentions |

---

## 3. Verdict engine v2

Current: `200 OK` ⇒ `possible`. That is why Google Fonts shows up.

New order of evaluation, per probe:

1. **Hard miss** — status in site `miss_code`, or site `miss_body` marker, or global
   `NOT_FOUND_MARKERS`, or redirect to `/login`, `/signin`, `/404`.
2. **Blocked** — WAF/captcha markers ⇒ `unknown` (never `hit`).
3. **Soft-404** — response body identical (normalized) to the platform's known
   missing-page fingerprint, or body length within 2% of the platform's empty-page
   length ⇒ `miss`.
4. **Handle evidence** — normalized handle appears in `<title>`, `og:title`,
   `og:url`, canonical URL, or `@handle` in body ⇒ `hit` / high.
5. **Real-name evidence** — target's display name / first+last appear in title or
   `og:title` ⇒ `hit` / medium.
6. **Generic landing** — title is a platform slogan, body contains login/search
   boilerplate, and no handle/name evidence ⇒ `miss` (not `possible`).
7. **Content presence** — 200 + meaningful body (>2 KB after boilerplate strip)
   + no negative markers ⇒ `possible` / low.
8. Anything else ⇒ `unknown`.

Additional guards:
- `noindex` + "not found" ⇒ miss.
- Same final URL as platform root ⇒ miss.
- Response is JSON error (`{"error": …}`) ⇒ miss.
- Repeated identical body across 3+ probes of the same platform ⇒ soft-404 table.

`possible` is capped and **never counted as a hit** in the confidence score. Only
`hit` and `verified` feed scoring.

---

## 4. CLI presentation v4

Sections, in order, each collapsible by content:

1. **Header card** — target, canonical handle, engine, sources probed, elapsed.
2. **Signal summary** — `hits / verified / possible / dead ends / blocked` bar with
   confidence gauge.
3. **Confirmed identity** — live API profiles (the trustworthy block), one row per
   source with name, bio, location, followers, created, proofs.
4. **Confirmed profiles from sweep** — only `hit` rows, grouped by category,
   paginated (default 25, `--show N`).
5. **Cross-platform personae** — shared title clusters + Keybase/Gravatar proofs.
6. **Digital footprint** — DNS, RDAP, subdomains, Wayback, Common Crawl, urlscan,
   OTX, InternetDB ports/CVEs.
7. **Email / credential exposure** — MX posture, SPF/DMARC, Gravatar, PGP, breach
   signals, paste hits.
8. **Trace leads** — grouped dorks (identity / social / code / breach / records),
   paginated.
9. **Dead ends** — collapsed count only, expandable with `--show-misses`.
10. **Bench notes** — phase timing, sources that timed out.

Rules:
- No table ever renders `… N more` without a way to see them: `--show N`, `--all-rows`.
- Width-aware: URL column folds, no mid-word truncation of titles.
- `--json` writes **only** JSON to stdout (banner suppressed, step logs to stderr).
- `--quiet` = summary + hits only.
- `--no-banner` documented in help.

---

## 5. JSON contract

```jsonc
{
  "schema": "hackit.osint.v4",
  "query": "torvalds",
  "handles": ["torvalds"],
  "engine": "rust",
  "elapsed": 12.4,
  "summary": {
    "hits": 12, "verified": 3, "possible": 4,
    "miss": 700, "blocked": 30, "checked": 746,
    "sources": 800, "confidence": "MEDIUM", "score": 58
  },
  "identity": { "name_format": "...", "aliases": [] },
  "profiles": [ { "platform": "", "category": "", "status": "", "confidence": "",
                  "url": "", "title": "", "note": "", "verified": true } ],
  "live_intel": {
    "profiles": [ { "source": "", "kind": "profile|code|social", "name": "",
                    "url": "", "facts": {} } ],
    "domain": { "rdap": {}, "dns": {}, "geo": {}, "subdomains": [],
                "wayback": {}, "commoncrawl": {}, "urlscan": [],
                "otx": {}, "internetdb": {} }
  },
  "email": {}, "phone": {}, "correlation": {}, "trace_leads": [],
  "errors": [ { "source": "", "error": "" } ]
}
```

---

## 6. Execution order

1. `live_sources.py` — collector registry with `kind`, `weight`, per-collector
   timeout; add all sources in §2.1/§2.2/§2.3/§2.4 that answer without keys.
2. `core.py` — verdict v2 (soft-404, handle evidence, generic landing), wire new
   live phases, per-source error capture.
3. `formatter.py` — section renderer, pagination, grouped tables.
4. `__init__.py` — `--json` purity, `--show`, `--all-rows`, `--no-banner`, banner
   suppression for machine output, progress to stderr in JSON mode.
5. Verify: username (`torvalds`), domain (`github.com`), email
   (`torvalds@linux-foundation.org`), phone. All flags exercised.
6. Regression: port scanner + NSE + GUI untouched.

---

## 7. Acceptance criteria

- `hackit osint torvalds --json` parses with `json.load` from a clean pipe.
- Google Fonts / Google Groups / Google Patents do **not** appear as `POSSIBLE`.
- At least **25** keyless live profile collectors answer for a common handle.
- Domain run produces RDAP + DNS + subdomains + Wayback + urlscan/OTX/InternetDB
  when the domain resolves.
- No `… N more` without `--show`.
- Zero API keys required anywhere.
- Port scanner CLI/GUI/NSE still pass their existing smoke tests.
