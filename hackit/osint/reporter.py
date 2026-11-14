import json, os, base64, hashlib
from datetime import datetime


def _gravatar_url(email: str, size: int = 100) -> str:
    h = hashlib.md5(email.lower().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?s={size}&d=mp"


def generate_html_report(data: dict, output_path: str = "") -> str:
    q = data.get("query", "unknown")
    s = data.get("summary", {})
    hits, possible, checked = s.get("hits", 0), s.get("possible", 0), s.get("checked", 0)
    an = data.get("analysis", {})
    conf = an.get("confidence", "NONE")
    score = an.get("confidence_score", 0)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    profiles = data.get("profiles", [])
    hits_p = [p for p in profiles if p.get("status") == "hit"]
    poss_p = [p for p in profiles if p.get("status") == "possible"]
    miss_p = [p for p in profiles if p.get("status") == "miss"]
    unk_p = [p for p in profiles if p.get("status") == "unknown"]

    blocked_notes = []
    for p in profiles:
        note = (p.get("note") or "").lower()
        if p.get("status") == "unknown" and any(k in note for k in ("rate-limited", "429", "blocked", "waf", "captcha", "wall")):
            blocked_notes.append((p.get("platform", "?"), p.get("note", ""), p.get("url", "")))
    notes_html = ""
    if blocked_notes:
        items = "".join(
            f'<li style="margin:4px 0"><strong>{plat}</strong> — {note} '
            f'<a href="{url}" target="_blank" style="color:#888;font-size:12px">link</a></li>'
            for plat, note, url in blocked_notes[:15])
        notes_html = ('<div class="section fade-in"><h2>Verification Notes — '
                      f'{len(blocked_notes)} probes throttled/blocked</h2>'
                      '<p style="color:#aaa;margin-bottom:8px">These platforms answered with rate-limit or anti-bot walls. '
                      'They returned no evidence either way — rerun with <code>--retry 3</code> or from another network '
                      'before treating the result set as complete.</p>'
                      f'<ul style="color:#ddd;font-size:13px;line-height:1.7">{items}</ul></div>')

    corr = data.get("correlation", {}) if isinstance(data.get("correlation"), dict) else {}
    persona_html = ""
    for cluster in (corr.get("shared_title_clusters", []) or [])[:6]:
        plats = ", ".join(cluster.get("platforms", [])[:8])
        persona_html += f'<p style="margin:6px 0">◆ <strong>{cluster.get("count", 0)}x</strong> <span style="color:#888">{plats}</span></p>'

    def pct(n): return round(n / checked * 100, 1) if checked else 0

    rows = ""
    for p in profiles:
        plat = p.get("platform", ""); url = p.get("url", "")
        st = p.get("status", ""); cat = p.get("category", "")
        title = p.get("title", "")[:100]
        icon = {"hit": "✅", "possible": "❓", "miss": "❌", "unknown": "⚠️"}.get(st, "➖")
        bg = {"hit": "rgba(0,200,83,.12)", "possible": "rgba(255,145,0,.1)", "miss": "rgba(255,23,68,.08)", "unknown": "rgba(158,158,158,.08)"}.get(st, "")
        cl = {"hit": "#00e676", "possible": "#ff9100", "miss": "#ff1744", "unknown": "#9e9e9e"}.get(st, "#666")
        link_display = url[:120] + (".." if len(url) > 120 else "")
        conf_v = (p.get("confidence") or "?").upper()
        conf_cl = {"HIGH": "#00e676", "MEDIUM": "#ffd740", "LOW": "#ff9100"}.get(conf_v, "#9e9e9e")
        rows += f"""<tr style="background:{bg}">
            <td style="padding:10px 12px;text-align:center">{icon}</td>
            <td style="padding:10px 12px;font-weight:600">{plat}</td>
            <td style="padding:10px 12px"><span class="badge" style="background:{cl}">{st.upper()}</span> <span class="badge" style="background:{conf_cl};font-size:10px;opacity:.85">{conf_v}</span></td>
            <td style="padding:10px 12px;color:#888;font-size:13px">{cat}</td>
            <td style="padding:10px 12px"><a href="{url}" target="_blank" class="truncate" title="{url}">{link_display}</a></td>
            <td style="padding:10px 12px;color:#aaa;font-size:12px">{title}</td>
        </tr>"""

    email = data.get("email", {})
    email_html = ""
    if email:
        email_html = '<div class="section fade-in"><h2>📧 Email Intelligence</h2>'
        if email.get("is_email"):
            email_html += f'''<div class="grid-2">
                <div class="info-card"><span class="label">Email</span><span class="value">{email.get("input","")}</span></div>
                <div class="info-card"><span class="label">Domain</span><span class="value">{email.get("domain","N/A")}</span></div>
                <div class="info-card"><span class="label">MX Records</span><span class="value">{', '.join(email.get("mx_records",[])[:3]) or 'None'}</span></div>
                <div class="info-card"><span class="label">Secure MX</span><span class="value" style="color:{"#00e676" if email.get("mx_secure") else "#ff9100"}">{"✓ Yes" if email.get("mx_secure") else "No"}</span></div>
                <div class="info-card"><span class="label">Gravatar</span><span class="value" style="color:{"#00e676" if email.get("gravatar",{}).get("exists") else "#888"}">{"✓ EXISTS" if email.get("gravatar",{}).get("exists") else "✗ None"}</span></div>
                <div class="info-card"><span class="label">PGP Key</span><span class="value" style="color:{"#00e676" if email.get("pgp_key") else "#888"}">{"✓ Found" if email.get("pgp_key") else "None"}</span></div>
            </div>'''
        else:
            cands = email.get("candidates", [])
            signals = email.get("candidate_signals", [])
            email_html += f'<p style="color:#aaa">Email not detected — {len(cands)} candidates generated</p>'
            if signals:
                email_html += '<h3 style="margin-top:15px;font-size:15px">✅ Live Emails Found via Gravatar:</h3>'
                for s in signals[:10]:
                    email_html += f'<div class="tag">{s.get("email","")}</div>'
            if cands:
                email_html += '<h3 style="margin-top:15px;font-size:15px;color:#aaa">Possible Candidates:</h3>'
                for c in cands[:20]:
                    email_html += f'<span class="tag">{c}</span>'
        breaches = email.get("breaches", [])
        if breaches:
            email_html += '<h3 style="margin-top:20px;color:#ff5252;font-size:15px">⚠️ Data Breaches Found</h3>'
            for b in breaches[:10]:
                if isinstance(b, dict):
                    email_html += f'''<div class="breach-item">
                        <strong>{b.get("source","Unknown")}</strong>
                        <span style="color:#aaa;font-size:12px;margin-left:10px">{b.get("date","")}</span>
                        <p style="color:#ddd;font-size:13px;margin-top:4px">{b.get("data_class","")}</p>
                    </div>'''
        email_html += '</div>'

    phone = data.get("phone", {})
    phone_html = ""
    if phone and "error" not in phone:
        phone_html = f'''<div class="section fade-in"><h2>📱 Phone Intelligence</h2>
        <div class="grid-2">
            <div class="info-card"><span class="label">Number</span><span class="value">{phone.get("number","")}</span></div>
            <div class="info-card"><span class="label">Country</span><span class="value">{phone.get("country","N/A")}</span></div>
            <div class="info-card"><span class="label">Carrier</span><span class="value">{phone.get("carrier","N/A")}</span></div>
            <div class="info-card"><span class="label">Line Type</span><span class="value">{phone.get("line_type","N/A")}</span></div>
            <div class="info-card"><span class="label">Location</span><span class="value">{phone.get("location","N/A")}</span></div>
        </div>'''
        soc = phone.get("social_found", [])
        if soc:
            phone_html += f'<h3 style="margin-top:15px;font-size:15px">Social Apps: {" · ".join(f"<span class=\"tag\">{s}</span>" for s in soc)}</h3>'
        mentions = phone.get("google_mentions", 0)
        if mentions:
            phone_html += f'<p style="color:#aaa;margin-top:10px">🌐 ~{mentions} Google mentions</p>'
        snips = phone.get("google_snippets", [])
        if snips:
            phone_html += '<div style="margin-top:10px">'
            for sn in snips[:3]:
                phone_html += f'<p style="color:#888;font-size:13px;padding:6px;background:rgba(255,255,255,.05);border-radius:6px;margin:4px 0">{sn}</p>'
            phone_html += '</div>'
        phone_html += '</div>'

    domain = data.get("domain", {})
    domain_html = ""
    if domain:
        domain_html = f'''<div class="section fade-in"><h2>🌐 Domain Intelligence</h2>
        <div class="grid-2">
            <div class="info-card"><span class="label">Domain</span><span class="value">{domain.get("domain","")}</span></div>
            <div class="info-card"><span class="label">Registrar</span><span class="value">{domain.get("registrar","N/A")}</span></div>
            <div class="info-card"><span class="label">Created</span><span class="value">{domain.get("creation_date","N/A")}</span></div>
            <div class="info-card"><span class="label">Expires</span><span class="value">{domain.get("expiration_date","N/A")}</span></div>
        </div>'''
        if domain.get("name_servers"):
            domain_html += f'<p style="margin-top:10px;color:#aaa;font-size:13px">NS: {", ".join(domain["name_servers"][:4])}</p>'
        if domain.get("mx_records"):
            domain_html += f'<p style="color:#aaa;font-size:13px">MX: {", ".join(domain["mx_records"][:4])}</p>'
        domain_html += '</div>'

    identity_html = ""
    if data.get("handles"):
        identity_html = f'''<div class="section fade-in"><h2>👤 Identity Profile</h2>
    <div class="grid-2">
        <div class="info-card"><span class="label">Display Name</span><span class="value">{data.get("display_name","N/A")}</span></div>
        <div class="info-card"><span class="label">Name Format</span><span class="value">{data.get("name_format","N/A")}</span></div>
        <div class="info-card"><span class="label">First Name</span><span class="value">{data.get("first_name","N/A")}</span></div>
        <div class="info-card"><span class="label">Last Name</span><span class="value">{data.get("last_name","N/A")}</span></div>
        <div class="info-card"><span class="label">Middle Name</span><span class="value">{data.get("middle_name","N/A") if data.get("middle_name") else "—"}</span></div>
        <div class="info-card"><span class="label">Initials</span><span class="value">{data.get("initials","N/A")}</span></div>
    </div>'''
        aliases = data.get("aliases", [])
        if aliases:
            identity_html += (f'<h3 style="margin-top:15px;font-size:15px">🔀 Aliases '
                              f'({len(aliases)})</h3>' + " ".join(
                                  f'<span class="tag">{a}</span>' for a in aliases[:20]))
        identity_html += '</div>'

    meta = data.get("metadata", {})
    meta_html = ""
    if meta:
        meta_html = '<div class="section fade-in"><h2>📜 Metadata & History</h2>'
        wb = meta.get("wayback", {})
        if wb.get("total_archived"):
            meta_html += f'''<div class="grid-2">
                <div class="info-card"><span class="label">Wayback Snapshots</span><span class="value">{wb["total_archived"]}</span></div>
                <div class="info-card"><span class="label">Oldest</span><span class="value">{wb.get("oldest","")[:10]}</span></div>
                <div class="info-card"><span class="label">Newest</span><span class="value">{wb.get("newest","")[:10]}</span></div>
            </div>'''
        gc = meta.get("google_cache", {})
        if gc.get("available"):
            meta_html += f'<p style="color:#00e676">✅ Google Cache: Available ({gc.get("cached_date","")})</p>'
        pb = meta.get("pastebin", {})
        pastes = pb.get("pastes_found", [])
        if pastes:
            meta_html += f'<h3 style="margin-top:15px;font-size:15px">📋 Pastebin ({len(pastes)})</h3>'
            for p_url in pastes[:8]:
                meta_html += f'<p style="font-size:13px;margin:4px 0"><a href="{p_url}" target="_blank">{p_url}</a></p>'
        gh = meta.get("github", {})
        if gh.get("code_results", "0") != "0":
            meta_html += f'<p style="color:#ff9100;margin-top:8px">💻 GitHub: {gh["code_results"]} code results</p>'
        gm = meta.get("google_mentions", {})
        if gm.get("total_results", "0") != "0":
            meta_html += f'<p style="color:#888;margin-top:4px">🌐 Google: ~{gm["total_results"]} mentions</p>'
            sites = gm.get("top_sites", [])
            if sites:
                for site in sites[:5]:
                    meta_html += f'<p style="font-size:12px;color:#666;margin:2px 0">  {site}</p>'
        meta_html += '</div>'

    live = data.get("live_intel") or {}
    live_html = ""

    def _kv(rows, title, accent="#00e5ff"):
        """Render a label/value grid; skips empty values."""
        rows = [(k, v) for k, v in rows if v not in (None, "", [], {})]
        if not rows:
            return ""
        body = "".join(
            f'<div class="kv-row"><span class="kv-k">{k}</span>'
            f'<span class="kv-v">{v}</span></div>' for k, v in rows)
        return (f'<h3 class="sub-h" style="color:{accent}">{title}</h3>'
                f'<div class="kv-grid">{body}</div>')

    def _esc(value):
        return (str(value).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))

    profiles = live.get("profiles") or []
    if profiles or live.get("subdomains") or live.get("rdap") or live.get("dns"):
        live_html = ('<div class="section fade-in">'
                     '<h2>🛰️ Live Public Intelligence <span style="font-size:13px;'
                     'color:#888;font-weight:400">keyless APIs · no credentials</span></h2>')

        if profiles:
            by_kind = {}
            for prof in profiles:
                by_kind.setdefault(prof.get("kind") or "other", []).append(prof)
            order = ["identity", "social", "code", "messaging", "media", "gaming",
                     "security", "forum", "blog", "books", "writing", "other"]
            live_html += (f'<h3 class="sub-h" style="color:#00e676">'
                          f'Verified profiles ({len(profiles)})</h3>')
            for kind in order:
                group = by_kind.get(kind)
                if not group:
                    continue
                live_html += (f'<div class="kind-label">{kind} · {len(group)}</div>')
                for prof in group:
                    facts = []
                    for key, label in (("location", "location"), ("company", "org"),
                                       ("followers", "followers"), ("created", "since"),
                                       ("repos", "repos"), ("karma", "karma"),
                                       ("proofs", "proofs"), ("accounts", "accounts"),
                                       ("instance", "instance"), ("handle", "handle"),
                                       ("top_ratings", "ratings"), ("steamid64", "steam64"),
                                       ("statuses", "posts"), ("blog", "blog"),
                                       ("public_email", "email")):
                        value = (prof.get("facts") or {}).get(key)
                        if value not in (None, "", 0):
                            facts.append(f"{label}: {_esc(str(value)[:90])}")
                    if not facts and prof.get("bio"):
                        facts.append(_esc(str(prof["bio"])[:180]))
                    live_html += f'''<div class="info-card" style="margin:8px 0">
                        <span class="label">{_esc(prof.get("source", ""))}</span>
                        <span class="value"><a href="{_esc(prof.get("url", ""))}" target="_blank" rel="noopener">{_esc(prof.get("name") or prof.get("url", ""))}</a></span>
                        <p style="color:#888;font-size:12px;margin:6px 0 0">{" · ".join(facts)}</p>
                    </div>'''

        rdap = live.get("rdap") or {}
        if rdap:
            ns = rdap.get("nameservers") or []
            live_html += _kv([
                ("Registrar", _esc(rdap.get("registrar", ""))),
                ("Created", _esc(rdap.get("created", ""))),
                ("Updated", _esc(rdap.get("updated", ""))),
                ("Expires", _esc(rdap.get("expires", ""))),
                ("Status", _esc(rdap.get("status", ""))),
                ("Nameservers", _esc(", ".join(ns[:6]))),
            ], "📜 Registration (RDAP)")

        dns = live.get("dns") or {}
        if dns:
            dns_rows = [(rtype, _esc(", ".join(str(v)[:70] for v in values[:4])))
                        for rtype, values in dns.items() if values]
            live_html += _kv(dns_rows, "🌐 DNS records")

        geo = live.get("geo") or {}
        if geo:
            live_html += _kv([
                ("IP", _esc(geo.get("ip", ""))),
                ("Location", _esc(" / ".join(x for x in (
                    geo.get("city"), geo.get("region"), geo.get("country")) if x))),
                ("Network", _esc(geo.get("asn") or geo.get("isp", ""))),
                ("Hosting", "yes" if geo.get("hosting") else ""),
                ("Proxy/VPN", "yes" if geo.get("proxy") else ""),
            ], "🌍 Hosting")

        idb = live.get("internetdb") or {}
        if idb.get("ports") or idb.get("cves"):
            ports = ", ".join(str(p) for p in (idb.get("ports") or [])[:20])
            live_html += _kv([
                ("Exposed ports", _esc(ports)),
                ("CVEs", f'<span style="color:#ff1744">{idb.get("cves", 0)}</span>'
                 if idb.get("cves") else ""),
                ("Hostnames", _esc(", ".join((idb.get("hostnames") or [])[:6]))),
                ("Tags", _esc(", ".join((idb.get("tags") or [])[:8]))),
            ], "🔓 InternetDB (Shodan keyless)")

        mail = live.get("mail") or {}
        if mail:
            live_html += _kv([
                ("MX", _esc(", ".join(str(m)[:50] for m in (mail.get("mx") or [])[:3]))),
                ("SPF", _esc(str(mail.get("spf", ""))[:120])),
                ("DMARC", _esc(str(mail.get("dmarc", ""))[:120])),
                ("DKIM hint", "present" if mail.get("dkim_hint") else ""),
            ], "📧 Mail posture")

        wayback = live.get("wayback") or {}
        if wayback:
            live_html += _kv([
                ("Snapshots", wayback.get("snapshots", 0)),
                ("First", _esc(wayback.get("first", ""))),
                ("Last", _esc(wayback.get("last", ""))),
            ], "🕰️ Wayback Machine")

        otx = live.get("otx") or {}
        if otx.get("pulses") or otx.get("passive_dns"):
            live_html += _kv([
                ("Threat pulses", otx.get("pulses", 0)),
                ("Tags", _esc(otx.get("tags", ""))),
                ("Passive DNS", f"{len(otx.get('passive_dns') or [])} records"),
            ], "🛡️ AlienVault OTX")

        ssl = live.get("ssllabs") or {}
        hsts = live.get("hstspreload") or {}
        checks = live.get("domain_checks") or {}
        if ssl or hsts or checks:
            live_html += _kv([
                ("TLS grade", _esc(ssl.get("grade", ""))),
                ("HSTS", _esc(hsts.get("status", ""))),
                ("Domain age", f"{checks['age_days']} days" if checks.get("age_days") else ""),
                ("Disposable", "yes" if checks.get("disposable") else ""),
            ], "🔒 Transport & reputation")

        subs = live.get("subdomains") or []
        if subs:
            live_html += (f'<h3 class="sub-h" style="color:#00e5ff">'
                          f'🧾 Subdomains ({len(subs)})</h3><div class="tag-wrap">')
            live_html += "".join(
                f'<span class="tag">{_esc(s.get("host", ""))}</span>' for s in subs[:120])
            live_html += "</div>"
            if len(subs) > 120:
                live_html += (f'<p style="color:#666;font-size:12px">'
                              f'… {len(subs) - 120} more in the JSON report</p>')

        pdns = live.get("passive_dns") or []
        if pdns:
            live_html += (f'<h3 class="sub-h" style="color:#00e5ff">'
                          f'📡 Passive DNS ({len(pdns)})</h3><div class="tag-wrap">')
            live_html += "".join(
                f'<span class="tag">{_esc(r.get("host", ""))} → {_esc(r.get("ip", ""))}</span>'
                for r in pdns[:30])
            live_html += "</div>"

        scans = live.get("urlscan") or []
        if scans:
            live_html += ('<h3 class="sub-h" style="color:#00e5ff">'
                          '🔎 Recent urlscan.io scans</h3>'
                          '<table class="mini"><tr><th>date</th><th>ip</th>'
                          '<th>server</th><th>url</th></tr>')
            for row in scans[:10]:
                live_html += (f'<tr><td>{_esc(row.get("scanned", ""))}</td>'
                              f'<td>{_esc(row.get("ip", ""))}</td>'
                              f'<td>{_esc(str(row.get("server", ""))[:28])}</td>'
                              f'<td><a href="{_esc(row.get("result", ""))}" '
                              f'target="_blank" rel="noopener">{_esc(str(row.get("url", ""))[:70])}</a></td></tr>')
            live_html += "</table>"

        email_checks = live.get("email_checks") or {}
        pgp = live.get("pgp") or {}
        if email_checks or pgp:
            disify = email_checks.get("disify") or {}
            ucheck = email_checks.get("usercheck_email") or {}
            live_html += _kv([
                ("PGP key", _esc(f"{pgp.get('server', '')} · {', '.join(pgp.get('uids', [])[:2])}")
                 if pgp else ""),
                ("Disposable", "yes" if disify.get("disposable") else "no"
                 if disify else ""),
                ("Role account", "yes" if disify.get("role") else "no" if disify else ""),
                ("Free provider", "yes" if disify.get("free") else "no" if disify else ""),
                ("MX host", _esc(str((ucheck.get("mx_records") or [{}])[0].get("hostname", "")))
                 if ucheck.get("mx_records") else ""),
            ], "✉️ Email exposure")

        errors = live.get("errors") or []
        if errors:
            names = sorted({str(e.get("source", "?")) for e in errors})
            live_html += (f'<p style="color:#666;font-size:12px;margin-top:14px">'
                          f'⚠ {len(errors)} collector errors: {_esc(", ".join(names[:12]))}</p>')

        live_html += "</div>"

    categories = an.get("top_categories", [])
    cat_bars = ""
    for c in categories[:10]:
        w = min(c["hits"] * 10, 100)
        clr = "#00e676" if w > 60 else "#ff9100" if w > 30 else "#ff1744"
        cat_bars += f'''<div style="margin:10px 0">
            <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px">
                <span>{c["category"]}</span><span style="color:#888">{c["hits"]} hits</span>
            </div>
            <div class="bar"><div class="bar-fill" style="width:{w}%;background:{clr}"></div></div>
        </div>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HackIT OSINT — {q}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Inter',sans-serif; background:#0a0a0f; color:#e0e0e0; min-height:100vh; }}
.bg {{ position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;
    background:radial-gradient(ellipse at 20% 50%, rgba(30,60,180,.15) 0%,transparent 50%),
               radial-gradient(ellipse at 80% 20%, rgba(180,30,60,.1) 0%,transparent 50%),
               radial-gradient(ellipse at 50% 80%, rgba(60,180,30,.08) 0%,transparent 50%); }}
.container {{ max-width:1100px;margin:0 auto;padding:20px;position:relative; }}
.header {{ background:rgba(255,255,255,.04);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.06);
    border-radius:20px;padding:40px;margin-bottom:30px;position:relative;overflow:hidden; }}
.header::before {{ content:'';position:absolute;top:0;left:0;right:0;height:3px;
    background:linear-gradient(90deg,#00e676,#00bcd4,#7c4dff); }}
.header h1 {{ font-size:32px;font-weight:800;background:linear-gradient(135deg,#00e676,#00bcd4);
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px; }}
.header .meta {{ color:#888;font-size:14px; }}
.stats {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:30px; }}
.stat {{ background:rgba(255,255,255,.04);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.06);
    border-radius:16px;padding:24px;text-align:center;transition:transform .2s; }}
.stat:hover {{ transform:translateY(-4px); }}
.stat .num {{ font-size:36px;font-weight:800; }}
.stat .lbl {{ color:#888;font-size:13px;margin-top:6px; }}
.stat.score .num {{ background:linear-gradient(135deg,#00e676,#00bcd4);-webkit-background-clip:text;-webkit-text-fill-color:transparent; }}
.stat.hits .num {{ color:#00e676; }}
.stat.poss .num {{ color:#ff9100; }}
.stat.miss .num {{ color:#ff1744; }}
.stat.probed .num {{ color:#7c4dff; }}
.section {{ background:rgba(255,255,255,.03);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.06);
    border-radius:16px;padding:28px;margin-bottom:20px; }}
.section h2 {{ font-size:20px;font-weight:700;margin-bottom:18px; }}
.grid-2 {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px; }}
.info-card {{ background:rgba(255,255,255,.04);border-radius:10px;padding:14px; }}
.info-card .label {{ display:block;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#888;margin-bottom:4px; }}
.info-card .value {{ font-size:15px;font-weight:600;word-break:break-all; }}
.tag {{ display:inline-block;background:rgba(0,230,118,.1);color:#00e676;padding:4px 12px;border-radius:20px;
    font-size:12px;margin:3px;border:1px solid rgba(0,230,118,.2); }}
.badge {{ display:inline-block;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:700;color:#fff; }}
table {{ width:100%;border-collapse:collapse;font-size:13px; }}
th {{ background:rgba(255,255,255,.04);padding:12px;text-align:left;font-weight:600;color:#888;
    border-bottom:1px solid rgba(255,255,255,.06);position:sticky;top:0; }}
td {{ border-bottom:1px solid rgba(255,255,255,.03);vertical-align:middle; }}
.truncate {{ max-width:300px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#7c4dff;text-decoration:none; }}
.truncate:hover {{ color:#00e676;text-decoration:underline; }}
.breach-item {{ background:rgba(255,82,82,.08);border-left:3px solid #ff5252;border-radius:0 8px 8px 0;
    padding:12px;margin:8px 0; }}
.bar {{ height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden; }}
.bar-fill {{ height:100%;border-radius:3px;transition:width 1s ease; }}
.fade-in {{ animation:fadeIn .6s ease; }}
@keyframes fadeIn {{ from{{opacity:0;transform:translateY(12px)}} to{{opacity:1;transform:translateY(0)}} }}
.sub-h {{ font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:1px;
    margin:22px 0 10px;padding-bottom:6px;border-bottom:1px solid rgba(255,255,255,.06); }}
.kv-grid {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:4px 18px; }}
.kv-row {{ display:flex;gap:10px;font-size:13px;padding:4px 0;
    border-bottom:1px solid rgba(255,255,255,.03); }}
.kv-k {{ color:#888;min-width:110px;flex:0 0 110px; }}
.kv-v {{ color:#ddd;word-break:break-word;flex:1; }}
.kind-label {{ font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#555;
    margin:14px 0 4px; }}
.tag-wrap {{ display:flex;flex-wrap:wrap;gap:2px;max-height:260px;overflow-y:auto; }}
table.mini th {{ padding:8px;font-size:11px;text-transform:uppercase;letter-spacing:1px; }}
table.mini td {{ padding:8px;color:#aaa; }}
table.mini a {{ color:#7c4dff;text-decoration:none; }}
table.mini a:hover {{ color:#00e676;text-decoration:underline; }}
.footer {{ text-align:center;padding:30px;color:#555;font-size:13px; }}
.footer strong {{ color:#888; }}
@media(max-width:640px) {{ .header h1 {{font-size:22px}} .stat .num {{font-size:28px}} .grid-2 {{grid-template-columns:1fr}} }}
</style>
</head>
<body>
<div class="bg"></div>
<div class="container">

<div class="header fade-in">
    <h1>🔍 OSINT Report: {q}</h1>
    <div class="meta">Generated {now} · {checked} platforms probed · {hits} accounts found</div>
</div>

<div class="stats">
    <div class="stat hits fade-in"><div class="num">{hits}</div><div class="lbl">Accounts Found</div></div>
    <div class="stat poss fade-in"><div class="num">{possible}</div><div class="lbl">Possible</div></div>
    <div class="stat miss fade-in"><div class="num">{len(miss_p)}</div><div class="lbl">Not Found</div></div>
    <div class="stat probed fade-in"><div class="num">{checked}</div><div class="lbl">Platforms Probed</div></div>
    <div class="stat score fade-in"><div class="num">{score}%</div><div class="lbl">{conf} Confidence</div></div>
</div>

{identity_html}
{email_html}
{phone_html}
{domain_html}
{meta_html}

{live_html}
{notes_html}

<div class="section fade-in"><h2>📊 Category Distribution</h2>{cat_bars or '<p style="color:#888">No categories to display</p>'}</div>

<div class="section fade-in"><h2>🧬 Cross-Platform Personae</h2>{persona_html or '<p style="color:#888">No shared-identity clusters detected</p>'}</div>

<div class="section fade-in">
    <h2>📋 Profile Results ({hits} hits · {possible} possible · {len(miss_p)} miss)</h2>
    <div style="overflow-x:auto">
    <table>
    <thead><tr><th></th><th>Platform</th><th>Status</th><th>Category</th><th>URL</th><th>Title</th></tr></thead>
    <tbody>{rows}</tbody>
    </table>
    </div>
</div>

''' + (f'''<div class="section fade-in"><h2>🔗 Trace Leads</h2>
''' + "".join(f'<p style="margin:6px 0"><a href="{l.get("url","")}" target="_blank" style="color:#7c4dff;text-decoration:none;font-size:14px">{l.get("name","")}</a></p>' for l in data.get("trace_leads",[])[:30]) + '</div>' if data.get("trace_leads") else '') + f'''

<div class="footer">Generated by <strong>HackIT OSINT Engine v2.1</strong> · {now}</div>
</div>
</body>
</html>'''

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html)
        print(f"[+] HTML report → {output_path}")

    return html
