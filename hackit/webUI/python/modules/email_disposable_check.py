import httpx
import re
import dns.resolver
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

DISPOSABLE_DOMAINS = [
    "10minutemail.com", "10minutemail.net", "10minutemail.org", "20minutemail.com",
    "20minutemail.net", "30minutemail.com", "33mail.com", "anonaddy.com",
    "anonaddy.me", "anonymousness.com", "boun.cr", "burnermail.io",
    "chacuo.net", "cock.li", "emailfake.com", "emailnator.com",
    "emailondeck.com", "emailsilo.net", "emailtmp.com", "emailto.de",
    "fakeinbox.com", "fakemail.com", "fakemail.net", "fakemailgenerator.com",
    "fakemailjet.com", "fakemailtemp.com", "getairmail.com", "getnada.com",
    "gettempmail.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "harakirimail.com", "hidemail.pro", "hizli.email",
    "inboxbear.com", "inboxkitten.com", "irzrfax.com", "jetable.com",
    "jourrapide.com", "koiqp.com", "mail.td", "mail1a.de", "mail4trash.com",
    "mailcatch.com", "maildrop.cc", "maildu.de", "mailfa.tk", "mailgutter.com",
    "mailinator.com", "mailinator.net", "mailinator.org", "mailinator2.com",
    "mailmetrash.com", "mailmoat.com", "mailnator.com", "mailpoof.com",
    "mailproxsy.com", "mailquack.com", "mailsac.com", "mailshiv.com",
    "mailtemp.net", "mailtemporaire.com", "mailto.plus", "mailtrash.net",
    "mailtrix.net", "mailver.de", "mohmal.com", "moakt.com", "moakt.ws",
    "my10minutemail.com", "mytrashmail.com", "nada.email", "negated.com",
    "nepwk.com", "no-junk.email", "nobulk.com", "nofax.org", "nomail.xl.cx",
    "nomorespam.eml", "nospam.ze.tc", "nowmymail.com", "nullbox.info",
    "oneoffemail.com", "onewhitelabel.com", "onlatedotcom.info",
    "opayq.com", "owlymail.com", "pookmail.com", "privacy-mail.top",
    "proxymail.eu", "quickinbox.com", "rcpt.at", "recobin.com",
    "receiveee.com", "receive-sms.cc", "regbypass.com", "reqbin.com",
    "safetymail.info", "safrica.com", "sandelf.de", "scay.net",
    "secretemail.de", "server.ms", "sharemail.net", "sharklasers.com",
    "shhmail.com", "sify.com", "simplelogin.co", "slaskpost.se",
    "sneakemail.com", "sogetthis.com", "sofort-mail.com", "sofortmail.de",
    "softpls.asia", "spam.care", "spam.la", "spam4.me", "spamavert.com",
    "spambob.com", "spambob.org", "spambog.com", "spambog.de", "spamcowboy.com",
    "spamcowboy.net", "spamex.com", "spamfree24.com", "spamfree24.de",
    "spamfree24.info", "spamfree24.net", "spamfree24.org", "spamgoes.in",
    "spamgourmet.com", "spamherelots.com", "spamhereplease.com", "spamhole.com",
    "spamify.com", "spaminator.de", "spamkill.info", "spaml.com",
    "spamlot.net", "spammotel.com", "spamobox.com", "spamsandwich.com",
    "spamserver.info", "spamslicer.com", "spamspy.com", "spamstack.net",
    "spamthis.co.uk", "spamthisplease.com", "spamtrail.com", "spamtrap.in",
    "spamwc.de", "spambox.org", "spambox.us", "speed.1s.fr",
    "spoofmail.de", "stopdropandroll.com", "suioe.com", "suremail.info",
    "temporaryemail.net", "temporaryforwarding.com", "temporaryinbox.com",
    "temp-mail.com", "temp-mail.org", "temp-mail.ru", "temp.emeraldwebmail.com",
    "tempalias.com", "tempemail.biz", "tempemail.co.za", "tempemail.net",
    "tempinbox.co.uk", "tempmail.co", "tempmail.de", "tempmail.eu",
    "tempmail.it", "tempmail.net", "tempmail.org", "tempmail.us",
    "tempmail.ws", "tempmail2.com", "tempmaildemo.com", "tempmailer.com",
    "tempmailer.de", "tempomail.fr", "temporarily.de", "temporarioemail.com.br",
    "temporaryemail.us", "temporarymail.net", "tempr.email", "ternaknews.com",
    "texacobut.com", "thc.st", "thrott.com", "throwam.com", "throwaway.email",
    "throwaway.mailinator.com", "throwaway.io", "throwaway.org", "throya.com",
    "tilien.com", "tinymail.org", "tippza.com", "tittbit.in", "toiea.com",
    "top101.de", "topranklist.de", "tormail.net", "tradermail.info",
    "trash2009.com", "trash2010.com", "trash2011.com", "trash247.com",
    "trashbox.eu", "trashcan.org", "trashdevil.com", "trashemail.de",
    "trashmail.at", "trashmail.com", "trashmail.me", "trashmail.net",
    "trashmail.org", "trashmail.ws", "trashmailer.com", "trashymail.com",
    "trashymail.net", "trbvm.com", "trialmail.de", "trump.be",
    "turual.com", "tvchd.com", "uggsrock.com", "umail.net", "upliftnow.com",
    "uplipht.com", "upmunkey.com", "ureach.com", "urfey.com", "ushijima1129.com",
    "utilities-online.info", "valemail.net", "veryrealemail.com", "vidchart.com",
    "viewcastmedia.com", "viewcastmedia.net", "vinth.net", "vipmail.name",
    "vipmail.pw", "viralemail.org", "vjtim.com", "vomoto.com", "vpn.st",
    "vsimcard.com", "vssms.com", "vualto.com", "vvvv.de", "vvvv.it",
    "vzw.com", "w-w-w.com", "w3internet.co.uk", "wakingupest.com",
    "walala.org", "walkmail.net", "walkmail.ru", "wannadance.com",
    "wasd.dropmail.me", "watch-harry-potter.com", "watchever.biz",
    "waterinspace.com", "weaponstech.com", "webm4il.in", "webmail.er",
    "webmail.gg", "webmail.xyz", "webuser.in", "wee.my", "wefjo.gq",
    "wegwerf-email.de", "wegwerfadresse.de", "wegwerfmail.de", "wegwerfmail.net",
    "wegwerfmail.org", "weiboopp.com", "wetrainbayarea.com", "wetrainbayarea.org",
    "wfgdfhj.com", "wg0.com", "whale-mail.com", "whatifanalytics.com",
    "whispers.ai", "whopy.com", "whtjddn.33mail.com", "whyspam.me",
    "wickmail.net", "wims.cf", "winemaven.info", "wins.com.br",
    "wisbuy.info", "wkzgwg.com", "wmail.cf", "wmcanada.com", "woelter.com",
    "woif.me", "wolfmail.ml", "wolfsmail.tk", "wollan.info", "worldbreak.com",
    "wp.vip", "wqopq.com", "wr9v6v7.com", "wralawfirm.com", "wronghead.com",
    "wudet.men", "wuespd.com", "wuzup.net", "wuzupmail.net", "wwjmp.com",
    "www.e4ward.com", "www.mailinator.com", "xagloo.com", "xagloo.co",
    "xemaps.com", "xents.com", "xing886.uu.gl", "xmail.com", "xmaily.com",
    "xn--9kq967foz3a.com", "xoxox.cc", "xperiae5.com", "xrho.com",
    "xwaretech.com", "xwaretech.info", "xwaretech.net", "xww.ro",
    "xy9ce.tk", "xyzfree.net", "xzqyes.com", "yacht-tour.xyz",
    "yacdn.org", "yada-yada.com", "yandere.cu", "yanet.me", "yannmail.net",
    "yapped.net", "yarnpedia.info", "ycare.de", "ycn.ro", "ye.vc",
    "yedi.org", "yep.it", "yepmail.net", "yhg.biz", "ynmrealty.com",
    "yogamaven.com", "yomail.info", "yoo.ro", "yopmail.com", "yopmail.fr",
    "yopmail.net", "yopmail.org", "yopmail.pp.ua", "yordanmail.cf",
    "you-spam.com", "yougotgoated.com", "youmail.ga", "youmailr.com",
    "youneedmore.info", "youpymail.com", "yourdomain.com", "youremail.ml",
    "yourlifedynamics.com", "yourlms.biz", "yoursuccessforums.com",
    "yourvideos.ru", "yroid.com", "yspend.com", "yt-google.com",
    "yuurok.com", "yxzx.net", "z0d.eu", "z1p.biz", "z3w.net",
    "z86.ru", "za.com", "zain.site", "zainmax.net", "zaktouni.fr",
    "zasod.com", "zazazamail.com", "zebins.com", "zebins.eu", "zehnminutenmail.de",
    "zepp.dk", "zetmail.com", "zfymail.com", "zhaoqian.cn", "zhewei88.com",
    "zhorachu.com", "zik.dj", "zipcad.com", "zipsendtest.com", "zoaxe.com",
    "zoemail.com", "zoemail.net", "zoemail.org", "zombo2.com", "zonnet-mail.nl",
    "zoogi.com", "zovs.com", "zumpat.com", "zvmail.com", "zw6provider.com",
    "zxcv.com", "zxcvbnm.com", "zz.mu", "zzz.com", "zzz.pl",
]

ROLE_PREFIXES = [
    "admin", "info", "support", "sales", "contact", "help",
    "webmaster", "postmaster", "hostmaster", "marketing", "billing",
    "careers", "jobs", "hr", "recruitment", "partners", "press",
    "media", "legal", "abuse", "noc", "security", "privacy",
    "copyright", "dmca", "noreply", "no-reply", "newsletter",
    "feedback", "enquiries", "office", "team", "hello", "hi",
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def check_domain_age(domain: str, client: httpx.AsyncClient) -> dict:
    result = {"age_days": None, "is_recent": False}
    try:
        whois_resp = await safe_fetch(client, f"https://who.is/whois/{domain}", timeout=10.0,
            headers={"User-Agent": UA})
        if whois_resp.status_code == 200:
            text = whois_resp.text
            date_m = re.search(r'Creation Date[:\s]+([^\n\r]+)', text, re.IGNORECASE)
            if date_m:
                from datetime import datetime
                date_str = date_m.group(1).strip()
                for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y"]:
                    try:
                        created = datetime.strptime(date_str[:len(fmt.replace("%Y","2025").replace("%m","12").replace("%d","15").replace("T"," ")) if "%" in fmt else len(date_str)], fmt)
                        days = (datetime.now() - created).days
                        result["age_days"] = days
                        result["is_recent"] = days < 365
                        break
                    except ValueError:
                        continue
    except Exception:
        pass
    return result

async def check_mx_pattern(domain: str) -> dict:
    result = {"has_mx": False, "mx_pattern": "", "suspicious": False}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "MX")
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        if mx_hosts:
            result["has_mx"] = True
            for mx in mx_hosts:
                mx_lower = mx.lower()
                if any(x in mx_lower for x in ["mailinator", "guerrilla", "10minutemail", "yopmail"]):
                    result["suspicious"] = True
                    result["mx_pattern"] = f"Temporary mail MX: {mx}"
                    break
                if any(x in mx_lower for x in ["catch", "catchall", "wildcard"]):
                    result["suspicious"] = True
                    result["mx_pattern"] = f"Suspicious MX: {mx}"
                    break
    except Exception:
        pass
    return result

async def check_disposable_apis(domain: str, client: httpx.AsyncClient) -> dict:
    result = {"detected": False, "sources": []}
    apis = [
        ("BlockTemporary", f"https://block-temporary-email.com/check/domain/{domain}"),
        ("DisposableEmailCheck", f"https://disposable.email/api/check/{domain}"),
        ("EmailValidatorAPI", f"https://api.emailvalidator.io/v1/disposable?domain={domain}"),
        ("IsTemporary", f"https://istemporary.com/api/?domain={domain}"),
    ]
    for name, url in apis:
        try:
            resp = await safe_fetch(client, url, timeout=8.0, headers={"User-Agent": UA})
            if resp.status_code == 200:
                text = resp.text.lower()
                if any(x in text for x in ["true", "yes", "disposable", "temporary", "1"]):
                    result["detected"] = True
                    result["sources"].append(name)
        except Exception:
            pass
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    if "@" not in email:
        findings.append(make_finding(
            entity="Not a valid email address",
            ftype="Disposable Check Error",
            source="EmailDisposableCheck",
            confidence="High", color="red", category="General OSINT",
            threat_level="Informational", status="Error",
            tags=["error"]
        ))
        return findings

    domain = email.split("@")[1]
    local_part = email.split("@")[0]

    is_disposable = domain.lower() in DISPOSABLE_DOMAINS
    if is_disposable:
        findings.append(make_finding(
            entity=f"DISPOSABLE EMAIL: {domain} is a known disposable/temporary email domain",
            ftype="Disposable Email Detected",
            source="EmailDisposableCheck",
            confidence="High",
            color="red",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status="Disposable",
            resolution=f"Domain {domain} is in the known disposable domains list ({len(DISPOSABLE_DOMAINS)} entries)",
            raw_data=f"Domain: {domain} | Local part: {local_part} | List match: exact",
            tags=["disposable", "temporary-email", "high-risk", domain]
        ))
    else:
        findings.append(make_finding(
            entity=f"Domain {domain} not in disposable domains list",
            ftype="Disposable Domain Check",
            source="EmailDisposableCheck",
            confidence="High",
            color="emerald",
            category="Email Risk Intelligence",
            threat_level="Informational",
            status="Clean",
            tags=["disposable", "domain-check", domain]
        ))

    findings.append(make_finding(
        entity=f"Testing {domain} against {len(DISPOSABLE_DOMAINS)} known disposable domains",
        type="Domain List Coverage",
        source="EmailDisposableCheck",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        status=f"{len(DISPOSABLE_DOMAINS)} domains checked",
        tags=["disposable", "coverage"]
    ))

    domain_age = await check_domain_age(domain, client)
    if domain_age.get("age_days") is not None:
        age_color = "red" if domain_age["is_recent"] else "emerald"
        findings.append(make_finding(
            entity=f"Domain age: {domain_age['age_days']} days ({'RECENT - likely disposable' if domain_age['is_recent'] else 'Established'})",
            type="Domain Age Analysis",
            source="EmailDisposableCheck",
            confidence="Medium",
            color=age_color,
            category="Domain Intelligence",
            threat_level="Elevated Risk" if domain_age["is_recent"] else "Informational",
            status="Recent Registration" if domain_age["is_recent"] else "Established",
            tags=["domain-age", "whois", "new-domain" if domain_age["is_recent"] else "aged-domain"]
        ))
    else:
        findings.append(make_finding(
            entity=f"Could not determine age for {domain}",
            ftype="Domain Age Unknown",
            source="EmailDisposableCheck",
            confidence="Low",
            color="slate",
            category="Domain Intelligence",
            threat_level="Informational",
            tags=["domain-age", "unavailable"]
        ))

    mx_check = await check_mx_pattern(domain)
    if mx_check["has_mx"]:
        if mx_check["suspicious"]:
            findings.append(make_finding(
                entity=f"Suspicious MX pattern: {mx_check['mx_pattern']}",
                ftype="MX Server Pattern Analysis",
                source="EmailDisposableCheck",
                confidence="Medium",
                color="red",
                category="Email Risk Intelligence",
                threat_level="Elevated Risk",
                status="Suspicious MX",
                tags=["mx", "suspicious", "disposable-mx"]
            ))
        else:
            findings.append(make_finding(
                entity="MX servers appear legitimate (not disposable patterns)",
                type="MX Server Pattern Analysis",
                source="EmailDisposableCheck",
                confidence="Medium",
                color="emerald",
                category="Email Risk Intelligence",
                threat_level="Informational",
                status="Legitimate MX",
                tags=["mx", "legitimate"]
            ))
    else:
        findings.append(make_finding(
            entity="No MX records found - domain may not accept email",
            ftype="MX Server Check",
            source="EmailDisposableCheck",
            confidence="High",
            color="orange",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status="No MX",
            tags=["mx", "missing-mx"]
        ))

    api_result = await check_disposable_apis(domain, client)
    if api_result["detected"]:
        sources = ", ".join(api_result["sources"])
        findings.append(make_finding(
            entity=f"External APIs confirm {domain} is disposable ({sources})",
            type="API Disposable Confirmation",
            source="EmailDisposableCheck",
            confidence="Medium",
            color="red",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status="Confirmed Disposable",
            raw_data=f"APIs reporting disposable: {sources}",
            tags=["disposable", "api-check", "confirmed"]
        ))
    else:
        findings.append(make_finding(
            entity=f"External APIs do not classify {domain} as disposable",
            ftype="API Disposable Check",
            source="EmailDisposableCheck",
            confidence="Low",
            color="emerald",
            category="Email Risk Intelligence",
            threat_level="Informational",
            status="Not Flagged",
            tags=["disposable", "api-check"]
        ))

    is_role = local_part.lower() in ROLE_PREFIXES
    if is_role:
        findings.append(make_finding(
            entity=f"Role-based local part: {local_part}@{domain}",
            ftype="Role-Based Email Detected",
            source="EmailDisposableCheck",
            confidence="High",
            color="orange",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status="Role Account",
            tags=["role-based", "generic-account", local_part]
        ))

    total_indicators = sum([is_disposable, domain_age.get("is_recent", False),
                           mx_check["suspicious"], api_result["detected"]])
    if total_indicators >= 2:
        findings.append(make_finding(
            entity=f"HIGH CONFIDENCE DISPOSABLE: {email} ({total_indicators}/4 indicators positive)",
            type="Disposable Confidence Assessment",
            source="EmailDisposableCheck",
            confidence="High",
            color="red",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status="Disposable - High Confidence",
            raw_data=f"Indicators: domain_list={is_disposable}, new_domain={domain_age.get('is_recent')}, suspicious_mx={mx_check['suspicious']}, api_flag={api_result['detected']}",
            tags=["disposable", "high-confidence", "temporary"]
        ))
    elif total_indicators >= 1:
        findings.append(make_finding(
            entity=f"POSSIBLY DISPOSABLE: {email} ({total_indicators}/4 indicators positive)",
            type="Disposable Confidence Assessment",
            source="EmailDisposableCheck",
            confidence="Medium",
            color="orange",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status="Possibly Disposable",
            tags=["disposable", "medium-confidence"]
        ))
    else:
        findings.append(make_finding(
            entity=f"LIKELY LEGITIMATE: {email} (0/4 disposable indicators)",
            type="Disposable Confidence Assessment",
            source="EmailDisposableCheck",
            confidence="Medium",
            color="emerald",
            category="Email Risk Intelligence",
            threat_level="Informational",
            status="Legitimate",
            tags=["disposable", "legitimate", "clean"]
        ))

    findings.append(make_finding(
        entity=f"Disposable email check complete for {email}",
        ftype="Disposable Check Summary",
        source="EmailDisposableCheck",
        confidence="High",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Domain: {domain} | List: {'MATCH' if is_disposable else 'NOT FOUND'} | Age: {domain_age.get('age_days', 'unknown')}d | MX: {'suspicious' if mx_check['suspicious'] else 'normal'} | APIs: {' + '.join(api_result['sources']) if api_result['detected'] else 'clean'}",
        tags=["disposable", "summary"]
    ))

    return findings
