import httpx
import asyncio
import socket
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

ALL_TLDS = [
    "com", "net", "org", "co", "io", "me", "tv", "info", "biz", "dev",
    "app", "xyz", "online", "site", "tech", "store", "blog", "cloud",
    "uk", "de", "fr", "eu", "ru", "jp", "cn", "br", "au", "in",
    "ca", "nl", "it", "es", "se", "no", "pl", "at", "ch", "be",
    "dk", "fi", "ie", "nz", "sg", "hk", "za", "mx", "ar", "cl",
    "cc", "email", "pro", "name", "mobi", "asia", "tel", "travel",
    "shop", "club", "vip", "live", "news", "media", "video", "wiki",
    "guru", "guide", "link", "world", "today", "space", "press",
    "social", "network", "agency", "group", "team", "consulting",
    "services", "solutions", "management", "systems", "digital",
    "finance", "money", "cash", "credit", "loan", "invest",
    "health", "doctor", "hospital", "clinic", "pharmacy",
    "law", "legal", "attorney", "lawyer", "claim", "justice",
    "london", "nyc", "paris", "tokyo", "berlin", "moscow", "dubai",
    "gdn", "uno", "win", "bid", "trade", "webcam", "science",
    "date", "men", "loan", "download", "review", "racing", "accountant",
    "christmas", "rest", "faith", "country", "mom", "cricket", "work",
    "click", "party", "top", "icu", "cf", "ga", "ml", "tk", "gq",
    "academy", "actor", "africa", "agency", "apartments", "archi",
    "army", "art", "associates", "attorney", "auction", "audio",
    "auto", "band", "bank", "bar", "bargains", "beauty", "beer",
    "best", "bet", "bike", "bingo", "bio", "black", "blue", "boo",
    "book", "boston", "bot", "boutique", "broker", "build", "builders",
    "business", "cab", "cafe", "call", "cam", "camera", "camp",
    "capital", "car", "cards", "care", "careers", "cars", "casa",
    "case", "cash", "casino", "catering", "catholic", "center", "ceo",
    "channel", "chat", "cheap", "church", "city", "claims", "cleaning",
    "click", "clinic", "clothing", "cloud", "club", "coach", "codes",
    "coffee", "college", "community", "company", "computer", "condos",
    "construction", "consulting", "contact", "contractors", "cooking",
    "cool", "coop", "country", "coupon", "courses", "cpa", "credit",
    "creditcard", "cricket", "cruises", "dad", "dance", "date", "dating",
    "day", "deals", "degree", "delivery", "democrat", "dental", "dentist",
    "design", "dev", "diamonds", "diet", "digital", "direct", "directory",
    "discount", "doctor", "dog", "domains", "download", "earth", "eat",
    "education", "email", "energy", "engineer", "engineering",
    "enterprises", "equipment", "estate", "events", "exchange", "expert",
    "exposed", "express", "fail", "faith", "family", "fans", "farm",
    "fashion", "film", "finance", "financial", "fish", "fishing", "fit",
    "fitness", "flights", "florist", "flowers", "fly", "foo", "food",
    "football", "forex", "forsale", "foundation", "fund", "furniture",
    "futbol", "fyi", "gallery", "games", "garden", "gift", "gifts",
    "gives", "glass", "global", "gmbh", "gold", "golf", "graphics",
    "gratis", "green", "gripe", "grocery", "group", "guide", "guitars",
    "guru", "hair", "haus", "health", "healthcare", "help", "here",
    "hiphop", "hiv", "hockey", "holdings", "holiday", "homes", "horses",
    "hospital", "host", "hosting", "hotel", "house", "how", "immo",
    "immobilien", "industries", "ing", "ink", "institute", "insure",
    "international", "investments", "irish", "ist", "jeep", "jewelry",
    "juegos", "kaufen", "kim", "kitchen", "land", "law", "lawyer",
    "lease", "legal", "lgbt", "life", "lighting", "limited", "limo",
    "link", "live", "llc", "loan", "loans", "lol", "love", "ltd",
    "luxury", "maison", "management", "map", "market", "marketing",
    "markets", "mba", "med", "media", "memorial", "menu", "miami",
    "moda", "money", "monster", "mortgage", "movie", "museum", "music",
    "nagoya", "navy", "network", "news", "ngo", "ninja", "nyc", "okinawa",
    "one", "ong", "onl", "online", "ooo", "organic", "partners", "parts",
    "party", "pay", "pet", "pets", "photo", "photography", "photos",
    "physio", "pics", "pictures", "pink", "pizza", "place", "plumbing",
    "plus", "poker", "porn", "press", "pro", "productions", "prof",
    "promo", "properties", "property", "pub", "radio", "re", "realty",
    "recipes", "red", "rehab", "reise", "reisen", "rent", "rentals",
    "repair", "report", "republican", "rest", "restaurant", "review",
    "reviews", "rich", "rocks", "rodeo", "room", "run", "sale", "salon",
    "school", "schule", "science", "scot", "security", "services",
    "sex", "sexy", "shiksha", "shoes", "shop", "shopping", "show",
    "shows", "site", "ski", "skin", "soccer", "social", "software",
    "solar", "solutions", "song", "space", "spa", "store", "stream",
    "studio", "study", "style", "sucks", "supplies", "supply", "support",
    "surf", "surgery", "systems", "talk", "tattoo", "tax", "taxi",
    "team", "tech", "technology", "tennis", "theater", "theatre",
    "tickets", "tips", "tires", "today", "tools", "top", "tours",
    "town", "toys", "trade", "trading", "training", "tube", "university",
    "uno", "vacations", "vegas", "ventures", "vet", "viajes", "video",
    "villas", "vin", "vip", "vision", "vlaanderen", "vodka", "vote",
    "voting", "voto", "voyage", "wang", "watch", "webcam", "website",
    "wedding", "wiki", "win", "wine", "work", "works", "world", "wtf",
    "xxx", "xyz", "yachts", "yoga", "yokohama", "zone",
]

CC_TLDS = {
    "af": "Afghanistan", "al": "Albania", "dz": "Algeria", "as": "American Samoa",
    "ad": "Andorra", "ao": "Angola", "ai": "Anguilla", "aq": "Antarctica",
    "ag": "Antigua", "ar": "Argentina", "am": "Armenia", "aw": "Aruba",
    "au": "Australia", "at": "Austria", "az": "Azerbaijan", "bs": "Bahamas",
    "bh": "Bahrain", "bd": "Bangladesh", "bb": "Barbados", "by": "Belarus",
    "be": "Belgium", "bz": "Belize", "bj": "Benin", "bm": "Bermuda",
    "bt": "Bhutan", "bo": "Bolivia", "ba": "Bosnia", "bw": "Botswana",
    "br": "Brazil", "bn": "Brunei", "bg": "Bulgaria", "bf": "Burkina Faso",
    "bi": "Burundi", "kh": "Cambodia", "cm": "Cameroon", "ca": "Canada",
    "cv": "Cape Verde", "ky": "Cayman Islands", "cf": "Central African Rep",
    "td": "Chad", "cl": "Chile", "cn": "China", "co": "Colombia",
    "km": "Comoros", "cg": "Congo", "cd": "Congo DR", "ck": "Cook Islands",
    "cr": "Costa Rica", "ci": "Cote d'Ivoire", "hr": "Croatia", "cu": "Cuba",
    "cw": "Curacao", "cy": "Cyprus", "cz": "Czech Republic", "dk": "Denmark",
    "dj": "Djibouti", "dm": "Dominica", "do": "Dominican Republic",
    "ec": "Ecuador", "eg": "Egypt", "sv": "El Salvador", "gq": "Equatorial Guinea",
    "er": "Eritrea", "ee": "Estonia", "et": "Ethiopia", "fk": "Falkland Islands",
    "fo": "Faroe Islands", "fj": "Fiji", "fi": "Finland", "fr": "France",
    "pf": "French Polynesia", "ga": "Gabon", "gm": "Gambia", "ge": "Georgia",
    "de": "Germany", "gh": "Ghana", "gi": "Gibraltar", "gr": "Greece",
    "gl": "Greenland", "gd": "Grenada", "gu": "Guam", "gt": "Guatemala",
    "gg": "Guernsey", "gn": "Guinea", "gw": "Guinea-Bissau", "gy": "Guyana",
    "ht": "Haiti", "hn": "Honduras", "hk": "Hong Kong", "hu": "Hungary",
    "is": "Iceland", "in": "India", "id": "Indonesia", "ir": "Iran",
    "iq": "Iraq", "ie": "Ireland", "im": "Isle of Man", "il": "Israel",
    "it": "Italy", "jm": "Jamaica", "jp": "Japan", "je": "Jersey",
    "jo": "Jordan", "kz": "Kazakhstan", "ke": "Kenya", "ki": "Kiribati",
    "kr": "South Korea", "kw": "Kuwait", "kg": "Kyrgyzstan", "la": "Laos",
    "lv": "Latvia", "lb": "Lebanon", "ls": "Lesotho", "lr": "Liberia",
    "ly": "Libya", "li": "Liechtenstein", "lt": "Lithuania", "lu": "Luxembourg",
    "mo": "Macau", "mk": "Macedonia", "mg": "Madagascar", "mw": "Malawi",
    "my": "Malaysia", "mv": "Maldives", "ml": "Mali", "mt": "Malta",
    "mh": "Marshall Islands", "mq": "Martinique", "mr": "Mauritania",
    "mu": "Mauritius", "yt": "Mayotte", "mx": "Mexico", "fm": "Micronesia",
    "md": "Moldova", "mc": "Monaco", "mn": "Mongolia", "me": "Montenegro",
    "ms": "Montserrat", "ma": "Morocco", "mz": "Mozambique", "mm": "Myanmar",
    "na": "Namibia", "nr": "Nauru", "np": "Nepal", "nl": "Netherlands",
    "nc": "New Caledonia", "nz": "New Zealand", "ni": "Nicaragua",
    "ne": "Niger", "ng": "Nigeria", "nu": "Niue", "nf": "Norfolk Island",
    "mp": "Northern Mariana Islands", "no": "Norway", "om": "Oman",
    "pk": "Pakistan", "pw": "Palau", "ps": "Palestine", "pa": "Panama",
    "pg": "Papua New Guinea", "py": "Paraguay", "pe": "Peru", "ph": "Philippines",
    "pn": "Pitcairn", "pl": "Poland", "pt": "Portugal", "pr": "Puerto Rico",
    "qa": "Qatar", "re": "Reunion", "ro": "Romania", "ru": "Russia",
    "rw": "Rwanda", "bl": "Saint Barthelemy", "sh": "Saint Helena",
    "kn": "Saint Kitts", "lc": "Saint Lucia", "mf": "Saint Martin",
    "pm": "Saint Pierre", "vc": "Saint Vincent", "ws": "Samoa", "sm": "San Marino",
    "st": "Sao Tome", "sa": "Saudi Arabia", "sn": "Senegal", "rs": "Serbia",
    "sc": "Seychelles", "sl": "Sierra Leone", "sg": "Singapore", "sx": "Sint Maarten",
    "sk": "Slovakia", "si": "Slovenia", "sb": "Solomon Islands",
    "so": "Somalia", "za": "South Africa", "gs": "South Georgia",
    "ss": "South Sudan", "es": "Spain", "lk": "Sri Lanka", "sd": "Sudan",
    "sr": "Suriname", "sj": "Svalbard", "sz": "Swaziland", "se": "Sweden",
    "ch": "Switzerland", "sy": "Syria", "tw": "Taiwan", "tj": "Tajikistan",
    "tz": "Tanzania", "th": "Thailand", "tl": "Timor-Leste", "tg": "Togo",
    "tk": "Tokelau", "to": "Tonga", "tt": "Trinidad", "tn": "Tunisia",
    "tr": "Turkey", "tm": "Turkmenistan", "tc": "Turks and Caicos",
    "tv": "Tuvalu", "ug": "Uganda", "ua": "Ukraine", "ae": "United Arab Emirates",
    "uk": "United Kingdom", "us": "United States", "uy": "Uruguay",
    "uz": "Uzbekistan", "vu": "Vanuatu", "va": "Vatican City", "ve": "Venezuela",
    "vn": "Vietnam", "vg": "Virgin Islands (British)", "vi": "Virgin Islands (US)",
    "wf": "Wallis and Futuna", "eh": "Western Sahara", "ye": "Yemen",
    "zm": "Zambia", "zw": "Zimbabwe",
}

NEW_GTLDS = [t for t in ALL_TLDS if t not in CC_TLDS and t not in ("com", "net", "org", "info", "biz")]

async def check_dns(host: str):
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, 80, family=socket.AF_INET))
        return True, list(set(a[4][0] for a in ais[:3]))
    except:
        return False, []

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    if "." not in domain:
        sld = domain
        original_tld = ""
    else:
        parts = domain.rsplit(".", 1)
        sld = parts[0]
        original_tld = parts[1]

    resolved_tlds = []
    registered_count = 0
    batched = [ALL_TLDS[i:i+20] for i in range(0, len(ALL_TLDS), 20)]

    for batch in batched:
        tasks = []
        for tld in batch:
            fqdn = f"{sld}.{tld}"
            tasks.append(check_dns(fqdn))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for tld, result in zip(batch, results):
            if isinstance(result, tuple) and result[0]:
                registered_count += 1
                ok, ips = result
                fqdn = f"{sld}.{tld}"
                resolved_tlds.append((tld, ips))
                country = CC_TLDS.get(tld, "")
                is_cc = tld in CC_TLDS
                is_new_gtld = tld in NEW_GTLDS
                color = "blue" if is_cc else "orange" if is_new_gtld else "slate"
                findings.append(IntelligenceFinding(
                    entity=f"{fqdn} -> {', '.join(ips[:2])}",
                    type=f"Registered TLD ({'ccTLD' if is_cc else 'new gTLD' if is_new_gtld else 'legacy TLD'})",
                    source="TLD Intelligence",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status="Resolved",
                    resolution=fqdn,
                    raw_data=f"TLD: .{tld} | Country: {country} | IPs: {', '.join(ips[:3])}",
                    tags=["tld", tld, "cctld" if is_cc else "new-gtld" if is_new_gtld else "legacy"]
                ))

    if resolved_tlds:
        findings.append(IntelligenceFinding(
            entity=f"{registered_count}/{len(ALL_TLDS)} TLD variants resolve ({registered_count} registered domains)",
            type="TLD Registration Summary",
            source="TLD Intelligence",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status=f"{registered_count} Registered",
            raw_data=f"SLD: {sld} | Total TLDs tested: {len(ALL_TLDS)} | Resolved: {registered_count}",
            tags=["tld", "summary"]
        ))

        cc_resolved = [(t, ips) for t, ips in resolved_tlds if t in CC_TLDS]
        if cc_resolved:
            countries = [f"{CC_TLDS[t]} (.{t})" for t, _ in cc_resolved[:10]]
            findings.append(IntelligenceFinding(
                entity=f"ccTLDs: {', '.join(countries[:10])}",
                type="ccTLD Geographic Analysis",
                source="TLD Intelligence",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status=f"{len(cc_resolved)} ccTLDs",
                raw_data=f"Country code TLDs registered: {', '.join(t for t, _ in cc_resolved)}",
                tags=["tld", "cctld", "geo"]
            ))

        new_gtld_resolved = [(t, ips) for t, ips in resolved_tlds if t in NEW_GTLDS]
        if new_gtld_resolved:
            findings.append(IntelligenceFinding(
                entity=f"New gTLDs: {', '.join(t for t, _ in new_gtld_resolved[:15])}",
                type="New gTLD Registration",
                source="TLD Intelligence",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status=f"{len(new_gtld_resolved)} New gTLDs",
                tags=["tld", "new-gtld"]
            ))

        suspect_tlds = ["tk", "ml", "ga", "cf", "gq", "click", "party", "top", "icu", "review", "trade", "bid", "win", "men", "loan", "download", "racing", "science", "date", "rest", "faith", "work", "webcam", "accountant"]
        suspect_resolved = [(t, ips) for t, ips in resolved_tlds if t in suspect_tlds]
        if suspect_resolved:
            findings.append(IntelligenceFinding(
                entity=f"High-risk/suspect TLDs: {', '.join(t for t, _ in suspect_resolved)}",
                type="High-Risk TLD Alert",
                source="TLD Intelligence",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                status="Suspect TLD",
                tags=["tld", "high-risk", "suspect"]
            ))

        if original_tld and len(resolved_tlds) > 1:
            findings.append(IntelligenceFinding(
                entity=f"{sld} is registered in {registered_count} TLD(s) including non-{original_tld} variants",
                type="TLD Squatting Analysis",
                source="TLD Intelligence",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status="Multiple TLDs",
                tags=["tld", "squatting"]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No registered TLD variants found for {sld}",
            type="TLD Registration Summary",
            source="TLD Intelligence",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="No TLDs",
            tags=["tld", "summary"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"TLD intelligence scan complete for {sld}",
        type="TLD Intelligence Summary",
        source="TLD Intelligence",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["tld", "summary"]
    ))

    return findings
