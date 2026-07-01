import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

OSINT_CATEGORIES = {
    "Search Engines": {
        "description": "General search engines and specialized search tools",
        "techniques": ["Google Dorking", "Bing Search", "DuckDuckGo", "Yandex", "Baidu", "Brave Search", "SearX"],
        "tools": ["Google", "Bing", "DuckDuckGo", "Yandex", "Baidu", "Brave", "SearX"],
        "passive": True,
        "effectiveness": "High",
    },
    "Domain & IP": {
        "description": "Domain registration, DNS, and IP address intelligence",
        "techniques": ["WHOIS Lookup", "DNS Enumeration", "Reverse DNS", "IP Geolocation", "ASN Lookup", "Certificate Transparency"],
        "tools": ["whois", "dig", "nslookup", "Shodan", "Censys", "SecurityTrails"],
        "passive": True,
        "effectiveness": "Very High",
    },
    "Social Media": {
        "description": "Social network profile and content discovery",
        "techniques": ["Profile Search", "Username Search", "Content Mining", "Friend/Follower Analysis", "Post History"],
        "tools": ["WhatsMyName", "Social-Searcher", "SocialBlade", "Spokeo", "Pipl"],
        "passive": True,
        "effectiveness": "Medium",
    },
    "People & Contact": {
        "description": "Personal information, contact details, and relationship mapping",
        "techniques": ["Email Search", "Phone Lookup", "Address Search", "Public Records", "People Search Engines"],
        "tools": ["Pipl", "Spokeo", "BeenVerified", "Whitepages", "Intelius"],
        "passive": True,
        "effectiveness": "Medium",
    },
    "Code Repositories": {
        "description": "Source code, public repositories, and code sharing platforms",
        "techniques": ["GitHub Search", "GitLab Search", "Bitbucket Search", "Gist Search", "Code Search"],
        "tools": ["GitHub API", "GitLab API", "SourceGraph", "SearchCode", "PublicWWW"],
        "passive": True,
        "effectiveness": "High",
    },
    "Dark Web": {
        "description": "Darknet marketplaces, forums, and hidden services intelligence",
        "techniques": ["Onion Site Crawling", "Marketplace Monitoring", "Forum Scraping", "Ransomware Blog Tracking"],
        "tools": ["Tor Browser", "Ahmia", "DarkWebLinks", "dnm.watch", "Ransomware.live"],
        "passive": False,
        "effectiveness": "Medium",
    },
    "Paste Sites": {
        "description": "Pastebin and code snippet sites for credential and data leaks",
        "techniques": ["Paste Search", "Paste Content Analysis", "Credential Extraction", "API Key Discovery"],
        "tools": ["Pastebin", "Ghostbin", "Rentry", "ControlC", "LeakIX"],
        "passive": True,
        "effectiveness": "High",
    },
    "Data Breaches": {
        "description": "Known data breach databases and credential leak aggregation",
        "techniques": ["HIBP Check", "DeHashed Search", "LeakCheck", "IntelX Search", "Breach Directory"],
        "tools": ["HaveIBeenPwned", "Firefox Monitor", "DeHashed", "LeakCheck", "IntelX"],
        "passive": True,
        "effectiveness": "Very High",
    },
    "News & Media": {
        "description": "News articles, press releases, and media coverage monitoring",
        "techniques": ["Google News Search", "RSS Feed Monitoring", "Media Sentiment Analysis", "Press Release Tracking"],
        "tools": ["Google News", "Bing News", "Yahoo News", "NewsAPI", "RSS Readers"],
        "passive": True,
        "effectiveness": "High",
    },
    "Forums & Discussions": {
        "description": "Online forums, Q&A platforms, and discussion board monitoring",
        "techniques": ["Reddit Search", "Stack Overflow Search", "Quora Search", "Hacker News Search", "Forum Crawling"],
        "tools": ["Reddit Search", "Stack Overflow", "Quora", "Hacker News", "Lobsters"],
        "passive": True,
        "effectiveness": "Medium",
    },
    "Academic & Research": {
        "description": "Academic papers, research publications, and scholarly databases",
        "techniques": ["Google Scholar Search", "Semantic Scholar", "CrossRef Search", "arXiv Search", "PubMed Search"],
        "tools": ["Google Scholar", "Semantic Scholar", "CrossRef", "BASE", "CORE"],
        "passive": True,
        "effectiveness": "Medium",
    },
    "Government Records": {
        "description": "Government databases, public records, and regulatory filings",
        "techniques": ["SEC EDGAR Search", "USPTO Search", "OpenCorporates Search", "FCC Search", "SAM.gov Search"],
        "tools": ["SEC EDGAR", "USPTO", "OpenCorporates", "FCC", "SAM.gov"],
        "passive": True,
        "effectiveness": "High",
    },
    "Financial": {
        "description": "Financial data, stock information, and economic intelligence",
        "techniques": ["SEC Filings Analysis", "Stock Performance Tracking", "Funding Round Discovery", "Credit Rating Check"],
        "tools": ["SEC EDGAR", "Yahoo Finance", "Crunchbase", "PitchBook", "Bloomberg"],
        "passive": True,
        "effectiveness": "Medium",
    },
    "Image & Video": {
        "description": "Reverse image search, video metadata, and visual content analysis",
        "techniques": ["Reverse Image Search", "EXIF Data Extraction", "Video Metadata Analysis", "Face Recognition"],
        "tools": ["Google Images", "TinEye", "Yandex Images", "Baidu Images", "Forensically"],
        "passive": True,
        "effectiveness": "Medium",
    },
    "IoT & Devices": {
        "description": "Internet-connected devices, IoT search engines, and device fingerprinting",
        "techniques": ["Shodan Search", "Censys Search", "Device Discovery", "Firmware Analysis", "Default Credential Check"],
        "tools": ["Shodan", "Censys", "ZoomEye", "Fofa", "Netlas"],
        "passive": True,
        "effectiveness": "High",
    },
    "Threat Intelligence": {
        "description": "Cyber threat intelligence, IOC feeds, and vulnerability databases",
        "techniques": ["CVE Search", "Threat Feed Analysis", "Malware Check", "C2 Detection", "OSINT Framework"],
        "tools": ["CVE Details", "AlienVault OTX", "VirusTotal", "AbuseIPDB", "GreyNoise"],
        "passive": True,
        "effectiveness": "High",
    },
}


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    total_passive = sum(1 for c in OSINT_CATEGORIES.values() if c["passive"])
    total_active = sum(1 for c in OSINT_CATEGORIES.values() if not c["passive"])

    for cat_name, cat_data in OSINT_CATEGORIES.items():
        tools_str = ", ".join(cat_data["tools"])
        techniques_str = ", ".join(cat_data["techniques"])

        findings.append(IntelligenceFinding(
            entity=f"OSINT Category: {cat_name}",
            type="Framework: Category",
            source="OSINTFramework",
            confidence="Very High",
            color="blue",
            category="OSINT Framework",
            threat_level="Informational",
            status="Applicable",
            resolution=t,
            raw_data=f"Techniques: {techniques_str}\nTools: {tools_str}",
            tags=["osint", "framework", cat_name.lower().replace(" ", "-")],
        ))

        findings.append(IntelligenceFinding(
            entity=f"Techniques for {cat_name}: {techniques_str}",
            type="Framework: Techniques",
            source="OSINTFramework",
            confidence="High",
            color="sky",
            category="OSINT Framework",
            threat_level="Informational",
            status="Mapped",
            resolution=t,
            tags=["osint", "techniques", cat_name.lower().replace(" ", "-")],
        ))

        findings.append(IntelligenceFinding(
            entity=f"Recommended tools for {cat_name}: {tools_str}",
            type="Framework: Tools",
            source="OSINTFramework",
            confidence="High",
            color="indigo",
            category="OSINT Framework",
            threat_level="Informational",
            status="Recommended",
            resolution=t,
            tags=["osint", "tools", cat_name.lower().replace(" ", "-")],
        ))

        mode = "Passive" if cat_data["passive"] else "Active"
        findings.append(IntelligenceFinding(
            entity=f"{cat_name}: {mode} collection ({cat_data['effectiveness']} effectiveness)",
            type="Framework: Collection Mode",
            source="OSINTFramework",
            confidence="Very High",
            color="slate",
            category="OSINT Framework",
            threat_level="Informational",
            status="Classified",
            resolution=t,
            tags=["osint", "mode", mode.lower(), cat_data["effectiveness"].lower().replace(" ", "-")],
        ))

        findings.append(IntelligenceFinding(
            entity=f"{cat_name}: {cat_data['description']}",
            type="Framework: Description",
            source="OSINTFramework",
            confidence="High",
            color="slate",
            category="OSINT Framework",
            threat_level="Informational",
            status="Described",
            resolution=t,
            tags=["osint", "description", cat_name.lower().replace(" ", "-")],
        ))

    applicable_for_target = []
    for cat_name, cat_data in OSINT_CATEGORIES.items():
        if any(tech_keyword.lower() in t for tech_keyword in [cat_name] if len(t) > 3):
            applicable_for_target.append(cat_name)

    if not applicable_for_target:
        applicable_for_target = list(OSINT_CATEGORIES.keys())[:5]

    findings.append(IntelligenceFinding(
        entity=f"Most applicable categories for {t}: {', '.join(applicable_for_target[:5])}",
        type="Framework: Priority Categories",
        source="OSINTFramework",
        confidence="Medium",
        color="violet",
        category="OSINT Framework",
        threat_level="Informational",
        status="Prioritized",
        resolution=t,
        tags=["osint", "priority", "applicable"],
    ))

    findings.append(IntelligenceFinding(
        entity=f"OSINT Framework coverage: {len(OSINT_CATEGORIES)} categories ({total_passive} passive, {total_active} active)",
        type="Framework: Coverage Summary",
        source="OSINTFramework",
        confidence="Very High",
        color="slate",
        category="OSINT Framework",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["osint", "coverage", "summary"],
    ))

    return findings
