import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

ACADEMIC_SOURCES = [
    ("Google Scholar", "https://scholar.google.com/scholar?q={}&hl=en&as_sdt=0%2C5"),
    ("Semantic Scholar", "https://api.semanticscholar.org/graph/v1/paper/search?query={}&limit=10"),
    ("CrossRef", "https://api.crossref.org/works?query={}&rows=10"),
    ("OpenAlex", "https://api.openalex.org/works?search={}&per_page=10"),
    ("arXiv", "https://export.arxiv.org/api/query?search_query=all:{}&max_results=10"),
    ("PubMed", "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term={}&retmax=10&retmode=json"),
    ("CORE", "https://api.core.ac.uk/v3/search/works?q={}&limit=10"),
    ("BASE", "https://api.base-search.net/v3/search?query={}&size=10"),
    ("Zenodo", "https://zenodo.org/api/records?q={}&size=10"),
    ("Figshare", "https://api.figshare.com/v2/articles/search?search={}&limit=10"),
    ("ResearchGate", "https://www.researchgate.net/search/publication?q={}"),
    ("Academia.edu", "https://www.academia.edu/search?q={}"),
    ("SSRN", "https://papers.ssrn.com/sol3/DisplayAbstractSearch.cfm?searchWord={}"),
]

RESEARCH_PATTERNS = {
    "email": re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'),
    "doi": re.compile(r'10\.\d{4,}/[-._;()/:A-Za-z0-9]+'),
    "orcid": re.compile(r'\b\d{4}-\d{4}-\d{4}-\d{3}[0-9X]\b'),
    "affiliation": re.compile(r'(?:University|Institute|College|School|Laboratory|Centre|Center|Department)\s+of\s+[A-Za-z\s]+', re.IGNORECASE),
}


async def search_semantic(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://api.semanticscholar.org/graph/v1/paper/search",
            params={"query": target, "limit": 10, "fields": "title,publicationDate,authors,externalIds,abstract"},
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            for paper in data.get("data", []):
                results.append({
                    "source": "Semantic Scholar",
                    "title": paper.get("title", ""),
                    "date": paper.get("publicationDate", ""),
                    "authors": [a.get("name", "") for a in paper.get("authors", [])],
                    "abstract": (paper.get("abstract") or "")[:300],
                    "externalIds": paper.get("externalIds", {}),
                })
    except:
        pass
    return results


async def search_crossref(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://api.crossref.org/works",
            params={"query": target, "rows": 10},
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            for item in resp.json().get("message", {}).get("items", []):
                results.append({
                    "source": "CrossRef",
                    "title": item.get("title", [""])[0],
                    "doi": item.get("DOI", ""),
                    "publisher": item.get("publisher", ""),
                    "type": item.get("type", ""),
                    "created": item.get("created", {}).get("date-time", ""),
                    "authors": [a.get("family", "") for a in item.get("author", [])],
                })
    except:
        pass
    return results


async def search_openalex(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://api.openalex.org/works",
            params={"search": target, "per_page": 10},
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            for work in resp.json().get("results", []):
                results.append({
                    "source": "OpenAlex",
                    "title": work.get("title", ""),
                    "publication_year": work.get("publication_year"),
                    "doi": work.get("doi", ""),
                    "authorships": [a.get("author", {}).get("display_name", "") for a in work.get("authorships", [])],
                    "institutions": list(set(a.get("institutions", [{}])[0].get("display_name", "") for a in work.get("authorships", []) if a.get("institutions"))),
                    "cited_by": work.get("cited_by_count", 0),
                })
    except:
        pass
    return results


async def search_arxiv(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://export.arxiv.org/api/query?search_query=all:{quote(target)}&max_results=10",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            entries = re.findall(r'<entry>(.*?)</entry>', resp.text, re.DOTALL)
            for entry in entries:
                title = re.search(r'<title>(.*?)</title>', entry, re.DOTALL)
                authors = re.findall(r'<name>(.*?)</name>', entry)
                date = re.search(r'<published>(.*?)</published>', entry)
                abstract = re.search(r'<summary>(.*?)</summary>', entry, re.DOTALL)
                results.append({
                    "source": "arXiv",
                    "title": title.group(1).strip() if title else "",
                    "authors": authors[:5],
                    "date": date.group(1)[:10] if date else "",
                    "abstract": (abstract.group(1).strip()[:300] if abstract else ""),
                })
    except:
        pass
    return results


async def search_pubmed(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi",
            params={"db": "pubmed", "term": target, "retmax": 10, "retmode": "json"},
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            id_list = resp.json().get("esearchresult", {}).get("idlist", [])
            if id_list:
                results.append({
                    "source": "PubMed",
                    "count": len(id_list),
                    "ids": id_list,
                })
    except:
        pass
    return results


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    ss_results = await search_semantic(t, client)
    cr_results = await search_crossref(t, client)
    oa_results = await search_openalex(t, client)
    arxiv_results = await search_arxiv(t, client)
    pubmed_results = await search_pubmed(t, client)

    all_papers = ss_results + cr_results + oa_results + arxiv_results

    for paper in all_papers[:15]:
        source = paper.get("source", "Unknown")
        title = paper.get("title", "")[:150]
        authors = paper.get("authors", [])
        author_str = ", ".join(authors[:3]) if authors else "Unknown"

        findings.append(IntelligenceFinding(
            entity=f"[{source}] {title}",
            type="Academic: Paper Found",
            source="AcademicResearch",
            confidence="High",
            color="blue",
            category="Academic Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            raw_data=f"Authors: {author_str}",
            tags=["academic", "paper", source.lower().replace(" ", "-")],
        ))

        institutions = paper.get("institutions", [])
        if institutions:
            findings.append(IntelligenceFinding(
                entity=f"Research institutions: {', '.join(institutions[:3])}",
                type="Academic: Affiliation",
                source="AcademicResearch",
                confidence="Medium",
                color="slate",
                category="Academic Intelligence",
                threat_level="Informational",
                status="Identified",
                resolution=t,
                tags=["academic", "affiliation", "institution"],
            ))

        cited_by = paper.get("cited_by", 0)
        if cited_by and cited_by > 0:
            findings.append(IntelligenceFinding(
                entity=f"Paper cited by {cited_by} other works",
                type="Academic: Citation Count",
                source="AcademicResearch",
                confidence="High",
                color="slate",
                category="Academic Intelligence",
                threat_level="Informational",
                status="Analyzed",
                resolution=t,
                tags=["academic", "citation", "impact"],
            ))

    if pubmed_results:
        for pr in pubmed_results:
            findings.append(IntelligenceFinding(
                entity=f"PubMed: {pr['count']} articles found for {t}",
                type="Academic: PubMed Results",
                source="AcademicResearch",
                confidence="Medium",
                color="sky",
                category="Academic Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["academic", "pubmed", "medical"],
            ))

    all_author_names = []
    for p in all_papers:
        all_author_names.extend(p.get("authors", []))

    unique_authors = list(set(all_author_names))
    if unique_authors:
        findings.append(IntelligenceFinding(
            entity=f"{len(unique_authors)} unique researchers mentioned: {', '.join(unique_authors[:5])}",
            type="Academic: Researcher Network",
            source="AcademicResearch",
            confidence="Medium",
            color="slate",
            category="Academic Intelligence",
            threat_level="Informational",
            status="Mapped",
            resolution=t,
            tags=["academic", "researchers", "network"],
        ))

    total_papers = len(all_papers)
    if total_papers > 0:
        findings.append(IntelligenceFinding(
            entity=f"Total academic papers found: {total_papers} across {len(ACADEMIC_SOURCES)} databases",
            type="Academic: Research Volume",
            source="AcademicResearch",
            confidence="High",
            color="slate",
            category="Academic Intelligence",
            threat_level="Informational",
            status="Counted",
            resolution=t,
            tags=["academic", "volume", "papers"],
        ))

    if not all_papers and not pubmed_results:
        findings.append(IntelligenceFinding(
            entity="No academic research found for target",
            type="Academic: Scan Complete",
            source="AcademicResearch",
            confidence="Low",
            color="emerald",
            category="Academic Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["academic", "clean"],
        ))

    return findings
