import re
from urllib.parse import urlparse, quote
from typing import List
from module_common import safe_fetch, make_finding

NEWS_SOURCES = [
    ("Google News", "https://news.google.com/search?q={}&hl=en-US&gl=US&ceid=US:en"),
    ("Yahoo News", "https://news.yahoo.com/search?q={}"),
    ("Bing News", "https://www.bing.com/news/search?q={}"),
    ("DuckDuckGo News", "https://lite.duckduckgo.com/lite/?q={}&t=news"),
    ("BBC News", "https://www.bbc.co.uk/search?q={}&d=news"),
    ("CNN", "https://www.cnn.com/search?q={}"),
    ("Reuters", "https://www.reuters.com/search/news?blob={}"),
    ("AP News", "https://apnews.com/search?q={}"),
    ("Al Jazeera", "https://www.aljazeera.com/search/{}"),
    ("The Guardian", "https://www.theguardian.com/search?q={}"),
    ("NY Times", "https://www.nytimes.com/search?query={}"),
    ("WSJ", "https://www.wsj.com/search?query={}"),
    ("Bloomberg", "https://www.bloomberg.com/search?query={}"),
    ("WaPo", "https://www.washingtonpost.com/news/search/?query={}"),
    ("NPR", "https://www.npr.org/search?q={}"),
    ("USA Today", "https://www.usatoday.com/search/?q={}"),
    ("Fox News", "https://www.foxnews.com/search?q={}"),
    ("MSNBC", "https://www.msnbc.com/search?q={}"),
    ("ABC News", "https://abcnews.go.com/search?q={}"),
    ("CBS News", "https://www.cbsnews.com/search?q={}"),
    ("NBC News", "https://www.nbcnews.com/search?q={}"),
    ("Sky News", "https://news.sky.com/search?term={}"),
    ("RT", "https://www.rt.com/search?q={}"),
    ("France 24", "https://www.france24.com/en/search?q={}"),
    ("DW", "https://www.dw.com/en/search?q={}"),
    ("The Hill", "https://thehill.com/search/?q={}"),
    ("Politico", "https://www.politico.com/search?q={}"),
    ("Axios", "https://www.axios.com/search?q={}"),
    ("Vox", "https://www.vox.com/search?q={}"),
    ("Business Insider", "https://www.businessinsider.com/search?q={}"),
    ("CNBC", "https://www.cnbc.com/search/?query={}"),
    ("Financial Times", "https://www.ft.com/search?q={}"),
    ("TechCrunch", "https://techcrunch.com/search/{}"),
    ("The Verge", "https://www.theverge.com/search?q={}"),
    ("Wired", "https://www.wired.com/search?q={}"),
    ("Ars Technica", "https://arstechnica.com/search/?q={}"),
]

SENTIMENT_POSITIVE = ["success", "growth", "profit", "innovation", "leader", "award", "partnership", "expansion", "breakthrough", "achievement"]
SENTIMENT_NEGATIVE = ["breach", "hack", "attack", "scandal", "lawsuit", "fine", "penalty", "fraud", "crisis", "bankruptcy", "layoff", "downfall", "collapse", "violation", "misconduct"]
SENTIMENT_NEUTRAL = ["announce", "report", "statement", "update", "release", "launch", "introduce", "present", "discuss"]

TOPIC_CATEGORIES = {
    "technology": ["tech", "software", "digital", "cyber", "AI", "data", "cloud", "security"],
    "finance": ["stock", "market", "financial", "revenue", "funding", "investment", "acquisition"],
    "legal": ["lawsuit", "court", "legal", "regulation", "compliance", "fine", "settlement"],
    "security": ["breach", "hack", "vulnerability", "attack", "malware", "ransomware", "phishing"],
    "business": ["partnership", "merger", "expansion", "strategy", "management", "executive"],
    "product": ["launch", "release", "feature", "update", "version", "product"],
}


async def fetch_news_source(name: str, url_template: str, target: str, client) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await safe_fetch(
            client,
            url,
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
            follow_redirects=True,
        )
        if resp and resp.status_code == 200 and len(resp.text) > 500:
            text = resp.text
            headlines = re.findall(r'<h[1-4][^>]*>(.*?)</h[1-4]>', text, re.IGNORECASE | re.DOTALL)
            headlines = [re.sub(r'<[^>]+>', '', h).strip() for h in headlines if h.strip()]
            articles = re.findall(r'<article[^>]*>(.*?)</article>', text, re.IGNORECASE | re.DOTALL)
            links = re.findall(r'href=["\'](https?://[^"\']+)["\']', text)
            target_mentions = text.lower().count(target.lower())
            return {
                "name": name,
                "url": url,
                "headlines": headlines[:10],
                "article_count": len(articles),
                "links": links[:10],
                "target_mentions": target_mentions,
                "content_length": len(text),
            }
    except:
        pass
    return None


def analyze_sentiment(text: str) -> str:
    text_lower = text.lower()
    pos_count = sum(1 for w in SENTIMENT_POSITIVE if w in text_lower)
    neg_count = sum(1 for w in SENTIMENT_NEGATIVE if w in text_lower)
    neu_count = sum(1 for w in SENTIMENT_NEUTRAL if w in text_lower)
    if pos_count > neg_count and pos_count > neu_count:
        return "Positive"
    elif neg_count > pos_count and neg_count > neu_count:
        return "Negative"
    return "Neutral"


def categorize_topics(text: str) -> list:
    topics = []
    text_lower = text.lower()
    for category, keywords in TOPIC_CATEGORIES.items():
        if any(kw in text_lower for kw in keywords):
            topics.append(category)
    return topics


async def crawl(target: str, client) -> List:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_results = []
    sources_with_data = 0

    for name, url_template in NEWS_SOURCES:
        result = await fetch_news_source(name, url_template, t, client)
        if result:
            all_results.append(result)
            sources_with_data += 1

    if all_results:
        findings.append(make_finding(
            f"News scan: {sources_with_data}/{len(NEWS_SOURCES)} sources had mentions of {t}",
            ftype="News: Coverage Report",
            source="NewsMonitor",
            confidence="High",
            color="slate",
            category="News Intelligence",
            threat_level="Informational",
            status="Complete",
            resolution=t,
            tags=["news", "coverage", "media"],
        ))

    for result in all_results:
        hl_count = len(result["headlines"])
        mention_count = result["target_mentions"]

        findings.append(make_finding(
            f"{result['name']}: {mention_count} mentions, {hl_count} headlines for {t}",
            ftype="News: Source Result",
            source="NewsMonitor",
            confidence="Medium",
            color="sky",
            category="News Intelligence",
            threat_level="Informational",
            status="Found" if mention_count > 0 else "No Mentions",
            resolution=t,
            tags=["news", result['name'].lower().replace(" ", "-"), "source"],
        ))

        if result["headlines"]:
            for headline in result["headlines"][:3]:
                sentiment = analyze_sentiment(headline)
                topics = categorize_topics(headline)
                sentiment_color = {"Positive": "emerald", "Negative": "red", "Neutral": "slate"}.get(sentiment, "slate")

                findings.append(make_finding(
                    f"Headline: {headline[:150]}",
                    ftype="News: Headline",
                    source="NewsMonitor",
                    confidence="Medium",
                    color=sentiment_color,
                    category="News Intelligence",
                    threat_level="Informational",
                    status="Detected",
                    resolution=t,
                    tags=["news", "headline", sentiment.lower()] + topics,
                ))

    all_headlines = []
    for r in all_results:
        all_headlines.extend(r.get("headlines", []))

    if all_headlines:
        sentiments = [analyze_sentiment(h) for h in all_headlines]
        pos_count = sentiments.count("Positive")
        neg_count = sentiments.count("Negative")
        neu_count = sentiments.count("Neutral")

        if neg_count > pos_count and neg_count > 0:
            findings.append(make_finding(
                f"Negative news sentiment detected ({neg_count}/{len(sentiments)} headlines negative)",
                ftype="News: Sentiment Alert",
                source="NewsMonitor",
                confidence="Medium",
                color="red",
                category="News Intelligence",
                threat_level="High Risk",
                status="Reputation Risk",
                resolution=t,
                tags=["news", "sentiment", "negative", "alert"],
            ))

        findings.append(make_finding(
            f"News sentiment: {pos_count} positive, {neg_count} negative, {neu_count} neutral headlines",
            ftype="News: Sentiment Analysis",
            source="NewsMonitor",
            confidence="High",
            color="slate",
            category="News Intelligence",
            threat_level="Informational",
            status="Analyzed",
            resolution=t,
            tags=["news", "sentiment", "analysis"],
        ))

    all_topics = set()
    for r in all_results:
        for hl in r.get("headlines", []):
            for topic in categorize_topics(hl):
                all_topics.add(topic)

    if all_topics:
        findings.append(make_finding(
            f"News topics covering {t}: {', '.join(sorted(all_topics))}",
            ftype="News: Topic Coverage",
            source="NewsMonitor",
            confidence="Medium",
            color="slate",
            category="News Intelligence",
            threat_level="Informational",
            status="Mapped",
            resolution=t,
            tags=["news", "topics"] + list(all_topics),
        ))

    total_mentions = sum(r.get("target_mentions", 0) for r in all_results)
    if total_mentions > 0:
        findings.append(make_finding(
            f"Total news mentions: {total_mentions} across {sources_with_data} sources",
            ftype="News: Mention Volume",
            source="NewsMonitor",
            confidence="Medium",
            color="slate",
            category="News Intelligence",
            threat_level="Informational",
            status="Measured",
            resolution=t,
            tags=["news", "volume", "mentions"],
        ))

    if not all_results:
        findings.append(make_finding(
            "No news mentions found for target",
            ftype="News: Scan Complete",
            source="NewsMonitor",
            confidence="Low",
            color="emerald",
            category="News Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["news", "clean"],
        ))

    return findings
