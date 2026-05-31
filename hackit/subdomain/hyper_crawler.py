import asyncio
import aiohttp
import re
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class HyperCrawler:
    def __init__(self, domain, max_depth=3, max_concurrency=50):
        self.domain = domain
        self.max_depth = max_depth
        self.max_concurrency = max_concurrency
        self.subdomains = set()
        self.visited = set()
        self.queue = asyncio.Queue()
        self.session = None
        # Pattern to match subdomains of the target domain
        self.sub_pattern = re.compile(rf'([a-zA-Z0-9-]+\.)+{re.escape(self.domain)}')
        # Ignored extensions
        self.ignore_exts = {'.png', '.jpg', '.jpeg', '.gif', '.css', '.pdf', '.zip', '.rar', '.exe', '.svg', '.mp4'}

    async def fetch(self, url):
        try:
            async with self.session.get(url, timeout=10, ssl=False, allow_redirects=True) as response:
                if response.status == 200:
                    text = await response.text()
                    return text
        except Exception:
            pass
        return ""

    def extract_links(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Find hrefs in a tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            links.add(full_url)
            
        # Find src in scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            links.add(full_url)
            
        return links

    def extract_subdomains(self, text):
        matches = self.sub_pattern.finditer(text)
        for match in matches:
            sub = match.group(0).lower().strip(".")
            if sub.endswith("." + self.domain) or sub == self.domain:
                self.subdomains.add(sub)

    async def worker(self):
        while True:
            try:
                current_depth, url = await self.queue.get()
                
                parsed_url = urlparse(url)
                if any(url.lower().endswith(ext) for ext in self.ignore_exts):
                    self.queue.task_done()
                    continue

                html = await self.fetch(url)
                if html:
                    self.extract_subdomains(html)
                    
                    if current_depth < self.max_depth:
                        links = self.extract_links(html, url)
                        for link in links:
                            link_parsed = urlparse(link)
                            if link_parsed.hostname and self.domain in link_parsed.hostname:
                                # Clean URL (remove fragments and queries for uniqueness)
                                clean_url = f"{link_parsed.scheme}://{link_parsed.netloc}{link_parsed.path}"
                                if clean_url not in self.visited:
                                    self.visited.add(clean_url)
                                    await self.queue.put((current_depth + 1, clean_url))
                
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception:
                self.queue.task_done()

    async def run(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=self.max_concurrency)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        async with aiohttp.ClientSession(connector=connector, headers=headers) as self.session:
            # Seed URLs
            seed_urls = [
                f"http://{self.domain}",
                f"https://{self.domain}",
                f"http://www.{self.domain}",
                f"https://www.{self.domain}"
            ]
            
            for url in seed_urls:
                self.visited.add(url)
                await self.queue.put((1, url))

            workers = [asyncio.create_task(self.worker()) for _ in range(self.max_concurrency)]
            
            # Wait for queue to process
            await self.queue.join()
            
            for w in workers:
                w.cancel()
                
        return list(self.subdomains)

def run_hyper_crawler(domain):
    crawler = HyperCrawler(domain, max_depth=3, max_concurrency=100)
    # Using asyncio.run directly (works in Python 3.7+)
    return asyncio.run(crawler.run())
