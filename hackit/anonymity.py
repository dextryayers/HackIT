"""
HackIt Anonymity & Stealth Engine
Provides robust evasion capabilities:
- Header Rotation (User-Agent, Referer, etc.)
- Proxy Management (Tor, SOCKS5, HTTP)
- DNS Leak Protection (Public Resolver Rotation)
- Traffic Shaping (Jitter, Delays)
"""
import random
import time
import asyncio
import os
from typing import Dict, List, Optional

# Public Trusted DNS Resolvers (Logless/Privacy-focused preferred)
PUBLIC_RESOLVERS = [
    '1.1.1.1', '1.0.0.1',           # Cloudflare
    '8.8.8.8', '8.8.4.4',           # Google
    '9.9.9.9', '149.112.112.112',   # Quad9
    '208.67.222.222', '208.67.220.220', # OpenDNS
    '8.26.56.26', '8.20.247.20',    # Comodo Secure DNS
    '64.6.64.6', '64.6.65.6',       # Verisign
    '185.228.168.9', '185.228.169.9', # CleanBrowsing
    '76.76.2.0', '76.76.10.0',      # Control D
    '94.140.14.14', '94.140.15.15'  # AdGuard DNS
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
]

class StealthManager:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.proxies: List[str] = []
        self.current_resolver_index = 0
        
    def get_headers(self) -> Dict[str, str]:
        """Get stealthy headers with randomized User-Agent"""
        if not self.enabled:
            return {'User-Agent': 'HackIt-Security-Scanner/2.0'}
            
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache'
        }

    def get_dns_resolvers(self) -> List[str]:
        """Get list of public DNS resolvers for rotation"""
        if not self.enabled:
            return [] # Use system default
        
        # Shuffle to distribute load across different providers
        resolvers = PUBLIC_RESOLVERS.copy()
        random.shuffle(resolvers)
        return resolvers

    async def sleep_jitter(self, base_delay: float = 0.5, max_jitter: float = 1.5):
        """Sleep for a random amount of time to evade timing analysis"""
        if not self.enabled:
            return
        
        delay = random.uniform(base_delay, max_jitter)
        await asyncio.sleep(delay)

    def configure_resolver_stealth(self, resolver_obj):
        """Configure a dns.resolver object to use stealthy public nameservers"""
        if not self.enabled:
            return
            
        resolver_obj.nameservers = self.get_dns_resolvers()
        # Rotate logic can be handled by the resolver library automatically trying multiple NS
        # But we force it to use our list instead of /etc/resolv.conf

# Global singleton
stealth_engine = StealthManager()

def enable_stealth_mode():
    stealth_engine.enabled = True
    
def is_stealth_enabled():
    return stealth_engine.enabled
