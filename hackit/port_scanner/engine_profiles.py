from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Profile:
    name: str = 'Quick'
    description: str = ''
    ports: Optional[List[int]] = None
    workers: int = 150
    timeout_ms: int = 1000
    scan_mode: str = 'tcp-connect'
    stealth: bool = False
    stages: List[str] = field(default_factory=lambda: ['tcp_scan', 'service_detect'])
    engines: List[str] = field(default_factory=lambda: ['go'])
    deep: bool = False
    os_detect: bool = False
    vuln_scan: bool = False
    adaptive: bool = False
    quantum: bool = False
    script: str = ''
    min_rate: int = 0
    max_rate: int = 0
    max_retries: int = 3
    host_timeout: int = 300
    no_ping: bool = False

    def merge(self, **overrides):
        d = {}
        for k in ('name', 'description', 'ports', 'workers', 'timeout_ms', 'scan_mode',
                   'stealth', 'stages', 'engines', 'deep', 'os_detect', 'vuln_scan',
                   'adaptive', 'quantum', 'script', 'min_rate', 'max_rate', 'max_retries',
                   'host_timeout', 'no_ping'):
            d[k] = getattr(self, k)
        for k, v in overrides.items():
            if v is not None:
                if k == 'engines' and isinstance(v, str):
                    v = [e.strip() for e in v.split(',')]
                if k == 'stages' and isinstance(v, str):
                    v = [s.strip() for s in v.split(',')]
                d[k] = v
        return Profile(**d)


_BUILTIN_PROFILES = {}


def _init_profiles():
    global _BUILTIN_PROFILES
    _BUILTIN_PROFILES = {
        'quick': Profile(
            name='Quick',
            description='Fast scan of top 100 common ports (nmap-style)',
            workers=200,
            timeout_ms=1000,
            scan_mode='connect',
            stages=['tcp_scan', 'service_detect'],
            engines=['go'],
            adaptive=True,
            quantum=True,
            max_retries=2,
            host_timeout=60,
        ),
        'stealth': Profile(
            name='Stealth',
            description='Low-and-slow SYN scan with evasion techniques',
            workers=10,
            timeout_ms=3000,
            scan_mode='syn',
            stealth=True,
            stages=['tcp_scan', 'service_detect', 'os_detect'],
            engines=['go'],
            os_detect=True,
            adaptive=True,
            quantum=True,
            min_rate=1,
            max_rate=10,
            max_retries=5,
            host_timeout=600,
            no_ping=True,
        ),
        'full': Profile(
            name='Full',
            description='Comprehensive scan of all 65535 ports with service detection',
            workers=150,
            timeout_ms=1500,
            scan_mode='syn',
            stages=['discovery', 'tcp_scan', 'service_detect', 'os_detect', 'vuln_scan', 'enrich'],
            engines=['rust'],
            deep=True,
            os_detect=True,
            vuln_scan=True,
            adaptive=True,
            quantum=True,
            min_rate=3,
            max_rate=50,
            max_retries=3,
            host_timeout=1800,
        ),
        'web': Profile(
            name='Web',
            description='Web server focused scan (HTTP/HTTPS + common web services)',
            ports=[80, 443, 8080, 8443, 8000, 8888, 9443, 3000, 4000, 5000, 8008, 8069, 9000, 9090, 21, 22, 25, 53, 110, 143, 3306, 5432, 6379, 27017, 3389, 5900, 6443, 2375, 2376, 9200, 11211, 1433, 1521, 5672, 5984, 9042, 9092, 8200, 8500, 2181, 10250, 10255],
            workers=100,
            timeout_ms=1000,
            scan_mode='connect',
            stages=['tcp_scan', 'service_detect', 'vuln_scan'],
            engines=['go'],
            deep=True,
            vuln_scan=True,
            quantum=True,
            max_retries=2,
            host_timeout=300,
            no_ping=True,
            script='http-enum',
        ),
        'lan': Profile(
            name='LAN',
            description='Optimized for local network scanning (low latency, high throughput)',
            workers=300,
            timeout_ms=300,
            scan_mode='syn',
            stages=['discovery', 'tcp_scan', 'service_detect', 'os_detect', 'enrich'],
            engines=['go', 'c'],
            deep=True,
            os_detect=True,
            adaptive=True,
            quantum=True,
            min_rate=10,
            max_rate=200,
            max_retries=1,
            host_timeout=120,
        ),
        'comprehensive': Profile(
            name='Comprehensive',
            description='Maximum depth - all ports, all engines, full vulnerability analysis',
            workers=200,
            timeout_ms=2000,
            scan_mode='c-turbo',
            stages=['discovery', 'tcp_scan', 'service_detect', 'os_detect', 'vuln_scan', 'enrich'],
            engines=['go', 'rust', 'c', 'cpp'],
            deep=True,
            os_detect=True,
            vuln_scan=True,
            adaptive=True,
            quantum=True,
            max_retries=4,
            host_timeout=3600,
            script='all',
        ),
    }


def get_profile(name='quick'):
    if not _BUILTIN_PROFILES:
        _init_profiles()
    name = name.strip().lower()
    return _BUILTIN_PROFILES.get(name, _BUILTIN_PROFILES['quick'])


def list_profiles():
    if not _BUILTIN_PROFILES:
        _init_profiles()
    return list(_BUILTIN_PROFILES.values())
