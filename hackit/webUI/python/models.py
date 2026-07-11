from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime


class IntelligenceFinding(BaseModel):
    entity: str
    type: str
    source: str
    confidence: str
    color: str
    category: Optional[str] = "General OSINT"
    threat_level: Optional[str] = "Informational"
    status: Optional[str] = "Unknown"
    resolution: Optional[str] = None
    raw_data: Optional[str] = None
    tags: List[str] = []


class IntelligenceStats(BaseModel):
    total_findings: int
    risk_distribution: Dict[str, int]
    type_distribution: Dict[str, int]
    timeline: List[Dict[str, Any]]
    module_logs: List[Dict[str, str]] = []
    source_distribution: Dict[str, int] = {}
    category_distribution: Dict[str, int] = {}


class SummaryItem(BaseModel):
    type: str
    unique_count: int
    total_count: int
    last_finding: Optional[str] = None
    category: str = "UNCLASSIFIED"


class RustSSLResponse(BaseModel):
    hostname: str
    port: int = 443
    grade: Optional[str] = None
    score: Optional[int] = None
    duration_ms: Optional[int] = None
    
    certificate: Optional[Dict[str, Any]] = None
    chain: Optional[Dict[str, Any]] = None
    ciphers: Optional[Dict[str, Any]] = None
    vulnerabilities: Optional[Dict[str, Any]] = None
    tls_features: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, Any]] = None
    crypto: Optional[Dict[str, Any]] = None
    ports: Optional[Dict[str, Any]] = None
    all_issues: List[str] = []
    error: Optional[str] = None


class SettingsResponse(BaseModel):
    api_keys: Dict[str, str]
    scan_defaults: Dict[str, Any]


class ScanJob(BaseModel):
    job_id: str
    target: str
    target_type: str = "Domain"
    status: str
    findings: List[IntelligenceFinding] = []
    summary: List[SummaryItem] = []
    stats: Optional[IntelligenceStats] = None
    duration: str = "0s"
    live_logs: List[str] = []
    created_at: datetime = datetime.now()
    settings: Dict[str, Any] = {}


class DNSRecord(BaseModel):
    type: str
    name: str
    value: str
    ttl: Optional[int] = None


class DNSResponse(BaseModel):
    domain: str
    records: List[DNSRecord] = []
    email_security: Optional[Dict[str, Any]] = None
    mx_analysis: Optional[Dict[str, Any]] = None
    nameservers: List[str] = []
    has_wildcard: bool = False
    error: Optional[str] = None


class SSLResponse(BaseModel):
    hostname: str
    issuer: Optional[Dict[str, str]] = None
    subject: Optional[Dict[str, str]] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_remaining: Optional[int] = None
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    subject_alt_names: List[str] = []
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    chain_length: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    error: Optional[str] = None


class HTTPHeaderResponse(BaseModel):
    url: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = {}
    security_headers: Dict[str, Any] = {}
    missing_security_headers: List[str] = []
    server: Optional[str] = None
    technology: List[str] = []
    cdn: Optional[str] = None
    cookies: List[str] = []
    redirect_chain: List[str] = []
    error: Optional[str] = None


class WHOISResponse(BaseModel):
    domain: str
    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_email: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = []
    status: List[str] = []
    abuse_email: Optional[str] = None
    abuse_phone: Optional[str] = None
    raw_text: Optional[str] = None
    error: Optional[str] = None


class IPGeoResponse(BaseModel):
    ip: str
    hostname: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    continent: Optional[str] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    rdap_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class SubdomainResponse(BaseModel):
    domain: str
    subdomains: List[Dict[str, str]] = []
    total: int = 0
    sources: List[str] = []
    error: Optional[str] = None


class EmailResponse(BaseModel):
    domain: str
    emails: List[str] = []
    total: int = 0
    sources: List[str] = []
    breach_count: Optional[int] = None
    error: Optional[str] = None


class PortScanResponse(BaseModel):
    target: str
    open_ports: List[Dict[str, Any]] = []
    total_open: int = 0
    scan_time: str = ""
    error: Optional[str] = None
