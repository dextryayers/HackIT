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

class SummaryItem(BaseModel):
    type: str
    unique_count: int
    total_count: int
    last_finding: Optional[str] = None

class ScanJob(BaseModel):
    job_id: str
    target: str
    target_type: str = "Domain" # Default
    status: str 
    findings: List[IntelligenceFinding] = []
    summary: List[SummaryItem] = [] # For the SpiderFoot Browse table
    stats: Optional[IntelligenceStats] = None
    duration: str = "0s"
    created_at: datetime = datetime.now()
