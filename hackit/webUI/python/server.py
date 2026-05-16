from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uuid
import time
import asyncio
from models import ScanJob, IntelligenceFinding, IntelligenceStats
from crawler_engine import OSINTCrawler
from typing import Dict
import random

app = FastAPI(title="HackIT OSINT Engine (Python)")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job storage
jobs: Dict[str, ScanJob] = {}

@app.get("/api/ping")
async def ping():
    return {"status": "alive", "engine": "Python/FastAPI"}

@app.get("/")
async def root():
    return {
        "engine": "HackIT Python Engine",
        "status": "Operational",
        "version": "2.0.0-async"
    }

async def run_scan_task(job_id: str, target: str):
    job = jobs[job_id]
    start_time = time.time()
    
    try:
        crawler = OSINTCrawler(target)
        # 1. Crawl
        job.findings = await crawler.crawl_all()
        
        # 2. Verify (DNS)
        await crawler.verify_assets()
        await crawler.close()

        # 3. Process & Stats (Heuristics)
        risk_dist = {"High Risk": 0, "Elevated Risk": 0, "Standard Target": 0, "Informational": 0}
        type_dist = {}
        
        for f in job.findings:
            # Simple heuristic
            if any(x in f.entity.lower() for x in ['admin', 'vpn', 'cpanel']):
                f.threat_level = "High Risk"
                f.color = "red"
            
            risk_dist[f.threat_level] = risk_dist.get(f.threat_level, 0) + 1
            type_dist[f.type] = type_dist.get(f.type, 0) + 1

        job.stats = IntelligenceStats(
            total_findings=len(job.findings),
            risk_distribution=risk_dist,
            type_distribution=type_dist,
            timeline=[{"time": time.strftime("%H:%M:%S"), "count": random.randint(5, 20)} for _ in range(5)]
        )
        
        job.status = "Completed"
        job.duration = f"{round(time.time() - start_time, 2)}s"
        
    except Exception as e:
        job.status = "Error"
        print(f"Scan Task Error: {str(e)}")

@app.get("/api/scan")
async def start_scan(target: str, background_tasks: BackgroundTasks):
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    job_id = f"job_{uuid.uuid4().hex[:8]}"
    job = ScanJob(job_id=job_id, target=target, status="Running")
    jobs[job_id] = job
    
    background_tasks.add_task(run_scan_task, job_id, target)
    
    return {"job_id": job_id, "status": "Started"}

@app.get("/api/status")
async def get_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081) # Keep port 8081 to maintain compatibility with Astro
