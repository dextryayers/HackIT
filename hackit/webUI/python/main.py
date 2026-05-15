from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uuid
import time
import asyncio
import os
from models import ScanJob, IntelligenceFinding, IntelligenceStats, SummaryItem
from orchestrator import run_modular_scan
from typing import Dict
import random

app = FastAPI(title="HackIT Industrial OSINT Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

jobs: Dict[str, ScanJob] = {}

@app.get("/api/ping")
async def ping():
    return {"status": "alive", "engine": "Industrial Python"}

async def run_scan_task(job_id: str, target: str, target_type: str):
    job = jobs[job_id]
    start_time = time.time()
    
    try:
        # Run modular orchestrator
        findings, summary, logs = await run_modular_scan(target, target_type)
        
        # Calculate Stats
        risk_dist = {"High Risk": 0, "Elevated Risk": 0, "Standard Target": 0, "Informational": 0}
        type_dist = {}
        
        for f in findings:
            risk_dist[f.threat_level] = risk_dist.get(f.threat_level, 0) + 1
            type_dist[f.type] = type_dist.get(f.type, 0) + 1

        job.stats = IntelligenceStats(
            total_findings=len(findings),
            risk_distribution=risk_dist,
            type_distribution=type_dist,
            timeline=[{"time": time.strftime("%H:%M:%S"), "count": random.randint(1, 15)} for _ in range(5)],
            module_logs=logs
        )
        
        job.findings = findings
        job.summary = summary
        job.status = "Completed"
        job.duration = f"{round(time.time() - start_time, 2)}s"
        
    except Exception as e:
        job.status = "Error"
        print(f"Modular Scan Error: {str(e)}")

@app.get("/api/scan")
async def start_scan(target: str, target_type: str = "Domain", background_tasks: BackgroundTasks = None):
    job_id = f"job_{uuid.uuid4().hex[:8]}"
    job = ScanJob(job_id=job_id, target=target, target_type=target_type, status="Running")
    jobs[job_id] = job
    
    if background_tasks:
        background_tasks.add_task(run_scan_task, job_id, target, target_type)
    else:
        # Fallback for manual testing
        asyncio.create_task(run_scan_task(job_id, target, target_type))
        
    return {"job_id": job_id, "status": "Started"}

@app.get("/api/status")
async def get_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]

# --- Static File Serving ---
dist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dist")

if os.path.exists(dist_path):
    # Mount the dist folder for static assets
    app.mount("/_astro", StaticFiles(directory=os.path.join(dist_path, "_astro")), name="astro_assets")
    
    # Catch-all for pages (Astro builds pages as folder/index.html or page.html)
    @app.get("/{path:path}")
    async def serve_static(path: str):
        # Try to serve exact file
        file_path = os.path.join(dist_path, path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        
        # Try to serve as directory (index.html)
        index_path = os.path.join(dist_path, path, "index.html")
        if os.path.isfile(index_path):
            return FileResponse(index_path)
        
        # Fallback to main index
        return FileResponse(os.path.join(dist_path, "index.html"))
else:
    print(f"[!] Warning: {dist_path} not found. Run 'npm run build' first.")

if __name__ == "__main__":
    import uvicorn
    # Changed to port 8080 as requested
    uvicorn.run(app, host="0.0.0.0", port=8080)
