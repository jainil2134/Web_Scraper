from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import socket
import threading
import requests
import json
import os
import re
import whois
from datetime import datetime
from urllib.parse import urlparse
from scrapy.crawler import CrawlerProcess
from twisted.internet import reactor
from scraper import scrape_url
import importlib.util
import uuid
import subprocess
import sys

# --- YOUR EXISTING LOGIC START ---
# (Keep your SecuritySpider class and helper functions here)

app = FastAPI()

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str


# In-memory job store for long-running Scrapy scans
jobs = {}


# Load the existing Scrapy-based backend implementation from scans/updated_file.py
_updated_path = os.path.join(os.path.dirname(__file__), 'scans', 'updated_file.py')
spec = importlib.util.spec_from_file_location('updated_file', _updated_path)
updated = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updated)


def _run_full_scan(job_id: str, user_url: str):
    try:
        if not user_url.startswith('http'):
            user_url = 'https://' + user_url

        scan_start_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        parsed_url = urlparse(user_url)
        hostname = parsed_url.netloc.split(':')[0]

        try:
            target_ip = socket.gethostbyname(hostname)
            intel = updated.get_free_ip_intel(target_ip)
            ports = updated.get_live_ports(target_ip)
            whois_info = updated.get_whois_data(hostname)
            vpn_indicators = [1194, 500, 4500, 1723]
            vpn_banners = [p['banner'] for p in ports if p['port'] in vpn_indicators]
            vpn_status = f"VPN Found! Banner: {vpn_banners[0]}" if vpn_banners else "No VPN Server Found"
        except Exception:
            target_ip = "Resolution Failed"
            intel, ports, whois_info = {}, [], {}
            vpn_status = "No VPN Server Found"

        domain_clean = hostname.replace('.', '_')
        folder = "scans"
        if not os.path.exists(folder): os.makedirs(folder)
        target_filename = os.path.join(folder, f"{domain_clean}_{datetime.now().strftime('%H%M%S')}.json")

        metadata = {
            "scan_start_time": scan_start_dt,
            "target_ip": target_ip,
            "target_port": parsed_url.port or (443 if parsed_url.scheme == "https" else 80),
            "geo_intel": intel,
            "open_ports": ports,
            "vpn_status": vpn_status,
            "domain_dates": whois_info,
            "findings": { "proxy_detected": "Pending...", "security_header_audit": {} }
        }

        # Run the Scrapy spider in a separate process (scan_worker.py)
        worker_py = os.path.join(os.path.dirname(__file__), 'scan_worker.py')
        try:
            subprocess.run([sys.executable, worker_py, user_url, target_filename], check=True, timeout=300)
        except subprocess.CalledProcessError as e:
            jobs[job_id].update(status='failed', error=str(e))
            return
        except subprocess.TimeoutExpired:
            jobs[job_id].update(status='failed', error='Scan worker timed out')
            return

        # Read results and store them
        if os.path.exists(target_filename):
            with open(target_filename, 'r') as f:
                data = json.load(f)
            jobs[job_id].update(status='done', result_path=target_filename, result_data=data)
        else:
            jobs[job_id].update(status='failed', error='Result file not created')
    except Exception as e:
        jobs[job_id].update(status='failed', error=str(e))


# @app.post('/api/fullscan')
# async def start_fullscan(request: ScanRequest):
#     """Start a full Scrapy-based scan in a background thread. Returns a job_id to poll."""
#     job_id = uuid.uuid4().hex
#     jobs[job_id] = {'status': 'running'}
#     thread = threading.Thread(target=_run_full_scan, args=(job_id, request.url), daemon=True)
#     thread.start()
#     return {'job_id': job_id}


@app.get('/api/job/{job_id}')
async def get_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        return {'error': 'job not found'}, 404
    # Return full job record (status + data when ready)
    return job

@app.post("/api/scrape")
async def scrape_endpoint(request: ScanRequest):
    """Lightweight HTML scrape using requests + BeautifulSoup.
    Returns title, description, h1s, and links (first 50).
    """
    user_url = request.url
    if not user_url.startswith('http'):
        user_url = 'http://' + user_url

    result = scrape_url(user_url)
    return result

# Serve the frontend static files (index.html, script.js, etc.)
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)