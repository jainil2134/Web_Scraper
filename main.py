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
from scrapy.crawler import CrawlerRunner
from twisted.internet import reactor
from scraper import scrape_url

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

@app.post("/api/audit")
async def start_audit(request: ScanRequest):
    user_url = request.url
    if not user_url.startswith("http"):
        user_url = "https://" + user_url

    # Initialize Timestamps
    scan_start_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    parsed_url = urlparse(user_url)
    hostname = parsed_url.netloc.split(':')[0]
    
    # 1. Run Helpers (Socket, WHOIS, IP-Intel)
    try:
        target_ip = socket.gethostbyname(hostname)
        intel = get_free_ip_intel(target_ip) 
        ports = get_live_ports(target_ip)    
        whois_info = get_whois_data(hostname) 
        
        vpn_indicators = [1194, 500, 4500, 1723]
        vpn_banners = [p['banner'] for p in ports if p['port'] in vpn_indicators]
        vpn_status = f"VPN Found! Banner: {vpn_banners[0]}" if vpn_banners else "No VPN Server Found"
    except:
        target_ip = "Resolution Failed"
        intel, ports, whois_info = {}, [], {}
        vpn_status = "No VPN Server Found"

    # 2. Setup Filename
    domain_clean = hostname.replace('.', '_')
    folder = "scans"
    if not os.path.exists(folder): os.makedirs(folder)
    target_filename = os.path.join(folder, f"{domain_clean}_{datetime.now().strftime('%H%M%S')}.json")

    # 3. Assemble Metadata for Response
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

    # Note: Scrapy normally blocks the thread. For a production-ready GUI, 
    # you would trigger the spider as a background task.
    return metadata


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