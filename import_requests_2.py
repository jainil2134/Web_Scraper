import scrapy
from scrapy.crawler import CrawlerProcess
from bs4 import BeautifulSoup, Comment
from tabulate import tabulate
from urllib.parse import urlparse
import json
import os
import socket
from datetime import datetime

class SecuritySpider(scrapy.Spider):
    name = "security_spider"
    
    def __init__(self, url=None, filename=None, audit_metadata=None, *args, **kwargs):
        super(SecuritySpider, self).__init__(*args, **kwargs)
        self.start_urls = [url]
        self.target_domain = urlparse(url).netloc
        self.output_file = filename
        self.audit_metadata = audit_metadata or {}
        self.final_data = {}

    def parse(self, response):
        soup = BeautifulSoup(response.text, 'html.parser')
        sensitive_keywords = ['password', 'config', 'key', 'admin', 'db', 'user']
        all_comments = [c.strip() for c in soup.find_all(string=lambda text: isinstance(text, Comment))]
        
        # 1. Identify Sub-URLs (Internal) vs External Links
        raw_links = [response.urljoin(a['href']) for a in soup.find_all('a', href=True)]
        sub_urls = sorted(list(set([link for link in raw_links if urlparse(link).netloc == self.target_domain])))
        external_links = sorted(list(set([link for link in raw_links if urlparse(link).netloc != self.target_domain])))

        # 2. Package Scraped Content
        scraped_content = {
            "URL": response.url,
            "Headers": [h.get_text().strip() for h in soup.find_all(['h1', 'h2'])],
            "Hidden_Inputs": [tag.get('name', 'unnamed') for tag in soup.find_all('input', type='hidden')],
            "Flagged_Comments": [c for c in all_comments if any(k in c.lower() for k in sensitive_keywords)],
            "Sub_URLs_Found": sub_urls,
            "External_Links_Found": external_links
        }
        
        self.final_data = {**self.audit_metadata, "findings": scraped_content}

    def closed(self, reason):
        end_time = datetime.now()
        start_time = datetime.fromisoformat(self.final_data["scan_start_time"])
        duration = end_time - start_time
        
        self.final_data["scan_end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
        self.final_data["total_time_taken"] = str(duration)

        with open(self.output_file, 'w') as f:
            json.dump(self.final_data, f, indent=4)

def run_audit():
    print("\n" + "="*40)
    print("  STRATEGIC WEB & NETWORK AUDITOR")
    print("="*40)
    user_url = input("Enter URL to scan: ").strip()
    if not user_url.startswith("http"):
        user_url = "https://" + user_url

    start_time = datetime.now()
    parsed_url = urlparse(user_url)
    hostname = parsed_url.netloc
    port = parsed_url.port if parsed_url.port else (443 if parsed_url.scheme == "https" else 80)
    
    try:
        target_ip = socket.gethostbyname(hostname)
    except Exception:
        target_ip = "Resolution Failed"

    audit_metadata = {
        "target_hostname": hostname,
        "target_ip": target_ip,
        "target_port": port,
        "scan_start_time": start_time.isoformat()
    }

    domain_clean = hostname.replace('.', '_')
    folder = "scans"
    if not os.path.exists(folder): os.makedirs(folder)
    target_filename = os.path.join(folder, f"{domain_clean}.json")

    process = CrawlerProcess(settings={
        "LOG_LEVEL": "ERROR", 
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    })

    process.crawl(SecuritySpider, url=user_url, filename=target_filename, audit_metadata=audit_metadata)
    process.start() 

    with open(target_filename, 'r') as f:
        data = json.load(f)

    # --- Final Tabular Summary ---
    summary_table = [
        ["Metric", "Details"],
        ["Hostname", data["target_hostname"]],
        ["IP Address", data["target_ip"]],
        ["Port", data["target_port"]],
        ["Start Time", data["scan_start_time"]],
        ["End Time", data["scan_end_time"]],
        ["Duration", data["total_time_taken"]],
        ["Sub-URLs Found", len(data["findings"]["Sub_URLs_Found"])],
        ["Hidden Inputs", len(data["findings"]["Hidden_Inputs"])],
        ["Flagged Comments", len(data["findings"]["Flagged_Comments"])],
        ["Storage Path", target_filename]
    ]

    print("\n[*] SCAN COMPLETE")
    print(tabulate(summary_table, headers="firstrow", tablefmt="fancy_grid"))

if __name__ == "__main__":
    run_audit()