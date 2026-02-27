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
        self.final_data = audit_metadata or {}
        self.final_data["findings"] = {} 

    def parse(self, response):
        soup = BeautifulSoup(response.text, 'html.parser')
        sensitive_keywords = ['password', 'config', 'key', 'admin', 'db', 'user']
        all_comments = [c.strip() for c in soup.find_all(string=lambda text: isinstance(text, Comment))]
        
        raw_links = [response.urljoin(a['href']) for a in soup.find_all('a', href=True)]
        sub_urls = sorted(list(set([link for link in raw_links if urlparse(link).netloc == self.target_domain])))
        
        self.final_data["findings"] = {
            "URL": response.url,
            "Headers": [h.get_text().strip() for h in soup.find_all(['h1', 'h2'])],
            "Hidden_Inputs": [tag.get('name', 'unnamed') for tag in soup.find_all('input', type='hidden')],
            "Flagged_Comments": [c for c in all_comments if any(k in c.lower() for k in sensitive_keywords)],
            "Sub_URLs_Found": sub_urls
        }

    def closed(self, reason):
        end_time = datetime.now()
        start_time_str = self.final_data.get("scan_start_time")
        if start_time_str:
            start_time = datetime.fromisoformat(start_time_str)
            self.final_data["total_time_taken"] = str(end_time - start_time)
        
        self.final_data["scan_end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")

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
    
    try:
        target_ip = socket.gethostbyname(hostname)
    except:
        target_ip = "Resolution Failed"

    audit_metadata = {
        "target_hostname": hostname,
        "target_ip": target_ip,
        "target_port": 443 if parsed_url.scheme == "https" else 80,
        "scan_start_time": start_time.isoformat()
    }

    # --- ENHANCED FILENAME LOGIC ---
    domain_clean = hostname.replace('.', '_')
    folder = "scans"
    if not os.path.exists(folder): os.makedirs(folder)
    
    # Check for existing files and append number
    base_filename = os.path.join(folder, f"{domain_clean}")
    extension = ".json"
    target_filename = base_filename + extension
    counter = 1
    
    while os.path.exists(target_filename):
        target_filename = f"{base_filename}_{counter}{extension}"
        counter += 1
    # -------------------------------

    process = CrawlerProcess(settings={
        "LOG_LEVEL": "ERROR", 
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "ROBOTSTXT_OBEY": False 
    })

    process.crawl(SecuritySpider, url=user_url, filename=target_filename, audit_metadata=audit_metadata)
    process.start() 

    if os.path.exists(target_filename):
        with open(target_filename, 'r') as f:
            data = json.load(f)

        summary = [
            ["Metric", "Details"],
            ["Hostname", data["target_hostname"]],
            ["IP Address", data["target_ip"]],
            ["Duration", data.get("total_time_taken", "N/A")],
            ["Sub-URLs", len(data["findings"].get("Sub_URLs_Found", []))],
            ["File Path", target_filename]
        ]
        print("\n" + tabulate(summary, headers="firstrow", tablefmt="fancy_grid"))
    else:
        print("\n[!] Error: Scan failed to generate a report.")

if __name__ == "__main__":
    run_audit()