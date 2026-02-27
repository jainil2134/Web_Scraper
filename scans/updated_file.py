import scrapy
from scrapy.crawler import CrawlerProcess
from bs4 import BeautifulSoup, Comment
from tabulate import tabulate
from urllib.parse import urlparse
import json
import os
import socket
import requests 
import re
import whois
import threading
from datetime import datetime

class SecuritySpider(scrapy.Spider):
    name = "security_spider"
    
    def __init__(self, url=None, filename=None, audit_metadata=None, *args, **kwargs):
        super(SecuritySpider, self).__init__(*args, **kwargs)
        self.start_urls = [url]
        self.target_domain = urlparse(url).netloc
        self.output_file = filename
        
        self.final_data = audit_metadata or {}
        self.final_data["findings"] = {
            "http_headers": {},
            "server_software": "Unknown",
            "operating_system": "Unknown",
            "comments": [],
            "proxy_detected": "No Proxy Found",
            "security_header_audit": {} 
        }
        self.final_data["sub_urls"] = set()
        self.final_data["external_connections"] = set()
        self.final_data["navigation_map"] = []

    def parse(self, response):
        soup = BeautifulSoup(response.text, 'html.parser')
        self.final_data["sub_urls"].add(response.url)
        
        # Capture headers and decode them
        resp_headers = {k.decode('utf-8'): v[0].decode('utf-8') for k, v in response.headers.items()}
        self.final_data["findings"]["http_headers"] = resp_headers
        
        # --- NEW LOGIC: Case-Insensitive Security Header Audit ---
        # Convert all keys to lowercase to catch 'content-security-policy' or 'Content-Security-Policy'
        headers_lower = {k.lower(): v for k, v in resp_headers.items()}
        
        hsts = headers_lower.get('strict-transport-security', 'MISSING')
        csp = headers_lower.get('content-security-policy', 'MISSING')
        
        self.final_data["findings"]["security_header_audit"] = {
            "Strict-Transport-Security": hsts,
            "Content-Security-Policy": csp
        }
        
        # Debug print to see keys in your terminal during execution
        # print(f"[*] DEBUG - Available Headers for {response.url}: {list(headers_lower.keys())}")

        proxy_headers = ['via', 'x-forwarded-for', 'cf-ray', 'forwarded']
        detected = [h for h in proxy_headers if h in headers_lower]
        if detected or "cloudflare" in headers_lower.get('server', ''):
            self.final_data["findings"]["proxy_detected"] = f"Proxy Detected ({', '.join(detected) if detected else 'WAF'})"

        server_header = headers_lower.get('server', '')
        os_match = re.search(r'\((.*?)\)', server_header)
        self.final_data["findings"]["operating_system"] = os_match.group(1) if os_match else "Hidden"
        self.final_data["findings"]["server_software"] = re.sub(r'\s\(.*?\)', '', server_header).strip() or "Unknown"

        for a in soup.find_all('a', href=True):
            link = response.urljoin(a['href'])
            link_domain = urlparse(link).netloc
            
            self.final_data["navigation_map"].append({
                "from": response.url, "to": link, "text": a.get_text().strip() or "[Internal Link]"
            })

            if link_domain == self.target_domain:
                self.final_data["sub_urls"].add(link)
            elif link_domain:
                self.final_data["external_connections"].add(link_domain)

    def closed(self, reason):
        self.final_data["sub_urls"] = sorted(list(self.final_data["sub_urls"]))
        self.final_data["external_connections"] = sorted(list(self.final_data["external_connections"]))
        with open(self.output_file, 'w') as f:
            json.dump(self.final_data, f, indent=4, default=str)

# --- HELPERS ---

def get_free_ip_intel(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as")
        data = response.json()
        return data if data.get('status') == 'success' else {}
    except:
        return {}

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((ip, port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner.split('\n')[0] if banner else "No Banner Responded"
    except:
        return "Banner Grabbing Failed"

def scan_port_with_banner(ip, port, open_ports):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        if s.connect_ex((ip, port)) == 0:
            try: service = socket.getservbyport(port)
            except: service = "Unknown"
            banner = grab_banner(ip, port)
            open_ports.append({"port": port, "service": service, "banner": banner})

def get_live_ports(ip):
    vpn_ports = [1194, 500, 4500, 1723]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080] + vpn_ports
    open_ports = []
    threads = []
    for port in common_ports:
        t = threading.Thread(target=scan_port_with_banner, args=(ip, port, open_ports))
        t.start()
        threads.append(t)
    for t in threads: t.join()
    return open_ports

def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return {"created": created.strftime('%Y-%m-%d') if created else "N/A"}
    except:
        return {"created": "N/A"}

# --- MAIN ENGINE ---

def run_audit():
    print("\n" + "="*75)
    print("  STRATEGIC RECONNAISSANCE TOOL: DETAILED SUMMARY MODE")
    print("="*75)
    user_url = input("Enter URL to scan: ").strip()
    if not user_url.startswith("http"): user_url = "https://" + user_url

    scan_start_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    parsed_url = urlparse(user_url)
    hostname = parsed_url.netloc.split(':')[0]
    
    try:
        target_ip = socket.gethostbyname(hostname)
        print(f"[*] Gathering intelligence for {target_ip}...")
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

    domain_clean = hostname.replace('.', '_')
    folder = "scans"
    if not os.path.exists(folder): os.makedirs(folder)
    target_filename = os.path.join(folder, f"{domain_clean}_{datetime.now().strftime('%H%M%S')}.json")

    metadata = {
        "target_ip": target_ip,
        "target_port": parsed_url.port or (443 if parsed_url.scheme == "https" else 80),
        "geo_intel": intel,
        "open_ports": ports,
        "vpn_status": vpn_status,
        "domain_dates": whois_info,
        "scan_start_time": scan_start_dt 
    }

    process = CrawlerProcess(settings={
        "LOG_LEVEL": "ERROR", 
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "ROBOTSTXT_OBEY": False # Set to False for educational research on sites that block spiders
    })
    process.crawl(SecuritySpider, url=user_url, filename=target_filename, audit_metadata=metadata)
    process.start()

    scan_end_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if os.path.exists(target_filename):
        with open(target_filename, 'r') as f:
            data = json.load(f)
        
        # --- NEW LOGIC: Robust, Case-Insensitive Audit ---
        header_audit = data.get("findings", {}).get("security_header_audit", {})
        
        hsts_val = header_audit.get("Strict-Transport-Security", "MISSING")
        csp_val = header_audit.get("Content-Security-Policy", "MISSING")

        hsts_status = "PRESENT" if hsts_val != "MISSING" else "MISSING"
        csp_status = "PRESENT" if csp_val != "MISSING" else "MISSING"

        sum_table = [
            ["Metric", "Reconnaissance Details"],
            ["Scan Start Time", data.get("scan_start_time")],
            ["Scan End Time", scan_end_dt],
            ["Target IP", data["target_ip"]],
            ["Target Port", data["target_port"]],
            ["Server Software", data["findings"].get("server_software", "Unknown")],
            ["Operating System", data["findings"].get("operating_system", "Unknown")],
            ["VPN Software Info", data.get("vpn_status", "No VPN Server Found")],
            ["HSTS Header", hsts_status],
            ["CSP Header", csp_status],
            ["ISP / Org", f"{data['geo_intel'].get('isp', 'N/A')} / {data['geo_intel'].get('organization', 'N/A')}"] ,
            ["ASN Details", data["geo_intel"].get("as", "N/A")],
            ["Created", data["domain_dates"].get("created", "N/A")],
            ["Open Ports", ", ".join([str(p['port']) for p in data['open_ports']]) if data.get('open_ports') else "None Detected"],
            ["HTTP Headers Found", len(data["findings"].get("http_headers", {}))],
            ["Proxy Status", data["findings"].get("proxy_detected", "No Proxy Found")],
            ["Internal Pages", len(data.get("sub_urls", []))],
            ["External URLs", len(data.get("external_connections", []))],
            ["Navigation Routes", len(data.get("navigation_map", []))],
            ["Report Saved", target_filename]
        ]
        print("\n" + tabulate(sum_table, headers="firstrow", tablefmt="fancy_grid"))
    else:
        print("\n[!] Error: Scan results could not be generated.")

if __name__ == "__main__":
    run_audit()
