import sys
import os
import json
from datetime import datetime
import importlib.util

def load_updated_module():
    path = os.path.join(os.path.dirname(__file__), 'scans', 'updated_file.py')
    spec = importlib.util.spec_from_file_location('updated_file', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    if len(sys.argv) < 3:
        print('Usage: scan_worker.py <url> <output_path>')
        sys.exit(2)

    user_url = sys.argv[1]
    out_path = sys.argv[2]

    updated = load_updated_module()

    # Build initial metadata similar to main app
    from urllib.parse import urlparse
    import socket

    if not user_url.startswith('http'):
        user_url = 'https://' + user_url

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

    metadata = {
        "scan_start_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "target_ip": target_ip,
        "target_port": parsed_url.port or (443 if parsed_url.scheme == "https" else 80),
        "geo_intel": intel,
        "open_ports": ports,
        "vpn_status": vpn_status,
        "domain_dates": whois_info,
        "findings": { "proxy_detected": "Pending...", "security_header_audit": {} }
    }

    # Run Scrapy in this separate process
    from scrapy.crawler import CrawlerProcess

    process = CrawlerProcess(settings={
        "LOG_LEVEL": "ERROR",
        "USER_AGENT": "Mozilla/5.0",
        "ROBOTSTXT_OBEY": False
    })
    process.crawl(updated.SecuritySpider, url=user_url, filename=out_path, audit_metadata=metadata)
    process.start()


if __name__ == '__main__':
    main()
