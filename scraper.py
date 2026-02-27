import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scrape_url(url, max_links=50):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')

        title = soup.title.string.strip() if soup.title and soup.title.string else ''
        desc = ''
        desc_tag = soup.find('meta', attrs={'name': 'description'})
        if desc_tag and desc_tag.get('content'):
            desc = desc_tag['content'].strip()

        h1s = [h.get_text(strip=True) for h in soup.find_all('h1')]

        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            href = urljoin(resp.url, href)
            links.append(href)
            if len(links) >= max_links:
                break

        return {
            'url': resp.url,
            'status_code': resp.status_code,
            'title': title,
            'description': desc,
            'h1': h1s,
            'links': links
        }
    except Exception as e:
        return {'error': str(e)}
