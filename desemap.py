#!/usr/bin/env python3
import os, sys, time

if len(sys.argv) == 1:
    os.system("clear" if os.name == "posix" else "cls")
    banner = r"""
  ██████╗ ███████╗███████╗███████╗███╗   ███╗ █████╗ ██████╗ 
  ██╔══██╗██╔════╝██╔════╝██╔════╝████╗ ████║██╔══██╗██╔══██╗
  ██║  ██║█████╗  ███████╗█████╗  ██╔████╔██║███████║██████╔╝
  ██║  ██║██╔══╝  ╚════██║██╔══╝  ██║╚██╔╝██║██╔══██║██╔══╝ 
  ██████╔╝███████╗███████║███████╗██║ ╚═╝ ██║██║  ██║██║  
  ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  
                       Developer: 0x1A7
    """
    print(f"\033[96m{banner}\033[0m")
    print("──────────────────────────────────────────────────────────────")
    print("DESEMAP — Derin bağlantı haritalayıcı ve link toplayıcı.\n")
    print("Ne yapar:")
    print("   • HTML, JS, robots.txt ve sitemap.xml içinden linkleri toplar")
    print("   • JSON / CSV / TXT çıktı seçenekleri sunar")
    print("   • Aynı domain veya harici domain taraması yapabilir")
    print("   • Çoklu thread ile hızlı çalışır (default 6 eşzamanlı istek)\n")
    print("Kullanım örnekleri:\n")
    print("   python3 site_link_collector.py https://testphp.vulnweb.com")
    print("   python3 site_link_collector.py https://site.com --depth 2 --format all\n")
    print("──────────────────────────────────────────────────────────────")
    input("Devam etmek için ENTER'a bas...")
    os.system("clear" if os.name == "posix" else "cls")
# ============================================================


# -*- coding: utf-8 -*-
"""
site_link_collector.py
Basit, sağlam ve kullanımı kolay link toplama aracı (Türkçe).
Kullanım:
  python3 site_link_collector.py https://site.com --depth 1 --output sonuc --format json --follow-sitemap
"""
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse
import re
import json
import csv
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

USER_AGENT = "site-link-collector/1.0 (+https://github.com/yourname) "
HEADERS = {"User-Agent": USER_AGENT}
URL_RE = re.compile(r'(https?://[^\s\'"<>]+|\/[A-Za-z0-9_\-./~%]+)')

TAG_ATTRS = {
    'a': 'href', 'link': 'href', 'script': 'src', 'img': 'src',
    'iframe': 'src', 'form': 'action', 'source': 'src'
}

# ---------- helperler ----------
def normalize(base, link):
    if not link or not isinstance(link, str):
        return None
    link = link.strip()
    link, _ = urldefrag(link)  # anchorleri at
    if not link:
        return None
    # mailto/javascript/tel gibi şeyleri at
    if link.lower().startswith(('javascript:', 'mailto:', 'tel:')):
        return None
    try:
        return urljoin(base, link)
    except Exception:
        return None

def fetch_text(url, timeout=12):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        return r.text, r
    except Exception as e:
        return None, e

# ---------- robots.txt parser ----------
def parse_robots(base_url):
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"
    robots_url = urljoin(root, "/robots.txt")
    text, resp = fetch_text(robots_url)
    rules = {'raw': None, 'allows': [], 'disallows': [], 'sitemaps': []}
    if not text:
        return rules
    rules['raw'] = text
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' not in line:
            continue
        k, v = line.split(':',1)
        k = k.strip().lower()
        v = v.strip()
        if k == 'allow':
            rules['allows'].append(urljoin(root, v))
        elif k == 'disallow':
            rules['disallows'].append(urljoin(root, v))
        elif k == 'sitemap':
            rules['sitemaps'].append(v if v.startswith('http') else urljoin(root, v))
    return rules

# ---------- sitemap parser ----------
def parse_sitemap(sitemap_url):
    text, resp = fetch_text(sitemap_url)
    found = set()
    if not text:
        return found
    try:
        soup = BeautifulSoup(text, 'xml')
        for loc in soup.find_all('loc'):
            u = loc.get_text().strip()
            if u:
                found.add(u)
    except Exception:
        # fallback regex
        for m in URL_RE.finditer(text):
            u = m.group(0)
            if u:
                found.add(u)
    return found

# ---------- html parse ----------
def parse_html_for_links(base_url, html_text):
    soup = BeautifulSoup(html_text, 'lxml')
    found = set()
    # tag attr'lar
    for tag, attr in TAG_ATTRS.items():
        for t in soup.find_all(tag):
            val = t.get(attr)
            if val:
                u = normalize(base_url, val)
                if u:
                    found.add(u)
    # basit inline js url arama
    for s in soup.find_all('script'):
        if s.string:
            for m in URL_RE.finditer(s.string):
                u = normalize(base_url, m.group(0))
                if u:
                    found.add(u)
    # title
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    return found, title

# ---------- worker ----------
def worker_fetch(url, timeout):
    text, resp = fetch_text(url, timeout=timeout)
    return url, text, resp

# ---------- main collector ----------
def collect(start_url, depth=1, concurrency=6, obey_robots=True, follow_external=False, follow_sitemap=False, js_scan=True, timeout=12, max_pages=2000):
    parsed_start = urlparse(start_url)
    base_root = f"{parsed_start.scheme}://{parsed_start.netloc}"
    domain = parsed_start.netloc

    results = {}  # url -> info dict
    sources = defaultdict(set)  # url -> set(sources)

    queue = [(start_url, 0, None)]
    seen = set()
    to_process = []

    # robots
    robots = {}
    if obey_robots:
        robots = parse_robots(start_url)
        # sitemap from robots
        if follow_sitemap and robots.get('sitemaps'):
            for sm in robots['sitemaps']:
                for u in parse_sitemap(sm):
                    sources[u].add('sitemap')
                    if u not in seen:
                        queue.append((u, 0, sm))

    # Thread pool
    executor = ThreadPoolExecutor(max_workers=concurrency)

    while queue and len(seen) < max_pages:
        url, cur_depth, parent = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        # robots disallow check (prefix match) - basit
        if obey_robots and robots.get('disallows'):
            path = urlparse(url).path or '/'
            skip = False
            for d in robots['disallows']:
                # robots disallows are absolute here; karşılaştır
                try:
                    if url.startswith(d):
                        results[url] = {'url': url, 'skipped_by_robots': True, 'parent': parent}
                        sources[url].add('robots-disallow')
                        skip = True
                        break
                except Exception:
                    pass
            if skip:
                continue

        # fetch
        try:
            u, text, resp = worker_fetch(url, timeout)
        except Exception as e:
            results[url] = {'url': url, 'error': str(e), 'parent': parent}
            continue

        if text is None:
            # fetch error (resp contains exception)
            results[url] = {'url': url, 'error': str(resp), 'parent': parent}
            continue

        # store basic info
        info = {
            'url': url,
            'status_code': getattr(resp, 'status_code', None),
            'content_type': resp.headers.get('Content-Type') if resp is not None else None,
            'parent': parent,
            'depth': cur_depth
        }
        results[url] = info
        sources[url].add('html' if 'text/html' in (info['content_type'] or '') else 'other')

        # parse html / find new links
        if 'text/html' in (info['content_type'] or '') or '<html' in text[:300].lower():
            found, title = parse_html_for_links(url, text)
            info['title'] = title
            for f in found:
                sources[f].add('discovered-html')
                # add only same-domain unless follow_external
                p = urlparse(f)
                if (p.netloc == domain) or follow_external:
                    if f not in seen:
                        if cur_depth + 1 <= depth:
                            queue.append((f, cur_depth + 1, url))
                # JS scan: if script file links found, we can scan them too (cheap)
            if js_scan:
                # find all script srcs and scan simple url regex inside them
                soup = BeautifulSoup(text, 'lxml')
                scripts = [s.get('src') for s in soup.find_all('script') if s.get('src')]
                for s in scripts:
                    s_full = normalize(url, s)
                    if not s_full:
                        continue
                    txt, r = fetch_text(s_full, timeout=timeout)
                    if txt:
                        for m in URL_RE.finditer(txt):
                            jf = normalize(s_full, m.group(0))
                            if jf:
                                sources[jf].add('discovered-js')
                                if (urlparse(jf).netloc == domain) or follow_external:
                                    if jf not in seen and cur_depth + 1 <= depth:
                                        queue.append((jf, cur_depth + 1, s_full))
        else:
            # non-html: quick regex scan for URLs
            for m in URL_RE.finditer(text[:200000]):
                u2 = normalize(url, m.group(0))
                if u2:
                    sources[u2].add('discovered-regex')
                    if (urlparse(u2).netloc == domain) or follow_external:
                        if u2 not in seen and cur_depth + 1 <= depth:
                            queue.append((u2, cur_depth + 1, url))

    return {
        'base': start_url,
        'generated_at': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        'results': results,
        'sources': {k: list(v) for k, v in sources.items()},
        'robots': robots
    }

def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_csv(path, data):
    # data: dict results
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['url','status_code','content_type','parent','depth'])
        for u, info in data.items():
            w.writerow([u, info.get('status_code',''), info.get('content_type',''), info.get('parent',''), info.get('depth','')])

def save_txt(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        for u in data.keys():
            f.write(u + "\n")

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="site_link_collector - site içi link toplayıcı (Türkçe, kolay)")
    p.add_argument('url', help='Tarayacağın site (ör: https://site.com)')
    p.add_argument('--depth', type=int, default=1, help='Recursive derinlik (default 1)')
    p.add_argument('--concurrency', type=int, default=6, help='Eşzamanlı istek sayısı (thread) (şimdilik sınırlı)')
    p.add_argument('--obey-robots', choices=['yes','no'], default='yes', help='robots.txt kurallarına uy (default yes)')
    p.add_argument('--follow-external', choices=['yes','no'], default='no', help='Farklı domainlerdeki linkleri takip et')
    p.add_argument('--follow-sitemap', choices=['yes','no'], default='no', help='robots.txt içindeki sitemapları parse et')
    p.add_argument('--js-scan', choices=['yes','no'], default='yes', help='Bağlı JS dosyalarını tarayıp içindeki URLleri bul (cheap regex)')
    p.add_argument('--timeout', type=int, default=12, help='HTTP timeout saniye')
    p.add_argument('--max-pages', type=int, default=2000, help='Maks sayfa limiti')
    p.add_argument('--output', default='site_links', help='Çıktı dosya adı (uzantı eklenecek)')
    p.add_argument('--format', choices=['json','csv','txt','all'], default='json', help='Çıktı formatı')
    return p.parse_args()

def main():
    args = parse_args()
    url = args.url
    if not url.startswith(('http://','https://')):
        print("Lütfen URL'ye http:// veya https:// ekleyin.")
        sys.exit(1)

    print(f"[i] Tarama başlıyor: {url} (depth={args.depth})")
    res = collect(
        url,
        depth=args.depth,
        concurrency=args.concurrency,
        obey_robots=(args.obey_robots=='yes'),
        follow_external=(args.follow_external=='yes'),
        follow_sitemap=(args.follow_sitemap=='yes'),
        js_scan=(args.js_scan=='yes'),
        timeout=args.timeout,
        max_pages=args.max_pages
    )
    base = args.output
    if args.format in ('json','all'):
        json_path = base if base.endswith('.json') else base + '.json'
        save_json(json_path, res)
        print(f"[+] JSON kaydedildi: {json_path}")
    if args.format in ('csv','all'):
        csv_path = base if base.endswith('.csv') else base + '.csv'
        save_csv(csv_path, res['results'])
        print(f"[+] CSV kaydedildi: {csv_path}")
    if args.format in ('txt','all'):
        txt_path = base if base.endswith('.txt') else base + '.txt'
        save_txt(txt_path, res['results'])
        print(f"[+] TXT kaydedildi: {txt_path}")
    print(f"[i] Toplam bulunan URL sayısı (sources tablosuna göre): {len(res['sources'])}")

if __name__ == '__main__':
    main()
