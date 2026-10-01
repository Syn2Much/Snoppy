"""Crawl a bounded number of same-host HTML pages and extract site details."""

from collections import deque
import requests
from urllib.parse import urljoin, urlsplit, urlunsplit

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted


def _normalize_url(target):
    url = target if "://" in target else f"https://{target}"
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}")
    return url


def _canonical_url(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _get(url, timeout, proxy_pool):
    headers = get_random_headers()
    if proxy_pool is not None:
        return proxy_pool.get(url, headers=headers, timeout=timeout, allow_redirects=False)
    return requests.get(
        url,
        headers=headers,
        timeout=timeout,
        verify=False,
        allow_redirects=False,
    )


def crawl_site(target, timeout=3, proxy_pool=None, max_pages=25):
    from bs4 import BeautifulSoup

    start_url = _canonical_url(_normalize_url(target))
    site_host = urlsplit(start_url).hostname
    pending = deque([start_url])
    queued = {start_url}
    visited = set()
    pages = []
    internal_links = set()
    external_links = set()
    broken_links = []

    while pending and len(visited) < max_pages:
        url = pending.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            response = _get(url, timeout, proxy_pool)
        except (ProxyPoolExhausted, requests.RequestException) as error:
            pages.append({"url": url, "error": str(error)})
            broken_links.append({"url": url, "error": str(error)})
            continue

        page = {
            "url": response.url,
            "status_code": response.status_code,
            "title": None,
            "forms": [],
            "links": [],
        }
        if response.status_code >= 400:
            broken_links.append({"url": response.url, "status_code": response.status_code})
        location = response.headers.get("Location")
        if response.status_code in {301, 302, 303, 307, 308} and location:
            next_url = _canonical_url(urljoin(response.url, location))
            if urlsplit(next_url).hostname == site_host:
                internal_links.add(next_url)
                if next_url not in queued:
                    pending.append(next_url)
                    queued.add(next_url)
            else:
                external_links.add(next_url)
            page["redirect"] = next_url
            pages.append(page)
            continue

        content_type = response.headers.get("Content-Type", "").lower()
        if response.status_code < 400 and ("html" in content_type or not content_type):
            soup = BeautifulSoup(response.text, "html.parser")
            page["title"] = soup.title.get_text(" ", strip=True) if soup.title else None
            for form in soup.find_all("form"):
                page["forms"].append({
                    "action": urljoin(response.url, form.get("action") or response.url),
                    "method": (form.get("method") or "GET").upper(),
                    "fields": [
                        {"name": field.get("name"), "type": field.get("type", field.name)}
                        for field in form.find_all(["input", "textarea", "select", "button"])
                    ],
                })
            for anchor in soup.find_all("a", href=True):
                absolute = _canonical_url(urljoin(response.url, anchor["href"]))
                parsed = urlsplit(absolute)
                if parsed.scheme not in {"http", "https"}:
                    continue
                page["links"].append(absolute)
                if parsed.hostname == site_host:
                    internal_links.add(absolute)
                    if absolute not in queued:
                        pending.append(absolute)
                        queued.add(absolute)
                else:
                    external_links.add(absolute)
        pages.append(page)

    return {
        "target": start_url,
        "pages_scanned": len(pages),
        "page_limit": max_pages,
        "truncated": bool(pending),
        "pages": pages,
        "internal_links": sorted(internal_links),
        "external_links": sorted(external_links),
        "broken_links": broken_links,
    }