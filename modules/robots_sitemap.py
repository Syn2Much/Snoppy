"""Parse robots.txt rules and retrieve linked or conventional sitemaps."""

from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

import requests

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted


def _site_root(target):
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}")
    return f"{parsed.scheme}://{parsed.netloc}/"


def _get(url, timeout, proxy_pool):
    headers = get_random_headers()
    if proxy_pool is not None:
        return proxy_pool.get(url, headers=headers, timeout=timeout)
    return requests.get(url, headers=headers, timeout=timeout, verify=False)


def _parse_robots(text):
    rules = []
    sitemaps = []
    agents = []
    for line in text.splitlines():
        directive, _, value = line.partition("#")[0].partition(":")
        directive = directive.strip().lower()
        value = value.strip()
        if directive == "user-agent":
            agents = [value]
        elif directive in {"allow", "disallow"} and value:
            rules.append({
                "user_agent": agents[-1] if agents else "*",
                "directive": directive,
                "path": value,
            })
        elif directive == "sitemap" and value:
            sitemaps.append(value)
    return rules, sitemaps


def _parse_sitemap(response):
    try:
        root = ElementTree.fromstring(response.content)
    except ElementTree.ParseError:
        return []
    locations = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "loc" and element.text:
            locations.append(element.text.strip())
    return locations


def inspect_robots_sitemap(target, timeout=3, proxy_pool=None, max_sitemaps=5):
    root_url = _site_root(target)
    robots_url = urljoin(root_url, "robots.txt")
    robots_result = {"url": robots_url, "status_code": None, "rules": [], "sitemaps": []}
    sitemap_urls = []

    try:
        response = _get(robots_url, timeout, proxy_pool)
        robots_result["status_code"] = response.status_code
        if response.status_code == 200:
            rules, sitemap_urls = _parse_robots(response.text)
            robots_result["rules"] = rules
            robots_result["sitemaps"] = sitemap_urls
    except (ProxyPoolExhausted, requests.RequestException) as error:
        robots_result["error"] = str(error)

    if not sitemap_urls:
        sitemap_urls = [urljoin(root_url, "sitemap.xml")]

    sitemaps = []
    for sitemap_url in dict.fromkeys(sitemap_urls[:max_sitemaps]):
        entry = {"url": sitemap_url, "status_code": None, "locations": []}
        try:
            response = _get(sitemap_url, timeout, proxy_pool)
            entry["status_code"] = response.status_code
            if response.status_code == 200:
                entry["locations"] = _parse_sitemap(response)[:100]
        except (ProxyPoolExhausted, requests.RequestException) as error:
            entry["error"] = str(error)
        sitemaps.append(entry)

    return {
        "target": root_url,
        "robots": robots_result,
        "sitemap_results": sitemaps,
    }