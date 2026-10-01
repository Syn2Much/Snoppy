"""Trace HTTP redirects one response at a time and detect loops."""

from urllib.parse import urljoin, urlsplit

import requests

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _normalize_url(target):
    url = target if "://" in target else f"https://{target}"
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}")
    return url


def _get(url, timeout, proxy_pool):
    headers = get_random_headers()
    if proxy_pool is not None:
        return proxy_pool.get(
            url, headers=headers, timeout=timeout, allow_redirects=False
        )
    return requests.get(
        url, headers=headers, timeout=timeout, verify=False, allow_redirects=False
    )


def trace_redirects(target, timeout=3, proxy_pool=None, max_redirects=10):
    current_url = _normalize_url(target)
    visited = set()
    chain = []
    loop_detected = False
    error = None

    for _ in range(max_redirects + 1):
        if current_url in visited:
            loop_detected = True
            break
        visited.add(current_url)
        try:
            response = _get(current_url, timeout, proxy_pool)
        except (ProxyPoolExhausted, requests.RequestException) as request_error:
            error = str(request_error)
            break

        location = response.headers.get("Location")
        next_url = urljoin(current_url, location) if location else None
        chain.append({
            "url": current_url,
            "status_code": response.status_code,
            "location": location,
            "next_url": next_url,
        })
        if response.status_code not in REDIRECT_STATUSES or not next_url:
            break
        if next_url in visited:
            loop_detected = True
            break
        current_url = next_url

    schemes = [urlsplit(entry["url"]).scheme for entry in chain]
    return {
        "target": target,
        "chain": chain,
        "redirect_count": max(0, len(chain) - 1),
        "loop_detected": loop_detected,
        "https_upgrade": "http" in schemes and "https" in schemes,
        "max_redirects_reached": len(chain) > max_redirects,
        "error": error,
    }