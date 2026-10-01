"""Audit a web response for common browser security headers."""

from urllib.parse import urlsplit

import requests

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted


SECURITY_HEADERS = (
    ("content-security-policy", "Content-Security-Policy"),
    ("strict-transport-security", "Strict-Transport-Security"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
)


def _normalize_url(target):
    url = target if "://" in target else f"https://{target}"
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}")
    return url


def audit_security_headers(target, timeout=3, proxy_pool=None):
    url = _normalize_url(target)
    headers = get_random_headers()
    try:
        if proxy_pool is not None:
            response = proxy_pool.get(url, headers=headers, timeout=timeout)
        else:
            response = requests.get(
                url, headers=headers, timeout=timeout, verify=False
            )
    except (ProxyPoolExhausted, requests.RequestException) as error:
        return {"url": url, "error": str(error)}

    response_headers = {name.lower(): value for name, value in response.headers.items()}
    csp = response_headers.get("content-security-policy", "")
    checks = []
    for key, display_name in SECURITY_HEADERS:
        if key == "strict-transport-security" and urlsplit(response.url).scheme != "https":
            checks.append({"header": display_name, "status": "not_applicable", "value": None})
            continue
        value = response_headers.get(key)
        checks.append({
            "header": display_name,
            "status": "present" if value else "missing",
            "value": value,
        })

    frame_options = response_headers.get("x-frame-options")
    frame_ancestors = "frame-ancestors" in csp.lower()
    checks.append({
        "header": "X-Frame-Options / CSP frame-ancestors",
        "status": "present" if frame_options or frame_ancestors else "missing",
        "value": frame_options or ("configured in CSP" if frame_ancestors else None),
    })
    return {
        "url": response.url,
        "status_code": response.status_code,
        "checks": checks,
        "missing_headers": [item["header"] for item in checks if item["status"] == "missing"],
    }