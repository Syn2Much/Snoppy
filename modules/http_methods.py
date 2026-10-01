"""Inspect supported HTTP methods and CORS response headers."""

import requests

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted


def inspect_methods_and_cors(target, timeout=3, proxy_pool=None):
    headers = get_random_headers({
        "Origin": "https://snoopy.invalid",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization,content-type",
    })
    try:
        if proxy_pool is not None:
            response = proxy_pool.request(
                "OPTIONS",
                target,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            response = requests.options(
                target,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
    except (ProxyPoolExhausted, requests.RequestException) as error:
        return {"url": target, "error": str(error)}

    response_headers = {name.lower(): value for name, value in response.headers.items()}
    allow = response_headers.get("allow", "")
    cors_headers = {
        name: response_headers.get(name)
        for name in (
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-allow-credentials",
            "access-control-max-age",
        )
    }
    return {
        "url": response.url,
        "status_code": response.status_code,
        "allow": [method.strip() for method in allow.split(",") if method.strip()],
        "cors": cors_headers,
    }