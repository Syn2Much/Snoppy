"""Collect HTTP response headers and page-title information for a URL."""

import json
import logging
from html.parser import HTMLParser

import requests
from urllib3.exceptions import InsecureRequestWarning

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title_parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def _get_title(body):
    parser = _TitleParser()
    parser.feed(body)
    return " ".join("".join(parser.title_parts).split()) or "Unknown"


def get_server_info(url, timeout=3, proxy_pool=None):
    headers = get_random_headers()
    try:
        if proxy_pool is not None:
            response = proxy_pool.get(
                url,
                headers=headers,
                timeout=timeout,
            )
        else:
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
            )

        return {
            "url": response.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "powered_by": response.headers.get("X-Powered-By", "Unknown"),
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "title": _get_title(response.text),
        }
    except ProxyPoolExhausted as error:
        logging.error("Proxy pool exhausted: %s", error)
        return {"url": url, "error": "proxy_pool_exhausted"}
    except requests.RequestException as error:
        logging.error("Request failed: %s", error)
        return {"url": url, "error": str(error)}


def print_server_info(info):
    print(json.dumps(info, indent=2, sort_keys=True))