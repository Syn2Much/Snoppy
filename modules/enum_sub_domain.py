"""Enumerate reachable subdomains using concurrent HTTP requests."""

import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from urllib3.exceptions import InsecureRequestWarning

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

subdomains = [
    "horizon.", "mail.", "ftp.", "localhost.", "webmail.",
    "smtp.", "pop.", "ns1.", "webdisk.", "ns2.",
    "cpanel.", "whm.", "autodiscover.", "autoconfig.", "m.",
    "imap.", "test.", "ns.", "blog.", "pop3.",
    "dev.", "www2.", "admin.", "forum.", "news.",
    "vpn.", "ns3.", "mail2.", "new.", "mysql.",
    "old.", "lists.", "support.", "mobile.", "mx.",
    "static.", "docs.", "beta.", "shop.", "sql.",
    "secure.", "demo.", "cp.", "calendar.", "wiki.",
    "web.", "media.", "email.", "images.", "img.",
    "www1.", "intranet.", "portal.", "video.", "sip.",
    "dns.", "dns1.", "dns2.", "api.", "cdn.",
    "stats.", "status.", "monitor.", "staging.", "stage.",
    "prod.", "production.", "app.", "apps.", "dashboard.",
    "gateway.", "proxy.", "remote.", "access.", "login.",
    "auth.", "sso.", "ldap.", "git.", "gitlab.",
    "github.", "jenkins.", "ci.", "cd.", "build.",
    "deploy.", "backup.", "backups.", "db.", "database.",
    "cache.", "assets.", "files.", "upload.", "downloads."
]

def sanatize_domain(url, prefix):
    if url.startswith("http://"):
        url = url.removeprefix("http://")
        url = prefix + url
        return "http://" + url
    elif url.startswith("https://"): 
        url = url.removeprefix("https://")
        url = prefix + url
        return "https://" + url

def _check_subdomain(target, prefix, timeout, proxy_pool):
    url = sanatize_domain(target, prefix)
    if not url:
        return prefix, None

    try:
        if proxy_pool:
            response = proxy_pool.get(url, timeout=timeout)
        else:
            response = requests.get(
                url,
                headers=get_random_headers(),
                timeout=timeout,
                verify=False,
            )
        return prefix, response.status_code
    except (ProxyPoolExhausted, requests.RequestException):
        return prefix, None


def _show_progress(done, total, found):
    if not sys.stdout.isatty():
        return

    progress = f"Checked {done}/{total}  |  HTTP 200: {found}"
    if os.getenv("TERM") != "dumb" and "NO_COLOR" not in os.environ:
        progress = f"\033[36m{progress}\033[0m"
    print(f"\r\033[2K{progress}", end="", flush=True)


def enum_domain(target, timeout=3, proxy_pool=None, max_workers=20):
    logger = logging.getLogger(__name__)
    alive = []
    done = 0
    workers = max(1, min(max_workers, len(subdomains)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_check_subdomain, target, prefix, timeout, proxy_pool)
            for prefix in subdomains
        ]
        for future in as_completed(futures):
            prefix, status_code = future.result()
            done += 1
            if status_code == 200:
                alive.append(prefix)
                logger.debug("Received HTTP 200 for subdomain %s", prefix)
            _show_progress(done, len(subdomains), len(alive))

    if sys.stdout.isatty():
        print()
    print(f"[+] Enumeration complete. Found {len(alive)} reachable subdomains: {alive}\n")
    return alive



