"""Rotate through proxies and retry requests when a proxy fails."""

from collections import deque
import logging
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit

import requests
from urllib3.exceptions import InsecureRequestWarning

from helpers.headers import get_random_headers

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ProxyPoolExhausted(RuntimeError):
    """Raised when no usable proxies remain for a request."""


class ProxyRotator:
    def __init__(self, proxies, logger=None):
        normalized = [self._normalize(proxy) for proxy in proxies]
        self._proxies = deque(dict.fromkeys(normalized))
        self._lock = Lock()
        self.logger = logger or logging.getLogger(__name__)
        self._current_proxy = None

    @classmethod
    def from_file(cls, path, logger=None):
        path = Path(path)
        with path.open("r", encoding="utf8") as proxy_file:
            proxies = [
                line.strip()
                for line in proxy_file
                if line.strip() and not line.lstrip().startswith("#")
            ]
        return cls(proxies, logger=logger)

    @staticmethod
    def _normalize(proxy):
        proxy = proxy.strip()
        if "://" not in proxy:
            proxy = f"http://{proxy}"

        scheme = urlsplit(proxy).scheme.lower()
        if scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
            raise ValueError(f"Unsupported proxy scheme: {scheme}")
        return proxy

    def __len__(self):
        with self._lock:
            return len(self._proxies)

    def _next_proxy(self):
        with self._lock:
            if not self._proxies:
                raise ProxyPoolExhausted("No working proxies remain")
            proxy = self._proxies.popleft()
            self._proxies.append(proxy)
            self._current_proxy = proxy
            self.logger.debug("Selected proxy %s (%d remain)", proxy, len(self._proxies))
            return proxy

    def _discard(self, proxy):
        with self._lock:
            if self._current_proxy == proxy:
                self._current_proxy = None
            try:
                self._proxies.remove(proxy)
            except ValueError:
                pass
            self.logger.debug(
                "Removed failed proxy %s (%d remain)", proxy, len(self._proxies)
            )

    @staticmethod
    def _proxy_settings(proxy):
        return {"http": proxy, "https": proxy}

    def request(self, method, url, *, timeout=3, **kwargs):
        attempts = len(self)
        if attempts == 0:
            raise ProxyPoolExhausted("No working proxies remain")

        kwargs.setdefault("verify", False)
        kwargs["headers"] = get_random_headers(kwargs.get("headers"))
        last_error = None
        tried = set()
        for _ in range(attempts):
            proxy = self._next_proxy()
            if proxy in tried:
                break
            tried.add(proxy)
            try:
                self.logger.debug("Requesting %s %s through %s", method, url, proxy)
                response = requests.request(
                    method,
                    url,
                    timeout=timeout,
                    proxies=self._proxy_settings(proxy),
                    **kwargs,
                )
                self.logger.debug(
                    "Proxy %s returned status %s and remains active",
                    proxy,
                    getattr(response, "status_code", "unknown"),
                )
                return response
            except requests.RequestException as error:
                last_error = error
                self.logger.debug("Proxy %s failed: %s", proxy, error)
                self._discard(proxy)

        raise ProxyPoolExhausted(
            f"All proxies failed for {url}: {last_error}"
        ) from last_error

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)
