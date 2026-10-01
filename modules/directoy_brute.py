"""Check common or supplied web paths concurrently on a target site."""

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests

from helpers.headers import get_random_headers
from helpers.proxy import ProxyPoolExhausted


DEFAULT_PATHS = (
	"admin", "api", "backup", "config", "dashboard", "docs", "health",
	"login", "logout", "robots.txt", "server-status", "sitemap.xml",
	"static", "status", "uploads", "user", "users", "wp-admin",
	"wp-content", ".env", ".git/HEAD", "phpinfo.php",
)
HIT_STATUSES = set(range(200, 400)) | {401, 403, 405}


def load_paths(wordlist=None):
	if wordlist is None:
		paths = DEFAULT_PATHS
	else:
		paths = Path(wordlist).read_text(encoding="utf8").splitlines()
	return list(dict.fromkeys(
		path.strip().lstrip("/")
		for path in paths
		if path.strip() and not path.lstrip().startswith("#")
	))


def _normalize_target(target):
	parsed = urlsplit(target if "://" in target else f"https://{target}")
	if parsed.scheme not in {"http", "https"} or not parsed.netloc:
		raise ValueError(f"Invalid target URL: {target}")
	return parsed.geturl().rstrip("/") + "/"


def _check_path(base_url, path, timeout, proxy_pool):
	url = urljoin(base_url, path)
	try:
		if proxy_pool:
			response = proxy_pool.get(
				url,
				timeout=timeout,
				allow_redirects=False,
			)
		else:
			response = requests.get(
				url,
				headers=get_random_headers(),
				timeout=timeout,
				verify=False,
				allow_redirects=False,
			)
	except (ProxyPoolExhausted, requests.RequestException):
		return None

	if response.status_code not in HIT_STATUSES:
		return None
	return {
		"path": f"/{path}",
		"url": url,
		"status_code": response.status_code,
		"content_length": len(response.content),
	}


def _show_progress(done, total, found):
	if not sys.stdout.isatty():
		return

	line = f"Checked {done}/{total}  |  Paths found: {found}"
	if os.getenv("TERM") != "dumb" and "NO_COLOR" not in os.environ:
		line = f"\033[36m{line}\033[0m"
	print(f"\r\033[2K{line}", end="", flush=True)


def brute_directories(target, wordlist=None, timeout=3, max_workers=10,
					  proxy_pool=None):
	base_url = _normalize_target(target)
	paths = load_paths(wordlist)
	if not paths:
		return []

	worker_count = max(1, min(int(max_workers), len(paths)))
	found = []
	with ThreadPoolExecutor(max_workers=worker_count) as executor:
		futures = {
			executor.submit(_check_path, base_url, path, timeout, proxy_pool): index
			for index, path in enumerate(paths)
		}
		for done, future in enumerate(as_completed(futures), start=1):
			result = future.result()
			if result:
				found.append((futures[future], result))
			_show_progress(done, len(paths), len(found))

	if sys.stdout.isatty():
		print()
	return [result for _, result in sorted(found)]
