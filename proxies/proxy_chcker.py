import argparse
import os
import requests
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

from helpers.headers import get_random_headers


SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt",
   
] 
# Thread-safe lock for writing to file
file_lock = threading.Lock()

# Config
TIMEOUT = 7
MAX_WORKERS = 650  # Adjust based on your needs/network
OUTPUT_FILE = Path(__file__).with_name("working_proxies.txt")
TEST_URL = "https://httpbin.org/ip"  # Returns your IP as seen by server


def get_proxy_scheme(proxy_address) -> str:
    scheme = proxy_address.partition("://")[0].lower()
    if scheme in {"http", "https", "socks4", "socks5", "socks5h"}:
        return scheme
    return "http"


def normalize_proxy(proxy_address, default_scheme="http"):
    proxy_address = proxy_address.strip()
    if "://" not in proxy_address:
        proxy_address = f"{default_scheme}://{proxy_address}"
    return proxy_address


def create_proxy_dict(proxy_address):
    proxy_address = normalize_proxy(proxy_address)
    return {
        "http": proxy_address,
        "https": proxy_address,
    }


def proxy_identity(proxy_address):
    address = urlsplit(normalize_proxy(proxy_address))
    return (address.hostname or address.path).lower()


def check_proxy(proxy_address, timeout=TIMEOUT):
    try:
        r = requests.get(
            TEST_URL,
            headers=get_random_headers(),
            timeout=timeout,
            proxies=create_proxy_dict(proxy_address)
        )
        if r.status_code == 200:
            # Optional: verify the response looks like a real IP response
            data = r.json()
            if "origin" in data:
                return True, data.get("origin", "")
        return False, None
    except Exception as e:
        return False, str(e)


def save_to_file(proxy_address, filename=OUTPUT_FILE):
    filename = Path(filename)
    with file_lock:
        entries = []
        identities = set()
        try:
            with open(filename, "r", encoding="utf-8") as file:
                entries = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            pass

        unique_entries = []
        for entry in entries:
            identity = proxy_identity(entry)
            if identity not in identities:
                identities.add(identity)
                unique_entries.append(entry)

        identity = proxy_identity(proxy_address)
        if identity not in identities:
            unique_entries.append(proxy_address)

        with open(filename, "w", encoding="utf-8") as file:
            file.write("\n".join(unique_entries))
            if unique_entries:
                file.write("\n")


def worker(proxy_address, output_file=OUTPUT_FILE):
    """Check a single proxy and save it when it works."""
    ok, info = check_proxy(proxy_address)
    if ok:
        save_to_file(proxy_address, output_file)
    return ok


def _show_progress(done, total, working, failed):
    if not sys.stdout.isatty():
        return

    working_text = f"Working: {working:,}"
    failed_text = f"Failed: {failed:,}"
    if os.getenv("TERM") != "dumb" and "NO_COLOR" not in os.environ:
        working_text = f"\033[32m{working_text}\033[0m"
        failed_text = f"\033[31m{failed_text}\033[0m"
    line = f"Checked {done:,}/{total:,}  {working_text}  {failed_text}"
    print(f"\r\033[2K{line}", end="", flush=True)


def load_proxies(filename=None):
    if filename:
        with open(filename, "r", encoding="utf-8") as file:
            lines = file.readlines()
        proxies = {
            normalize_proxy(line)
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        }
    else:
        proxies = set()
        for source in SOURCES:
            try:
                response = requests.get(
                    source,
                    headers=get_random_headers(),
                    timeout=TIMEOUT,
                )
                response.raise_for_status()
                if "/socks5/" in source:
                    scheme = "socks5"
                elif "/socks4/" in source:
                    scheme = "socks4"
                elif "/https/" in source:
                    scheme = "https"
                else:
                    scheme = "http"
                proxies.update(
                    normalize_proxy(line, scheme)
                    for line in response.text.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                )
            except requests.RequestException as error:
                continue

    return sorted(proxies)


def run_checker(input_file=None, output_file=OUTPUT_FILE):
    proxies = load_proxies(input_file)
    if not proxies:
        print("No proxies loaded; existing proxy file left unchanged.")
        return

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("", encoding="utf8")
    total = len(proxies)
    print(f"Loaded {total:,} proxies. Checking with {MAX_WORKERS} threads...")
    working = 0
    done = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(worker, proxy_address, output_file)
            for proxy_address in proxies
        ]

        for future in as_completed(futures):
            try:
                working += bool(future.result())
            except Exception:
                pass
            done += 1
            _show_progress(done, total, working, done - working)

    if sys.stdout.isatty():
        print()
    print(f"Done. Checked {done:,}/{total:,}: {working:,} working, "
          f"{done - working:,} failed. Saved to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Collect and check working proxies"
    )
    parser.add_argument(
        "-i", "--input",
        help="Read proxies from a local file instead of scraping SOURCES"
    )
    args = parser.parse_args()
    run_checker(args.input)