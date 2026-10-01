import curses
import json
import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from modules.enum_sub_domain import enum_domain
from modules.port_scan import port_scan
from modules.server_info import get_server_info
from modules.directoy_brute import brute_directories
from modules.robots_sitemap import inspect_robots_sitemap
from modules.dns_resolver import resolve_hosts
from modules.security_headers import audit_security_headers
from modules.redirect_chain import trace_redirects
from modules.http_methods import inspect_methods_and_cors
from modules.dns_posture import audit_dns_posture
from modules.rdap_lookup import lookup_rdap
from modules.html_crawler import crawl_site
from helpers.output import write_result
from helpers.proxy import ProxyRotator
from proxies.proxy_chcker import run_checker


DEFAULT_PROXY_FILE = Path(__file__).resolve().parent / "proxies" / "working_proxies.txt"
DEFAULT_PROXY_LABEL = "proxies/working_proxies.txt"

MENU_OPTIONS = (
    "Scan common ports",
    "Enumerate subdomains",
    "Fingerprint a web server",
    "Inspect SSL/TLS certificates",
    "Brute-force directories",
    "Web checks",
    "Proxy tools",
    "Exit",
)

MENU_CATEGORIES = (
    ("RECONNAISSANCE", (0, 1, 4), "96;1"),
    ("WEB ANALYSIS", (2, 3, 5), "92;1"),
    ("UTILITIES", (6, 7), "93;1"),
)

WEB_CHECK_OPTIONS = (
    "Robots.txt and sitemap",
    "DNS and host resolution",
    "HTTP security headers",
    "Redirect chain",
    "HTTP methods and CORS",
    "DNS posture audit",
    "RDAP and ASN lookup",
    "Same-site HTML crawler",
)

PROXY_MENU_OPTIONS = (
    "Check existing list again",
    "Scrape from sources",
    "Check custom list",
)

BANNER = (
    "  ██████  ███▄    █  ▒█████   ▒█████   ██▓███ ▓██   ██▓",
    "▒██    ▒  ██ ▀█   █ ▒██▒  ██▒▒██▒  ██▒▓██░  ██▒▒██  ██▒",
    "░ ▓██▄   ▓██  ▀█ ██▒▒██░  ██▒▒██░  ██▒▓██░ ██▓▒ ▒██ ██░",
    "  ▒   ██▒▓██▒  ▐▌██▒▒██   ██░▒██   ██░▒██▄█▓▒ ▒ ░ ▐██▓░",
    "▒██████▒▒▒██░   ▓██░░ ████▓▒░░ ████▓▒░▒██▒ ░  ░ ░ ██▒▓░",
    "▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▒░▒░▒░ ▒▓▒░ ░  ░  ██▒▒▒ ",
    "░ ░▒  ░ ░░ ░░   ░ ▒░  ░ ▒ ▒░   ░ ▒ ▒░ ░▒ ░     ▓██ ░▒░ ",
    "░  ░  ░     ░   ░ ░ ░ ░ ░ ▒  ░ ░ ░ ▒  ░░       ▒ ▒ ░░  ",
    "      ░           ░     ░ ░      ░ ░           ░ ░     ",
    "                                               ░ ░     ",
    "Snoopy - Scan | Analyze | Exploit"
)


def _ansi(text, code):
    if sys.stdout.isatty() and os.getenv("TERM") != "dumb" and "NO_COLOR" not in os.environ:
        return f"\033[{code}m{text}\033[0m"
    return text


def _read_proxy_entries():
    try:
        return [
            line.strip()
            for line in DEFAULT_PROXY_FILE.read_text(encoding="utf8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError:
        return []


def _menu_columns(options, categories=None, rows_per_column=4):
    if categories:
        columns = []
        for category, indices, color in categories:
            chunks = [
                indices[start:start + rows_per_column]
                for start in range(0, len(indices), rows_per_column)
            ]
            for chunk_index, indices_chunk in enumerate(chunks):
                heading = category if chunk_index == 0 else f"{category} +"
                columns.append((heading, indices_chunk, color))
        return columns

    indices = list(range(len(options)))
    return [
        (None, indices[start:start + rows_per_column], None)
        for start in range(0, len(indices), rows_per_column)
    ]


def _column_widths(options, columns, available_width):
    gaps = 2 * max(0, len(columns) - 1)
    natural = [
        max(
            len(heading or ""),
            *(len(f"{index + 1}. {options[index]}") for index in indices),
        ) + 2
        for heading, indices, _ in columns
    ]
    if sum(natural) + gaps <= available_width:
        return natural
    width = max(1, (available_width - gaps) // max(1, len(columns)))
    return [width] * len(columns)


def _move_selection(columns, selected, direction):
    positions = {
        index: (column_index, row_index)
        for column_index, (_, indices, _) in enumerate(columns)
        for row_index, index in enumerate(indices)
    }
    column_index, row_index = positions[selected]
    if direction == "up":
        indices = columns[column_index][1]
        return indices[(row_index - 1) % len(indices)]
    if direction == "down":
        indices = columns[column_index][1]
        return indices[(row_index + 1) % len(indices)]

    step = -1 if direction == "left" else 1
    for offset in range(1, len(columns) + 1):
        next_column = (column_index + step * offset) % len(columns)
        indices = columns[next_column][1]
        if indices:
            return indices[min(row_index, len(indices) - 1)]
    return selected


def _draw_selection(screen, title, options, quit_choice, categories=None):
    curses.curs_set(0)
    screen.keypad(True)
    has_colors = curses.has_colors()
    pair = curses.color_pair if has_colors else lambda _: 0
    if has_colors:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)
    selected = 0
    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        proxies = _read_proxy_entries()
        columns = _menu_columns(options, categories)
        widths = _column_widths(options, columns, max(1, width - 2))
        starts = []
        for column_index, column_width in enumerate(widths):
            previous_width = sum(widths[:column_index])
            starts.append(1 + previous_width + 2 * column_index)
        max_rows = max((len(indices) for _, indices, _ in columns), default=0)
        fixed_rows = len(BANNER) + 1 + 1 + 1 + 1 + max_rows + 1
        base_rows = fixed_rows
        preview_count = min(3, len(proxies), max(0, height - base_rows))
        for row, banner_line in enumerate(BANNER):
            banner_pair = 1 if row < 4 else (2 if row < 7 else 3)
            screen.addnstr(
                row, 1, banner_line, max(0, width - 2),
                pair(banner_pair) | curses.A_BOLD,
            )
        proxy_row = len(BANNER)
        screen.addnstr(
            proxy_row, 1,
            f"Loaded proxies: {len(proxies)} ({DEFAULT_PROXY_LABEL})",
            max(0, width - 2), pair(3) | curses.A_BOLD,
        )
        for row, proxy in enumerate(proxies[:preview_count], start=proxy_row + 1):
            screen.addnstr(row, 1, proxy, max(0, width - 2), pair(1))
        menu_top = proxy_row + preview_count + 2
        screen.addnstr(menu_top, 1, title, max(0, width - 2), pair(1) | curses.A_BOLD)
        headings_row = menu_top + 1
        for column_index, (heading, _, color) in enumerate(columns):
            if heading:
                heading_pair = {"96;1": 1, "92;1": 3, "93;1": 2}.get(color, 1)
                screen.addnstr(
                    headings_row, starts[column_index], heading,
                    max(0, widths[column_index] - 1),
                    pair(heading_pair) | curses.A_BOLD,
                )
        options_top = headings_row + (1 if categories else 0)
        for column_index, (_, indices, _) in enumerate(columns):
            for row_index, option_index in enumerate(indices):
                screen.addnstr(
                    options_top + row_index,
                    starts[column_index],
                    f"{option_index + 1}. {options[option_index]}",
                    max(0, widths[column_index] - 1),
                    (pair(4) | curses.A_BOLD) if option_index == selected else 0,
                )
        quit_hint = "q to quit" if quit_choice is not None else "q to return"
        help_row = options_top + max_rows + 1
        if help_row < height:
            screen.addnstr(
                help_row, 1,
                f"Arrow keys / numpad  |  Enter selects  |  {quit_hint}",
                max(0, width - 2), curses.A_DIM,
            )
        screen.refresh()

        key = screen.getch()
        if key == curses.KEY_UP:
            selected = _move_selection(columns, selected, "up")
        elif key == curses.KEY_DOWN:
            selected = _move_selection(columns, selected, "down")
        elif key in (curses.KEY_LEFT, curses.KEY_HOME, curses.KEY_PPAGE):
            if key == curses.KEY_HOME:
                selected = 0
            elif key == curses.KEY_PPAGE:
                selected = columns[0][1][0]
            else:
                selected = _move_selection(columns, selected, "left")
        elif key in (curses.KEY_RIGHT, curses.KEY_END, curses.KEY_NPAGE):
            if key == curses.KEY_END:
                selected = len(options) - 1
            elif key == curses.KEY_NPAGE:
                selected = columns[-1][1][-1]
            else:
                selected = _move_selection(columns, selected, "right")
        elif key in (curses.KEY_ENTER, 10, 13):
            return selected
        elif ord("1") <= key <= ord(str(len(options))):
            return key - ord("1")
        elif key in (ord("q"), ord("Q"), 27):
            return quit_choice


def _read_selection(options, title, quit_choice, categories=None):
    if sys.stdin.isatty() and sys.stdout.isatty():
        return curses.wrapper(
            lambda screen: _draw_selection(
                screen, title, options, quit_choice, categories
            )
        )

    proxies = _read_proxy_entries()
    for index, line in enumerate(BANNER):
        color = "96;1" if index < 4 else ("93;1" if index < 7 else "92;1")
        print(_ansi(line, color))
    print(_ansi(f"Loaded proxies: {len(proxies)}", "92;1")
          + _ansi(f" ({DEFAULT_PROXY_LABEL})", "90"))
    for proxy in proxies[:3]:
        print(_ansi(f"  {proxy}", "96"))
    if len(proxies) > 3:
        print(_ansi(f"  ... and {len(proxies) - 3} more", "90"))
    columns = _menu_columns(options, categories)
    widths = _column_widths(options, columns, 100)
    if categories:
        for column_index, (category, _, color) in enumerate(columns):
            padding = " " * (sum(widths[:column_index]) + 2 * column_index)
            print(padding + _ansi(category or "", color))
    rows = max((len(indices) for _, indices, _ in columns), default=0)
    for row_index in range(rows):
        cells = []
        for column_index, (_, indices, _) in enumerate(columns):
            text = ""
            if row_index < len(indices):
                option_index = indices[row_index]
                text = f"{option_index + 1}. {options[option_index]}"
            cells.append(text.ljust(widths[column_index]))
        print("  ".join(cells).rstrip())
    quit_hint = "quit" if quit_choice is not None else "return"
    choice = input(
        f"{title} [1-{len(options)} or q to {quit_hint}]: "
    ).strip().lower()
    if choice in {"q", "quit", "exit"}:
        return quit_choice
    try:
        return int(choice) - 1
    except ValueError:
        return -1


def _read_menu_choice():
    return _read_selection(
        MENU_OPTIONS,
        "Select an action:",
        len(MENU_OPTIONS) - 1,
        MENU_CATEGORIES,
    )


def _read_proxy_menu_choice():
    return _read_selection(PROXY_MENU_OPTIONS, "Proxy tools:", None)


def _read_web_check_choice():
    return _read_selection(WEB_CHECK_OPTIONS, "Web checks:", None)


def _ask_path(prompt):
    value = input(prompt).strip()
    return Path(value) if value else None


def _ask_verbose():
    return input("Show detailed logs? [y/N]: ").strip().lower() in {"y", "yes"}


def _ask_timeout():
    while True:
        value = input("Request timeout in seconds [3]: ").strip()
        if not value:
            return 3
        try:
            timeout = float(value)
            if timeout > 0:
                return timeout
        except ValueError:
            pass
        print("Enter a positive number.")


def _collect_scan_args():
    targets = input("Targets (space or comma separated, blank to use a file): ")
    targets = [target for target in targets.replace(",", " ").split()]
    return SimpleNamespace(
        targets=targets,
        file=_ask_path("Target file (optional): "),
        output=_ask_path("JSON output file (optional): "),
        verbose=_ask_verbose(),
    )


def _collect_tls_args():
    targets = input("Host(s), optionally with port (space or comma separated): ")
    return SimpleNamespace(
        targets=[target for target in targets.replace(",", " ").split()],
        output=_ask_path("JSON output file (optional): "),
    )


def _collect_directory_args():
    target = input("Target URL: ").strip()
    wordlist = _ask_path("Wordlist file (optional; built-in list if blank): ")
    timeout = _ask_timeout()
    while True:
        workers_value = input("Concurrent requests [10]: ").strip()
        try:
            workers = int(workers_value) if workers_value else 10
            if workers > 0:
                break
        except ValueError:
            pass
        print("Enter a positive whole number.")
    proxy_value = input(
        f"Proxy file [{DEFAULT_PROXY_LABEL}; '-' for direct]: "
    ).strip()
    proxy_file = None if proxy_value == "-" else (
        Path(proxy_value) if proxy_value else DEFAULT_PROXY_FILE
    )
    return SimpleNamespace(
        target=target,
        wordlist=wordlist,
        timeout=timeout,
        workers=workers,
        proxy_file=proxy_file,
        output=_ask_path("JSON output file (optional): "),
    )


def _collect_web_args():
    target = input("Target URL: ").strip()
    proxy_value = input(
        f"Proxy file [{DEFAULT_PROXY_LABEL}; '-' for direct]: "
    ).strip()
    proxy_file = None if proxy_value == "-" else (
        Path(proxy_value) if proxy_value else DEFAULT_PROXY_FILE
    )
    return SimpleNamespace(
        target=target,
        timeout=_ask_timeout(),
        output=_ask_path("JSON output file (optional): "),
        proxy_file=proxy_file,
        verbose=_ask_verbose(),
    )


def _collect_web_check_args():
    target = input("Target URL: ").strip()
    return SimpleNamespace(
        target=target,
        timeout=_ask_timeout(),
        proxy_file=_collect_proxy_path(),
        output=_ask_path("JSON output file (optional): "),
    )


def _collect_proxy_path():
    proxy_value = input(
        f"Proxy file [{DEFAULT_PROXY_LABEL}; '-' for direct]: "
    ).strip()
    return None if proxy_value == "-" else (
        Path(proxy_value) if proxy_value else DEFAULT_PROXY_FILE
    )


def _collect_dns_args():
    targets = input("Host(s), space or comma separated: ")
    return SimpleNamespace(
        targets=[target for target in targets.replace(",", " ").split()],
        output=_ask_path("JSON output file (optional): "),
    )


def _collect_single_target_args():
    return SimpleNamespace(
        target=input("Domain, host, IP, or URL: ").strip(),
        output=_ask_path("JSON output file (optional): "),
    )


def _collect_dns_posture_args():
    return SimpleNamespace(
        target=input("Domain: ").strip(),
        timeout=_ask_timeout(),
        output=_ask_path("JSON output file (optional): "),
    )


def _collect_crawler_args():
    args = _collect_web_check_args()
    while True:
        value = input("Maximum pages to crawl [25]: ").strip()
        try:
            args.max_pages = int(value) if value else 25
            if args.max_pages > 0:
                return args
        except ValueError:
            pass
        print("Enter a positive whole number.")


def _collect_proxy_input_file():
    while True:
        value = input("Proxy list file to check: ").strip()
        if value:
            return Path(value)
        print("Enter a file path.")


def run_scan(args):
    targets = list(args.targets)
    if args.file:
        try:
            targets.extend(
                line.strip()
                for line in args.file.read_text(encoding="utf8").splitlines()
                if line.strip()
            )
        except FileNotFoundError:
            print(f"Error: target file does not exist: {args.file}", file=sys.stderr)
            return 1
        except PermissionError:
            print(f"Error: cannot read target file: {args.file}", file=sys.stderr)
            return 1

    if not targets:
        print("Error: provide a target or use --file", file=sys.stderr)
        return 2

    should_write = args.file is not None or args.output is not None
    output_path = args.output or Path("results/results.json")
    for target in targets:
        if getattr(args, "verbose", False):
            logging.getLogger(__name__).debug("Scanning target: %s", target)
        scan_result = port_scan(target)
        if should_write:
            write_result(
                output_path,
                target,
                "port_scan",
                scan_result,
            )
    return 0


def run_enum(args):
    proxy_pool = None
    if args.proxy_file:
        try:
            proxy_pool = ProxyRotator.from_file(
                args.proxy_file,
            )
        except (FileNotFoundError, PermissionError) as error:
            print(f"Error: cannot read proxy file: {error}", file=sys.stderr)
            return 1
        except ValueError as error:
            print(f"Error: invalid proxy file: {error}", file=sys.stderr)
            return 1

    alive_subdomains = enum_domain(
        args.target,
        timeout=args.timeout,
        proxy_pool=proxy_pool,
    )
    if args.output:
        write_result(
            args.output,
            args.target,
            "enum_domain",
            {"alive_subdomains": alive_subdomains},
        )
    return 0


def run_info(args):
    proxy_pool = None
    if args.proxy_file:
        try:
            proxy_pool = ProxyRotator.from_file(args.proxy_file)
        except (FileNotFoundError, PermissionError) as error:
            print(f"Error: cannot read proxy file: {error}", file=sys.stderr)
            return 1
        except ValueError as error:
            print(f"Error: invalid proxy file: {error}", file=sys.stderr)
            return 1

    result = get_server_info(
        args.target,
        timeout=args.timeout,
        proxy_pool=proxy_pool,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.output:
        write_result(args.output, args.target, "server_info", result)
    return 0


def run_tls_inspector(args):
    if not args.targets:
        print("Enter at least one host to inspect.")
        return 2
    try:
        from modules.ssl_fingerprint import inspect_targets, print_report
    except ModuleNotFoundError as error:
        if error.name == "cryptography":
            print(
                "SSL/TLS inspection requires cryptography. "
                "Install it with: python3 -m pip install cryptography",
                file=sys.stderr,
            )
            return 1
        raise

    results = inspect_targets(args.targets)
    for result in results:
        if "error" in result:
            print(f"\n=== {result['host']} ===\n  [x] {result['error']}")
        else:
            print_report(result)
        if args.output:
            write_result(
                args.output,
                result["host"],
                "ssl_fingerprint",
                json.loads(json.dumps(result, default=str)),
            )
    return 0


def run_directory_brute(args):
    proxy_pool = None
    if args.proxy_file:
        try:
            proxy_pool = ProxyRotator.from_file(args.proxy_file)
        except (FileNotFoundError, PermissionError) as error:
            print(f"Error: cannot read proxy file: {error}", file=sys.stderr)
            return 1
        except ValueError as error:
            print(f"Error: invalid proxy file: {error}", file=sys.stderr)
            return 1

    try:
        found = brute_directories(
            args.target,
            wordlist=args.wordlist,
            timeout=args.timeout,
            max_workers=args.workers,
            proxy_pool=proxy_pool,
        )
    except (OSError, ValueError) as error:
        print(f"Directory scan failed: {error}", file=sys.stderr)
        return 1

    print(f"Found {len(found)} paths on {args.target}.")
    for result in found:
        print(f"[{result['status_code']}] {result['url']}")
    if args.output:
        write_result(
            args.output,
            args.target,
            "directory_brute",
            {"found": found},
        )
    return 0


def _build_proxy_pool(proxy_file):
    if proxy_file is None:
        return None
    return ProxyRotator.from_file(proxy_file)


def _run_http_check(args, module_name, check):
    try:
        proxy_pool = _build_proxy_pool(args.proxy_file)
    except (FileNotFoundError, PermissionError) as error:
        print(f"Error: cannot read proxy file: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Error: invalid proxy file: {error}", file=sys.stderr)
        return 1

    result = check(args.target, timeout=args.timeout, proxy_pool=proxy_pool)
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.output:
        write_result(args.output, args.target, module_name, result)
    return 0


def run_robots_sitemap(args):
    return _run_http_check(args, "robots_sitemap", inspect_robots_sitemap)


def run_security_headers(args):
    return _run_http_check(args, "security_headers", audit_security_headers)


def run_redirect_chain(args):
    return _run_http_check(args, "redirect_chain", trace_redirects)


def run_http_methods(args):
    return _run_http_check(args, "http_methods_cors", inspect_methods_and_cors)


def run_dns_resolver(args):
    if not args.targets:
        print("Enter at least one hostname to resolve.")
        return 2
    results = resolve_hosts(args.targets)
    print(json.dumps(results, indent=2, sort_keys=True))
    if args.output:
        for result in results:
            write_result(args.output, result["target"], "dns_resolver", result)
    return 0


def _run_optional_dependency(operation, package, install_name=None):
    try:
        return operation()
    except ModuleNotFoundError as error:
        if error.name != package:
            raise
        dependency = install_name or package
        print(
            f"This check requires {dependency}. Install dependencies with: "
            f"{sys.executable} -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        return None


def run_dns_posture(args):
    result = _run_optional_dependency(
        lambda: audit_dns_posture(args.target, timeout=args.timeout),
        "dns",
        "dnspython",
    )
    if result is None:
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.output:
        write_result(args.output, args.target, "dns_posture", result)
    return 0


def run_rdap_lookup(args):
    result = _run_optional_dependency(
        lambda: lookup_rdap(args.target), "ipwhois"
    )
    if result is None:
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.output:
        write_result(args.output, args.target, "rdap_lookup", result)
    return 0


def run_html_crawler(args):
    try:
        proxy_pool = _build_proxy_pool(args.proxy_file)
    except (FileNotFoundError, PermissionError) as error:
        print(f"Error: cannot read proxy file: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Error: invalid proxy file: {error}", file=sys.stderr)
        return 1

    result = _run_optional_dependency(
        lambda: crawl_site(
            args.target,
            timeout=args.timeout,
            proxy_pool=proxy_pool,
            max_pages=args.max_pages,
        ),
        "bs4",
        "beautifulsoup4",
    )
    if result is None:
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.output:
        write_result(args.output, args.target, "html_crawler", result)
    return 0


WEB_CHECK_ACTIONS = (
    (run_robots_sitemap, _collect_web_check_args),
    (run_dns_resolver, _collect_dns_args),
    (run_security_headers, _collect_web_check_args),
    (run_redirect_chain, _collect_web_check_args),
    (run_http_methods, _collect_web_check_args),
    (run_dns_posture, _collect_dns_posture_args),
    (run_rdap_lookup, _collect_single_target_args),
    (run_html_crawler, _collect_crawler_args),
)


def main():
    actions = (
        (run_scan, _collect_scan_args),
        (run_enum, _collect_web_args),
        (run_info, _collect_web_args),
        (run_tls_inspector, _collect_tls_args),
        (run_directory_brute, _collect_directory_args),
    )
    try:
        while True:
            choice = _read_menu_choice()
            if choice == len(MENU_OPTIONS) - 1:
                return 0
            if choice == len(MENU_OPTIONS) - 3:
                while True:
                    web_choice = _read_web_check_choice()
                    if web_choice is None:
                        break
                    if web_choice < 0 or web_choice >= len(WEB_CHECK_ACTIONS):
                        print("Choose one of the listed web checks.")
                        continue
                    handler, collect_args = WEB_CHECK_ACTIONS[web_choice]
                    handler(collect_args())
                    input("\nPress Enter to return to web checks...")
                continue
            if choice == len(MENU_OPTIONS) - 2:
                while True:
                    proxy_choice = _read_proxy_menu_choice()
                    if proxy_choice is None:
                        break
                    if proxy_choice < 0 or proxy_choice >= len(PROXY_MENU_OPTIONS):
                        print("Choose one of the listed proxy options.")
                        continue

                    if proxy_choice == 0:
                        input_file = DEFAULT_PROXY_FILE
                    elif proxy_choice == 1:
                        input_file = None
                    else:
                        input_file = _collect_proxy_input_file()

                    try:
                        run_checker(input_file, DEFAULT_PROXY_FILE)
                    except (OSError, ValueError) as error:
                        print(f"Proxy check failed: {error}", file=sys.stderr)
                    input("\nPress Enter to return to proxy tools...")
                continue
            if choice < 0 or choice >= len(actions):
                print("Choose one of the listed options.")
                continue

            handler, collect_args = actions[choice]
            args = collect_args()
            logging.basicConfig(format="%(levelname)s: %(message)s")
            logging.getLogger().setLevel(
                logging.DEBUG if getattr(args, "verbose", False) else logging.CRITICAL
            )
            handler(args)
            input("\nPress Enter to return to the menu...")
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        return 130

if __name__ == "__main__":
    sys.exit(main())
  