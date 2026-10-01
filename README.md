# Snoopy

Snoopy is an interactive command-line toolkit for authorized network reconnaissance. It groups port, web, DNS, TLS, directory, and proxy checks behind a keyboard-driven menu and can save results as JSON.

## Requirements

- Python 3.10 or newer
- Network access to the systems you are authorized to assess
- The Python packages listed in `requirements.txt`

## Install

Create a virtual environment so dependencies are installed for the same Python interpreter that runs Snoopy:

```bash
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate` instead of the `source` command.

## Launch

From the project directory, run:

```bash
python main.py
```

Use the arrow keys or numpad arrows to move, Enter to select, or the displayed number to launch an action directly. Press `q` in a submenu to return to its parent; press `q` in the main menu to exit. In non-interactive terminals, Snoopy displays a numbered menu.

## Menu

### Reconnaissance

- **Scan common ports** checks the port list defined in `modules/port_scan.py`.
- **Enumerate subdomains** tries Snoopy's built-in subdomain prefixes. Checks run concurrently, up to 20 workers.
- **Brute-force directories** uses a built-in path list or a supplied wordlist. The default is 10 concurrent requests; the worker count and timeout are prompted for each run.

### Web analysis

- **Fingerprint a web server** reports the HTTP status, server headers, content type, and page title.
- **Inspect SSL/TLS certificates** reports certificate details and probes supported TLS versions.
- **Web checks** opens these focused checks:
  - Robots.txt and sitemap inspection
  - DNS and host resolution
  - HTTP security-header audit
  - Redirect-chain tracing
  - HTTP methods and CORS headers
  - DNS posture: MX, TXT, SPF, DMARC, CAA, NS, and common DKIM selectors
  - RDAP and ASN lookup for resolved IP addresses
  - Same-site HTML crawling, limited to 25 pages by default

**Planned:** an OWASP Top 10 vulnerability scanner. This feature is not currently implemented or available in the menu.

### Utilities

- **Proxy tools** checks the current proxy list, fetches and checks candidates from configured public sources, or checks a custom proxy file.
- **Exit** closes Snoopy.

## Proxies

The shared proxy list is `proxies/working_proxies.txt`. Web checks that offer proxy selection use this file by default. Enter `-` at the proxy prompt to connect directly, or provide another proxy file path.

The proxy checker may use public proxies gathered from external sources. They are untrusted third parties and may be unreliable or observe traffic. Do not send credentials, private data, or sensitive requests through them. SOCKS proxies require the SOCKS extra included in `requests[socks]` in `requirements.txt`.

## Results

Most tools offer an optional JSON output path. Results are merged by target using this structure:

```json
{
  "targets": {
    "example.com": {
      "security_headers": {
        "status_code": 200
      }
    }
  }
}
```

The output helper creates parent directories when needed. Choose a path you can write to and keep generated results out of public commits if they contain sensitive target information.
