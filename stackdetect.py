#!/usr/bin/env python3
"""
stackdetect.py

Checks a list of subdomains for:
  - HTTP status code (tries https first, falls back to http)
  - Server / powered-by headers
  - Page title
  - Basic technology fingerprinting (headers + body signatures)

Usage:
    python3 stackdetect.py -i subdomains.txt -o results.csv
    python3 stackdetect.py -i subdomains.txt -o results.json --format json
    cat subdomains.txt | python3 stackdetect.py -o results.csv

Input file: one subdomain/host per line (with or without scheme).
"""

import argparse
import concurrent.futures
import csv
import json
import re
import sys
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}

TIMEOUT = 8

# (name, compiled regex to test against headers-blob or body)
TECH_SIGNATURES = [
    ("WordPress", re.compile(r"wp-content|wp-includes|/wp-json/", re.I)),
    ("Drupal", re.compile(r"Drupal\.settings|/sites/default/files|X-Generator: Drupal", re.I)),
    ("Joomla", re.compile(r"/media/jui/|Joomla!", re.I)),
    ("Nginx", re.compile(r"^nginx", re.I)),
    ("Apache", re.compile(r"^apache", re.I)),
    ("Microsoft-IIS", re.compile(r"Microsoft-IIS", re.I)),
    ("Cloudflare", re.compile(r"cloudflare", re.I)),
    ("Akamai", re.compile(r"akamai", re.I)),
    ("AWS CloudFront", re.compile(r"cloudfront", re.I)),
    ("Varnish", re.compile(r"varnish", re.I)),
    ("PHP", re.compile(r"X-Powered-By: PHP|\.php", re.I)),
    ("ASP.NET", re.compile(r"X-AspNet-Version|X-Powered-By: ASP\.NET|__VIEWSTATE", re.I)),
    ("Express (Node.js)", re.compile(r"X-Powered-By: Express", re.I)),
    ("Next.js", re.compile(r"__NEXT_DATA__|/_next/static", re.I)),
    ("React", re.compile(r"react-dom|data-reactroot", re.I)),
    ("Vue.js", re.compile(r"__VUE__|data-v-", re.I)),
    ("Angular", re.compile(r"ng-version|ng-app", re.I)),
    ("jQuery", re.compile(r"jquery(\.min)?\.js", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(\.min)?\.css", re.I)),
    ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
    ("Django", re.compile(r"csrftoken|django", re.I)),
    ("Ruby on Rails", re.compile(r"X-Powered-By: Phusion Passenger|_rails_session", re.I)),
    ("Shopify", re.compile(r"cdn\.shopify\.com|Shopify", re.I)),
    ("Magento", re.compile(r"Mage\.Cookies|/skin/frontend/", re.I)),
    ("Swagger/OpenAPI", re.compile(r"swagger-ui|openapi\.json", re.I)),
    ("Kibana", re.compile(r"kbn-version|Kibana", re.I)),
    ("Grafana", re.compile(r"Grafana", re.I)),
    ("Jenkins", re.compile(r"X-Jenkins", re.I)),
    ("GitLab", re.compile(r"gitlab", re.I)),
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def detect_tech(headers: dict, body: str) -> list:
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    found = []
    for name, pattern in TECH_SIGNATURES:
        if pattern.search(header_blob) or (body and pattern.search(body[:200000])):
            found.append(name)
    return sorted(set(found))


def get_title(body: str) -> str:
    if not body:
        return ""
    m = TITLE_RE.search(body)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:150]


def check_host(raw_host: str) -> dict:
    raw_host = raw_host.strip()
    if not raw_host or raw_host.startswith("#"):
        return None

    schemes = ["https", "http"] if not raw_host.startswith(("http://", "https://")) else [None]
    result = {
        "host": raw_host,
        "final_url": "",
        "status_code": "",
        "server": "",
        "powered_by": "",
        "title": "",
        "technologies": "",
        "error": "",
    }

    urls_to_try = (
        [raw_host] if schemes[0] is None else [f"{s}://{raw_host}" for s in schemes]
    )

    last_error = ""
    for url in urls_to_try:
        try:
            resp = requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            body = resp.text if resp.headers.get("Content-Type", "").lower().find("text") != -1 or True else ""
            techs = detect_tech(resp.headers, body)

            result.update({
                "final_url": resp.url,
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", ""),
                "powered_by": resp.headers.get("X-Powered-By", ""),
                "title": get_title(body),
                "technologies": ", ".join(techs),
                "error": "",
            })
            return result
        except requests.exceptions.RequestException as e:
            last_error = str(e).split("\n")[0][:150]
            continue

    result["error"] = last_error or "unreachable"
    return result


def load_hosts(path):
    if path:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return [line.strip() for line in sys.stdin if line.strip()]


def main():
    ap = argparse.ArgumentParser(description="Check subdomains for HTTP status + tech stack")
    ap.add_argument("-i", "--input", help="File with one subdomain per line (default: stdin)")
    ap.add_argument("-o", "--output", required=True, help="Output file path")
    ap.add_argument("--format", choices=["csv", "json"], default="csv")
    ap.add_argument("-t", "--threads", type=int, default=20, help="Concurrent workers (default 20)")
    args = ap.parse_args()

    hosts = load_hosts(args.input)
    hosts = [h for h in hosts if h and not h.startswith("#")]
    if not hosts:
        print("No hosts to check.", file=sys.stderr)
        sys.exit(1)

    print(f"Checking {len(hosts)} hosts with {args.threads} threads...", file=sys.stderr)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_host, h): h for h in hosts}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            done += 1
            if r:
                results.append(r)
                status = r["status_code"] or "ERR"
                print(f"[{done}/{len(hosts)}] {r['host']:<45} {status}", file=sys.stderr)

    # sort by host for readable output
    results.sort(key=lambda r: r["host"])

    if args.format == "json":
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
    else:
        fieldnames = ["host", "final_url", "status_code", "server", "powered_by", "title", "technologies", "error"]
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

    print(f"\nDone. Results written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()