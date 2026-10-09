# StackDetect

**A host fingerprinting tool that takes a list of subdomains or URLs and reports their HTTP status, server headers, page title, and detected technology stack. Can run with subscout output.**

> **Recon workflow:** Run [SubScout](https://github.com/oluwaseyi-rgb/SubScout.git) to discover live subdomains, then feed the output into StackDetect to fingerprint each host.

StackDetect doesn't discover subdomains itself — it's built to run *after* a discovery tool like SubScout, nmap, or any wordlist you already have. Feed it a list of hosts and it tells you what's actually running on each one: CMS, web server, frameworks, CDN, and more, based on header and response-body signatures.

---

## Features

- **HTTP status + final URL**: tries HTTPS first, falls back to HTTP automatically
- **Header extraction**: `Server` and `X-Powered-By` pulled out directly
- **Page title extraction**: grabbed from the response body
- **Technology fingerprinting**: 28 built-in signatures covering CMSs (WordPress, Drupal, Joomla), web servers (Nginx, Apache, IIS), CDNs (Cloudflare, Akamai, CloudFront), frameworks (React, Vue, Angular, Next.js, Laravel, Django, Rails), and dev tools (Jenkins, GitLab, Kibana, Grafana, Swagger)
- **Flexible input**: reads from a file (`-i`) or piped stdin — works great chained with other recon tools
- **Two output formats**: CSV or JSON (`--format`)
- **Concurrent scanning**: configurable thread count
- **Live progress** printed to stderr so it doesn't interfere with piped output

---

## Requirements

- Python 3.7+
- `requests`

```bash
pip install requests
```

---

## Usage

```bash
python3 stackdetect.py -i hosts.txt -o results.csv
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-i`, `--input` | File with one host per line | stdin |
| `-o`, `--output` | Output file path (required) | none |
| `--format` | Output format: `csv` or `json` | `csv` |
| `-t`, `--threads` | Concurrent workers | `20` |

### Input Format

One host per line, with or without a scheme. Lines starting with `#` are ignored.

```
# hosts.txt
www.example.com
api.example.com
https://admin.example.com
internal.example.com
```

### Examples

Basic scan from a file:

```bash
python3 stackdetect.py -i hosts.txt -o results.csv
```

JSON output:

```bash
python3 stackdetect.py -i hosts.txt -o results.json --format json
```

Pipe hosts straight from SubScout's output:

```bash
cat subscout_results.txt | python3 stackdetect.py -o results.csv
```

Higher concurrency for a large host list:

```bash
python3 stackdetect.py -i hosts.txt -o results.csv -t 50
```

---

## Output Fields

| Field | Description |
|---|---|
| `host` | The input host as given |
| `final_url` | URL after following redirects |
| `status_code` | HTTP status, or blank if unreachable |
| `server` | `Server` response header |
| `powered_by` | `X-Powered-By` response header |
| `title` | Page `<title>` content |
| `technologies` | Comma-separated list of detected tech |
| `error` | Error message if the host was unreachable |

---

## Example Output (CSV)

```
host,final_url,status_code,server,powered_by,title,technologies,error
api.example.com,https://api.example.com/,200,nginx,,API Docs,"Nginx, Swagger/OpenAPI",
www.example.com,https://www.example.com/,200,cloudflare,PHP,Example Site,"Cloudflare, PHP, WordPress",
old.example.com,,,,,,,Connection timed out
```

---

## How Fingerprinting Works

Each technology signature is a regex checked against the combined response headers and the first 200,000 characters of the response body. A host can match multiple technologies at once (e.g. `Cloudflare` + `WordPress` + `PHP`). This is signature-based detection, not deep analysis — it catches common, well-known markers but can miss obfuscated or heavily customized stacks.

---

## Limitations

- Does not render JavaScript, so client-side-only frameworks without server-side markers may be missed
- Fingerprinting is signature-based and can produce false negatives on hardened or customized deployments
- Only GET requests are used; no authentication or session handling
- Does not discover hosts itself — pair it with SubScout or another enumeration tool for a complete workflow

---

## Legal & Ethical Use

Only scan hosts you own or have explicit authorization to test, such as targets within the scope of a bug bounty program. Unauthorized scanning may be illegal and may violate a program's rules of engagement. The author is not responsible for misuse of this tool.

---

## Author

**Oladunni Oluwaseyi**
GitHub: [@oluwaseyi-rgb](https://github.com/oluwaseyi-rgb)
LinkedIn: [Oluwaseyi Oladunni](https://www.linkedin.com/in/oluwaseyi-oladunni-6a42b1407)

---

## License

Released under the MIT License.
