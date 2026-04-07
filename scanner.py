#!/usr/bin/env python3
"""
Domain file scanner

What it does:
- Crawls a target domain to discover JavaScript files.
- Probes a list of potentially sensitive file paths.
- Reports status codes, content type, and content length.

Usage:
  python domain_file_scanner.py https://example.com
  python domain_file_scanner.py example.com --max-pages 120 --timeout 10 --output report.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_GREEN = "\033[32m"
ANSI_CYAN = "\033[36m"
ANSI_GRAY = "\033[90m"


SENSITIVE_PATHS = [
    ".env",
    ".env.local",
    ".env.bak",
    "web.config",
    "wp-config.php",
    "wp-config.php~",
    "wp-config.php.bak",
    "config.php",
    "config.json",
    "config.yml",
    "connection.inc",
    "database.yml",
    "databases.yml",
    "php.ini",
    "phpinfo.php",
    "info.php",
    "adminer.php",
    "db.php",
    ".htaccess",
    ".htpasswd",
    "docker-compose.yml",
    "Dockerfile",
    ".git/",
    ".gitignore",
    ".svn/",
    "backup.zip",
    "backup.tar.gz",
    "db_backup.sql",
    "index.php.bak",
    "settings.py~",
    "config.old",
    "readme.txt",
    "readme.md",
    "changelog.txt",
    "error.log",
    "access.log",
    "laravel.log",
    "npm-debug.log",
    "WS_FTP.LOG",
    "robots.txt",
    "apc.php",
    "symfony_debug.log",
    "examples/jsp/snp/snoop.jsp",
    "examples/servlet/SessionExample",
    "WEB-INF/web.xml",
    "etc/passwd",
]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "api_key_assignment",
        re.compile(
            r"""(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'][^"'\\]{8,}["']"""
        ),
    ),
    (
        "aws_access_key_id",
        re.compile(r"""AKIA[0-9A-Z]{16}"""),
    ),
    (
        "google_api_key",
        re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""),
    ),
    (
        "stripe_secret_key",
        re.compile(r"""sk_(live|test)_[0-9a-zA-Z]{16,}"""),
    ),
    (
        "generic_secret_key_assignment",
        re.compile(
            r"""(?i)\b(secret|secret[_-]?key|jwt[_-]?secret|private[_-]?key|signing[_-]?key)\b\s*[:=]\s*["'][^"'\\]{8,}["']"""
        ),
    ),
    (
        "bearer_or_jwt_token_assignment",
        re.compile(
            r"""(?i)\b(token|bearer|id[_-]?token|refresh[_-]?token)\b\s*[:=]\s*["'][A-Za-z0-9\-\._]{12,}["']"""
        ),
    ),
    (
        "jwt_token_value",
        re.compile(r"""eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}"""),
    ),
    (
        "github_token",
        re.compile(r"""\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"""),
    ),
    (
        "slack_token",
        re.compile(r"""\bxox[baprs]-[A-Za-z0-9-]{10,}\b"""),
    ),
    (
        "twilio_sid_token",
        re.compile(r"""\b(AC[a-fA-F0-9]{32}|SK[a-fA-F0-9]{32})\b"""),
    ),
    (
        "azure_storage_connection_string",
        re.compile(
            r"""(?i)\bDefaultEndpointsProtocol=https;AccountName=[^;]{2,};AccountKey=[^;]{8,};EndpointSuffix=[^;"'\s]{3,}"""
        ),
    ),
    (
        "azure_sas_token",
        re.compile(r"""(?i)\bsv=\d{4}-\d{2}-\d{2}&ss=[^&\s]+&srt=[^&\s]+&sp=[^&\s]+&se=[^&\s]+&st=[^&\s]+&spr=[^&\s]+&sig=[A-Za-z0-9%/+_=.-]{10,}"""),
    ),
    (
        "firebase_url",
        re.compile(r"""https?:\/\/[a-z0-9-]+\.firebaseio\.com\/?""", re.IGNORECASE),
    ),
    (
        "firebase_storage_bucket",
        re.compile(r"""\b[a-z0-9][a-z0-9\-]{2,}\.appspot\.com\b""", re.IGNORECASE),
    ),
    (
        "password_assignment",
        re.compile(r"""(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*["'][^"'\\]{4,}["']"""),
    ),
    (
        "username_assignment",
        re.compile(r"""(?i)\b(user(name)?|login)\b\s*[:=]\s*["'][^"'\\]{3,}["']"""),
    ),
    (
        "default_credentials_pair",
        re.compile(
            r"""(?is)(default|test|demo|sample).{0,80}?(user(name)?|login).{0,80}?(pass(word)?|pwd)"""
        ),
    ),
    (
        "default_admin_credentials",
        re.compile(
            r"""(?i)\b(admin|root|test|demo)\b\s*[:=]\s*["']?(admin|root|password|123456|12345|qwerty|letmein|test)["']?"""
        ),
    ),
    (
        "database_url",
        re.compile(
            r"""(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|oracle):\/\/[^\s"'<>]{6,}"""
        ),
    ),
    (
        "database_connection_assignment",
        re.compile(
            r"""(?i)\b(db|database|connection|dsn|jdbc[_-]?url|database[_-]?url)\b\s*[:=]\s*["'][^"'\\]{8,}["']"""
        ),
    ),
    (
        "storage_bucket_url",
        re.compile(
            r"""(?i)\b(s3:\/\/[a-z0-9\.\-_]{3,}|gs:\/\/[a-z0-9\.\-_]{3,}|https?:\/\/[a-z0-9\.\-_]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/?|https?:\/\/storage\.googleapis\.com\/[a-z0-9\.\-_]+\/?|https?:\/\/[a-z0-9\.\-_]+\.blob\.core\.windows\.net\/?)"""
        ),
    ),
    (
        "aws_s3_bucket_name",
        re.compile(r"""\b[a-z0-9][a-z0-9\.-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b""", re.IGNORECASE),
    ),
    (
        "gcs_bucket_name",
        re.compile(r"""\bstorage\.googleapis\.com\/[a-z0-9][a-z0-9\.\-_]{2,}\b""", re.IGNORECASE),
    ),
    (
        "bucket_assignment",
        re.compile(
            r"""(?i)\b(bucket|bucket[_-]?name|s3[_-]?bucket|gcs[_-]?bucket|storage[_-]?bucket)\b\s*[:=]\s*["'][a-z0-9][a-z0-9\.\-_]{2,}["']"""
        ),
    ),
    (
        "admin_email",
        re.compile(
            r"""(?i)\b(admin|administrator|support|root|security)[._-]?[a-z0-9]*@[a-z0-9.-]+\.[a-z]{2,}\b"""
        ),
    ),
]


class LinkAndScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.scripts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag.lower() == "a":
            href = attrs_dict.get("href")
            if href:
                self.links.add(href)
        elif tag.lower() == "script":
            src = attrs_dict.get("src")
            if src:
                self.scripts.add(src)


def normalize_base_url(domain_or_url: str) -> str:
    raw = domain_or_url.strip()
    if not raw:
        raise ValueError("Domain/URL is empty")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("Invalid domain/URL")
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def is_same_host(base: str, candidate: str) -> bool:
    return urlparse(base).netloc.lower() == urlparse(candidate).netloc.lower()


def request_url(url: str, timeout: int) -> dict:
    req = Request(
        url,
        headers={
            "User-Agent": "DomainFileScanner/1.0 (+security-audit)",
            "Accept": "*/*",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = getattr(resp, "status", 200)
            return {
                "url": url,
                "status": status,
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": len(body),
                "error": "",
                "body": body,
            }
    except HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        return {
            "url": url,
            "status": e.code,
            "content_type": e.headers.get("Content-Type", "") if e.headers else "",
            "content_length": len(body),
            "error": "",
            "body": body,
        }
    except URLError as e:
        return {
            "url": url,
            "status": 0,
            "content_type": "",
            "content_length": 0,
            "error": str(e.reason),
            "body": b"",
        }
    except Exception as e:
        return {
            "url": url,
            "status": 0,
            "content_type": "",
            "content_length": 0,
            "error": str(e),
            "body": b"",
        }


def should_treat_as_html(content_type: str, body: bytes) -> bool:
    ctype = (content_type or "").lower()
    if "text/html" in ctype or "application/xhtml+xml" in ctype:
        return True
    # Fallback sniff
    start = body[:200].lower()
    return b"<html" in start or b"<!doctype html" in start


def discover_js_and_pages(base_url: str, max_pages: int, timeout: int) -> tuple[set[str], set[str]]:
    visited: set[str] = set()
    queued: set[str] = set()
    queue: deque[str] = deque()
    js_urls: set[str] = set()

    start = base_url + "/"
    queue.append(start)
    queued.add(start)

    while queue and len(visited) < max_pages:
        page_url = queue.popleft()
        if page_url in visited:
            continue
        visited.add(page_url)

        result = request_url(page_url, timeout)
        if result["status"] == 0:
            continue
        if result["status"] >= 400 and result["status"] not in {401, 403}:
            continue

        if not should_treat_as_html(result["content_type"], result["body"]):
            continue

        text = result["body"].decode("utf-8", errors="replace")
        parser = LinkAndScriptParser()
        try:
            parser.feed(text)
        except Exception:
            continue

        # Script tags
        for src in parser.scripts:
            full = urljoin(page_url, src)
            if is_same_host(base_url, full):
                if re.search(r"\.js(\?|#|$)", full, flags=re.IGNORECASE):
                    js_urls.add(full)

        # Raw JS references inside HTML (best effort)
        for m in re.finditer(r"""["']([^"']+\.js(?:\?[^"']*)?)["']""", text, flags=re.IGNORECASE):
            full = urljoin(page_url, m.group(1))
            if is_same_host(base_url, full):
                js_urls.add(full)

        # Queue links
        for href in parser.links:
            full = urljoin(page_url, href)
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"):
                continue
            if not is_same_host(base_url, full):
                continue
            cleaned = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
            if cleaned not in visited and cleaned not in queued:
                queue.append(cleaned)
                queued.add(cleaned)

    return js_urls, visited


def probe_sensitive_paths(base_url: str, paths: Iterable[str], timeout: int) -> list[dict]:
    findings: list[dict] = []
    for rel in paths:
        rel_clean = rel.lstrip("/")
        target = urljoin(base_url + "/", rel_clean)
        result = request_url(target, timeout)
        findings.append(
            {
                "path": "/" + rel_clean,
                "url": target,
                "status": result["status"],
                "content_type": result["content_type"],
                "content_length": result["content_length"],
                "error": result["error"],
            }
        )
    return findings


def scan_js_for_hardcoded_secrets(js_urls: Iterable[str], timeout: int, show_not_found: bool = False) -> list[dict]:
    findings: list[dict] = []
    for js_url in sorted(set(js_urls)):
        result = request_url(js_url, timeout)
        if result["status"] == 0 or result["status"] >= 400:
            continue

        text = result["body"].decode("utf-8", errors="replace")
        file_matches: list[dict] = []
        pattern_results: list[dict] = []

        for label, pattern in SECRET_PATTERNS:
            matches = list(pattern.finditer(text))

            match_dicts: list[dict] = []
            for m in matches:
                snippet = text[max(0, m.start() - 50) : min(len(text), m.end() + 50)]
                snippet = re.sub(r"\s+", " ", snippet).strip()
                match_dicts.append(
                    {
                        "type": label,
                        "match": m.group(0)[:180],
                        "snippet": snippet[:260],
                    }
                )

            if match_dicts:
                file_matches.extend(match_dicts)

            if show_not_found:
                pattern_results.append(
                    {
                        "type": label,
                        "matches_count": len(match_dicts),
                        "matches": match_dicts,
                    }
                )

        has_matches = len(file_matches) > 0
        if has_matches or show_not_found:
            findings.append(
                {
                    "js_url": js_url,
                    "status": result["status"],
                    "content_type": result["content_type"],
                    "matches_count": len(file_matches),
                    "matches": file_matches,
                    "has_matches": has_matches,
                    "pattern_results": pattern_results if show_not_found else [],
                }
            )

    return findings


def short(text: str, width: int = 110) -> str:
    clean = re.sub(r"\s+", " ", text).strip()
    if len(clean) <= width:
        return clean
    return clean[: width - 3] + "..."


def supports_color() -> bool:
    if not sys.stdout.isatty():
        return False
    if sys.platform.startswith("win"):
        return True
    return True


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{color}{text}{ANSI_RESET}"


def color_for_secret_type(secret_type: str) -> str:
    high = {
        "aws_access_key_id",
        "google_api_key",
        "stripe_secret_key",
        "api_key_assignment",
        "generic_secret_key_assignment",
        "bearer_or_jwt_token_assignment",
        "jwt_token_value",
        "github_token",
        "slack_token",
        "twilio_sid_token",
        "azure_storage_connection_string",
        "azure_sas_token",
    }
    medium = {
        "password_assignment",
        "default_credentials_pair",
        "default_admin_credentials",
        "database_url",
        "database_connection_assignment",
        "storage_bucket_url",
        "aws_s3_bucket_name",
        "gcs_bucket_name",
        "bucket_assignment",
        "firebase_url",
        "firebase_storage_bucket",
    }
    low = {"username_assignment", "admin_email"}
    if secret_type in high:
        return ANSI_RED
    if secret_type in medium:
        return ANSI_YELLOW
    if secret_type in low:
        return ANSI_GREEN
    return ANSI_CYAN


def print_section(title: str) -> None:
    print(f"\n{'=' * 78}")
    print(title)
    print(f"{'=' * 78}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a domain for JS files and sensitive file exposure.")
    parser.add_argument("target", help="Target domain or URL (e.g. example.com or https://example.com)")
    parser.add_argument("--max-pages", type=int, default=80, help="Maximum number of pages to crawl (default: 80)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--output", help="Optional JSON output file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--show-not-found", action="store_true", help="Print NOT FOUND for each regex per JS file")
    args = parser.parse_args()
    use_color = supports_color() and not args.no_color

    try:
        base_url = normalize_base_url(args.target)
    except ValueError as e:
        print(f"[!] {e}")
        return 1

    print_section("SCAN STARTED")
    print(f"Target        : {base_url}")
    print(f"Max pages     : {args.max_pages}")
    print(f"Timeout (sec) : {args.timeout}")
    print("\n[1/3] Crawling pages to discover JavaScript files...")
    js_urls, visited_pages = discover_js_and_pages(base_url, args.max_pages, args.timeout)
    js_sorted = sorted(js_urls)

    print(f"[2/3] Scanning {len(js_sorted)} discovered JS files for hardcoded secrets...")
    js_secret_findings = scan_js_for_hardcoded_secrets(js_sorted, args.timeout, show_not_found=args.show_not_found)

    print(f"[3/3] Probing {len(SENSITIVE_PATHS)} sensitive paths...")
    sensitive_results = probe_sensitive_paths(base_url, SENSITIVE_PATHS, args.timeout)

    interesting = [r for r in sensitive_results if r["status"] in {200, 206, 301, 302, 307, 308, 401, 403}]

    files_with_secret_matches = [item for item in js_secret_findings if item.get("has_matches")]
    matches_total = sum(item["matches_count"] for item in files_with_secret_matches)

    print_section("SUMMARY")
    print(f"Pages visited        : {len(visited_pages)}")
    print(f"JavaScript files     : {len(js_sorted)}")
    print(f"JS secret findings   : {len(files_with_secret_matches)} files, {matches_total} matches")
    print(f"Sensitive path hits  : {len(interesting)} / {len(sensitive_results)}")

    print_section("DISCOVERED JAVASCRIPT FILES")
    if js_sorted:
        for i, url in enumerate(js_sorted, start=1):
            print(f"{i:>3}. {url}")
    else:
        print("(none found via crawl)")

    print_section("POTENTIAL HARDCODED SECRETS IN JAVASCRIPT")
    if js_secret_findings:
        print(
            "Legend: "
            + colorize("HIGH", ANSI_RED, use_color)
            + " "
            + colorize("MEDIUM", ANSI_YELLOW, use_color)
            + " "
            + colorize("LOW", ANSI_GREEN, use_color)
        )
        for i, file_result in enumerate(js_secret_findings, start=1):
            print(colorize(f'{i:>3}. {file_result["js_url"]}', ANSI_BOLD + ANSI_CYAN, use_color))
            if args.show_not_found:
                print(f'     Matches: {colorize(str(file_result["matches_count"]), ANSI_BOLD, use_color)}')
                for pr in file_result["pattern_results"]:
                    tag = pr["type"]
                    if pr["matches_count"] == 0:
                        print(colorize(f"     - {tag}: NOT FOUND", ANSI_GRAY, use_color))
                        continue
                    tag_colored = colorize(tag, color_for_secret_type(tag), use_color)
                    print(colorize(f"     - {tag_colored}: FOUND {pr['matches_count']}", ANSI_BOLD, use_color))
                    for match in pr["matches"]:
                        print(
                            f"         * value={short(match['match'], 160)} | context={short(match['snippet'], 220)}"
                        )
            else:
                print(f'     Matches: {colorize(str(file_result["matches_count"]), ANSI_BOLD, use_color)}')
                for match in file_result["matches"]:
                    tag = match["type"]
                    tag_colored = colorize(tag, color_for_secret_type(tag), use_color)
                    print(f"     - {tag_colored}: value={short(match['match'], 160)} | context={short(match['snippet'], 220)}")
    else:
        print("(none detected with current patterns)")

    print_section("SENSITIVE PATH RESULTS (INTERESTING ONLY)")
    if interesting:
        for i, r in enumerate(interesting, start=1):
            print(
                f'{i:>3}. [{r["status"]}] {r["path"]} '
                f'| type={short(r["content_type"] or "unknown", 35)}'
                f' | size={r["content_length"]} bytes'
            )
    else:
        print("(no interesting responses)")

    report = {
        "target": base_url,
        "visited_pages_count": len(visited_pages),
        "js_files_count": len(js_sorted),
        "js_files": js_sorted,
        "js_secret_findings_count": len(js_secret_findings),
        "js_secret_findings": js_secret_findings,
        "sensitive_checks_count": len(sensitive_results),
        "sensitive_results": sensitive_results,
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print_section("REPORT SAVED")
        print(f"JSON report written to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

