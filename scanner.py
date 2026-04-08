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
import gzip
import json
import re
import sys
import zlib
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
        "client_secret_id_assignment",
        re.compile(
            r"""(?i)\b(client[_-]?secret[_-]?id|clientSecretId|secret[_-]?id)\b\s*[:=]\s*["'][^"'\\]{4,120}["']"""
        ),
    ),
    (
        "client_id_assignment",
        re.compile(
            r"""(?i)\b(client[_-]?id|clientId|oauth[_-]?client[_-]?id|merchant[_-]?client[_-]?id)\b\s*[:=]\s*["'][^"'\\]{2,120}["']"""
        ),
    ),
    (
        "organization_id_assignment",
        re.compile(
            r"""(?i)\b(org[_-]?id|organization[_-]?id|organisation[_-]?id|workspace[_-]?id|team[_-]?id)\b\s*[:=]\s*["'][^"'\\]{2,120}["']"""
        ),
    ),
    (
        "tenant_id_assignment",
        re.compile(
            r"""(?i)\b(tenant[_-]?id|directory[_-]?id|realm[_-]?id)\b\s*[:=]\s*["'][^"'\\]{2,120}["']"""
        ),
    ),
    (
        "project_id_assignment",
        re.compile(
            r"""(?i)\b(project[_-]?id|subscription[_-]?id|account[_-]?id|app[_-]?id|application[_-]?id)\b\s*[:=]\s*["'][^"'\\]{2,120}["']"""
        ),
    ),
    (
        "api_secret_assignment",
        re.compile(
            r"""(?i)\b(api[_-]?secret|service[_-]?secret|webhook[_-]?secret|signing[_-]?secret)\b\s*[:=]\s*["'][^"'\\]{8,}["']"""
        ),
    ),
    (
        "authorization_header_token",
        re.compile(
            r"""(?i)\bauthorization\b\s*[:=]\s*["'](?:Bearer|Basic)\s+[A-Za-z0-9\-\._~+/=]{8,}["']"""
        ),
    ),
    (
        "private_key_block",
        re.compile(
            r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{40,}-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"""
        ),
    ),
    (
        "bearer_or_jwt_token_assignment",
        re.compile(
            r"""(?i)\b(token|bearer|id[_-]?token|refresh[_-]?token)\b\s*[:=]\s*["'][A-Za-z0-9\-\._]{12,}["']"""
        ),
    ),
    (
        "client_id_assignment",
        re.compile(
            r"""(?i)\b(client[_-]?id|clientId|oauth[_-]?client[_-]?id|merchant[_-]?client[_-]?id)\b\s*[:=]\s*["'][^"'\\]{2,120}["']"""
        ),
    ),
    (
        "payment_link_url",
        re.compile(
            r"""(?i)\bhttps?:\/\/buy\.stripe\.com\/[A-Za-z0-9][A-Za-z0-9_-]*\b"""
        ),
    ),
    (
        "stripe_payment_link_id",
        re.compile(r"""\bplink_[A-Za-z0-9_]{8,}\b""", re.IGNORECASE),
    ),
    (
        "stripe_checkout_url",
        re.compile(r"""(?i)\bhttps?:\/\/checkout\.stripe\.com\/c\/pay\/[A-Za-z0-9_-]+\b"""),
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
        "slack_webhook_url",
        re.compile(
            r"""https?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\-_]{8,}\/[A-Za-z0-9\-_]{8,}\/[A-Za-z0-9\-_]{1,}""",
            re.IGNORECASE,
        ),
    ),
    (
        "sendgrid_api_key",
        re.compile(r"""\bSG\.[A-Za-z0-9\-_]{16,}\b""", re.IGNORECASE),
    ),
    (
        "firebase_api_key_in_config",
        re.compile(r"""(?i)\bapiKey\b\s*[:=]\s*["'](AIza[0-9A-Za-z\-_]{35})["']"""),
    ),
    (
        "firebase_database_url_assignment",
        re.compile(
            r"""(?i)\bdatabaseURL\b\s*[:=]\s*["']https?:\/\/[a-z0-9\.\-_]+\.firebaseio\.com\/[^"'\\\s]{0,200}["']"""
        ),
    ),
    (
        "access_token_value",
        re.compile(r"""(?i)\baccess[_-]?token\b\s*[:=]\s*["'][A-Za-z0-9\-\._~+/=]{10,}["']"""),
    ),
    (
        "refresh_token_value",
        re.compile(r"""(?i)\brefresh[_-]?token\b\s*[:=]\s*["'][A-Za-z0-9\-\._~+/=]{10,}["']"""),
    ),
    (
        "id_token_value",
        re.compile(r"""(?i)\bid[_-]?token\b\s*[:=]\s*["'][A-Za-z0-9\-\._~+/=]{10,}["']"""),
    ),
    (
        "oauth_token_querystring",
        re.compile(
            r"""(?i)[?&](access_token|refresh_token|id_token|oauth_token)=[A-Za-z0-9\-\._~%+/=]{10,}"""
        ),
    ),
    (
        "authorization_bearer_header",
        re.compile(
            r"""(?i)\bauthorization\b\s*[:=]\s*["']Bearer\s+[A-Za-z0-9\-\._~+/=]{10,}["']"""
        ),
    ),
    (
        "artifact_token_assignment",
        re.compile(r"""(?i)\bartifact[_-]?token\b\s*[:=]\s*["'][^"'\\]{10,}["']"""),
    ),
    (
        "jws_token_assignment",
        re.compile(
            r"""(?i)\bjws[_-]?token\b\s*[:=]\s*["'][A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+["']"""
        ),
    ),
    (
        "client_secret_custom",
        re.compile(
            r"""(?i)\b(client[_-]?secret|billing[_-]?secret|billing[_-]?key|merchant[_-]?key|checkout[_-]?secret|service[_-]?key)\b\s*[:=]\s*["'][^"'\\]{8,}["']"""
        ),
    ),
    (
        "internal_endpoint_path",
        re.compile(
            r"""(?i)["']\/(?:admin|internal|api\/v[0-9]+|api\/v[0-9]+\/|api|graphql|swagger|debug|private|hidden|actuator|wp-admin)(?:\/[^\s"'\\]{0,120})?["']"""
        ),
    ),
    (
        "feature_flag_or_bypass_logic",
        re.compile(
            r"""(?i)\b(feature[_-]?flag|enable[_-]?feature|toggle[_-]?feature|bypass|backdoor|disable[_-]?auth|skip[_-]?auth|allow[_-]?admin|isSuperUser)\b"""
        ),
    ),
    (
        "redis_password_assignment",
        re.compile(r"""(?i)\bredis(?:[_-]?(password|auth|secret)|Password|AuthToken|Secret)\b\s*[:=]\s*["'][^"'\\]{4,}["']"""),
    ),
    (
        "database_url_with_password",
        re.compile(
            r"""(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|oracle):\/\/[^\/:\s@]+:[^\/\s@]+@[^\/\s"'<>]{2,}"""
        ),
    ),
    (
        "jdbc_url_with_password",
        re.compile(
            r"""(?i)\bjdbc:(postgresql|mysql|mariadb|mssql|oracle):\/\/[^\/:\s@]+:[^\/\s@]+@[^\/\s"'<>]{2,}"""
        ),
    ),
    (
        "aws_s3_bucket_url_path",
        re.compile(
            r"""(?i)\bhttps?:\/\/[a-z0-9\.\-_]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/[a-z0-9\.\-_\/]{3,}"""
        ),
    ),
    (
        "bucket_assignment_extended",
        re.compile(
            r"""(?i)\b(storage[_-]?bucket|bucket_name|s3_bucket|gcs_bucket)\b\s*[:=]\s*["'][a-z0-9][a-z0-9\.\-_]{2,}["']"""
        ),
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
        elif tag.lower() == "link":
            rel = (attrs_dict.get("rel") or "").lower()
            as_type = (attrs_dict.get("as") or "").lower()
            href = attrs_dict.get("href")
            if href:
                # modulepreload / preload often includes JS chunks
                if "modulepreload" in rel or "preload" in rel and as_type in {"script", "module"}:
                    self.scripts.add(href)


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
            # Many CDNs deliver compressed assets; decompress to keep regex matching working.
            "Accept-Encoding": "gzip, deflate, br",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            encoding = (resp.headers.get("Content-Encoding") or "").lower()
            if encoding:
                try:
                    if "gzip" in encoding:
                        body = gzip.decompress(body)
                    elif "deflate" in encoding:
                        body = zlib.decompress(body)
                    elif "br" in encoding:
                        try:
                            import brotli  # type: ignore

                            body = brotli.decompress(body)  # type: ignore[attr-defined]
                        except Exception:
                            # If brotli isn't available, keep the raw body.
                            pass
                except Exception:
                    # If decompression fails, fall back to the raw body.
                    pass
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


def is_probably_text_body(body: bytes) -> bool:
    if not body:
        return False
    sample = body[:4096]
    # Allow common whitespace control chars, reject heavy binary blobs.
    non_text = 0
    for b in sample:
        if b in (9, 10, 13):
            continue
        if b < 32 or b > 126:
            non_text += 1
    return (non_text / max(1, len(sample))) < 0.35


def is_js_like_url(url: str) -> bool:
    return bool(re.search(r"\.m?js(\?|#|$)", url, flags=re.IGNORECASE))


JS_URL_RE = re.compile(
    r"""(?i)(?:["'])([^"'\\]{1,500}\.(?:m?js|map)(?:\?[^"'\\]{0,250})?)[\"']"""
)
JSON_URL_RE = re.compile(
    r"""(?i)(?:["'])([^"'\\]{1,500}\.json(?:\?[^"'\\]{0,250})?)[\"']"""
)
TXT_URL_RE = re.compile(
    r"""(?i)(?:["'])([^"'\\]{1,500}\.txt(?:\?[^"'\\]{0,250})?)[\"']"""
)
JS_IMPORT_REQUIRE_RE = re.compile(
    r"""(?i)\b(?:import|require)\(\s*["']([^"']+\.m?js(?:\?[^"']*)?)["']\s*\)"""
)
SOURCE_MAPPING_RE = re.compile(r"""(?i)\bsourceMappingURL\s*=\s*["']([^"']+\.map[^"']*)["']""")
WEBPACK_PUBLIC_PATH_RE = re.compile(
    r"""(?i)__webpack_require__\.(?:p|b)\s*[:=]\s*["']([^"']+)["']"""
)
WEBPACK_PUBLIC_PATH2_RE = re.compile(r"""(?i)__webpack_public_path__\s*[:=]\s*["']([^"']+)["']""")

ENDPOINT_URL_RE = re.compile(r"""(?i)(?:["'])(https?://[^"'\s\\]{8,})["']""")
ENDPOINT_REL_PATH_RE = re.compile(
    r"""(?i)(?:["'])(\/(?:api\/|v[0-9]+\/|internal\/|admin\/|graphql\/|oauth\/|auth\/|token\/|payment\/|payments\/|checkout\/|webhook\/|billing\/|subscribe\/|portal\/|account\/|users\/|projects\/)[^"'\s\\]{2,})["']"""
)
ENDPOINT_REL_PATH_NO_SLASH_RE = re.compile(
    r"""(?i)(?:["'])(api\/|v[0-9]+\/|internal\/|admin\/|graphql\/|oauth\/|auth\/|token\/|payment\/|payments\/|checkout\/|webhook\/|billing\/|subscribe\/|portal\/|account\/)[A-Za-z0-9_\-./?&=%#]{2,}["']"""
)
ENDPOINT_GENERIC_REL_PATH_RE = re.compile(
    r"""(?i)(?:["'])(\/(?:api|v[0-9]+|internal|admin|graphql|oauth|auth|token|payment|payments|checkout|webhook|billing|subscribe|portal|account)[A-Za-z0-9_\-./?&=%#]{2,})["']"""
)
FETCH_PATH_RE = re.compile(
    r"""(?i)\b(?:fetch|axios\.get|axios\.post|\$\.ajax)\(\s*["']([^"'\s\\]{2,})["']"""
)

STRIPE_BUY_LINK_RE = re.compile(r"""(?i)\bhttps?:\/\/buy\.stripe\.com\/[A-Za-z0-9][A-Za-z0-9_-]*\b""")
STRIPE_CHECKOUT_LINK_RE = re.compile(
    r"""(?i)\bhttps?:\/\/checkout\.stripe\.com\/c\/pay\/[A-Za-z0-9_-]+\b"""
)
STRIPE_PAYMENT_LINK_ID_RE = re.compile(r"""\bplink_[A-Za-z0-9_]{8,}\b""", re.IGNORECASE)
CLIENT_ID_RE = re.compile(r"""(?i)\b(client[_-]?id|clientId|oauth[_-]?client[_-]?id)\b\s*[:=]\s*["']([^"']{2,120})["']""")


def mine_js_urls_from_text(base_url: str, page_url: str, text: str) -> set[str]:
    # Tries to extract JS/chunk/map URLs from arbitrary JS/JSON/text.
    out: set[str] = set()

    public_paths = set()
    for m in WEBPACK_PUBLIC_PATH_RE.finditer(text):
        public_paths.add(m.group(1))
    for m in WEBPACK_PUBLIC_PATH2_RE.finditer(text):
        public_paths.add(m.group(1))

    def add_candidate(path: str) -> None:
        if not path:
            return
        # Build absolute URL.
        full = urljoin(page_url, path)
        if is_same_host(base_url, full):
            out.add(full)
            return

        # If it's a "relative filename" and webpack has a public path, combine against that.
        if public_paths and not (path.startswith("/") or "://" in path or path.startswith(".")):
            for pp in public_paths:
                public_prefix = urljoin(base_url + "/", pp.rstrip("/") + "/")
                full2 = urljoin(public_prefix, path)
                if is_same_host(base_url, full2):
                    out.add(full2)

    for m in JS_URL_RE.finditer(text):
        add_candidate(m.group(1))
    for m in JS_IMPORT_REQUIRE_RE.finditer(text):
        add_candidate(m.group(1))
    for m in SOURCE_MAPPING_RE.finditer(text):
        add_candidate(m.group(1))

    return out


def mine_manifest_urls_from_text(base_url: str, page_url: str, text: str) -> set[str]:
    out: set[str] = set()

    def add_candidate(path: str) -> None:
        if not path:
            return
        full = urljoin(page_url, path)
        if is_same_host(base_url, full):
            out.add(full)

    for m in JSON_URL_RE.finditer(text):
        add_candidate(m.group(1))
    for m in TXT_URL_RE.finditer(text):
        add_candidate(m.group(1))

    return out


def should_include_external_endpoint(base_url: str, full_url: str) -> bool:
    # Include common payment endpoints even if they are on external domains.
    try:
        host = urlparse(full_url).netloc.lower()
    except Exception:
        return False

    payment_hosts = {
        "buy.stripe.com",
        "stripe.com",
        "checkout.stripe.com",
        "api.stripe.com",
        "hooks.stripe.com",
        "merchant-api.stripe.com",
    }
    if host in payment_hosts:
        return True
    # Also allow common subdomains for stripe.
    if host.endswith(".stripe.com"):
        return True
    return False


def mine_endpoints_from_text(base_url: str, page_url: str, text: str) -> set[str]:
    out: set[str] = set()

    def add_full(url: str) -> None:
        if not url:
            return
        if is_same_host(base_url, url) or should_include_external_endpoint(base_url, url):
            out.add(url)

    def add_rel(path: str) -> None:
        if not path:
            return
        if path.startswith("/"):
            out.add(urljoin(base_url + "/", path.lstrip("/")))
            return
        if re.match(r"(?i)^(api\/|v[0-9]+\/|internal\/|admin\/|graphql\/|oauth\/|auth\/|token\/|payment\/|payments\/|checkout\/|webhook\/|billing\/|subscribe\/|portal\/|account\/)", path):
            out.add(urljoin(base_url + "/", path))
            return
        out.add(urljoin(page_url, path))

    # Full URLs in strings
    for m in ENDPOINT_URL_RE.finditer(text):
        add_full(m.group(1))

    # Fetch-like: fetch("...") or axios.get("...")
    for m in FETCH_PATH_RE.finditer(text):
        cand = m.group(1)
        # Strip simple concatenation wrappers by only allowing obvious strings.
        if cand.startswith("http://") or cand.startswith("https://"):
            add_full(cand)
        elif cand.startswith("/"):
            add_rel(cand)
        elif re.match(r"(?i)^(api\/|v[0-9]+\/|internal\/|admin\/|graphql\/|oauth\/|auth\/|token\/|payment\/|payments\/|checkout\/|webhook\/|billing\/|subscribe\/|portal\/|account\/)", cand):
            add_rel(cand)

    # Relative paths in strings with keyword hints
    for m in ENDPOINT_REL_PATH_RE.finditer(text):
        add_rel(m.group(1))
    for m in ENDPOINT_REL_PATH_NO_SLASH_RE.finditer(text):
        cand = m.group(0)
        # Remove surrounding quotes from full match.
        if len(cand) >= 2 and cand[0] in "\"'" and cand[-1] == cand[0]:
            cand = cand[1:-1]
        add_rel(cand)
    for m in ENDPOINT_GENERIC_REL_PATH_RE.finditer(text):
        add_rel(m.group(1))

    # Payment-specific extraction (Stripe Payment Links / Checkout URLs / IDs)
    for m in STRIPE_BUY_LINK_RE.finditer(text):
        add_full(m.group(0))
    for m in STRIPE_CHECKOUT_LINK_RE.finditer(text):
        add_full(m.group(0))
    for m in STRIPE_PAYMENT_LINK_ID_RE.finditer(text):
        # Include as a pseudo-endpoint for quick visibility.
        out.add("payment_link:" + m.group(0))

    # Client ID: we store as pseudo-endpoint for visibility.
    for m in CLIENT_ID_RE.finditer(text):
        out.add("client_id:" + m.group(2))

    return out


def discover_js_and_pages(base_url: str, max_pages: int, timeout: int) -> tuple[set[str], set[str]]:
    visited: set[str] = set()
    queued: set[str] = set()
    queue: deque[str] = deque()
    js_urls: set[str] = set()

    # Start with likely entry points and manifests.
    starters = [
        urljoin(base_url + "/", "/"),
        urljoin(base_url + "/", "robots.txt"),
        urljoin(base_url + "/", "sitemap.xml"),
        urljoin(base_url + "/", "manifest.json"),
        urljoin(base_url + "/", "asset-manifest.json"),
        urljoin(base_url + "/", "assets.txt"),
        urljoin(base_url + "/", "chunks.txt"),
        urljoin(base_url + "/", "chunk-list.txt"),
        urljoin(base_url + "/", "service-worker.js"),
        urljoin(base_url + "/", "precache-manifest.js"),
    ]
    for s in starters:
        if s not in queued:
            queue.append(s)
            queued.add(s)

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

        body = result["body"]
        # Limit discovery decoding so we don't spend too long on huge bundles.
        body_for_discover = body[: 2_000_000]
        try:
            text = body_for_discover.decode("utf-8", errors="replace")
        except Exception:
            continue

        # If HTML: follow anchors + script/link tags quickly.
        if should_treat_as_html(result["content_type"], body):
            parser = LinkAndScriptParser()
            try:
                parser.feed(text)
            except Exception:
                parser = None

            if parser is not None:
                for src in parser.scripts:
                    full = urljoin(page_url, src)
                    if is_same_host(base_url, full) and re.search(r"\.(?:m?js|map)(\?|#|$)", full, flags=re.IGNORECASE):
                        if is_js_like_url(full):
                            js_urls.add(full)
                        if full not in visited and full not in queued:
                            queue.append(full)
                            queued.add(full)

                # Queue links for broader crawling (same host).
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

        # JS-mining for chunks/maps inside any JS/JSON/text.
        for cand in mine_js_urls_from_text(base_url, page_url, text):
            # Keep only on same host.
            if is_same_host(base_url, cand):
                if is_js_like_url(cand):
                    js_urls.add(cand)
                if cand not in visited and cand not in queued:
                    queue.append(cand)
                    queued.add(cand)

        # Also try to discover manifest/text resources that may contain JS URLs.
        for mf in mine_manifest_urls_from_text(base_url, page_url, text):
            if mf not in visited and mf not in queued:
                queue.append(mf)
                queued.add(mf)

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


def scan_js_for_hardcoded_secrets(
    js_urls: Iterable[str],
    timeout: int,
    show_not_found: bool = False,
    mine_endpoints: bool = False,
    max_endpoints_per_file: int = 0,
    context_window: int = 50,
    collapse_whitespace: bool = True,
    max_match_len: int | None = 180,
    max_snippet_len: int | None = 260,
) -> list[dict]:
    findings: list[dict] = []
    for js_url in sorted(set(js_urls)):
        result = request_url(js_url, timeout)
        if result["status"] == 0 or result["status"] >= 400:
            continue
        if result["content_length"] == 0:
            # Skip empty responses to avoid noisy blank results.
            continue

        if not is_probably_text_body(result["body"]):
            # Skip binary/non-text payloads mislabeled as JS.
            continue

        text = result["body"].decode("utf-8", errors="replace")
        if not text.strip():
            continue
        file_matches: list[dict] = []
        pattern_results: list[dict] = []
        file_endpoints: set[str] = set()

        if mine_endpoints:
            parsed = urlparse(js_url)
            base_for_js = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
            file_endpoints = mine_endpoints_from_text(base_for_js, js_url, text)

        for label, pattern in SECRET_PATTERNS:
            matches = list(pattern.finditer(text))

            match_dicts: list[dict] = []
            for m in matches:
                snippet = text[max(0, m.start() - context_window) : min(len(text), m.end() + context_window)]
                if collapse_whitespace:
                    snippet = re.sub(r"\s+", " ", snippet).strip()
                match_text = m.group(0)
                if max_match_len is not None:
                    match_text = match_text[:max_match_len]
                if max_snippet_len is not None:
                    snippet = snippet[:max_snippet_len]
                match_dicts.append(
                    {
                        "type": label,
                        "match": match_text,
                        "snippet": snippet,
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
        has_endpoints = bool(file_endpoints)
        if has_matches or show_not_found or (mine_endpoints and has_endpoints):
            endpoints_list = sorted(file_endpoints)
            if max_endpoints_per_file and len(endpoints_list) > max_endpoints_per_file:
                endpoints_list = endpoints_list[:max_endpoints_per_file]
            findings.append(
                {
                    "js_url": js_url,
                    "status": result["status"],
                    "content_type": result["content_type"],
                    "matches_count": len(file_matches),
                    "matches": file_matches,
                    "has_matches": has_matches,
                    "pattern_results": pattern_results if show_not_found else [],
                    "endpoints": endpoints_list if mine_endpoints else [],
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
        "api_secret_assignment",
        "bearer_or_jwt_token_assignment",
        "authorization_header_token",
        "private_key_block",
        "authorization_bearer_header",
        "jwt_token_value",
        "jws_token_assignment",
        "artifact_token_assignment",
        "github_token",
        "slack_token",
        "slack_webhook_url",
        "twilio_sid_token",
        "sendgrid_api_key",
        "client_secret_custom",
        "firebase_api_key_in_config",
        "firebase_database_url_assignment",
        "access_token_value",
        "refresh_token_value",
        "id_token_value",
        "oauth_token_querystring",
        "azure_storage_connection_string",
        "azure_sas_token",
        "redis_password_assignment",
        "database_url_with_password",
        "jdbc_url_with_password",
    }
    medium = {
        "password_assignment",
        "client_secret_id_assignment",
        "client_id_assignment",
        "organization_id_assignment",
        "tenant_id_assignment",
        "project_id_assignment",
        "default_credentials_pair",
        "default_admin_credentials",
        "database_url",
        "database_connection_assignment",
        "storage_bucket_url",
        "client_id_assignment",
        "payment_link_url",
        "stripe_payment_link_id",
        "stripe_checkout_url",
        "aws_s3_bucket_name",
        "gcs_bucket_name",
        "bucket_assignment",
        "aws_s3_bucket_url_path",
        "bucket_assignment_extended",
        "firebase_url",
        "firebase_storage_bucket",
    }
    low = {"username_assignment", "admin_email", "internal_endpoint_path", "feature_flag_or_bypass_logic"}
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
    parser.add_argument("--context-window", type=int, default=50, help="Chars of context around a match (default: 50)")
    parser.add_argument("--no-truncate", action="store_true", help="Do not truncate matched values/snippets")
    parser.add_argument("--raw", action="store_true", help="Do not collapse whitespace in snippets (no minify)")
    parser.add_argument("--no-endpoints", action="store_true", help="Do not mine endpoints from JS for API/payment URLs")
    parser.add_argument("--max-endpoints-per-file", type=int, default=0, help="Max endpoints printed/stored per JS file (0=unlimited)")
    parser.add_argument("--max-endpoints-total", type=int, default=0, help="Max endpoints printed/stored total (0=unlimited)")
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
    max_match_len = None if args.no_truncate else 180
    max_snippet_len = None if args.no_truncate else 260
    js_secret_findings = scan_js_for_hardcoded_secrets(
        js_sorted,
        args.timeout,
        show_not_found=args.show_not_found,
        mine_endpoints=not args.no_endpoints,
        max_endpoints_per_file=args.max_endpoints_per_file,
        context_window=max(0, args.context_window),
        collapse_whitespace=not args.raw,
        max_match_len=max_match_len,
        max_snippet_len=max_snippet_len,
    )

    print(f"[3/3] Probing {len(SENSITIVE_PATHS)} sensitive paths...")
    sensitive_results = probe_sensitive_paths(base_url, SENSITIVE_PATHS, args.timeout)

    interesting = [r for r in sensitive_results if r["status"] in {200, 206, 301, 302, 307, 308, 401, 403}]

    files_with_secret_matches = [item for item in js_secret_findings if item.get("has_matches")]
    matches_total = sum(item["matches_count"] for item in files_with_secret_matches)

    # Aggregate endpoints from all scanned JS files.
    endpoints_total_set: set[str] = set()
    if not args.no_endpoints:
        for item in js_secret_findings:
            for ep in item.get("endpoints", []):
                endpoints_total_set.add(ep)
    endpoints_total_list = sorted(endpoints_total_set)
    if args.max_endpoints_total and len(endpoints_total_list) > args.max_endpoints_total:
        endpoints_total_list = endpoints_total_list[: args.max_endpoints_total]

    print_section("SUMMARY")
    print(f"Pages visited        : {len(visited_pages)}")
    print(f"JavaScript files     : {len(js_sorted)}")
    print(f"JS secret findings   : {len(files_with_secret_matches)} files, {matches_total} matches")
    print(f"Sensitive path hits  : {len(interesting)} / {len(sensitive_results)}")
    if not args.no_endpoints:
        print(f"Discovered endpoints : {len(endpoints_total_list)}")

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

    if not args.no_endpoints:
        print_section("DISCOVERED ENDPOINTS / PAYMENT LINKS")
        if endpoints_total_list:
            for i, ep in enumerate(endpoints_total_list, start=1):
                print(f"{i:>3}. {ep}")
        else:
            print("(none discovered from JS strings)")

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
        "discovered_endpoints": endpoints_total_list if not args.no_endpoints else [],
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

