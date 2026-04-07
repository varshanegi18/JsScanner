# Domain File Scanner

Security scanner with real-time progress UI. Crawls a target domain to find JavaScript files, scan them for 40+ hardcoded secret patterns, and probe for sensitive file exposures.

## Quick Start

```bash
# Build and run (recommended)
docker compose up --build

# Or Docker only
docker build -t domain-scanner .
docker run -p 8000:8000 domain-scanner
```

Open **http://localhost:8000**

## Features

| Feature | Detail |
|---------|--------|
| Live progress | 3-phase SSE stream — Crawl → Secrets → Paths |
| Grouped secrets | 7 categories: Cloud Keys, Auth Tokens, DB/Storage, etc. |
| Risk badges | HIGH / MEDIUM / LOW per finding type |
| Export | JSON (instant), CSV (server), PDF/HTML report |
| 40+ patterns | AWS, GCP, Azure, GitHub, Stripe, Firebase, JWT, … |

## Secret Categories

- **Cloud Provider Keys** — AWS, Google, Stripe, SendGrid, Twilio, Firebase
- **API & Auth Tokens** — JWT, Bearer, OAuth, client secrets
- **VCS & Chat** — GitHub tokens, Slack tokens & webhooks
- **Azure** — Storage connection strings, SAS tokens
- **Database & Storage** — DB URLs with creds, S3/GCS buckets, Redis
- **Credentials** — Passwords, usernames, default admin creds
- **Recon** — Internal endpoints, feature flags / auth bypasses

## Files

| File | Purpose |
|------|---------|
| `scanner.py` | Core crawler + 40+ secret patterns |
| `app.py` | Flask web UI with SSE + exports |
| `Dockerfile` | Container (Gunicorn + gthread for SSE) |
| `docker-compose.yml` | Easy one-command launch |
# 🕵️ DomainSecretHunter

**Crawl, Discover, Expose.**  
A lightweight, container‑ready web tool that scans any domain to uncover exposed JavaScript files, detect hardcoded secrets (API keys, passwords, tokens, database URLs), and probe sensitive paths (`.env`, `wp-config.php`, backups, logs, etc.).

![Docker Pulls](https://img.shields.io/docker/pulls/yourusername/domainsecrethunter)
![License](https://img.shields.io/github/license/yourusername/domainsecrethunter)

---

## 🚀 Features

- **Crawl** – follows internal links up to a configurable depth (max pages).
- **Discover** – lists every JavaScript file found on the domain.
- **Detect** – scans JS files for 20+ hardcoded secret patterns with severity badges (HIGH/MEDIUM/LOW):
  - AWS keys, Google API keys, Stripe tokens, JWT, GitHub tokens, Slack tokens
  - Database connection strings (MongoDB, PostgreSQL, MySQL, Redis)
  - Storage bucket URLs (S3, GCS, Azure)
  - Email addresses, admin credentials, password assignments
- **Probe** – checks 50+ common sensitive paths (`.env`, `web.config`, `.git/`, backup files, log files, etc.).
- **Web UI** – clean, responsive interface (Flask + Gunicorn) with live results.
- **JSON Report** – download the full scan result as JSON.
- **Zero dependencies on host** – runs anywhere Docker is available.

---

## 📦 Quick Start (Docker)

Pull and run the image in one command:

```bash
docker run --rm -p 8000:8000 yourusername/domainsecrethunter:latest
