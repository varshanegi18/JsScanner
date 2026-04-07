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