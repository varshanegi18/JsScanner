# 🕵️ DomainScanner

**Crawl, Discover, Expose.**  
A lightweight, container‑ready web tool that scans any domain to uncover exposed JavaScript files, detect hardcoded secrets (API keys, passwords, tokens, database URLs), and probe sensitive paths (`.env`, `wp-config.php`, backups, logs, etc.).



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

## 📦 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/varshanegi18/JsScanner.git
cd JsScanner
```
### 2. Run the scanner
#### GUI Version

```bash
# Build and run (recommended)
docker build -t js_scanner .
docker run --rm -p 8000:8000 js_scanner
```
Open **http://localhost:8000**

#### CLI version 

```bash
# Run the scanner
python scanner.py https://example.com
```
Advanced usage
```bash
python scanner.py example.com --max-pages 120 --timeout 10 --output report.json
```
## Files

| File | Purpose |
|------|---------|
| `scanner.py` | Core crawler + 40+ secret patterns |
| `app.py` | Flask web UI with SSE + exports |
| `Dockerfile` | Container (Gunicorn + gthread for SSE) |
| `docker-compose.yml` | Easy one-command launch |
