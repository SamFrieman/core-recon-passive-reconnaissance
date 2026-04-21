<div align="center">

# CoreRecon

**Passive reconnaissance platform for security researchers**

[![Version](https://img.shields.io/badge/version-2.2.2-blue)](https://github.com/SamFrieman/core-recon-passive-reconnaissance/releases)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://core-recon-passive-reconnaissance.vercel.app/)

Point it at any domain, IP, or URL and get back a full intelligence report with a **0–100 security posture score** in under 5 seconds.

**[Try the live demo →](https://core-recon-passive-reconnaissance.vercel.app/)**

</div>

---

## What It Does

CoreRecon runs **8 intelligence modules in parallel** and scores the target across 6 weighted security categories. No active scanning, no intrusive probes — purely passive OSINT against public data sources.

| Module | Intelligence Gathered |
|---|---|
| Infrastructure | IP, ASN, CDN detection, cloud provider, open ports |
| DNS | SPF, DMARC, DNSSEC, MX/NS provider classification |
| TLS/SSL | Certificate validity, algorithm strength, expiry risk |
| HTTP Headers | Security grade (A–F), HSTS, CSP, cookie flags |
| Subdomains | Certificate transparency + passive DNS enumeration |
| Technology | 60+ signatures across 15 categories, EOL detection |
| WHOIS | Registrar, registration dates, name servers |
| Web Archive | Wayback history, exposed paths, API endpoints |

**Scoring:** TLS 25% · Web Security 25% · Infrastructure 15% · DNS 15% · Technology 10% · Exposure 10%

Results export as a **PDF report**.

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │          React Frontend              │
                    │       (Vite + Tailwind CSS)          │
                    └──────────────┬──────────────────────┘
                                   │ REST
                    ┌──────────────▼──────────────────────┐
                    │         FastAPI Backend              │
                    │  Rate limiting · Auth · 8-layer      │
                    │  input sanitizer · TTL cache         │
                    └──┬──────────────────────────────┬───┘
                       │  ThreadPoolExecutor (parallel)│
       ┌───────────────▼──────────────────────────┐   │
       │         8 Intelligence Modules           │   │
       │  infrastructure · dns · tls              │   │
       │  web_headers · subdomains · technology   │   │
       │  whois · wayback                         │   │
       └───────────────┬──────────────────────────┘   │
                       │                               │
            ┌──────────▼──────────┐      ┌────────────▼─────────┐
            │  Correlation &      │      │  Risk Engine (v2.1)  │
            │  Exposure Engine    │      │  6-category weighted │
            └──────────┬──────────┘      │  score 0–100         │
                       │                 └──────────────────────┘
            ┌──────────▼──────────┐
            │  SQLite / PostgreSQL │
            │   Scan history DB   │
            └─────────────────────┘
```

---

## Quickstart

Requires **Python 3.8+** and **Node 16+**.

```bash
git clone https://github.com/SamFrieman/core-recon-passive-reconnaissance.git
cd core-recon-passive-reconnaissance

# Install dependencies
pip install -r requirements.txt
cd frontend && npm install && cd ..

# Configure environment (optional — see .env.example)
cp .env.example .env

# Terminal 1 — backend
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 — frontend
cd frontend && npm run dev
```

Open `http://localhost:5173`

---

## API

```bash
# Run a scan
curl https://corerecon-api.onrender.com/api/v1/recon/example.com

# Download PDF report
curl https://corerecon-api.onrender.com/api/v1/report/example.com --output report.pdf
```

Example response:
```json
{
  "target": "example.com",
  "score": 74,
  "grade": "B",
  "category_scores": {
    "tls": 85, "web_security": 60, "infrastructure": 90,
    "dns": 70, "technology": 80, "exposure": 75
  },
  "risk_issues": [
    {
      "issue": "DMARC policy is 'none' — no enforcement active",
      "severity": "MEDIUM",
      "category": "dns"
    }
  ]
}
```

> **First time using the hosted instance?** The backend runs on Render's free tier and sleeps when idle. Visit [corerecon-api.onrender.com](https://corerecon-api.onrender.com/) first and give it ~30 seconds to wake.

---

## Security Design

| Layer | Implementation |
|---|---|
| Input validation | 8-layer sanitizer: SQL injection, XSS, command injection, path traversal, SSRF |
| CORS | Locked to `ALLOWED_ORIGINS` env var — no wildcard |
| Rate limiting | 10 scans/min · 5 reports/min per IP (via slowapi) |
| Admin endpoints | Gated behind `X-Admin-Token` header |
| Request size | Hard-capped at 16 KB |
| Response headers | Security headers on all API responses |
| Error handling | Internal errors never leaked to clients |
| Module isolation | One timeout does not abort the full scan (soft-fail) |

Install the pre-commit hook to block accidental secret commits:
```bash
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | SQLite | PostgreSQL connection string |
| `ALLOWED_ORIGINS` | `localhost:5173` | Comma-separated CORS origins |
| `CORERECON_ADMIN_TOKEN` | *(disabled)* | Token for `/health` and `/history` |
| `SCAN_CACHE_TTL` | `300` | Cache TTL in seconds |

Copy `.env.example` to `.env` to get started.

---

## Deployment

**Render + Vercel (hosted):** `render.yaml` and `vercel.json` are preconfigured — just connect your fork.

**Docker:**
```bash
docker-compose up --build
```

**Manual:**
```bash
DATABASE_URL=postgresql://... ALLOWED_ORIGINS=https://yourdomain.com \
  uvicorn backend.main:app --host 0.0.0.0 --port 8000

cd frontend && npm run build   # outputs to frontend/dist/
```

---

## Changelog

**v2.2.2** — Bugfix. Risk engine key mismatch corrected: `hsts_analysis`/`csp_analysis` keys now aligned between `web_headers.py` and `risk.py`, eliminating a permanent −35 pt web security penalty that dragged final scores ~8–9 pts below real values on every scan.

**v2.2.1** — Security hardening. CORS locked to configured origins, rate limiting added (10/min scans, 5/min reports), admin endpoints gated behind `X-Admin-Token` header, request body size capped, security headers on all API responses, PDF filename sanitized, internal errors no longer leaked to clients. TLS verification restored (`verify=True` by default in web_headers.py).

**v2.1** — Intelligence expansion. CDN detection, multi-IP resolution, IPv6 support, SPF/DMARC/DNSSEC analysis, MX/NS provider classification, per-subdomain risk classification, HSTS/CSP/cookie security parsing, header grade (A–F), TLS version risk rating, self-signed cert detection, weak algorithm flagging, EOL software detection, retry logic with backoff across all external API calls.

**v2.0** — Major refactor. Monolithic `main.py` split into `backend/modules/` and `backend/core/`. Risk engine rebuilt with 6 weighted categories. Intelligence correlation layer added. In-memory TTL cache added. PostgreSQL support added alongside SQLite. Per-module soft-fail isolation.

**v1.0** — Initial release. Infrastructure, DNS, HTTP fingerprinting, TLS, subdomain discovery, WHOIS, technology detection, Wayback Machine history, flat risk scoring, PDF export.

---

## Contributing

Pull requests are welcome.

- **Keep it passive.** CoreRecon is a passive reconnaissance tool. PRs introducing active scanning or exploitation will not be merged.
- **Do not break the API.** Existing response fields are stable. Adding new fields is fine; removing or renaming is not.
- **Modules must soft-fail.** Timeouts and external API errors should return a failure record, not crash the scan. See any existing module for the pattern.
- **Open an issue first for significant changes** so we can align before you invest the time.
- **Install the pre-commit hook** (see Security Design above).

---

## Legal

> Only scan domains and IPs you own or have explicit permission to test. CoreRecon queries publicly available data sources and does not send active probes to target systems.

---

<div align="center">

[MIT License](LICENSE) · [Security Policy](SECURITY.md) · [Changelog](backend/CHANGELOG.md)

</div>
