# CoreRecon

Passive reconnaissance platform for security researchers. Point it at any domain, IP, or URL and get back a full intelligence report in seconds.

**Live:** https://core-recon-passive-reconnaissance.vercel.app/
**First time?** Visit https://corerecon-api.onrender.com/ first to wake the backend (Render free tier sleeps when idle, give it 30 seconds).

> Only scan targets you own or have permission to test.

---

## What It Does

Runs 8 intelligence modules in parallel and scores the target 0-100 based on security posture. Results export as a PDF report.

| Module | What You Get |
|---|---|
| Infrastructure | IP, ASN, CDN, cloud provider, open ports |
| DNS | SPF, DMARC, DNSSEC, all record types |
| TLS/SSL | Certificate validity, algorithm strength, expiry risk |
| HTTP Headers | Security grade (A-F), HSTS, CSP, cookie flags |
| Subdomains | Certificate transparency + passive DNS enumeration |
| Technology | 60+ signatures across 15 categories, EOL detection |
| WHOIS | Registrar, registration dates, name servers |
| Web Archive | Wayback history, exposed paths, API endpoints |

---

## Run Locally

Requires Python 3.8+ and Node 16+.
```bash
git clone https://github.com/SamFrieman/core-recon-passive-reconnaissance.git
cd core-recon-passive-reconnaissance

pip install -r requirements.txt
cd frontend && npm install && cd ..

# Terminal 1
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2
cd frontend && npm run dev
```

Open `http://localhost:5173`

---

## API
```bash
curl https://corerecon-api.onrender.com/api/v1/recon/example.com
curl https://corerecon-api.onrender.com/api/v1/report/example.com --output report.pdf
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | SQLite | PostgreSQL connection string |
| `ALLOWED_ORIGINS` | localhost | Comma-separated CORS origins |
| `CORERECON_ADMIN_TOKEN` | none | Gates `/health` and `/history` endpoints |
| `SCAN_CACHE_TTL` | 300 | Cache TTL in seconds |

---

## Security

Input runs through an 8-layer sanitizer covering SQL injection, XSS, command injection, and path traversal. CORS is locked to configured origins, rate limiting is enforced on all scan endpoints, and admin routes require a token header.

Install the pre-commit hook to block accidental secret commits:
```bash
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

## Changelog

**v2.2** - Security hardening. CORS locked to configured origins, rate limiting added (10/min scans, 5/min reports), admin endpoints gated behind X-Admin-Token header, request body size capped, security headers added to all API responses, PDF filename sanitized, internal errors no longer leaked to clients.

**v2.1** - Intelligence expansion. CDN detection, multi-IP resolution, IPv6 support, SPF/DMARC/DNSSEC analysis, MX and NS provider classification, per-subdomain risk classification, HSTS/CSP/cookie security parsing, header grade (A-F), TLS version risk rating, self-signed cert detection, weak algorithm flagging, EOL software detection, retry logic with backoff across all external API calls.

**v2.0** - Major refactor. Monolithic `main.py` split into `backend/modules/` and `backend/core/`. Risk engine rebuilt with 6 weighted categories (TLS, Web Security, Infrastructure, DNS, Technology, Exposure). Intelligence correlation layer added. In-memory TTL cache added. All print statements replaced with structured JSON logging. PostgreSQL support added alongside SQLite. Per-module soft-fail isolation so one timeout does not abort the full scan.

**v1.0** - Initial release. Infrastructure, DNS, HTTP fingerprinting, TLS, subdomain discovery, WHOIS, technology detection, Wayback Machine history, flat risk scoring, PDF report export.

## Contributing

Pull requests are welcome. A few things to keep in mind:

**Keep it passive.** CoreRecon is a passive reconnaissance tool and will stay that way. PRs that introduce active scanning or exploitation techniques will not be merged.

**Don't break the API.** Existing response fields are stable. Adding new fields is fine, removing or renaming them is not.

**Modules must soft-fail.** If your module hits a timeout or external API error it should return a failure record, not crash the scan. Look at any existing module for the pattern.

**Open an issue first for big changes.** If you're planning something significant, open an issue before writing code so we can align on approach before you invest the time.

**Install the pre-commit hook.** It blocks secrets and sensitive files from being committed. Run this once after cloning:
```bash
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```
