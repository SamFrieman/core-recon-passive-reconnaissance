# CoreRecon Changelog

## [2.0.0] — 2026-03

### Architecture
- Monolith `backend/main.py` refactored into `backend/modules/` and `backend/core/`
- `backend/core/` contains: logger, errors, normalizer, cache, risk engine
- `backend/db.py` abstracts all database operations (SQLite default, PostgreSQL optional via `DATABASE_URL`)
- All v1 API endpoints preserved at identical paths with identical response fields

### Intelligence Enhancements (Additive)

**Infrastructure**
- CDN/hosting provider classification from ASN and reverse DNS (`infrastructure.cdn`)
- Multi-IP detection for load-balanced targets (`infrastructure.all_ips`)
- IPv6 address resolution (`infrastructure.ipv6_addresses`)
- ASN fallback: if HackerTarget fails, falls back to ip-api.com AS field

**DNS**
- SPF record parsing and policy strength assessment (`dns.spf`)
- DMARC policy extraction and enforcement level classification (`dns.dmarc`)
- DNSSEC presence detection via DNSKEY record query (`dns.dnssec`)
- MX provider classification (Google Workspace, M365, Proofpoint, etc.) (`dns.mx_provider`)
- NS provider classification (Cloudflare, Route53, Azure DNS, etc.) (`dns.ns_provider`)

**Subdomains**
- Risk classification per subdomain by naming pattern (`subdomains.risk_classified`)
- High-risk subdomains surfaced separately (`subdomains.high_risk_subdomains`, `subdomains.high_risk_count`)
- Patterns flagged: dev/staging/admin/vpn/api/jenkins/database environments

**HTTP Fingerprinting**
- HSTS header parsed for max-age, includeSubDomains, preload (`fingerprint.hsts_analysis`)
- CSP analyzed for unsafe-inline, unsafe-eval, wildcard sources (`fingerprint.csp_analysis`)
- Cookie security flag inspection (`fingerprint.cookie_analysis`)
- Header security grade A+/A/B/C/D/F (`fingerprint.header_grade`)

**SSL/TLS**
- Self-signed certificate detection (`ssl_certificate.is_self_signed`)
- Weak signature algorithm detection — SHA-1, MD5, MD2 flagged (`ssl_certificate.algorithm_analysis`)
- Public key type and size (`ssl_certificate.key_info`)
- TLS version risk rating (`ssl_certificate.tls_risk`)
- Expiry risk classification with contextual notes (`ssl_certificate.expiry_risk`)
- Wildcard certificate detection (`ssl_certificate.wildcard_cert`)
- Total SAN count (`ssl_certificate.san_count`)

**Technology**
- EOL/deprecated version detection for jQuery, PHP, WordPress, Bootstrap, AngularJS, Python, Drupal (`technology.*.eol_risk`, `technology.*.eol_note`)

### Risk Scoring (Stage 3 — Replacement)
- Replaced flat additive model with weighted category-aware engine
- Six categories: TLS (25%), Web Security (25%), Infrastructure (20%), DNS (15%), Technology (10%), Exposure (5%)
- Each category scored 0–100 independently, then composited — score is always mathematically bounded
- Risk bands revised: MINIMAL (0–15), LOW (16–35), MEDIUM (36–60), HIGH (61–80), CRITICAL (81–100)
- Per-category breakdown in `risk_breakdown`
- Data completeness confidence rating in `risk_confidence` (HIGH/MEDIUM/LOW)
- All v1 risk fields preserved: `risk_score`, `risk_level`, `risk_status`, `risk_issues`, `recommendations`

### Resilience (Additive)
- Per-module soft-fail isolation — one module failure does not abort the scan
- Per-module execution timing (`module_timings`)
- Per-module status reporting (`module_status`) — shows SOFT_FAIL reason if applicable
- Total scan duration (`scan_duration_ms`)
- In-memory TTL cache (5 min, configurable via `SCAN_CACHE_TTL` env var)
- Structured JSON logging replacing all `print()` statements

### New API Fields (Additive — no existing fields removed)
- `risk_breakdown` — per-category subscores and findings
- `risk_confidence` — HIGH/MEDIUM/LOW scan completeness rating
- `module_timings` — per-module execution time in ms
- `module_status` — per-module OK/SOFT_FAIL status
- `scan_duration_ms` — total scan time
- `corerecon_version` — version string for client-side tracking
- `infrastructure.cdn` — CDN/cloud provider detection
- `infrastructure.all_ips` — all resolved A records
- `infrastructure.ipv6_addresses` — AAAA records
- `dns.spf` — SPF analysis
- `dns.dmarc` — DMARC policy
- `dns.dnssec` — DNSSEC status
- `dns.mx_provider` — mail provider classification
- `dns.ns_provider` — DNS provider classification
- `subdomains.risk_classified` — per-subdomain risk ratings
- `subdomains.high_risk_subdomains` — high-risk subdomains only
- `subdomains.high_risk_count`
- `fingerprint.hsts_analysis` — parsed HSTS breakdown
- `fingerprint.csp_analysis` — CSP policy evaluation
- `fingerprint.cookie_analysis` — cookie security flags
- `fingerprint.header_grade` — A-F header security grade
- `ssl_certificate.is_self_signed`
- `ssl_certificate.algorithm_analysis`
- `ssl_certificate.key_info`
- `ssl_certificate.tls_risk`
- `ssl_certificate.expiry_risk` / `expiry_note`
- `ssl_certificate.wildcard_cert`
- `ssl_certificate.san_count`

### New Endpoints (Additive)
- `GET /api/v1/health` — uptime check, version, cache stats

### New Environment Variables
- `DATABASE_URL` — PostgreSQL connection string (optional; SQLite used if unset)
- `SCAN_CACHE_TTL` — Cache TTL in seconds (default: 300)
- `SCAN_CACHE_MAX_SIZE` — Max cached domains (default: 100)

## [1.0.0] — 2026-03
- Initial release
