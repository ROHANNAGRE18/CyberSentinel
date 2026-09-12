# CyberSentinel – Website Security Analyzer

A passive, non-intrusive website security analysis tool built as a cybersecurity portfolio project. Submit a URL you own or are authorised to test, and CyberSentinel performs read-only checks across HTTPS, SSL/TLS, security headers, cookies, and DNS — returning a scored report with prioritised remediation recommendations.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![Next.js](https://img.shields.io/badge/Next.js-14-black)
![Tests](https://img.shields.io/badge/tests-274%20passed-brightgreen)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Key Features and Security Checks](#key-features-and-security-checks)
3. [SSRF and Redirect-Chain Protection](#ssrf-and-redirect-chain-protection)
4. [Tech Stack](#tech-stack)
5. [Project Structure](#project-structure)
6. [Backend Setup](#backend-setup)
7. [Frontend Setup](#frontend-setup)
8. [API Overview](#api-overview)
9. [Testing](#testing)
10. [Security and Authorisation Disclaimer](#security-and-authorisation-disclaimer)
11. [Future Improvements](#future-improvements)

---

## Project Overview

CyberSentinel analyses the publicly visible security configuration of a website without making any intrusive or destructive requests. It is designed as a learning and portfolio project demonstrating secure-by-design backend architecture, passive security analysis techniques, and a clean full-stack implementation.

Every scan runs five check modules concurrently and produces:

- An **overall security score** (0–100) with a risk level label
- **Per-check findings** with pass / warn / fail status and severity
- **Prioritised remediation recommendations** linked to authoritative references (MDN, Let's Encrypt, RFC docs)
- **Scan history** accessible by scan ID

---

## Key Features and Security Checks

Each scan produces up to **22 structured check results** across five modules, all running concurrently.

### HTTPS (2 checks)
| Check | What it detects |
|---|---|
| HTTPS Available | Whether the HTTPS endpoint is reachable and responds |
| HTTP→HTTPS Redirect | Whether plain HTTP redirects to HTTPS with a 3xx response |

### SSL/TLS Certificate (4 checks)
| Check | What it detects |
|---|---|
| Certificate Valid | Full chain and hostname validation via Python `ssl` module |
| Certificate Expiry | Days remaining; warns at ≤59d (medium), ≤29d (high/urgent); fails at ≤14d (critical) or if already expired |
| Certificate Issuer | CA identity; flags self-signed certificates |
| Certificate Subject | Common Name and Subject Alternative Names |

### Security Headers (6 checks)
| Check | Header inspected |
|---|---|
| Content-Security-Policy | Presence and quality; flags `unsafe-inline` / `unsafe-eval` without nonce or hash |
| Strict-Transport-Security | Presence and `max-age` value (minimum 180 days recommended) |
| X-Frame-Options | `DENY` or `SAMEORIGIN`; flags deprecated `ALLOW-FROM` |
| X-Content-Type-Options | Must be `nosniff` |
| Referrer-Policy | Recognised safe values; flags `unsafe-url` |
| Permissions-Policy | Presence check |

### Cookie Security (4 checks)
| Check | What it detects |
|---|---|
| Cookie Overview | Summary of cookies found and issue count |
| Secure Flag | Any cookie missing `Secure` on an HTTPS response |
| HttpOnly Flag | Any cookie accessible to JavaScript via `document.cookie` |
| SameSite Attribute | Missing `SameSite`; `SameSite=None` without `Secure` (rejected by modern browsers) |

### DNS (6 checks — informational)
| Check | What it reports |
|---|---|
| A Records | IPv4 addresses; fails if none found (site cannot resolve) |
| AAAA Records | IPv6 addresses (informational) |
| NS Records | Authoritative name servers (informational) |
| MX Records | Mail exchange servers (informational; absence is not a website vulnerability) |
| SPF Record | Sender Policy Framework TXT record (email security, informational only) |
| DMARC Record | DMARC policy at `_dmarc.<domain>` (email security, informational only) |

> DNS results are informational and do not affect the security score. SPF and DMARC are email-security concepts — their absence is not treated as a website vulnerability.

### Scoring Engine
- Starts at **100** and deducts points for FAIL and WARN findings only
- PASS and INFO results never reduce the score
- Duplicate penalties for the same check are prevented
- Score clamped to [0, 100]

| Status | Critical | High | Medium | Low |
|---|---|---|---|---|
| FAIL | −25 | −15 | −10 | −5 |
| WARN | −12 | −7 | −5 | −2 |

| Score | Risk Level |
|---|---|
| 90–100 | Excellent |
| 70–89 | Good |
| 40–69 | Fair |
| 0–39 | Poor |

---

## SSRF and Redirect-Chain Protection

Preventing Server-Side Request Forgery (SSRF) is the first security requirement enforced before any outbound network request is made.

### Pre-scan URL Validation Pipeline (7 steps)

Every submitted URL passes through all seven steps before any scanner module runs:

1. **Scheme allowlist** — only `http://` and `https://` accepted; `file://`, `ftp://`, and all others are rejected
2. **Credential rejection** — URLs containing `user:pass@host` are blocked
3. **Raw IP literal check** — if the user submits an IP address directly, it is validated against the full blocklist before any DNS lookup
4. **Cloud metadata hostname block** — `metadata.google.internal` and known metadata hostnames are blocked by name before DNS resolution is attempted
5. **DNS resolution** — the hostname is resolved to all its IP addresses (A and AAAA records)
6. **All resolved IPs checked** — every IP is checked, not just the first, to prevent DNS re-binding attacks
7. **Redirect guard** — an httpx response event hook re-runs the same IP blocklist check on every redirect hop mid-request, preventing open-redirect pivots into internal infrastructure

### Blocked Address Ranges

| Range | Category |
|---|---|
| `127.0.0.0/8`, `::1` | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC-1918 private |
| `169.254.0.0/16` | Link-local / cloud metadata (includes `169.254.169.254`) |
| `fc00::/7`, `fe80::/10` | IPv6 unique local and link-local |
| `100.64.0.0/10` | Shared address space (RFC-6598) |
| `224.0.0.0/4`, `ff00::/8` | Multicast |
| `fd00:ec2::254` | AWS IPv6 instance metadata |
| NAT64 `64:ff9b::/96` | Blocked only when the embedded IPv4 is itself in a blocked range |

### Redirect-Chain Protection

The redirect guard is attached as an httpx response event hook on every HTTP client used by the scanner. It fires on every response in a redirect chain — not just the first hop — and validates the `Location` header's resolved IP against the same blocklist before httpx follows the redirect. A redirect to `http://192.168.1.1/` or `http://169.254.169.254/` mid-chain raises an SSRF error immediately.

### Additional Passive-Scan Constraints

- No port scanning
- No authentication attempts or brute force
- No form submission or data modification
- Response bodies are received and then discarded; the scanner does not currently stream and terminate the response immediately after reading headers
- 10-second connection timeout, 15-second read timeout
- Rate limiting: 10 scan requests per minute per IP

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, React 18, TypeScript, Tailwind CSS |
| Backend | Python 3.11+, FastAPI 0.111, SQLAlchemy 2.0 (async) |
| Database | SQLite via `aiosqlite` (development); PostgreSQL-ready via env var swap |
| HTTP client | httpx 0.27 (async, with SSRF redirect guard) |
| DNS | dnspython 2.6 |
| TLS inspection | Python `ssl` + `socket` stdlib |
| Rate limiting | slowapi |
| Testing | pytest, pytest-asyncio, unittest.mock |

---

## Project Structure

```
CyberSentinel/
│
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── health.py          # GET /api/v1/health
│   │   │   ├── scans.py           # POST/GET /api/v1/scans
│   │   │   └── router.py
│   │   ├── core/
│   │   │   ├── config.py          # Pydantic settings
│   │   │   ├── security.py        # SSRF protection and URL validation
│   │   │   └── rate_limiter.py    # slowapi rate limiting
│   │   ├── models/scan.py         # SQLAlchemy ORM models
│   │   ├── schemas/scan.py        # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── scanner.py         # Orchestrator — runs all checks concurrently
│   │   │   └── analyzer/
│   │   │       ├── base.py        # CheckResult, CheckBundle dataclasses
│   │   │       ├── https_checker.py
│   │   │       ├── ssl_checker.py
│   │   │       ├── headers_checker.py
│   │   │       ├── cookie_checker.py
│   │   │       ├── dns_checker.py
│   │   │       └── scoring_engine.py
│   │   └── db/
│   │       ├── database.py        # Async engine and session factory
│   │       └── init_db.py         # Table creation on startup
│   ├── tests/
│   │   ├── test_security.py       # SSRF and URL validation tests
│   │   ├── test_api.py            # API endpoint tests
│   │   ├── test_https_checker.py
│   │   ├── test_headers_checker.py
│   │   ├── test_ssl_checker.py
│   │   ├── test_cookie_checker.py
│   │   └── test_scoring_engine.py
│   ├── alembic/                   # Database migrations
│   ├── .env.example
│   ├── pytest.ini
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx           # Home — URL input and scanner form
│   │   │   ├── results/[scanId]/  # Scan results page with polling
│   │   │   └── history/           # Scan history list
│   │   ├── components/
│   │   │   └── (results, scanner, history, ui components)
│   │   ├── hooks/
│   │   │   ├── useScan.ts         # Submit → poll lifecycle
│   │   │   └── useScanHistory.ts
│   │   ├── lib/
│   │   │   ├── api.ts             # Typed fetch client
│   │   │   └── utils.ts           # Score colours, formatters, helpers
│   │   └── types/index.ts         # TypeScript interfaces (mirrors backend schemas)
│   ├── next.config.js
│   ├── tailwind.config.ts
│   └── package.json
│
├── .gitignore
└── README.md
```

---

## Backend Setup

### Prerequisites

- Python 3.11 or higher
- pip

### Install and run

```bash
cd backend

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# Install dependencies
pip install -r requirements.txt

# Start the development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The database (`cybersentinel.db`) is created automatically on first startup.

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8000` | API root |
| `http://127.0.0.1:8000/api/docs` | Swagger UI — interactive API explorer |
| `http://127.0.0.1:8000/api/redoc` | ReDoc — clean API reference |

### Environment variables

Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

Key variables:

```env
DATABASE_URL=sqlite+aiosqlite:///./cybersentinel.db
ALLOWED_ORIGINS=http://localhost:3000
RATE_LIMIT_SCANS_PER_MINUTE=10
CONNECT_TIMEOUT=10
READ_TIMEOUT=15
```

To switch to PostgreSQL, change `DATABASE_URL` to:
```env
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/cybersentinel
```

---

## Frontend Setup

### Prerequisites

- Node.js 18 or higher
- npm

### Install and run

```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

The frontend is available at `http://localhost:3000`.

The `next.config.js` proxies all `/api/*` requests to the FastAPI backend on port 8000, so no CORS configuration is needed during development.

---

## API Overview

All endpoints are prefixed with `/api/v1`.

### `POST /api/v1/scans`

Submit a new scan. Returns immediately with a `scan_id`; the scan runs as a background task.

```
Request:  { "url": "https://example.com" }
Response: 202 Accepted
          { "scan_id": "uuid", "status": "running", "message": "..." }

Errors:
  400  Invalid URL format
  400  URL resolves to a blocked IP (SSRF protection)
  422  Request body validation failed
  429  Rate limit exceeded (10/min per IP)
```

### `GET /api/v1/scans/{scan_id}`

Retrieve full results for a scan. Poll until `status` is `completed` or `failed`.

```
Response: 200 OK
{
  "scan_id": "uuid",
  "url": "https://example.com",
  "status": "completed",
  "score": 74,
  "created_at": "2026-09-10T10:00:00Z",
  "scan_duration": 4.2,
  "checks": [ { "check_name": "...", "status": "pass|warn|fail|info",
                "title": "...", "detail": "...", "severity": "..." }, ... ],
  "recommendations": [ { "check_name": "...", "priority": "...",
                          "title": "...", "description": "...",
                          "reference_url": "..." }, ... ]
}

Errors:
  404  Scan not found
```

### `GET /api/v1/scans`

Paginated scan history list.

```
Query params: page (default 1), limit (default 20, max 100),
              sort (created_at | score), order (asc | desc)
Response: 200 OK
          { "total": 42, "page": 1, "limit": 20, "scans": [ ... ] }
```

### `GET /api/v1/health`

API and database liveness check.

```
Response: 200 OK
          { "status": "healthy", "version": "1.0.0", "database": "connected" }
```

---

## Testing

The backend has a comprehensive test suite covering SSRF protection, every scanner module, API endpoints, and the scoring engine.

```bash
cd backend
venv\Scripts\activate   # Windows
# source venv/bin/activate  # macOS / Linux

# Run all offline tests (no network required)
pytest -v -m "not network"

# Run the full suite including live network integration tests
pytest -v

# Run a specific module
pytest tests/test_security.py -v       # SSRF and URL validation
pytest tests/test_ssl_checker.py -v    # SSL/TLS certificate checks
pytest tests/test_scoring_engine.py -v # Scoring logic
```

**Current test results: 274 passed, 0 failed.**

| Test file | Coverage area |
|---|---|
| `test_security.py` | SSRF blocklist, `is_safe_ip`, `validate_url`, NAT64 handling |
| `test_api.py` | All API endpoints, status codes, pagination, SSRF via API |
| `test_https_checker.py` | HTTPS availability, HTTP→HTTPS redirect detection |
| `test_headers_checker.py` | All 6 security headers, pass/warn/fail logic |
| `test_ssl_checker.py` | Certificate validity, expiry thresholds, issuer, self-signed detection |
| `test_cookie_checker.py` | Secure, HttpOnly, SameSite attribute analysis |
| `test_scoring_engine.py` | Deduction table, DNS exclusions, duplicate prevention, clamping |

Tests marked `@pytest.mark.network` make live DNS and HTTP requests. Skip them in offline environments with `-m "not network"`.

---

## Security and Authorisation Disclaimer

**Only scan websites you own or have explicit written authorisation to test.**

CyberSentinel is a passive analysis tool. It reads publicly available HTTP responses and DNS records. It does not attempt authentication, submit forms, exploit vulnerabilities, or modify any data on the target. However, making HTTP requests to a website you do not control may still be subject to legal restrictions depending on your jurisdiction and the site's terms of service.

Unauthorised scanning may violate computer fraud and abuse laws. The authors of this project accept no liability for misuse.

---

## Future Improvements

These are planned enhancements not yet implemented:

- **User authentication** — private scan history scoped to individual accounts; currently all scans are accessible by scan ID only
- **Scan comparison** — diff two scans of the same domain to track security posture over time
- **Scheduled / recurring scans** — monitor a site on a schedule and alert on score changes
- **Extended SSL checks** — TLS protocol version (TLS 1.0/1.1 deprecation), cipher suite weakness detection, OCSP stapling
- **Subresource Integrity check** — detect third-party scripts and stylesheets loaded without SRI hashes
- **Rate-limit improvements** — persistent rate limiting backed by Redis for multi-process deployments
- **PostgreSQL migration** — the codebase is database-agnostic via SQLAlchemy; switching requires only a `DATABASE_URL` change and running `alembic upgrade head`
- **Docker Compose setup** — single-command local development environment
- **CI pipeline** — GitHub Actions workflow running the test suite on every push
