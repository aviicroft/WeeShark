# 🏗️ WebGuard – Technical Architecture & System Design

This document details the architectural design, security boundaries, data workflows, database schemas, and scoring models powering WebGuard.

---

## 1. Dual-Stack Architectural Overview

WebGuard adopts a dual-stack layout designed to balance rapid client-side responsiveness with cross-platform backend simplicity:

```
+-----------------------------------------------------------------------------------+
|                                 USER INTERFACES                                   |
|                                                                                   |
|  [React 19 SPA (Vite + Tailwind v4)]        [Flask Multi-Page (Jinja2 Templates)] |
|  - Real-time Stage Stepper                   - Dynamic View Routes                |
|  - In-browser jsPDF Generator                - Server-side ReportLab Generator    |
|  - Responsive Modern Dashboard               - Lightweight, Zero-Build Required   |
+--------------------------+--------------------------------+-----------------------+
                           |                                |
                           | HTTP /api REST                 | Internal Invocation
                           v                                v
+--------------------------+--------------------------------+-----------------------+
|                                API & ENGINE LAYER                                 |
|                                                                                   |
|  [Express Gateway (server.ts)] <--------------------------+                       |
|  - Express Router & SSRF Gate                                                     |
|  - Parameterized Child Process                                                    |
|                                                                                   |
|  [Security Audit Engine (webguard/scanner.py)]                                    |
|  - Multi-tiered SSRF Validation (DNS + IP + SafeRedirectHandler)                  |
|  - TLS Handshake & Certificate Verification (port 443)                            |
|  - HTTP Defense Headers Inspection (CSP, HSTS, XFO, XCTO)                         |
|  - Redacted Cookie Attribute Inspection (Secure, HttpOnly, SameSite)              |
|  - Information Disclosure Banner Detection (Server, X-Powered-By)                 |
|  - Non-destructive Concurrent TCP Socket Probing (80, 443, 22, 21, 8080)          |
|  - Weighted 0–100 Dynamic Scoring Algorithm                                       |
+----------------------------------+------------------------------------------------+
                                   |
                                   v
+----------------------------------+------------------------------------------------+
|                             PERSISTENCE & REPORTING                               |
|                                                                                   |
|  [SQLite Database Ledger (webguard/database.py -> webguard.db)]                   |
|  - scans table with hydrated checks & recommendations JSON                        |
|                                                                                   |
|  [Report Generation (webguard/report.py)]                                         |
|  - Vector PDF Generation with ReportLab                                           |
|  - Plain-Text Formatted Fallback Generator                                        |
+-----------------------------------------------------------------------------------+
```

---

## 2. End-to-End Execution Flow

When a user initiates a scan (via the React SPA or Flask UI), the execution steps follow this deterministic pipeline:

```
1. Input Normalization & Sanity Check
   └─ Strips whitespace, auto-prefixes https:// if protocol is omitted.
   └─ Validates protocol scheme strictly against http:// and https://.

2. Hostname Validation & SSRF Gate (Tier 1)
   └─ Blocks localhost, 127.0.0.1, 0.0.0.0, ::1, metadata.google.internal.
   └─ Resolves hostname via DNS and verifies target IP is public (non-RFC 1918).

3. Concurrent Probing Pipeline
   ├─ TLS Handshake (Port 443)
   │  └─ Extracts TLS version, Certificate Issuer, expiry date.
   ├─ Safe HTTP Request
   │  └─ Uses SafeRedirectHandler to prevent open-redirect SSRF bypasses.
   │  └─ Extracts response headers (CSP, HSTS, X-Frame-Options, X-Content-Type).
   │  └─ Redacts Set-Cookie headers, extracting Secure, HttpOnly, SameSite.
   │  └─ Inspects Server and X-Powered-By banners for version exposure.
   └─ Parallel Socket Check
      └─ Tests ports 80, 443, 22, 21, 8080 with 1.2s timeout.

4. Dynamic Scoring & Risk Categorization
   └─ Weights: HTTPS (25), Headers (35), Cookies (15), Server Info (10), Ports (15).
   └─ Classifies risk tier: EXCELLENT, GOOD, MEDIUM, or CRITICAL.
   └─ Generates tailored, actionable remediation recommendations.

5. Ledger Persistence
   └─ Stores scan record into SQLite database (webguard.db).
   └─ Maintains historical ledger (scan_history.json).

6. Response & Visualization
   └─ Returns JSON payload to React UI or renders Jinja2 results.html view.
```

---

## 3. SSRF Defense-in-Depth Specification

WebGuard implements a **zero-trust boundary** for all network destinations:

| Layer | Protection Mechanism | Blocked Targets |
| :--- | :--- | :--- |
| **Layer 1: Protocol** | Explicit scheme check | `file://`, `ftp://`, `gopher://`, `dict://`, `ldap://` |
| **Layer 2: Hostname** | Blacklist pattern match | `localhost`, `*.local`, `*.internal`, `metadata.google.internal` |
| **Layer 3: Pre-Resolve** | DNS Resolution check | Hostnames that resolve to unroutable or private IPs |
| **Layer 4: IP Subnet** | `ipaddress` network boundary | `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fe80::/10`, `fc00::/7` |
| **Layer 5: Redirect** | `SafeRedirectHandler` | Any 3xx redirect hopping from public IP to private IP |

---

## 4. SQLite Database Schema (`webguard.db`)

All assessments are committed to the `scans` table:

```sql
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    resolved_ip TEXT,
    http_status INTEGER,
    scan_date TEXT NOT NULL,
    scan_time TEXT NOT NULL,
    scan_timestamp TEXT NOT NULL,
    scan_duration TEXT NOT NULL,
    duration_seconds REAL,
    score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    badge_color TEXT NOT NULL,
    issues_count INTEGER DEFAULT 0,
    checks_json TEXT NOT NULL,
    recommendations_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

- `checks_json`: Stores structured results for `https`, `headers`, `cookies`, `server`, and `ports`.
- `recommendations_json`: Stores array of remediation objects (`category`, `issue`, `recommendation`).
- `database.row_to_dict()` automatically hydrates `checks_json` and `recommendations_json` into native dictionaries.

---

## 5. Scoring Formulas & Weights

The overall security score \(S\) is calculated as:

\[
S = \max(0, \min(100, P_{\text{https}} + P_{\text{headers}} + P_{\text{cookies}} + P_{\text{server}} + P_{\text{ports}}))
\]

Where:
- \(P_{\text{https}} \in [0, 25]\):
  - Enforced HTTPS + TLS handshake: `25`
  - Plain HTTP with open 443: `12`
  - Certificate issue / Self-signed: `10`
  - No HTTPS support: `0`
- \(P_{\text{headers}} \in [0, 35]\):
  - Content-Security-Policy: `12`
  - Strict-Transport-Security: `10`
  - X-Frame-Options: `7`
  - X-Content-Type-Options: `6`
- \(P_{\text{cookies}} \in [0, 15]\):
  - Base = `15`
  - Each missing `Secure`: `-3`
  - Each missing `HttpOnly`: `-3`
  - Each missing/lax `SameSite`: `-2`
- \(P_{\text{server}} \in [0, 10]\):
  - Hidden / generic token: `10`
  - Specific software version disclosure: `4`
- \(P_{\text{ports}} \in [0, 15]\):
  - Base = `15`
  - Open FTP (21): `-8`
  - Open SSH (22): `-4`
  - Open Proxy (8080): `-3`

