# 🛡️ WeeShark – Real-Time Web Security Assessment & Vulnerability Scanner

[![Python Tests](https://img.shields.io/badge/Python%20Tests-42%20Passed-emerald.svg)](tests/)
[![Node Tests](https://img.shields.io/badge/Node%20API%20Tests-8%20Passed-emerald.svg)](tests/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict%20Checked-blue.svg)](server.ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Security: SSRF Protected](https://img.shields.io/badge/Security-SSRF%20Protected-cyan.svg)](#ssrf-protection-architecture)

**WeeShark** is a defensive, real-time web security assessment engine and basic vulnerability scanner. It performs passive, non-destructive audits of websites to evaluate SSL/TLS transport security, HTTP defense headers, cookie privacy flags, technology disclosure, and common open network ports.

WeeShark ships with a **dual-architecture implementation**:
1. **Modern Single-Page Application (SPA)**: Powered by React 19, TypeScript, TailwindCSS v4, Vite, and an Express API server with client-side PDF export (`jsPDF`).
2. **Multi-Page Web Application**: Powered by Python 3, Flask, Jinja2 templates, and server-side PDF generation (`ReportLab`).
3. **Shared Python Core**: Both interfaces utilize the same high-performance Python security engine (`scanner.py`) and SQLite audit ledger (`database.py`).

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Security Checks & Methodology](#-security-checks--methodology)
- [Dynamic Scoring Algorithm](#-dynamic-scoring-algorithm)
- [SSRF Defense-in-Depth](#-ssrf-defense-in-depth)
- [Installation & Setup](#-installation--setup)
  - [Prerequisites](#prerequisites)
  - [Quick Start: React + Express SPA](#quick-start-react--express-spa)
  - [Quick Start: Python Flask App](#quick-start-python-flask-app)
- [Running Automated Tests](#-running-automated-tests)
- [API Reference](#-api-reference)
- [PDF Security Reports](#-pdf-security-reports)
- [Project Structure](#-project-structure)
- [Responsible Use & Disclaimer](#-responsible-use--disclaimer)

---

## ✨ Key Features

- 🔒 **Zero-Impact Passive Auditing**: Non-destructive, ethical security checks designed to assess posture without invasive penetration attacks.
- 🌐 **Dual Frontends**: Choose between the reactive TypeScript SPA dashboard or the lightweight Python Flask multi-page application.
- 🛡️ **Hardened SSRF Protection**: Multi-layered IP and DNS inspection blocks scanning of loopback (`127.0.0.1`), private RFC 1918 subnets, link-local addresses, and cloud provider metadata services (`169.254.169.254`), with redirect boundary enforcement.
- ⚡ **Concurrent Port Probing**: Non-blocking TCP socket verification across standard exposed ports (`80`, `443`, `22`, `21`, `8080`).
- 📊 **Dynamic 0–100 Scoring & Risk Ratings**: Real-time scoring categorized into **EXCELLENT**, **GOOD**, **MEDIUM**, and **CRITICAL** tiers.
- 📄 **Exportable PDF Reports**: Download professional security audit reports with color-coded score cards, check breakdowns, and remediation advice.
- 💾 **SQLite Audit Ledger**: Scans and recommendations are saved to an embedded SQLite database (`webguard.db`).
- 🧪 **100% Automated Test Suite**: Built-in automated unit and integration tests across both Python (`pytest`) and TypeScript (`tsx`).

---

## 🏛️ System Architecture

```
                                  ┌───────────────────────────┐
                                  │      Client Browser       │
                                  └─────────────┬─────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     ▼                                                     ▼
      ┌─────────────────────────────┐                       ┌─────────────────────────────┐
      │   React 19 + Vite SPA (UI)  │                       │   Flask Multi-Page App      │
      │   (TypeScript / Tailwind)   │                       │   (Python / Jinja2)         │
      └──────────────┬──────────────┘                       └──────────────┬──────────────┘
                     │ HTTP API                                            │ HTTP / Templates
                     ▼                                                     │
      ┌─────────────────────────────┐                                      │
      │   Express API Server        │                                      │
      │   (server.ts / Node.js)     │                                      │
      └──────────────┬──────────────┘                                      │
                     │ Child Process (Python)                              │ Direct Python Call
                     └──────────────────────────┬──────────────────────────┘
                                                ▼
                               ┌─────────────────────────────────┐
                               │     WeeShark Engine Core        │
                               │  - scanner.py (SSRF + Checks)   │
                               │  - database.py (SQLite Ledger)  │
                               │  - report.py (ReportLab PDF)    │
                               └────────────────┬────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │   Target Host (Public Domain)   │
                               │   - TLS Handshake (Port 443)    │
                               │   - HTTP Response Headers       │
                               │   - Cookie Attributes           │
                               │   - Common Socket Probes        │
                               └─────────────────────────────────┘
```

For comprehensive details on internal component interactions, refer to [ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🔍 Security Checks & Methodology

WeeShark evaluates 5 distinct vectors on each target website:

### 1. Transport Encryption & TLS Verification
- Verifies that target enforces HTTPS over port 443.
- Initiates TLS handshake to record protocol version (`TLSv1.2`, `TLSv1.3`).
- Inspects Certificate Authority (CA) issuer details and expiration validity.
- Flags plain HTTP usage and untrusted/self-signed certificates.

### 2. HTTP Defense Response Headers
- **Content-Security-Policy (CSP)**: Protects against Cross-Site Scripting (XSS) and code injection.
- **Strict-Transport-Security (HSTS)**: Prevents SSL stripping and protocol downgrade attacks.
- **X-Frame-Options**: Mitigates UI redress and clickjacking attacks (`DENY` or `SAMEORIGIN`).
- **X-Content-Type-Options**: Enforces MIME-type sniffing prevention (`nosniff`).

### 3. Cookie Security & Privacy Flags
- Inspects all returned `Set-Cookie` headers.
- **Secure**: Ensures cookies are only transmitted over encrypted TLS connections.
- **HttpOnly**: Restricts JavaScript access via `document.cookie` to prevent session token theft.
- **SameSite**: Enforces `Lax` or `Strict` to mitigate Cross-Site Request Forgery (CSRF).
- *Sensitive cookie values are never extracted or stored.*

### 4. Technology & Version Disclosure
- Inspects `Server` and `X-Powered-By` response headers.
- Detects whether exact software version numbers (e.g. `Apache/2.4.41`, `PHP/7.4.3`) are exposed to attackers for CVE identification.

### 5. Common Port Analysis
- Non-destructive concurrent TCP socket connection probes:
  - Port **80**: Standard HTTP
  - Port **443**: Secure HTTPS
  - Port **22**: SSH (Remote Administration) — *Flagged as risk if publicly reachable*
  - Port **21**: FTP (Unencrypted File Transfer) — *Flagged as risk if publicly reachable*
  - Port **8080**: Alt-HTTP / Proxy — *Flagged as risk if publicly reachable*

---

## 📈 Dynamic Scoring Algorithm

WeeShark calculates a deterministic score from **0 to 100 points** based on the following weighted model:

| Category | Maximum Points | Criteria |
| :--- | :---: | :--- |
| **HTTPS Encryption** | **25 pts** | Active TLS connection = 25 pts; HTTP with open 443 = 12 pts; No HTTPS = 0 pts |
| **Security Headers** | **35 pts** | CSP = 12 pts; HSTS = 10 pts; X-Frame-Options = 7 pts; X-Content-Type-Options = 6 pts |
| **Cookie Flags** | **15 pts** | No cookies = 15 pts; Deductions: -3 per missing Secure, -3 per missing HttpOnly, -2 per missing SameSite |
| **Information Disclosure** | **10 pts** | Hidden/generic server banners = 10 pts; Software version exposed = 4 pts |
| **Port Hygiene** | **15 pts** | Standard web ports only = 15 pts; Open FTP (21) = -8 pts; Open SSH (22) = -4 pts; Open Proxy (8080) = -3 pts |

### Risk Classifications

- **90 – 100 (EXCELLENT / Emerald)**: Robust defensive configuration and transport hygiene.
- **75 – 89 (GOOD / Cyan)**: Solid baseline security with minor configuration enhancements advised.
- **50 – 74 (MEDIUM / Amber)**: Moderate exposure; missing defensive headers or cookie flags.
- **0 – 49 (CRITICAL / Rose)**: Urgent security vulnerabilities detected; unencrypted transport or exposed administrative ports.

---

## 🛡️ SSRF Defense-in-Depth

Server-Side Request Forgery (SSRF) is a primary concern for web auditing tools. WeeShark implements multi-tier defense:

1. **Protocol Restriction**: Only `http://` and `https://` schemes are accepted. Protocols such as `file://`, `ftp://`, `gopher://`, or `data://` are immediately rejected.
2. **Hostname Blacklist**: Hostnames matching `localhost`, loopback IPs, `.local`, `.internal`, or cloud metadata endpoints (`metadata.google.internal`) are blocked.
3. **DNS Pre-Resolution**: Hostnames are resolved to their target IP addresses prior to initiating any socket or HTTP connection.
4. **Private IP Subnet Blocking**: Target IPs belonging to private or restricted ranges are dropped:
   - Loopback: `127.0.0.0/8`, `::1`
   - RFC 1918 Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-Local & Cloud Metadata: `169.254.0.0/16`, `fe80::/10`
   - Unique Local IPv6: `fc00::/7`
5. **Open Redirect Validation**: The custom `SafeRedirectHandler` validates the destination URL on every HTTP redirect hop. If a target responds with a 301/302 redirecting to an internal IP, the request is blocked.

---

## 🚀 Installation & Setup

### Prerequisites

- **Python**: 3.10+ (`python` available in system PATH)
- **Node.js**: v20+ / v22+ / v24+
- **npm**: v10+

### Quick Start: React + Express SPA

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aviicroft/WeeShark.git
   cd WeeShark
   ```

2. **Install Node dependencies:**
   ```bash
   npm install
   ```

3. **Install Python dependencies:**
   ```bash
   pip install -r webguard/requirements.txt
   ```

4. **Launch development server:**
   ```bash
   npm run dev
   ```
   Open your browser at **http://localhost:3000** to access the WeeShark SPA.

5. **Build for production:**
   ```bash
   npm run build
   npm start
   ```

### Quick Start: Python Flask App

If you prefer to run the lightweight Python multi-page Flask interface:

1. **Install Python dependencies:**
   ```bash
   pip install -r webguard/requirements.txt
   ```

2. **Start the Flask server:**
   ```bash
   python webguard/app.py
   ```
   Open your browser at **http://localhost:5000** to access the Flask dashboard.

---

## 🧪 Running Automated Tests

WeeShark includes comprehensive test suites covering unit logic, SSRF defenses, database operations, and API endpoints.

### Run Python Test Suite (pytest)
```bash
python -m pytest tests/ -v
```
Runs 42 automated tests covering:
- SSRF prevention & IP validation
- URL normalization & scheme rejection
- Open-redirect SSRF blocking
- HTTP response security headers evaluation
- Cookie flag inspection & SameSite case insensitivity
- Server banner & technology disclosure checks
- Concurrent port socket checks
- Scoring calculation & recommendation generation
- SQLite database initialization, storage, and hydration
- PDF & text report generation
- Flask multi-page routes & JSON endpoints

### Run Express API Test Suite (npm)
```bash
npm test
```
Runs automated endpoint tests validating:
- `GET /api/dashboard`
- `GET /api/history`
- `POST /api/scan` (input validation & SSRF blocking)
- `GET /api/scans/:id` (sanitization & RCE protection)

### Run Linter & Type Check
```bash
npm run lint
```

---

## 📡 API Reference

For detailed endpoint schemas, request/response payloads, and curl snippets, view the complete [API Documentation](docs/API.md).

### Summary Endpoints:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan` | Execute live security assessment against a URL |
| `GET` | `/api/dashboard` | Retrieve overall metrics and latest scan summary |
| `GET` | `/api/history` | Retrieve historical scan ledger from SQLite |
| `GET` | `/api/scans/:id` | Retrieve detailed scan record by integer ID |

---

## 📑 PDF Security Reports

WeeShark allows downloading executive and technical audit reports in PDF format:

- **From React SPA**: Click **Download PDF Report** on any scan result card or reports table to generate a vector-drawn PDF directly in the browser via `jsPDF`.
- **From Flask App**: Click **Download PDF** on any result to invoke `/download-pdf/<id>`, generating a formatted PDF via `ReportLab` with a plain-text fallback option.

---

## 📁 Project Structure

```
WeeShark/
├── docs/
│   ├── ARCHITECTURE.md          # Architectural specification and data flows
│   └── API.md                   # REST API documentation and examples
├── src/
│   ├── App.tsx                  # Main React SPA (Dashboard, Scanner, Deep Dives, Reports)
│   ├── index.css                # Global styles & Tailwind configuration
│   └── main.tsx                 # React DOM mount point
├── tests/
│   ├── test_scanner.py          # Scanner engine, SSRF, & scoring unit tests
│   ├── test_database.py         # SQLite CRUD & serialization unit tests
│   ├── test_report.py           # PDF and text report generation tests
│   ├── test_flask_app.py        # Flask route integration tests
│   └── test_server.ts           # Express API automated test suite
├── webguard/
│   ├── app.py                   # Multi-page Flask application
│   ├── database.py              # SQLite storage layer (webguard.db)
│   ├── report.py                # Server-side PDF report generator (ReportLab)
│   ├── requirements.txt         # Python package dependencies
│   ├── scanner.py               # Real-time scanning & SSRF engine
│   ├── static/                  # CSS styles and client scripts for Flask app
│   └── templates/               # Jinja2 multi-page templates
├── index.html                   # HTML entry point for Vite SPA
├── package.json                 # Node dependencies, build scripts, & test runner
├── server.ts                    # Express API server & Vite middleware host
├── tsconfig.json                # TypeScript compiler configuration
└── vite.config.ts               # Vite build tool configuration
```

---

## ⚖️ Responsible Use & Disclaimer

> [!CAUTION]
> **Authorized Defensive Audit Only**: WeeShark is built for system administrators, security engineers, and developers to assess and harden websites they own or have explicit authorization to test. Conducting unauthorized network scans or port probes against third-party systems without prior written consent may violate applicable cybersecurity laws and regulations.

