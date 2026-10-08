# 📡 WebGuard REST API Specification

WebGuard provides RESTful JSON endpoints hosted by the Express gateway (port 3000) and the Flask application (port 5000).

---

## Base URLs

- **Express Gateway**: `http://localhost:3000/api`
- **Flask Server**: `http://localhost:5000/api`

---

## Endpoints

### 1. Perform Real-Time Security Scan

Executes a live security audit on a website, performs SSRF validation, and stores the results in the SQLite ledger.

- **Method**: `POST`
- **Path**: `/api/scan`
- **Headers**: `Content-Type: application/json`

#### Request Body:
```json
{
  "url": "https://example.com"
}
```

#### Successful Response (`200 OK`):
```json
{
  "id": 4,
  "target_url": "https://example.com",
  "hostname": "example.com",
  "resolved_ip": "93.184.216.34",
  "http_status": 200,
  "scan_date": "08 October 2026",
  "scan_time": "09:40:00 PM",
  "scan_timestamp": "2026-10-08T21:40:00.123456",
  "scan_duration": "1.35s",
  "duration_seconds": 1.35,
  "score": 88,
  "risk_level": "GOOD",
  "badge_color": "cyan",
  "checks": {
    "https": {
      "status": "PASS",
      "score_points": 25,
      "message": "HTTPS is enabled with a valid TLS connection.",
      "tls_version": "TLSv1.3",
      "issuer": "DigiCert Inc"
    },
    "headers": [
      {
        "header": "Content-Security-Policy",
        "status": "Present",
        "value": "default-src 'self' ...",
        "rating": "PASS",
        "recommendation": "CSP is active."
      },
      {
        "header": "X-Frame-Options",
        "status": "Present",
        "value": "DENY",
        "rating": "PASS",
        "recommendation": "X-Frame-Options is set to 'DENY'."
      },
      {
        "header": "X-Content-Type-Options",
        "status": "Present",
        "value": "nosniff",
        "rating": "PASS",
        "recommendation": "MIME-type sniffing prevention is enforced."
      },
      {
        "header": "Strict-Transport-Security",
        "status": "Present",
        "value": "max-age=31536000",
        "rating": "PASS",
        "recommendation": "HSTS header is present."
      }
    ],
    "cookies": {
      "count": 0,
      "has_cookies": false,
      "status": "PASS",
      "message": "No cookies were set in the initial HTTP response.",
      "cookies": []
    },
    "server": {
      "status": "PASS",
      "server": "ECS (dcb/7F82)",
      "x_powered_by": "None",
      "exposed_details": "Server: ECS (dcb/7F82)",
      "message": "Generic server tokens detected."
    },
    "ports": [
      { "port": 80, "service": "HTTP (Standard Web)", "status": "Open", "is_risk": false },
      { "port": 443, "service": "HTTPS (Secure Web)", "status": "Open", "is_risk": false },
      { "port": 22, "service": "SSH (Remote Administration)", "status": "Closed", "is_risk": false },
      { "port": 21, "service": "FTP (File Transfer)", "status": "Closed", "is_risk": false },
      { "port": 8080, "service": "HTTP-Proxy / Alt-HTTP", "status": "Closed", "is_risk": false }
    ]
  },
  "recommendations": [
    {
      "category": "Security Posture",
      "issue": "No high-priority vulnerabilities detected in standard checks.",
      "recommendation": "Maintain regular automated audits."
    }
  ]
}
```

#### Error Responses:
- `400 Bad Request`: Missing URL or invalid URL format.
  ```json
  { "error": "Please enter a valid website URL." }
  ```
- `403 Forbidden`: SSRF Protection triggered (target resolved to loopback or private network).
  ```json
  { "error": "Access to internal hostnames and localhost is strictly blocked (SSRF Protection)." }
  ```

---

### 2. Get Dashboard Metrics

Returns summary metrics and recent scans for the dashboard overview.

- **Method**: `GET`
- **Path**: `/api/dashboard`

#### Successful Response (`200 OK`):
```json
{
  "total_scans": 24,
  "latest_scan": {
    "id": 24,
    "target_url": "https://example.com",
    "hostname": "example.com",
    "score": 88,
    "risk_level": "GOOD",
    "badge_color": "cyan",
    "issues_count": 0,
    "scan_date": "08 October 2026",
    "scan_time": "09:40:00 PM"
  },
  "recent_scans": [ ... ]
}
```

---

### 3. Get Historical Scans Ledger

Returns previous scan records recorded in the SQLite database.

- **Method**: `GET`
- **Path**: `/api/history`

#### Successful Response (`200 OK`):
```json
[
  {
    "id": 24,
    "target_url": "https://example.com",
    "hostname": "example.com",
    "score": 88,
    "risk_level": "GOOD",
    "badge_color": "cyan",
    "scan_date": "08 October 2026",
    "scan_time": "09:40:00 PM",
    "scan_duration": "1.35s"
  }
]
```

---

### 4. Get Scan Record by ID

Retrieves complete assessment breakdown for an individual scan.

- **Method**: `GET`
- **Path**: `/api/scans/:id`

#### Parameters:
- `id` *(path, required)*: Integer scan identifier (must match `/^\d+$/`).

#### Successful Response (`200 OK`):
Full hydrated scan record object including `checks` and `recommendations`.

#### Error Responses:
- `400 Bad Request`: Non-integer ID provided.
  ```json
  { "error": "Invalid scan ID. ID must be an integer." }
  ```
- `404 Not Found`: Scan record ID not found in database.
  ```json
  { "error": "Scan not found" }
  ```

---

## 🛠️ Example cURL Commands

```bash
# 1. Trigger a security assessment
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# 2. Fetch dashboard metrics
curl -X GET http://localhost:3000/api/dashboard

# 3. Retrieve scan history
curl -X GET http://localhost:3000/api/history

# 4. Fetch details for scan #1
curl -X GET http://localhost:3000/api/scans/1
```

