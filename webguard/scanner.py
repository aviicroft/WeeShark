"""
WeeShark - Real-Time Web Security Assessment & Basic Vulnerability Scanner
Scanner Engine (scanner.py)

Performs live security checks:
- SSRF prevention & IP validation
- HTTPS negotiation & verification
- Security response headers inspection (CSP, X-Frame-Options, X-Content-Type-Options, HSTS)
- Cookie security flags inspection (Secure, HttpOnly, SameSite)
- Server & framework disclosure headers (Server, X-Powered-By)
- Non-destructive common port socket checks (80, 443, 22, 21, 8080)
- Dynamic security scoring (0-100) & risk rating (EXCELLENT, GOOD, MEDIUM, CRITICAL)
- Actionable recommendations compilation
"""

import socket
import ssl
import time
import json
import os
import sys
import re
from datetime import datetime
import urllib.parse
import urllib.request
import ipaddress
import concurrent.futures

# Ensure directory is on path for database import
_CURR_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURR_DIR not in sys.path:
    sys.path.insert(0, _CURR_DIR)

# Force UTF-8 encoding on standard streams (especially on Windows)
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Optional requests import if available in user's environment
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

PORTS_TO_CHECK = [80, 443, 22, 21, 8080]
PORT_DESCRIPTIONS = {
    80: "HTTP (Standard Web)",
    443: "HTTPS (Secure Web)",
    22: "SSH (Remote Administration)",
    21: "FTP (File Transfer)",
    8080: "HTTP-Proxy / Alt-HTTP"
}

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "scan_history.json")


def is_private_or_restricted_ip(ip_str):
    """
    SSRF Protection: Checks if the IP address belongs to loopback, private,
    link-local, reserved, or multicast ranges.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_unspecified
        )
    except ValueError:
        return True


def get_ip_geolocation(ip_str):
    """
    Retrieves geographic location and hosting ISP metadata for the resolved server IP address.
    Uses reliable external GeoIP endpoints (ipwho.is with fallback to freeipapi.com).
    Returns a standardized dictionary containing coordinates, location, and ASN info.
    """
    default_geo = {
        "ip": ip_str,
        "success": False,
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "country_code": "",
        "continent": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "isp": "Unknown ISP",
        "org": "Unknown Organization",
        "asn": "",
        "timezone": "",
        "postal": "",
        "is_private": False
    }

    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost", "0.0.0.0") or is_private_or_restricted_ip(ip_str):
        default_geo["is_private"] = True
        default_geo["city"] = "Localhost / Internal"
        default_geo["country"] = "Private Network"
        default_geo["isp"] = "Loopback / RFC1918 (SSRF Restricted)"
        return default_geo

    # Check for commercial GeoIP key in environment (e.g. ipinfo.io)
    geoip_api_key = os.environ.get("GEOIP_API_KEY", "").strip() or os.environ.get("IPINFO_TOKEN", "").strip()
    if geoip_api_key:
        try:
            req = urllib.request.Request(
                f"https://ipinfo.io/{ip_str}/json?token={geoip_api_key}",
                headers={"User-Agent": "WeeShark-Security-Scanner/2.0"}
            )
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                loc = (data.get("loc") or "").split(",")
                lat = float(loc[0]) if len(loc) == 2 else 0.0
                lon = float(loc[1]) if len(loc) == 2 else 0.0
                org_parts = (data.get("org") or "").split(" ", 1)
                asn = org_parts[0] if org_parts and org_parts[0].startswith("AS") else ""
                isp = org_parts[1] if len(org_parts) > 1 else (data.get("org") or "Unknown ISP")
                return {
                    "ip": ip_str,
                    "success": True,
                    "city": data.get("city") or "Unknown",
                    "region": data.get("region") or "Unknown",
                    "country": data.get("country") or "Unknown",
                    "country_code": data.get("country") or "",
                    "continent": "Unknown",
                    "latitude": lat,
                    "longitude": lon,
                    "isp": isp,
                    "org": data.get("org") or "Unknown Organization",
                    "asn": asn,
                    "timezone": data.get("timezone") or "",
                    "postal": str(data.get("postal") or ""),
                    "is_private": False
                }
        except Exception:
            pass

    # Try Primary Provider: ipwho.is
    try:
        req = urllib.request.Request(
            f"https://ipwho.is/{ip_str}",
            headers={"User-Agent": "WeeShark-Security-Scanner/2.0"}
        )
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if data.get("success"):
                conn = data.get("connection", {})
                tz = data.get("timezone", {})
                return {
                    "ip": ip_str,
                    "success": True,
                    "city": data.get("city") or "Unknown",
                    "region": data.get("region") or "Unknown",
                    "country": data.get("country") or "Unknown",
                    "country_code": data.get("country_code") or "",
                    "continent": data.get("continent") or "Unknown",
                    "latitude": float(data.get("latitude") or 0.0),
                    "longitude": float(data.get("longitude") or 0.0),
                    "isp": conn.get("isp") or conn.get("org") or "Unknown ISP",
                    "org": conn.get("org") or conn.get("isp") or "Unknown Organization",
                    "asn": str(conn.get("asn") or ""),
                    "timezone": tz.get("id") or "",
                    "postal": str(data.get("postal") or ""),
                    "is_private": False
                }
    except Exception:
        pass

    # Try Fallback Provider: freeipapi.com
    try:
        req = urllib.request.Request(
            f"https://freeipapi.com/api/json/{ip_str}",
            headers={"User-Agent": "WeeShark-Security-Scanner/2.0"}
        )
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            lat = float(data.get("latitude") or 0.0)
            lon = float(data.get("longitude") or 0.0)
            return {
                "ip": ip_str,
                "success": bool(lat or lon or data.get("countryName")),
                "city": data.get("cityName") or "Unknown",
                "region": data.get("regionName") or "Unknown",
                "country": data.get("countryName") or "Unknown",
                "country_code": data.get("countryCode") or "",
                "continent": data.get("continent") or "Unknown",
                "latitude": lat,
                "longitude": lon,
                "isp": data.get("isp") or "Unknown ISP",
                "org": data.get("isp") or "Unknown Organization",
                "asn": str(data.get("asn") or ""),
                "timezone": data.get("timeZone") or "",
                "postal": str(data.get("zipCode") or ""),
                "is_private": False
            }
    except Exception:
        pass

    return default_geo


def get_reverse_dns(ip_str):
    """
    Performs a PTR reverse DNS query to discover associated domain names for an IP address.
    Returns PTR hostname string or None.
    """
    if not ip_str or is_private_or_restricted_ip(ip_str):
        return None
    try:
        host_info = socket.gethostbyaddr(ip_str)
        if host_info and host_info[0]:
            return host_info[0]
    except Exception:
        pass
    return None


def validate_url(url_input):
    """
    Validates user input URL, parses components, and enforces SSRF boundaries.
    Supports both domain names and raw public IP addresses.
    Returns: (normalized_url, hostname, resolved_ip) or raises ValueError
    """
    if not url_input or not isinstance(url_input, str):
        raise ValueError("Please provide a valid website URL.")

    url = url_input.strip()

    # If explicit scheme is present, check it directly
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise ValueError("Invalid protocol. Only HTTP and HTTPS are permitted for scanning.")
    else:
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Invalid protocol. Only HTTP and HTTPS are permitted for scanning.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Unable to determine hostname from URL.")

    # Block localhost / internal keywords immediately
    blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"}
    if hostname.lower() in blocked_hosts or hostname.lower().endswith(".local") or hostname.lower().endswith(".internal"):
        raise ValueError("Access to internal hostnames and localhost is strictly blocked (SSRF Protection).")

    # Check if hostname is an IP literal
    clean_host = hostname.strip("[]")
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        if is_private_or_restricted_ip(str(ip_obj)):
            raise ValueError(f"Target resolves to restricted/private IP address ({ip_obj}). Scanning internal resources is prohibited (SSRF Protection).")
        resolved_ip = str(ip_obj)
    else:
        # Resolve hostname to IPv4/IPv6
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            raise ValueError(f"DNS failure: Could not resolve hostname '{hostname}'. Verify the domain name.")

        # Verify resolved IP against SSRF blacklists
        if is_private_or_restricted_ip(resolved_ip):
            raise ValueError(f"Target resolves to restricted/private IP address ({resolved_ip}). Scanning internal resources is prohibited (SSRF Protection).")

    return url, hostname, resolved_ip


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    SSRF Protection: Validates that HTTP redirects do not navigate
    to private, internal, or restricted network resources.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Enforce SSRF validation on the target of any redirect
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_https(url, hostname):
    """
    Checks if the target supports and enforces HTTPS with valid TLS handshake.
    """
    is_https_url = url.lower().startswith("https://")

    tls_supported = False
    cert_info = {}
    cert_error = None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_supported = True
                cert = ssock.getpeercert()
                if cert:
                    cert_info = {
                        "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Verified CA"),
                        "expiry": cert.get("notAfter", "Valid"),
                        "version": ssock.version()
                    }
    except ssl.SSLCertVerificationError as e:
        tls_supported = False
        cert_error = f"Certificate verification failed ({e.verify_message or 'untrusted or self-signed'})"
    except Exception:
        tls_supported = False

    if is_https_url and tls_supported:
        return {
            "status": "PASS",
            "score_points": 25,
            "message": "HTTPS is enabled with a valid TLS connection.",
            "tls_version": cert_info.get("version", "TLSv1.2+"),
            "issuer": cert_info.get("issuer", "Trusted CA")
        }
    elif tls_supported:
        return {
            "status": "WARNING",
            "score_points": 12,
            "message": "HTTPS is supported on port 443, but the scanned URL used plain HTTP. Ensure 301 redirection to HTTPS.",
            "tls_version": cert_info.get("version", "TLSv1.2+"),
            "issuer": cert_info.get("issuer", "Trusted CA")
        }
    elif cert_error:
        return {
            "status": "WARNING",
            "score_points": 10,
            "message": f"HTTPS port 443 is active, but {cert_error}.",
            "tls_version": "TLS Handshake Issue",
            "issuer": "Untrusted / Invalid Certificate"
        }
    else:
        return {
            "status": "FAIL",
            "score_points": 0,
            "message": "Target website does not use or support HTTPS encryption on port 443. Traffic is transmitted in plain text.",
            "tls_version": "None",
            "issuer": "None"
        }


def check_headers(headers_dict):
    """
    Checks HTTP response headers for essential security protections:
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - Strict-Transport-Security (HSTS)
    """
    # Normalize headers to lower case for reliable inspection
    normalized = {k.lower(): v for k, v in headers_dict.items()}

    checks = []

    # 1. Content-Security-Policy
    csp_val = normalized.get("content-security-policy")
    if csp_val:
        checks.append({
            "header": "Content-Security-Policy",
            "status": "Present",
            "value": csp_val[:120] + ("..." if len(csp_val) > 120 else ""),
            "rating": "PASS",
            "recommendation": "CSP is active. Regularly audit directives (e.g. avoid 'unsafe-inline' where possible)."
        })
    else:
        checks.append({
            "header": "Content-Security-Policy",
            "status": "Missing",
            "value": "Not configured",
            "rating": "WARNING",
            "recommendation": "Implement Content-Security-Policy to restrict unauthorized script execution and prevent Cross-Site Scripting (XSS)."
        })

    # 2. X-Frame-Options
    xfo_val = normalized.get("x-frame-options")
    if xfo_val:
        checks.append({
            "header": "X-Frame-Options",
            "status": "Present",
            "value": xfo_val,
            "rating": "PASS",
            "recommendation": f"X-Frame-Options is set to '{xfo_val}', mitigating clickjacking attacks."
        })
    else:
        checks.append({
            "header": "X-Frame-Options",
            "status": "Missing",
            "value": "Not configured",
            "rating": "WARNING",
            "recommendation": "Configure X-Frame-Options: DENY or SAMEORIGIN to prevent malicious iframing (Clickjacking)."
        })

    # 3. X-Content-Type-Options
    xcto_val = normalized.get("x-content-type-options")
    if xcto_val and "nosniff" in xcto_val.lower():
        checks.append({
            "header": "X-Content-Type-Options",
            "status": "Present",
            "value": xcto_val,
            "rating": "PASS",
            "recommendation": "MIME-type sniffing prevention is actively enforced with 'nosniff'."
        })
    else:
        checks.append({
            "header": "X-Content-Type-Options",
            "status": "Missing",
            "value": xcto_val or "Not configured",
            "rating": "WARNING",
            "recommendation": "Set 'X-Content-Type-Options: nosniff' to instruct browsers not to override declared MIME types."
        })

    # 4. Strict-Transport-Security (HSTS)
    hsts_val = normalized.get("strict-transport-security")
    if hsts_val:
        checks.append({
            "header": "Strict-Transport-Security",
            "status": "Present",
            "value": hsts_val,
            "rating": "PASS",
            "recommendation": "HSTS header is present, protecting against SSL-stripping and protocol downgrade attacks."
        })
    else:
        checks.append({
            "header": "Strict-Transport-Security",
            "status": "Missing",
            "value": "Not configured",
            "rating": "WARNING",
            "recommendation": "Enable 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS only."
        })

    return checks


def parse_raw_cookie_attributes(cookie_string):
    """
    Parses a single Set-Cookie string.
    DO NOT extract or store sensitive cookie values!
    Only extracts security attributes (Secure, HttpOnly, SameSite).
    """
    parts = cookie_string.split(";")
    name = "session_cookie"
    if parts:
        name_part = parts[0].strip()
        if "=" in name_part:
            name = name_part.split("=")[0].strip()

    attributes = {
        "name": name,
        "secure": False,
        "httponly": False,
        "samesite": "None"
    }

    for p in parts[1:]:
        cleaned = p.strip()
        lower = cleaned.lower()
        if lower == "secure":
            attributes["secure"] = True
        elif lower == "httponly":
            attributes["httponly"] = True
        elif lower.startswith("samesite"):
            if "=" in cleaned:
                raw_ss = cleaned.split("=")[1].strip()
                attributes["samesite"] = raw_ss.capitalize() if raw_ss else "Default"
            else:
                attributes["samesite"] = "Default"

    return attributes


def check_cookies(raw_set_cookie_headers):
    """
    Inspects Set-Cookie headers for security flags (Secure, HttpOnly, SameSite).
    Never exposes sensitive values.
    """
    if not raw_set_cookie_headers:
        return {
            "count": 0,
            "has_cookies": False,
            "status": "PASS",
            "cookies": [],
            "message": "No cookies were set in the initial HTTP response. No cookie risk identified."
        }

    parsed_cookies = []
    missing_secure = 0
    missing_httponly = 0
    missing_samesite = 0

    for raw in raw_set_cookie_headers:
        # Multiple cookies can be combined or separate
        c_info = parse_raw_cookie_attributes(raw)
        parsed_cookies.append(c_info)

        if not c_info["secure"]:
            missing_secure += 1
        if not c_info["httponly"]:
            missing_httponly += 1
        if c_info["samesite"].title() in ("None", "Default"):
            missing_samesite += 1

    total = len(parsed_cookies)
    all_secure = (missing_secure == 0)
    all_httponly = (missing_httponly == 0)

    if all_secure and all_httponly:
        status = "PASS"
        message = f"All {total} cookie(s) have Secure and HttpOnly flags configured."
    else:
        status = "WARNING"
        issues = []
        if missing_secure > 0:
            issues.append(f"{missing_secure} cookie(s) missing 'Secure' flag")
        if missing_httponly > 0:
            issues.append(f"{missing_httponly} cookie(s) missing 'HttpOnly' flag")
        if missing_samesite > 0:
            issues.append(f"{missing_samesite} cookie(s) without strict 'SameSite'")
        message = "; ".join(issues)

    return {
        "count": total,
        "has_cookies": True,
        "status": status,
        "message": message,
        "cookies": parsed_cookies
    }


def check_server_info(headers_dict):
    """
    Inspects Server and X-Powered-By response headers for information disclosure.
    """
    normalized = {k.lower(): v for k, v in headers_dict.items()}

    server_val = normalized.get("server")
    powered_by = normalized.get("x-powered-by")

    disclosures = []
    if server_val:
        disclosures.append(f"Server: {server_val}")
    if powered_by:
        disclosures.append(f"X-Powered-By: {powered_by}")

    # Check if version numbers are exposed (e.g., Apache/2.4.41, nginx/1.18.0)
    version_pattern = re.compile(r"/\d+(\.\d+)+")
    has_exact_version = any(version_pattern.search(d) for d in disclosures)

    if not disclosures:
        return {
            "status": "PASS",
            "server": "Hidden / Not Disclosed",
            "x_powered_by": "Hidden / None",
            "exposed_details": "None",
            "message": "No server banner or backend framework headers were exposed."
        }
    elif has_exact_version:
        return {
            "status": "WARNING",
            "server": server_val or "Not specified",
            "x_powered_by": powered_by or "Not specified",
            "exposed_details": ", ".join(disclosures),
            "message": "Specific software version numbers are exposed in headers, assisting attackers in targeting known CVE vulnerabilities."
        }
    else:
        return {
            "status": "PASS",
            "server": server_val or "Not specified",
            "x_powered_by": powered_by or "None",
            "exposed_details": ", ".join(disclosures),
            "message": "Generic server tokens detected. Specific software version numbers appear suppressed."
        }


def probe_single_port(ip, port):
    """
    Attempts a benign TCP socket connection to a specific port with a 1.2s timeout.
    Supports both IPv4 and IPv6 addresses.
    Returns: (port, 'Open' | 'Closed')
    """
    af = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(1.2)
    try:
        res = s.connect_ex((ip, port))
        s.close()
        return port, ("Open" if res == 0 else "Closed")
    except Exception:
        return port, "Closed"


# Alias for backwards compatibility
test_single_port = probe_single_port


def check_ports(ip):
    """
    Scans only allowed common ports (80, 443, 22, 21, 8080) concurrently
    to minimize latency while avoiding aggressive scanning.
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(probe_single_port, ip, p): p for p in PORTS_TO_CHECK}
        for future in concurrent.futures.as_completed(futures):
            port, status = future.result()
            results[port] = {
                "port": port,
                "service": PORT_DESCRIPTIONS.get(port, "Unknown"),
                "status": status,
                "is_risk": (status == "Open" and port in (21, 22, 8080))
            }

    # Order by port number
    ordered = [results[p] for p in PORTS_TO_CHECK]
    return ordered


def calculate_score(https_res, headers_res, cookies_res, server_res, ports_res):
    """
    Calculates dynamic security score (0-100) and risk level:
    - HTTPS: 25 pts
    - Headers: 35 pts (CSP: 12, HSTS: 10, X-Frame: 7, X-Content-Type: 6)
    - Cookies: 15 pts
    - Server Disclosure: 10 pts
    - Port Hygiene: 15 pts
    """
    score = 0

    # 1. HTTPS (max 25)
    score += https_res.get("score_points", 0)

    # 2. Security Headers (max 35)
    header_weights = {
        "Content-Security-Policy": 12,
        "Strict-Transport-Security": 10,
        "X-Frame-Options": 7,
        "X-Content-Type-Options": 6
    }
    for h in headers_res:
        if h["status"] == "Present":
            score += header_weights.get(h["header"], 5)

    # 3. Cookies (max 15)
    if not cookies_res["has_cookies"]:
        score += 15
    else:
        # Deduct if missing security flags
        pts = 15
        for c in cookies_res.get("cookies", []):
            if not c["secure"]:
                pts -= 3
            if not c["httponly"]:
                pts -= 3
            if str(c.get("samesite", "")).title() in ("None", "Default"):
                pts -= 2
        score += max(0, pts)

    # 4. Server Disclosure (max 10)
    if server_res["status"] == "PASS":
        score += 10
    else:
        score += 4

    # 5. Port check (max 15)
    port_pts = 15
    for p in ports_res:
        if p["status"] == "Open":
            if p["port"] == 21:  # Insecure FTP open
                port_pts -= 8
            elif p["port"] == 22:  # Exposed SSH
                port_pts -= 4
            elif p["port"] == 8080:  # Exposed dev/admin port
                port_pts -= 3
    score += max(0, port_pts)

    final_score = max(0, min(100, score))

    if final_score >= 90:
        risk_level = "EXCELLENT"
        badge_color = "emerald"
    elif final_score >= 75:
        risk_level = "GOOD"
        badge_color = "cyan"
    elif final_score >= 50:
        risk_level = "MEDIUM"
        badge_color = "amber"
    else:
        risk_level = "CRITICAL"
        badge_color = "rose"

    return final_score, risk_level, badge_color


def generate_recommendations(https_res, headers_res, cookies_res, server_res, ports_res):
    """
    Generates actionable, beginner-friendly recommendations for any warnings or failures.
    """
    recommendations = []

    if https_res["status"] != "PASS":
        recommendations.append({
            "category": "Encryption & Transport",
            "issue": https_res["message"],
            "recommendation": "Obtain a free automated TLS certificate (e.g., Let's Encrypt) and enforce HTTP-to-HTTPS 301 redirects on all incoming requests."
        })

    for h in headers_res:
        if h.get("status") == "Missing":
            recommendations.append({
                "category": "HTTP Security Headers",
                "issue": f"{h['header']} header is not configured.",
                "recommendation": h.get("recommendation", f"Configure {h['header']} header with defensive settings.")
            })

    if cookies_res.get("has_cookies") and cookies_res.get("status") == "WARNING":
        recommendations.append({
            "category": "Cookie Security",
            "issue": f"Cookie security attribute issues: {cookies_res.get('message', 'Missing Secure/HttpOnly flags')}",
            "recommendation": "Ensure Set-Cookie headers include 'Secure; HttpOnly; SameSite=Lax' to protect session tokens against XSS theft and CSRF attacks."
        })

    if server_res.get("status") == "WARNING":
        recommendations.append({
            "category": "Information Disclosure",
            "issue": f"Server exposed technology details: {server_res.get('exposed_details', 'Software information exposed')}",
            "recommendation": "Disable verbose server tokens in web server configuration (e.g. 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx) and remove 'X-Powered-By'."
        })

    for p in ports_res:
        if p.get("is_risk"):
            recommendations.append({
                "category": "Port Exposure",
                "issue": f"Port {p.get('port')} ({p.get('service', 'Unknown')}) is reachable from the public internet.",
                "recommendation": f"Restrict access to port {p.get('port')} using a firewall (UFW, AWS Security Groups) or require a private VPN connection."
            })

    if not recommendations:
        recommendations.append({
            "category": "Security Posture",
            "issue": "No high-priority vulnerabilities detected in standard checks.",
            "recommendation": "Maintain regular automated audits and ensure software dependencies are kept up-to-date."
        })

    return recommendations


def scan_target(target_url_input):
    """
    Main real-time scanning workflow:
    1. Validates URL / IP & enforces SSRF rules
    2. Records actual start timestamp
    3. Performs HTTP/HTTPS connection with fallback, pulling headers & cookies
    4. Evaluates HTTPS, Headers, Cookies, Server Disclosure, Common Ports, Reverse DNS
    5. Calculates dynamic score & risk level
    6. Generates actionable recommendations
    7. Records completion timestamp and duration
    8. Appends to scan history & SQLite
    """
    # Step 1: Validate URL & SSRF
    url, hostname, resolved_ip = validate_url(target_url_input)

    # Detect if target is an IP literal
    clean_host = hostname.strip("[]")
    is_ip_target = False
    try:
        ipaddress.ip_address(clean_host)
        is_ip_target = True
    except ValueError:
        is_ip_target = False

    # Reverse DNS resolution
    reverse_dns = get_reverse_dns(resolved_ip)

    # Step 2: Record actual scan start time
    start_time_dt = datetime.now()
    start_perf = time.perf_counter()

    # Step 3: Real HTTP/HTTPS Request
    headers_dict = {}
    raw_cookies = []
    http_status_code = None

    request_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WeeShark/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    # Determine probe order: try primary URL first, with HTTP fallback if HTTPS was auto-prefixed
    urls_to_try = [url]
    has_explicit_https = target_url_input.strip().lower().startswith("https://")
    if not has_explicit_https and url.lower().startswith("https://"):
        urls_to_try.append("http://" + url[8:])

    last_conn_error = None
    request_succeeded = False

    for attempt_url in urls_to_try:
        try:
            req = urllib.request.Request(attempt_url, headers=request_headers)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            opener = urllib.request.build_opener(
                SafeRedirectHandler(),
                urllib.request.HTTPSHandler(context=ctx)
            )
            with opener.open(req, timeout=5.0) as response:
                http_status_code = response.status
                for key, val in response.headers.items():
                    headers_dict[key] = val
                raw_cookies = response.headers.get_all("Set-Cookie") or []
            request_succeeded = True
            url = attempt_url
            break
        except urllib.error.HTTPError as e:
            http_status_code = e.code
            for key, val in e.headers.items():
                headers_dict[key] = val
            raw_cookies = e.headers.get_all("Set-Cookie") or []
            request_succeeded = True
            url = attempt_url
            break
        except ValueError as e:
            raise ValueError(f"Security validation error: {str(e)}")
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            last_conn_error = e
            continue
        except Exception as e:
            last_conn_error = e
            continue

    if not request_succeeded:
        if is_ip_target:
            # For IP targets without an HTTP daemon on port 80/443, do not crash.
            # Proceed with port checks, GeoIP, PTR, and score calculation.
            http_status_code = None
        else:
            reason = getattr(last_conn_error, 'reason', str(last_conn_error)) if last_conn_error else "Connection failed"
            raise ConnectionError(f"Unable to connect to target website ({reason}). Please verify the domain and ensure the server is online.")

    # Step 4: Perform real-time security checks & network geolocation
    https_result = check_https(url, hostname)
    headers_result = check_headers(headers_dict)
    cookies_result = check_cookies(raw_cookies)
    server_result = check_server_info(headers_dict)
    ports_result = check_ports(resolved_ip)
    geo_result = get_ip_geolocation(resolved_ip)

    # Step 5: Dynamic score & recommendations
    score, risk_level, badge_color = calculate_score(
        https_result, headers_result, cookies_result, server_result, ports_result
    )
    recommendations = generate_recommendations(
        https_result, headers_result, cookies_result, server_result, ports_result
    )

    # Step 6: Scan completion timestamp & duration
    end_time_dt = datetime.now()
    duration_seconds = round(time.perf_counter() - start_perf, 2)

    scan_date_str = start_time_dt.strftime("%d %B %Y")
    scan_time_str = start_time_dt.strftime("%I:%M:%S %p")

    result_payload = {
        "target_url": url,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "is_ip": is_ip_target,
        "reverse_dns": reverse_dns,
        "geo": geo_result,
        "http_status": http_status_code,
        "scan_date": scan_date_str,
        "scan_time": scan_time_str,
        "scan_timestamp": start_time_dt.isoformat(),
        "scan_duration": f"{duration_seconds}s",
        "duration_seconds": duration_seconds,
        "score": score,
        "risk_level": risk_level,
        "badge_color": badge_color,
        "checks": {
            "https": https_result,
            "headers": headers_result,
            "cookies": cookies_result,
            "server": server_result,
            "ports": ports_result
        },
        "recommendations": recommendations
    }

    # Step 7: Store scan in SQLite database
    try:
        from database import save_scan
        scan_id = save_scan(result_payload)
        result_payload["id"] = scan_id
    except Exception as db_err:
        print(f"Database save notice: {db_err}", file=sys.stderr)
        result_payload["id"] = 1

    # Also keep JSON history for backwards compatibility
    save_to_history(result_payload)

    return result_payload


def save_to_history(scan_result):
    """
    Appends the scan summary to scan_history.json
    """
    try:
        history = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                try:
                    history = json.load(f)
                except Exception:
                    history = []

        summary_entry = {
            "target_url": scan_result["target_url"],
            "hostname": scan_result["hostname"],
            "resolved_ip": scan_result.get("resolved_ip", ""),
            "is_ip": scan_result.get("is_ip", False),
            "reverse_dns": scan_result.get("reverse_dns"),
            "geo": scan_result.get("geo", {}),
            "score": scan_result["score"],
            "risk_level": scan_result["risk_level"],
            "badge_color": scan_result["badge_color"],
            "scan_date": scan_result["scan_date"],
            "scan_time": scan_result["scan_time"],
            "scan_duration": scan_result["scan_duration"]
        }

        # Keep latest 25 scans, prepending newest first
        history = [summary_entry] + [h for h in history if h.get("target_url") != summary_entry["target_url"]][:24]

        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        # Don't let disk write errors fail the scan
        print(f"Warning: Could not save scan history: {e}", file=sys.stderr)


def get_history():
    """
    Reads and returns scan history entries.
    """
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    try:
        res = scan_target(target)
        print(json.dumps(res, indent=2))
    except Exception as err:
        print(json.dumps({"error": str(err)}))
        sys.exit(1)
