"""
Integration Tests for WebGuard Multi-Page Flask Application (app.py)
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'webguard')))

from app import app
import database


@pytest.fixture
def client(monkeypatch, tmp_path):
    """Provides Flask test client with isolated SQLite database."""
    db_file = str(tmp_path / "flask_test.db")
    monkeypatch.setattr(database, "DB_PATH", db_file)
    database.init_db()

    # Pre-populate 1 scan
    database.save_scan({
        "target_url": "https://flask-test.org",
        "hostname": "flask-test.org",
        "resolved_ip": "1.1.1.1",
        "http_status": 200,
        "scan_date": "08 October 2026",
        "scan_time": "10:30:00 PM",
        "scan_timestamp": "2026-10-08T22:30:00",
        "scan_duration": "1.0s",
        "duration_seconds": 1.0,
        "score": 90,
        "risk_level": "EXCELLENT",
        "badge_color": "emerald",
        "checks": {
            "https": {"status": "PASS", "tls_version": "TLSv1.3", "issuer": "Cloudflare", "message": "OK"},
            "headers": [{"header": "X-Frame-Options", "status": "Present", "value": "DENY", "rating": "PASS", "recommendation": "OK"}],
            "cookies": {"count": 0, "has_cookies": False, "status": "PASS", "message": "OK", "cookies": []},
            "server": {"status": "PASS", "server": "cloudflare", "exposed_details": "None"},
            "ports": [{"port": 443, "service": "HTTPS", "status": "Open", "is_risk": False}]
        },
        "recommendations": []
    })

    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_dashboard_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"WEBGUARD" in res.data
    assert b"Security Dashboard" in res.data


def test_scan_page_get(client):
    res = client.get("/scan")
    assert res.status_code == 200
    assert b"New Security Audit" in res.data or b"Scan" in res.data


def test_scan_post_empty_url_redirects(client):
    res = client.post("/scan", data={"target_url": ""}, follow_redirects=True)
    assert res.status_code == 200
    assert b"Please enter a valid website URL" in res.data


def test_results_route(client):
    res = client.get("/results/1")
    assert res.status_code == 200
    assert b"flask-test.org" in res.data
    assert b"EXCELLENT" in res.data


def test_results_not_found_redirects(client):
    res = client.get("/results/999", follow_redirects=True)
    assert res.status_code == 200
    assert b"Requested scan record could not be found" in res.data


def test_deep_dive_pages(client):
    for route in ["/headers/1", "/cookies/1", "/ports/1", "/server-info/1"]:
        res = client.get(route)
        assert res.status_code == 200
        assert b"flask-test.org" in res.data


def test_history_and_reports_pages(client):
    res_hist = client.get("/history")
    assert res_hist.status_code == 200
    assert b"flask-test.org" in res_hist.data

    res_rep = client.get("/reports")
    assert res_rep.status_code == 200
    assert b"flask-test.org" in res_rep.data


def test_download_pdf_route(client):
    res = client.get("/download-pdf/1")
    assert res.status_code == 200
    assert res.headers.get("Content-Type") in ("application/pdf", "text/plain")
    assert len(res.data) > 100


def test_flask_json_api_dashboard(client):
    res = client.get("/api/dashboard")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_scans"] == 1
    assert data["latest_scan"]["hostname"] == "flask-test.org"


def test_flask_json_api_history(client):
    res = client.get("/api/history")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) == 1


def test_flask_json_api_scan_validation(client):
    res = client.post("/api/scan", json={"url": ""})
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data

    res_ssrf = client.post("/api/scan", json={"url": "http://127.0.0.1"})
    assert res_ssrf.status_code == 400
    data_ssrf = res_ssrf.get_json()
    assert "error" in data_ssrf
    assert "SSRF" in data_ssrf["error"]

