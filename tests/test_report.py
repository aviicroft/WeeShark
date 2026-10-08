"""
Unit Tests for WeeShark PDF and Text Report Generation (report.py)
"""

import pytest
import sys
import os
import io

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'webguard')))

from report import generate_pdf_report


@pytest.fixture
def mock_scan():
    return {
        "id": 42,
        "target_url": "https://secure-target.org",
        "hostname": "secure-target.org",
        "resolved_ip": "104.21.5.12",
        "http_status": 200,
        "scan_date": "08 October 2026",
        "scan_time": "10:15:00 PM",
        "scan_duration": "1.10s",
        "score": 92,
        "risk_level": "EXCELLENT",
        "badge_color": "emerald",
        "checks": {
            "https": {
                "status": "PASS",
                "tls_version": "TLSv1.3",
                "issuer": "Let's Encrypt",
                "message": "Enforced TLS"
            },
            "headers": [
                {
                    "header": "Content-Security-Policy",
                    "status": "Present",
                    "recommendation": "CSP is active."
                }
            ],
            "cookies": {
                "status": "PASS",
                "message": "All cookies have Secure/HttpOnly."
            },
            "server": {
                "status": "PASS",
                "exposed_details": "None"
            },
            "ports": [
                {"port": 80, "service": "HTTP", "status": "Open"},
                {"port": 443, "service": "HTTPS", "status": "Open"}
            ]
        },
        "recommendations": [
            {
                "category": "Security Posture",
                "issue": "Standard baseline verified",
                "recommendation": "Maintain periodic scanning."
            }
        ]
    }


def test_generate_pdf_report_structure(mock_scan):
    buffer, filename, mimetype = generate_pdf_report(mock_scan)
    assert filename.startswith("WeeShark-Report-secure-target.org")
    assert filename.endswith(".pdf")
    assert mimetype == "application/pdf"

    pdf_bytes = buffer.getvalue()
    assert len(pdf_bytes) > 500
    # PDF magic bytes
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_pdf_fallback_text(monkeypatch, mock_scan):
    # Simulate environment where reportlab is unavailable
    import builtins
    orig_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "reportlab" in name:
            raise ImportError("Mocked missing reportlab")
        return orig_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    buffer, filename, mimetype = generate_pdf_report(mock_scan)
    assert filename.endswith(".txt")
    assert mimetype == "text/plain"

    content = buffer.getvalue().decode("utf-8")
    assert "WEESHARK" in content
    assert "secure-target.org" in content
    assert "92 / 100" in content

