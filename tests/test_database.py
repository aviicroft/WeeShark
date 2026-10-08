"""
Unit Tests for WeeShark Database Layer (database.py)
"""

import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'webguard')))

import database


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Provides a fresh isolated SQLite database file for each test."""
    db_file = str(tmp_path / "test_webguard.db")
    monkeypatch.setattr(database, "DB_PATH", db_file)
    database.init_db()
    return db_file


@pytest.fixture
def sample_scan():
    return {
        "target_url": "https://audit-target.com",
        "hostname": "audit-target.com",
        "resolved_ip": "93.184.216.34",
        "http_status": 200,
        "scan_date": "08 October 2026",
        "scan_time": "10:00:00 PM",
        "scan_timestamp": "2026-10-08T22:00:00",
        "scan_duration": "1.25s",
        "duration_seconds": 1.25,
        "score": 85,
        "risk_level": "GOOD",
        "badge_color": "cyan",
        "checks": {
            "https": {"status": "PASS", "tls_version": "TLSv1.3", "issuer": "DigiCert"},
            "headers": [{"header": "X-Frame-Options", "status": "Present", "rating": "PASS"}],
            "cookies": {"count": 0, "has_cookies": False, "status": "PASS"},
            "server": {"status": "PASS", "server": "nginx"},
            "ports": [{"port": 443, "status": "Open", "is_risk": False}]
        },
        "recommendations": [
            {
                "category": "HTTP Security Headers",
                "issue": "Content-Security-Policy header is not configured.",
                "recommendation": "Configure CSP to prevent XSS."
            }
        ]
    }


def test_init_db_creates_table(temp_db):
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
    table = cursor.fetchone()
    conn.close()
    assert table is not None
    assert table["name"] == "scans"


def test_save_scan_and_get_by_id(temp_db, sample_scan):
    scan_id = database.save_scan(sample_scan)
    assert isinstance(scan_id, int)
    assert scan_id > 0

    record = database.get_scan_by_id(scan_id)
    assert record is not None
    assert record["id"] == scan_id
    assert record["hostname"] == "audit-target.com"
    assert record["score"] == 85
    assert record["risk_level"] == "GOOD"
    assert record["issues_count"] == 1  # 1 recommendation

    # Verify JSON hydration
    assert isinstance(record["checks"], dict)
    assert record["checks"]["https"]["status"] == "PASS"
    assert isinstance(record["recommendations"], list)
    assert len(record["recommendations"]) == 1


def test_get_latest_scan(temp_db, sample_scan):
    assert database.get_latest_scan() is None

    id1 = database.save_scan(sample_scan)
    sample_scan_2 = dict(sample_scan)
    sample_scan_2["hostname"] = "second-target.com"
    id2 = database.save_scan(sample_scan_2)

    latest = database.get_latest_scan()
    assert latest is not None
    assert latest["id"] == id2
    assert latest["hostname"] == "second-target.com"


def test_get_all_scans_with_limit(temp_db, sample_scan):
    for i in range(5):
        s = dict(sample_scan)
        s["hostname"] = f"target-{i}.com"
        database.save_scan(s)

    all_scans = database.get_all_scans(limit=3)
    assert len(all_scans) == 3
    # Ordered DESC by id
    assert all_scans[0]["id"] > all_scans[1]["id"]


def test_get_dashboard_stats(temp_db, sample_scan):
    # Empty stats
    stats_empty = database.get_dashboard_stats()
    assert stats_empty["total_scans"] == 0
    assert stats_empty["latest_scan"] is None
    assert stats_empty["recent_scans"] == []

    # After saving scans
    database.save_scan(sample_scan)
    stats = database.get_dashboard_stats()
    assert stats["total_scans"] == 1
    assert stats["latest_scan"] is not None
    assert stats["latest_scan"]["hostname"] == "audit-target.com"
    assert len(stats["recent_scans"]) == 1

