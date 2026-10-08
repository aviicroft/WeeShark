"""
WeeShark - SQLite Database Layer (database.py)
Stores real-time scan results, metadata, security checks, and recommendations.
"""

import sqlite3
import json
import os
import sys
from datetime import datetime

_CURR_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURR_DIR not in sys.path:
    sys.path.insert(0, _CURR_DIR)

DB_PATH = os.path.join(os.path.dirname(__file__), "webguard.db")


def get_db_connection():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the SQLite schema if it does not already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
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
            geo_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migrations: check for optional columns
    cursor.execute("PRAGMA table_info(scans)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "geo_json" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN geo_json TEXT")
    if "reverse_dns" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN reverse_dns TEXT")
    if "is_ip" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN is_ip INTEGER DEFAULT 0")
    conn.commit()
    conn.close()


def save_scan(scan_data):
    """
    Inserts a newly completed real-time scan into SQLite.
    Returns: newly generated integer scan ID.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    checks = scan_data.get("checks", {})
    recs = scan_data.get("recommendations", [])
    geo = scan_data.get("geo", {})

    # Calculate issues count (failed/warning checks)
    issues_count = len(recs)

    cursor.execute("""
        INSERT INTO scans (
            target_url, hostname, resolved_ip, http_status,
            scan_date, scan_time, scan_timestamp, scan_duration, duration_seconds,
            score, risk_level, badge_color, issues_count,
            checks_json, recommendations_json, geo_json, reverse_dns, is_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data.get("target_url"),
        scan_data.get("hostname"),
        scan_data.get("resolved_ip"),
        scan_data.get("http_status"),
        scan_data.get("scan_date"),
        scan_data.get("scan_time"),
        scan_data.get("scan_timestamp"),
        scan_data.get("scan_duration"),
        scan_data.get("duration_seconds", 0.0),
        scan_data.get("score", 0),
        scan_data.get("risk_level", "MEDIUM"),
        scan_data.get("badge_color", "amber"),
        issues_count,
        json.dumps(checks),
        json.dumps(recs),
        json.dumps(geo),
        scan_data.get("reverse_dns"),
        1 if scan_data.get("is_ip") else 0
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def row_to_dict(row):
    """Converts a SQLite row into a hydrated scan dictionary."""
    if not row:
        return None
    d = dict(row)
    try:
        d["checks"] = json.loads(d.get("checks_json", "{}")) or {}
    except Exception:
        d["checks"] = {}
    try:
        d["recommendations"] = json.loads(d.get("recommendations_json", "[]")) or []
    except Exception:
        d["recommendations"] = []
    try:
        d["geo"] = json.loads(d.get("geo_json") or "{}") or {}
    except Exception:
        d["geo"] = {}
    d["reverse_dns"] = d.get("reverse_dns")
    d["is_ip"] = bool(d.get("is_ip", 0))
    return d


def get_scan_by_id(scan_id):
    """Retrieves a single scan by ID."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)


def get_latest_scan():
    """Retrieves the most recent scan record."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row_to_dict(row)


def get_all_scans(limit=50):
    """Retrieves list of previous scans for history and reports."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


def get_dashboard_stats():
    """Computes summary metrics for the main Dashboard page."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = cursor.fetchone()["total"]

    latest = get_latest_scan()
    recent = get_all_scans(limit=6)

    conn.close()

    return {
        "total_scans": total_scans,
        "latest_scan": latest,
        "recent_scans": recent
    }


# Ensure DB is initialized when module is loaded
init_db()
