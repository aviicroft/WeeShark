"""
WeeShark - Multi-Page Flask Application (app.py)

Routes:
1.  GET /                      -> Dashboard (Overview metrics, recent scans, quick links)
2.  GET, POST /scan            -> New Scan (URL input, progress, live execution)
3.  GET /results/<scan_id>     -> Detailed Scan Results (Overall scores & check cards)
4.  GET /headers/<scan_id>     -> Dedicated Security Headers Page
5.  GET /cookies/<scan_id>     -> Dedicated Cookie Security Page
6.  GET /ports/<scan_id>       -> Dedicated Port Analysis Page
7.  GET /server-info/<scan_id> -> Dedicated Server Information Page
8.  GET /history               -> Scan History Page (from SQLite)
9.  GET /reports               -> Reports Page (Download PDF & View actions)
10. GET /download-pdf/<scan_id>-> Dynamic PDF Report Download
"""

import os
import sys

_CURR_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURR_DIR not in sys.path:
    sys.path.insert(0, _CURR_DIR)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from scanner import scan_target
from database import get_scan_by_id, get_latest_scan, get_all_scans, get_dashboard_stats
from report import generate_pdf_report

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "weeshark-multipage-key-2026")


@app.context_processor
def inject_global_data():
    """Provides current/latest scan to base layout navigation links."""
    latest = get_latest_scan()
    return {
        "latest_scan_id": latest["id"] if latest else 1,
        "has_scans": latest is not None,
        "mapbox_token": os.environ.get("VITE_MAPBOX_TOKEN", "").strip() or os.environ.get("MAPBOX_TOKEN", "").strip()
    }


# 1. Dashboard Page
@app.route("/")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


# 2. New Scan Page
@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        if not target_url:
            flash("Please enter a valid website URL to begin scanning.", "error")
            return redirect(url_for("scan"))

        try:
            # Perform live real-time scan (which saves to SQLite)
            scan_result = scan_target(target_url)
            scan_id = scan_result.get("id", 1)
            flash(f"Live security scan completed successfully for {scan_result['hostname']}.", "success")
            return redirect(url_for("results", scan_id=scan_id))
        except Exception as e:
            flash(f"Scan failed: {str(e)}", "error")
            return redirect(url_for("scan"))

    return render_template("scan.html")


# 3. Scan Results Page
@app.route("/results/<int:scan_id>")
def results(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        flash("Requested scan record could not be found.", "error")
        return redirect(url_for("dashboard"))
    return render_template("results.html", scan=scan_data)


# 4. Security Headers Page
@app.route("/headers/<int:scan_id>")
def headers(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        scan_data = get_latest_scan()
    if not scan_data:
        flash("No active scan records available. Please run a scan first.", "info")
        return redirect(url_for("scan"))
    return render_template("headers.html", scan=scan_data)


# 5. Cookie Security Page
@app.route("/cookies/<int:scan_id>")
def cookies(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        scan_data = get_latest_scan()
    if not scan_data:
        flash("No active scan records available. Please run a scan first.", "info")
        return redirect(url_for("scan"))
    return render_template("cookies.html", scan=scan_data)


# 6. Port Analysis Page
@app.route("/ports/<int:scan_id>")
def ports(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        scan_data = get_latest_scan()
    if not scan_data:
        flash("No active scan records available. Please run a scan first.", "info")
        return redirect(url_for("scan"))
    return render_template("ports.html", scan=scan_data)


# 7. Server Information Page
@app.route("/server-info/<int:scan_id>")
def server_info(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        scan_data = get_latest_scan()
    if not scan_data:
        flash("No active scan records available. Please run a scan first.", "info")
        return redirect(url_for("scan"))
    return render_template("server_info.html", scan=scan_data)


# 8. Scan History Page
@app.route("/history")
def history():
    scans = get_all_scans(limit=100)
    return render_template("history.html", scans=scans)


# 9. Reports Page
@app.route("/reports")
def reports():
    scans = get_all_scans(limit=100)
    return render_template("reports.html", scans=scans)


# 10. Dynamic PDF Download
@app.route("/download-pdf/<int:scan_id>")
def download_pdf(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        flash("Requested scan record not found for PDF generation.", "error")
        return redirect(url_for("reports"))

    buffer, filename, mimetype = generate_pdf_report(scan_data)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype=mimetype
    )


# API endpoints for programmatic / JSON access
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url") or request.form.get("url")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    try:
        res = scan_target(url)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(get_all_scans(limit=25))


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    return jsonify(get_dashboard_stats())


if __name__ == "__main__":
    print("WeeShark Multi-Page Dashboard running on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
