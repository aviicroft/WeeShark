"""
WeeShark - PDF Report Generator (report.py)
Creates real PDF documents dynamically from SQLite scan records.
"""

import io
import os


def generate_pdf_report(scan_data):
    """
    Generates a professional multi-section PDF security assessment report.
    Returns: BytesIO buffer containing the PDF bytes, and a filename.
    """
    filename = f"WeeShark-Report-{scan_data.get('hostname', 'scan')}-{scan_data.get('id', 'latest')}.pdf"

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors

        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter

        # --- COVER / HEADER BANNER ---
        c.setFillColor(colors.HexColor("#0B0F19"))
        c.rect(0, height - 100, width, 100, stroke=0, fill=1)

        c.setFillColor(colors.HexColor("#06B6D4"))
        c.setFont("Helvetica-Bold", 22)
        c.drawString(40, height - 45, "WEESHARK")

        c.setFillColor(colors.white)
        c.setFont("Helvetica", 11)
        c.drawString(40, height - 65, "Web Security Assessment & Vulnerability Audit Report")

        c.setFillColor(colors.HexColor("#94A3B8"))
        c.setFont("Helvetica", 8)
        c.drawString(40, height - 82, f"Report ID: #{scan_data.get('id', 1)} | Generated: {scan_data.get('scan_date')} at {scan_data.get('scan_time')}")

        y = height - 125

        # --- EXECUTIVE SUMMARY ---
        c.setFillColor(colors.HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 13)
        c.drawString(40, y, "1. Executive Summary & Target Details")
        y -= 16

        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor("#334155"))
        geo = scan_data.get("geo") or {}
        loc_parts = []
        if geo.get("city") and geo.get("city") != "Unknown":
            loc_parts.append(geo.get("city"))
        if geo.get("country") and geo.get("country") != "Unknown":
            loc_parts.append(geo.get("country"))
        location_str = ", ".join(loc_parts) if loc_parts else "N/A"
        isp_str = geo.get("isp") or "N/A"

        c.drawString(40, y, f"Target Website: {scan_data.get('target_url')}")
        c.drawString(330, y, f"Resolved IP Address: {scan_data.get('resolved_ip', 'N/A')}")
        y -= 14
        c.drawString(40, y, f"HTTP Status: {scan_data.get('http_status', 'N/A')}")
        c.drawString(330, y, f"Server Location: {location_str}")
        y -= 14
        c.drawString(40, y, f"Scan Execution Duration: {scan_data.get('scan_duration', 'N/A')}")
        c.drawString(330, y, f"Hosting ISP / Network: {isp_str[:28]}")
        y -= 25

        # Score & Risk Box
        score = scan_data.get("score", 0)
        risk = scan_data.get("risk_level", "MEDIUM")

        c.setFillColor(colors.HexColor("#F8FAFC"))
        c.setStrokeColor(colors.HexColor("#CBD5E1"))
        c.rect(40, y - 32, width - 80, 42, fill=1, stroke=1)

        c.setFillColor(colors.HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(55, y - 10, "ASSESSED SECURITY SCORE:")
        c.drawString(330, y - 10, "RISK LEVEL CLASSIFICATION:")

        c.setFont("Helvetica-Bold", 18)
        if score >= 90:
            c.setFillColor(colors.HexColor("#10B981"))
        elif score >= 75:
            c.setFillColor(colors.HexColor("#06B6D4"))
        elif score >= 50:
            c.setFillColor(colors.HexColor("#F59E0B"))
        else:
            c.setFillColor(colors.HexColor("#F43F5E"))

        c.drawString(55, y - 28, f"{score} / 100")
        c.drawString(330, y - 28, risk)

        y -= 55

        checks = scan_data.get("checks") or {}

        # --- SECTION 2: TRANSPORT ENCRYPTION ---
        c.setFillColor(colors.HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "2. HTTPS & Transport Layer Security")
        y -= 15

        https_check = checks.get("https") or {}
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(colors.HexColor("#1E293B"))
        c.drawString(45, y, f"Status: [{https_check.get('status', 'N/A')}]")
        y -= 12
        c.setFont("Helvetica", 8.5)
        c.setFillColor(colors.HexColor("#475569"))
        c.drawString(45, y, f"TLS Handshake: {https_check.get('tls_version', 'N/A')} | Certificate Issuer: {https_check.get('issuer', 'N/A')}")
        y -= 12
        c.drawString(45, y, f"Finding: {https_check.get('message', '')}")
        y -= 22

        # --- SECTION 3: HTTP RESPONSE SECURITY HEADERS ---
        c.setFillColor(colors.HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "3. HTTP Defense Response Headers")
        y -= 15

        headers = checks.get("headers") or []
        for h in headers:
            c.setFont("Helvetica-Bold", 8.5)
            c.setFillColor(colors.HexColor("#0F172A"))
            status_text = h.get("status")
            c.drawString(45, y, f"• {h.get('header')}: {status_text}")
            y -= 11
            c.setFont("Helvetica", 8)
            c.setFillColor(colors.HexColor("#64748B"))
            c.drawString(55, y, f"Recommendation: {h.get('recommendation')}")
            y -= 13

        y -= 8

        # --- SECTION 4: COOKIE & SERVER DISCLOSURE ---
        c.setFillColor(colors.HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "4. Cookie Flags & Server Disclosure")
        y -= 15

        cookies = checks.get("cookies") or {}
        c.setFont("Helvetica-Bold", 8.5)
        c.drawString(45, y, f"Cookie Security: [{cookies.get('status', 'PASS')}] - {cookies.get('message', '')}")
        y -= 14

        server = checks.get("server") or {}
        c.drawString(45, y, f"Server Banner Exposure: [{server.get('status', 'PASS')}]")
        y -= 11
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#64748B"))
        c.drawString(55, y, f"Observed Tokens: {server.get('exposed_details', 'None')}")
        y -= 20

        # --- SECTION 5: COMMON PORT SCAN ---
        c.setFillColor(colors.HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "5. Common Port Analysis (Passive Probe: 80, 443, 22, 21, 8080)")
        y -= 14

        ports = checks.get("ports") or []
        port_txt = " | ".join([f"Port {p.get('port')}: {p.get('status')}" for p in ports])
        c.setFont("Helvetica", 8.5)
        c.setFillColor(colors.HexColor("#334155"))
        c.drawString(45, y, port_txt)
        y -= 25

        # --- SECTION 6: ACTIONABLE RECOMMENDATIONS ---
        c.setFillColor(colors.HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "6. Key Remediation Recommendations")
        y -= 15

        recs = scan_data.get("recommendations", [])
        for rec in recs[:4]:
            c.setFont("Helvetica-Bold", 8)
            c.setFillColor(colors.HexColor("#0284C7"))
            c.drawString(45, y, f"[{rec.get('category')}] {rec.get('issue')}")
            y -= 10
            c.setFont("Helvetica", 7.5)
            c.setFillColor(colors.HexColor("#334155"))
            c.drawString(55, y, f"Remediation: {rec.get('recommendation')}")
            y -= 13

        # Footer Notice
        c.setStrokeColor(colors.HexColor("#E2E8F0"))
        c.line(40, 40, width - 40, 40)
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.HexColor("#94A3B8"))
        c.drawString(40, 28, "Authorized Use Notice: WeeShark is a passive security auditing tool. Conduct scans only on authorized assets.")
        c.drawRightString(width - 40, 28, "WeeShark Security Engine · 2026")

        c.showPage()
        c.save()
        buffer.seek(0)
        return buffer, filename, "application/pdf"

    except Exception:
        # Fallback to cleanly formatted text report if reportlab is not yet installed
        buffer = io.BytesIO()
        text_content = f"""===============================================================
WEESHARK - WEB SECURITY ASSESSMENT & VULNERABILITY AUDIT REPORT
===============================================================
Scan ID        : #{scan_data.get('id', 'N/A')}
Target URL     : {scan_data.get('target_url')}
Resolved IP    : {scan_data.get('resolved_ip')}
Scan Date      : {scan_data.get('scan_date')} at {scan_data.get('scan_time')}
Scan Duration  : {scan_data.get('scan_duration')}

SECURITY SCORE : {scan_data.get('score')} / 100
RISK LEVEL     : {scan_data.get('risk_level')}
===============================================================

1. HTTPS & TRANSPORT SECURITY:
Status: {scan_data.get('checks', {}).get('https', {}).get('status')}
Finding: {scan_data.get('checks', {}).get('https', {}).get('message')}

2. SECURITY HEADERS:
"""
        for h in scan_data.get('checks', {}).get('headers', []):
            text_content += f"- {h['header']}: {h['status']} | {h['recommendation']}\n"

        text_content += f"""
3. COOKIE SECURITY:
Status: {scan_data.get('checks', {}).get('cookies', {}).get('status')}
Detail: {scan_data.get('checks', {}).get('cookies', {}).get('message')}

4. SERVER INFORMATION DISCLOSURE:
Status: {scan_data.get('checks', {}).get('server', {}).get('status')}
Observed: {scan_data.get('checks', {}).get('server', {}).get('exposed_details')}

5. COMMON PORTS AUDIT:
"""
        for p in scan_data.get('checks', {}).get('ports', []):
            text_content += f"- Port {p['port']} ({p['service']}): {p['status']}\n"

        text_content += "\n6. RECOMMENDATIONS:\n"
        for rec in scan_data.get('recommendations', []):
            text_content += f"- [{rec['category']}] {rec['issue']}\n  Action: {rec['recommendation']}\n"

        text_content += "\nAuthorized Use Notice: Use WeeShark only on systems you own or have explicit permission to audit.\n"

        buffer.write(text_content.encode("utf-8"))
        buffer.seek(0)
        return buffer, f"WeeShark-Report-{scan_data.get('hostname')}.txt", "text/plain"
