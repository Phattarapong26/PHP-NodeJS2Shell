"""
Report Routes Blueprint
Handles TLP:AMBER Security Advisory generation, server-side PDF exports, and HTML preview.
"""

from flask import Blueprint, request, Response, jsonify
from reports.amber_builder import build_amber_advisory_html
from reports.pdf_engine import generate_amber_pdf

report_bp = Blueprint("reports", __name__)

# Sample fallback data if user triggers report before scanning
SAMPLE_DEMO_REPORT = {
    "target": "192.168.1.0/24 (เครือข่ายทดสอบภายใน)",
    "total_hosts": 3,
    "hosts": [
        {
            "ip": "192.168.1.10",
            "ports": [80, 443],
            "php": "8.1.12",
            "server": "nginx/1.26.2",
            "vulnerability": "Critical",
            "matched_cves": [
                {
                    "id": "CVE-2024-4577",
                    "cve": "CVE-2024-4577",
                    "name": "PHP CGI Argument Injection (php2shell)",
                    "category": "PHP",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "reason": "PHP (8.1.12) ต่ำกว่าเกณฑ์แพตช์ 8.2.20+ / 8.3.8+ เสี่ยงต่อ CVE-2024-4577",
                    "host_check": "php -v && (php -i | grep 'Server API')",
                    "confirm_vuln": "PHP < 8.2.20 / 8.3.8 บน Windows CGI/FastCGI",
                    "confirm_safe": "PHP ≥ 8.2.20 / 8.3.8 หรือรันบน Linux"
                },
                {
                    "id": "CVE-2026-15176",
                    "cve": "CVE-2026-15176",
                    "name": "NGINX Heap Buffer Overflow (alias + rewrite)",
                    "category": "NGINX",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "reason": "NGINX 1.26.2 อยู่ในช่วงเวอร์ชันที่ได้รับผลกระทบ",
                    "host_check": "nginx -T 2>/dev/null | grep -B5 -A15 'alias' || echo 'ไม่พบ alias (ปลอดภัย)'",
                    "confirm_vuln": "พบบล็อก location ที่มีทั้ง alias และ rewrite $request_filename บน NGINX < 1.30.6 / 1.31.7",
                    "confirm_safe": "ไม่พบ alias ร่วมกับ rewrite หรือ NGINX ≥ 1.30.6 / 1.31.7"
                }
            ],
            "deep_audit": {
                "primary_group": "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (WordPress / NGINX)",
                "nginx_audit": {"severity": "Critical"}
            }
        },
        {
            "ip": "192.168.1.25",
            "ports": [3000],
            "node": "v20.11.0",
            "server": "Node.js (Express)",
            "vulnerabilityNode": "Critical",
            "matched_cves": [
                {
                    "id": "CVE-2026-111497",
                    "cve": "CVE-2026-111497",
                    "name": "Node.js Brotli Out-of-bounds Write (Node2Shell RCE)",
                    "category": "Node.js",
                    "severity": "Critical",
                    "cvss": 9.2,
                    "reason": "Node.js (v20.11.0 EOL) เสี่ยงต่อ Node2Shell / CVE-2026-111497 (Brotli RCE)",
                    "host_check": "node -v",
                    "confirm_vuln": "Node.js < 22.23.4 / 24.22.1 / 26.12.1 หรือ EOL",
                    "confirm_safe": "Node.js ≥ 22.23.4 / 24.22.1 / 26.12.1"
                }
            ],
            "deep_audit": {
                "primary_group": "กลุ่ม 2: ระบบหลังบ้านแอปมือถือ และ API (Node.js REST API)"
            }
        },
        {
            "ip": "192.168.1.1",
            "ports": [80],
            "server": "MikroTik RouterOS",
            "vulnerability": "Secure",
            "matched_cves": [],
            "deep_audit": {
                "primary_group": "กลุ่ม 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Network Appliance / Router)"
            }
        }
    ]
}

# In-memory storage of last scan result for convenient 1-click GET /api/report/pdf
_LAST_SCAN_RESULT = None


def set_last_scan_result(data: dict):
    global _LAST_SCAN_RESULT
    _LAST_SCAN_RESULT = data


def get_current_report_data() -> dict:
    if _LAST_SCAN_RESULT and isinstance(_LAST_SCAN_RESULT, dict):
        return _LAST_SCAN_RESULT
    return SAMPLE_DEMO_REPORT


@report_bp.route("/api/report/preview", methods=["GET", "POST"])
def report_preview():
    """
    Renders A4 simulation HTML view for in-browser review or window.print().
    Accepts report JSON in POST body or uses last scan results for GET.
    """
    data = request.get_json(silent=True) if request.method == "POST" else None
    if not data:
        data = get_current_report_data()

    html_content = build_amber_advisory_html(data)
    return Response(html_content, mimetype="text/html; charset=utf-8")


@report_bp.route("/api/report/pdf", methods=["GET", "POST"])
def export_amber_pdf():
    """
    Directly exports and downloads official TLP:AMBER PDF with vector footers.
    Accepts report JSON in POST body or uses last scan results for GET.
    """
    data = request.get_json(silent=True) if request.method == "POST" else None
    if not data:
        data = get_current_report_data()

    try:
        pdf_bytes, filename = generate_amber_pdf(data)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
                "Cache-Control": "no-cache, no-store, must-revalidate",
            }
        )
    except Exception as e:
        # Fallback to returning HTML preview if chromium fails in host environment
        return jsonify({
            "error": f"ไม่สามารถสร้าง PDF ผ่าน Chromium ได้ ({e})",
            "hint": "กรุณาเปิดหน้าพรีวิวที่ /api/report/preview แล้วกดปุ่มพิมพ์ / บันทึกเป็น PDF ผ่านเบราว์เซอร์"
        }), 500
