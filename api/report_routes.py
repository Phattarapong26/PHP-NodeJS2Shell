"""
Report Routes Blueprint
Handles TLP:AMBER Security Advisory generation, server-side PDF exports, and HTML preview.
"""

import json
import os
from flask import Blueprint, request, Response, jsonify
from reports.amber_builder import build_amber_advisory_html
from reports.pdf_engine import generate_amber_pdf

report_bp = Blueprint("reports", __name__)

# Persistent storage of last scan result for reliable report export across server restarts
_LAST_SCAN_RESULT = None
_SCAN_STORAGE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "last_scan.json")


def set_last_scan_result(data: dict):
    global _LAST_SCAN_RESULT
    _LAST_SCAN_RESULT = data
    try:
        os.makedirs(os.path.dirname(_SCAN_STORAGE_PATH), exist_ok=True)
        with open(_SCAN_STORAGE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def get_current_report_data() -> dict:
    global _LAST_SCAN_RESULT
    if _LAST_SCAN_RESULT and isinstance(_LAST_SCAN_RESULT, dict):
        return _LAST_SCAN_RESULT
    if os.path.exists(_SCAN_STORAGE_PATH):
        try:
            with open(_SCAN_STORAGE_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    _LAST_SCAN_RESULT = loaded
                    return loaded
        except Exception:
            pass
    return {
        "target": "เครือข่ายปัจจุบัน (ยังไม่มีผลการตรวจประเมิน)",
        "total_hosts": 0,
        "hosts": [],
        "thaicert_summary": {
            "critical_hosts": 0,
            "high_hosts": 0,
            "warning_hosts": 0,
            "secure_hosts": 0
        }
    }


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
