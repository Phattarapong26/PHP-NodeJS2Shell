"""
Report Routes Blueprint
Handles TLP:AMBER Security Advisory generation, server-side PDF exports, and HTML preview.
"""

import hashlib
import io
import json
import os
import zipfile
from datetime import datetime
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
        return jsonify({
            "error": f"ไม่สามารถสร้าง PDF ผ่าน Chromium ได้ ({e})",
            "hint": "กรุณาเปิดหน้าพรีวิวที่ /api/report/preview แล้วกดปุ่มพิมพ์ / บันทึกเป็น PDF ผ่านเบราว์เซอร์"
        }), 500


@report_bp.route("/api/report/bundle", methods=["GET", "POST"])
def export_evidence_bundle():
    """
    Exports a tamper-evident Forensic Evidence Bundle (.ZIP) containing:
    1. audit_manifest.json (Scan metadata & operator info)
    2. audit_transcripts.json (Raw HTTP requests/responses & SHA-256 evidence digests)
    3. preconditions_matrix.json (Brotli, HTTP/3, NGINX alias, and baseline hashes)
    4. cve_findings_ledger.json (Structured CVE entries with tri-state verification status)
    5. SHA256SUMS.txt (Cryptographic integrity ledger for forensic verification)
    6. Executive_Report (PDF or HTML)
    """
    data = request.get_json(silent=True) if request.method == "POST" else None
    if not data:
        data = get_current_report_data()

    ts_str = datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")
    zip_buf = io.BytesIO()
    files_to_hash = {}

    # Extract target host
    host_summary = data.get("host_summary", {})
    target_ip = host_summary.get("target_ip", "target")
    sanitized_host = str(target_ip).replace(":", "_").replace("/", "_")

    # 1. Manifest
    manifest = {
        "generator": "ThaiCERT-OPScaner 2.0 (Precision Security Audit & Verification Engine)",
        "generated_at_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target_ip,
        "operator": data.get("meta", {}).get("operator", "security-auditor"),
        "overall_status": data.get("executive_summary", {}).get("overall_risk", "Unknown"),
        "evidence_bundle_version": "1.0-FORENSIC-COMPLIANT"
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    files_to_hash["audit_manifest.json"] = manifest_bytes

    # 2. Transcripts & SHA-256 digests
    transcripts = []
    preconditions = []
    cve_ledger = []

    for host_node in data.get("deep_findings", []):
        for port_node in host_node.get("ports", []):
            p_audit = port_node.get("deep_audit", {})
            rce_data = p_audit.get("rce_proof") or port_node.get("rce_proof") or {}
            if rce_data.get("audit_trail"):
                transcripts.append({
                    "port": port_node.get("port"),
                    "technique": rce_data.get("technique"),
                    "proof_status": rce_data.get("proof_status"),
                    "audit_trail": rce_data.get("audit_trail")
                })

            # Preconditions
            preconditions.append({
                "port": port_node.get("port"),
                "runtime": port_node.get("runtime"),
                "brotli_preconditions": p_audit.get("brotli_preconditions", {}),
                "nginx_preconditions": p_audit.get("nginx_preconditions", {}),
                "lfi_prerequisite": p_audit.get("lfi_prerequisite", {})
            })

            # CVEs
            for cve in port_node.get("matched_cves", []):
                cve_ledger.append({
                    "port": port_node.get("port"),
                    "cve": cve.get("cve"),
                    "name": cve.get("name"),
                    "severity": cve.get("severity"),
                    "verification_status": cve.get("verification_status", "SUSPECTED_RISK"),
                    "reason": cve.get("reason"),
                    "host_check": cve.get("host_check")
                })

    files_to_hash["audit_transcripts.json"] = json.dumps(transcripts, indent=2, ensure_ascii=False).encode("utf-8")
    files_to_hash["preconditions_matrix.json"] = json.dumps(preconditions, indent=2, ensure_ascii=False).encode("utf-8")
    files_to_hash["cve_findings_ledger.json"] = json.dumps(cve_ledger, indent=2, ensure_ascii=False).encode("utf-8")

    # 3. Report file (PDF if available, otherwise HTML preview)
    try:
        pdf_bytes, _ = generate_amber_pdf(data)
        files_to_hash[f"ThaiCERT_Audit_Report_{sanitized_host}.pdf"] = pdf_bytes
    except Exception:
        html_content = build_amber_advisory_html(data)
        files_to_hash[f"ThaiCERT_Audit_Report_{sanitized_host}.html"] = html_content.encode("utf-8")

    # 4. Compute SHA256SUMS.txt
    checksum_lines = []
    for fname, fbytes in sorted(files_to_hash.items()):
        fhash = hashlib.sha256(fbytes).hexdigest()
        checksum_lines.append(f"{fhash}  {fname}")
    checksum_bytes = ("\n".join(checksum_lines) + "\n").encode("utf-8")

    # Write ZIP
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, fbytes in files_to_hash.items():
            zf.writestr(fname, fbytes)
        zf.writestr("SHA256SUMS.txt", checksum_bytes)

    zip_bytes = zip_buf.getvalue()
    bundle_filename = f"ThaiCERT_Evidence_Bundle_{sanitized_host}_{ts_str}.zip"

    return Response(
        zip_bytes,
        mimetype="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{bundle_filename}"',
            "Content-Length": str(len(zip_bytes)),
            "Cache-Control": "no-cache, no-store, must-revalidate"
        }
    )

