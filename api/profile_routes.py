"""
OPScaner - Profile & System Update REST API Blueprint
Provides endpoints for SQLite scan profiles, detailed stealth headers, speed settings,
scan history auditing, and Git update mechanisms.
"""

import json
from flask import Blueprint, request, jsonify
from core.profile_db import (
    get_all_profiles,
    get_profile_by_id,
    get_active_profile,
    create_profile,
    update_profile,
    delete_profile,
    set_active_profile,
    add_scan_history,
    get_scan_history,
    get_scan_history_by_id,
    delete_scan_history
)
from core.update_checker import (
    check_for_updates,
    get_cached_update_status,
    apply_update
)
from api.report_routes import set_last_scan_result

profile_bp = Blueprint("profile_api", __name__)


# -------------------------------------------------------------
# Profile Management Endpoints
# -------------------------------------------------------------

@profile_bp.route("/api/profiles", methods=["GET"])
def list_profiles():
    """Lists all profiles and indicates the currently active profile."""
    profiles = get_all_profiles()
    active = get_active_profile()
    return jsonify({
        "status": "ok",
        "total": len(profiles),
        "profiles": profiles,
        "active_profile": active
    })


@profile_bp.route("/api/profiles", methods=["POST"])
def add_profile():
    """Creates a new scan profile with detailed enterprise configurations."""
    data = request.json or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"status": "error", "message": "กรุณาระบุชื่อ Profile"}), 400

    description = data.get("description", "").strip()
    network_target = data.get("network_target", "").strip()
    concurrency = int(data.get("concurrency", 100))
    timeout = float(data.get("timeout", 1.5))
    user_agent = data.get("user_agent", "").strip()
    custom_headers = data.get("custom_headers", "").strip()
    port_mode = data.get("port_mode", "standard").strip()
    custom_ports = data.get("custom_ports", "80, 443, 8080, 8000, 18080").strip()
    scope_preset = data.get("scope_preset", "all").strip()
    set_active = bool(data.get("set_active", True))

    try:
        new_prof = create_profile(
            title=title,
            description=description,
            network_target=network_target,
            concurrency=concurrency,
            timeout=timeout,
            user_agent=user_agent,
            custom_headers=custom_headers,
            port_mode=port_mode,
            custom_ports=custom_ports,
            scope_preset=scope_preset,
            set_active=set_active
        )
        return jsonify({
            "status": "ok",
            "message": "สร้าง Profile สำเร็จเรียบร้อย",
            "profile": new_prof
        }), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@profile_bp.route("/api/profiles/<int:profile_id>", methods=["GET"])
def get_single_profile(profile_id: int):
    """Retrieves a single profile by ID, along with its recent scan history."""
    prof = get_profile_by_id(profile_id)
    if not prof:
        return jsonify({"status": "error", "message": "ไม่พบ Profile ที่ระบุ"}), 404

    history = get_scan_history(profile_id=profile_id, limit=30)
    return jsonify({
        "status": "ok",
        "profile": prof,
        "history": history
    })


@profile_bp.route("/api/profiles/<int:profile_id>", methods=["PUT"])
def edit_profile(profile_id: int):
    """Updates an existing profile."""
    data = request.json or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"status": "error", "message": "กรุณาระบุชื่อ Profile"}), 400

    description = data.get("description", "")
    network_target = data.get("network_target", "")
    concurrency = data.get("concurrency")
    timeout = data.get("timeout")
    user_agent = data.get("user_agent")
    custom_headers = data.get("custom_headers")
    port_mode = data.get("port_mode")
    custom_ports = data.get("custom_ports")
    scope_preset = data.get("scope_preset")
    is_active = data.get("is_active")
    if is_active is None and "set_active" in data:
        is_active = 1 if data.get("set_active") else 0

    try:
        updated = update_profile(
            profile_id=profile_id,
            title=title,
            description=description,
            network_target=network_target,
            concurrency=concurrency,
            timeout=timeout,
            user_agent=user_agent,
            custom_headers=custom_headers,
            port_mode=port_mode,
            custom_ports=custom_ports,
            scope_preset=scope_preset,
            is_active=is_active
        )
        if not updated:
            return jsonify({"status": "error", "message": "ไม่พบ Profile ที่ต้องการแก้ไข"}), 404
        return jsonify({
            "status": "ok",
            "message": "อัปเดต Profile สำเร็จ",
            "profile": updated
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@profile_bp.route("/api/profiles/<int:profile_id>", methods=["DELETE"])
def remove_profile(profile_id: int):
    """Deletes a profile."""
    success = delete_profile(profile_id)
    if not success:
        return jsonify({"status": "error", "message": "ไม่พบ Profile ที่ต้องการลบ"}), 404
    return jsonify({"status": "ok", "message": "ลบ Profile สำเร็จ"})


@profile_bp.route("/api/profiles/<int:profile_id>/select", methods=["POST"])
def select_profile(profile_id: int):
    """Sets a profile as active."""
    activated = set_active_profile(profile_id)
    if not activated:
        return jsonify({"status": "error", "message": "ไม่พบ Profile ที่ต้องการเลือก"}), 404
    return jsonify({
        "status": "ok",
        "message": f"เลือกใช้งาน Profile: {activated['title']}",
        "active_profile": activated
    })


@profile_bp.route("/api/profiles/<int:profile_id>/history", methods=["GET"])
def profile_history(profile_id: int):
    """Returns past scan history conducted under this profile."""
    limit = int(request.args.get("limit", 50))
    history = get_scan_history(profile_id=profile_id, limit=limit)
    return jsonify({
        "status": "ok",
        "profile_id": profile_id,
        "history": history
    })


# -------------------------------------------------------------
# Scan History Inspection & Restoration
# -------------------------------------------------------------

@profile_bp.route("/api/scan-history/<int:history_id>", methods=["GET"])
def single_history(history_id: int):
    """Retrieves full details of a specific scan history item."""
    item = get_scan_history_by_id(history_id)
    if not item:
        return jsonify({"status": "error", "message": "ไม่พบประวัติการสแกน"}), 404

    # Parse stored result json
    results_obj = {}
    if item.get("scan_result_json"):
        try:
            results_obj = json.loads(item["scan_result_json"])
        except Exception:
            results_obj = {}

    return jsonify({
        "status": "ok",
        "history": item,
        "results": results_obj
    })


@profile_bp.route("/api/scan-history/<int:history_id>/restore", methods=["POST"])
def restore_history_result(history_id: int):
    """Restores a past scan into active session so the results modal displays it."""
    item = get_scan_history_by_id(history_id)
    if not item or not item.get("scan_result_json"):
        return jsonify({"status": "error", "message": "ไม่พบข้อมูลผลการสแกนในอดีต"}), 404

    try:
        data = json.loads(item["scan_result_json"])
        hosts_list = data.get("all_hosts", []) or data.get("hosts", [])
        # Set as last scan result for PDF export and UI view
        set_last_scan_result({
            "target": item["target_subnet"],
            "subnet": item["target_subnet"],
            "total_hosts": item["total_hosts"],
            "hosts": hosts_list,
            "elapsed_seconds": item["elapsed_seconds"],
            "scanned_hosts": item["total_hosts"],
            "profile": data.get("profile")
        })
        return jsonify({
            "status": "ok",
            "message": f"โหลดผลการสแกนย้อนหลังของวง {item['target_subnet']} เรียบร้อย",
            "scan_data": data,
            "history_record": item
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -------------------------------------------------------------
# System Update Endpoints
# -------------------------------------------------------------

@profile_bp.route("/api/system/check-update", methods=["GET"])
def check_update_route():
    """Checks for latest git commits on upstream repository."""
    force = request.args.get("force") == "1"
    if force:
        status = check_for_updates(force_refresh=True)
    else:
        status = get_cached_update_status()
    return jsonify({
        "status": "ok",
        "update_info": status
    })


@profile_bp.route("/api/system/apply-update", methods=["POST"])
def apply_update_route():
    """Applies git pull update."""
    result = apply_update()
    code = 200 if result.get("status") == "success" else 500
    return jsonify(result), code
