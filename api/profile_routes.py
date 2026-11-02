"""
OPScaner - Profile & System Update REST API Blueprint
Provides endpoints for SQLite scan profiles and Git update mechanisms.
"""

from flask import Blueprint, request, jsonify
from core.profile_db import (
    get_all_profiles,
    get_profile_by_id,
    get_active_profile,
    create_profile,
    update_profile,
    delete_profile,
    set_active_profile
)
from core.update_checker import (
    check_for_updates,
    get_cached_update_status,
    apply_update
)

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
    """Creates a new scan profile."""
    data = request.json or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"status": "error", "message": "กรุณาระบุชื่อ Profile"}), 400

    description = data.get("description", "").strip()
    network_target = data.get("network_target", "").strip()
    set_active = bool(data.get("set_active", True))

    try:
        new_prof = create_profile(
            title=title,
            description=description,
            network_target=network_target,
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
    """Retrieves a single profile by ID."""
    prof = get_profile_by_id(profile_id)
    if not prof:
        return jsonify({"status": "error", "message": "ไม่พบ Profile ที่ระบุ"}), 404
    return jsonify({"status": "ok", "profile": prof})


@profile_bp.route("/api/profiles/<int:profile_id>", methods=["PUT"])
def edit_profile(profile_id: int):
    """Updates an existing profile."""
    data = request.json or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"status": "error", "message": "กรุณาระบุชื่อ Profile"}), 400

    description = data.get("description", "").strip()
    network_target = data.get("network_target", "").strip()

    try:
        updated = update_profile(
            profile_id=profile_id,
            title=title,
            description=description,
            network_target=network_target
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
