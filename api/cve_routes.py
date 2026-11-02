"""
OPScaner - CVE & Dynamic Payload Rules REST API Blueprint
Provides endpoints for managing standard JSON/YAML vulnerability detection rules (ภาษากลาง),
importing/exporting rulesets, and conducting on-demand rule tests.
"""

import asyncio
from flask import Blueprint, request, jsonify, Response
from core.profile_db import (
    get_all_cve_rules,
    get_cve_rule_by_id,
    save_cve_rule,
    delete_cve_rule,
    toggle_cve_rule,
    export_cve_rules_json,
    import_cve_rules_json
)
from audit.dynamic_rule_engine import test_single_rule

cve_bp = Blueprint("cve_api", __name__)


@cve_bp.route("/api/cve/rules", methods=["GET"])
def list_cve_rules():
    """Returns list of CVE rules, optionally filtered by target_type and enabled status."""
    target_type = request.args.get("target_type")
    enabled_only = request.args.get("enabled_only", "false").lower() in ("true", "1")
    rules = get_all_cve_rules(target_type=target_type, enabled_only=enabled_only)
    return jsonify({
        "status": "ok",
        "total": len(rules),
        "rules": rules
    })


@cve_bp.route("/api/cve/rules/<rule_id>", methods=["GET"])
def get_rule(rule_id):
    """Retrieves a single CVE rule."""
    rule = get_cve_rule_by_id(rule_id)
    if not rule:
        return jsonify({"status": "error", "message": f"Rule {rule_id} not found"}), 404
    return jsonify({"status": "ok", "rule": rule})


@cve_bp.route("/api/cve/rules", methods=["POST"])
def upsert_rule():
    """Creates or updates a CVE rule from JSON payload."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Expected JSON object body"}), 400
    try:
        saved = save_cve_rule(data)
        return jsonify({"status": "ok", "message": "Rule saved successfully", "rule": saved})
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@cve_bp.route("/api/cve/rules/<rule_id>", methods=["DELETE"])
def remove_rule(rule_id):
    """Deletes a CVE rule."""
    success = delete_cve_rule(rule_id)
    if not success:
        return jsonify({"status": "error", "message": f"Rule {rule_id} not found"}), 404
    return jsonify({"status": "ok", "message": f"Rule {rule_id} deleted successfully"})


@cve_bp.route("/api/cve/rules/<rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    """Enables or disables a CVE rule."""
    data = request.get_json(silent=True) or {}
    is_enabled = bool(data.get("is_enabled", True))
    success = toggle_cve_rule(rule_id, is_enabled)
    if not success:
        return jsonify({"status": "error", "message": f"Rule {rule_id} not found"}), 404
    return jsonify({
        "status": "ok",
        "message": f"Rule {rule_id} {'enabled' if is_enabled else 'disabled'}"
    })


@cve_bp.route("/api/cve/export", methods=["GET"])
def export_rules():
    """Exports all or enabled CVE rules in standard JSON format as a downloadable attachment."""
    enabled_only = request.args.get("enabled_only", "false").lower() in ("true", "1")
    bundle = export_cve_rules_json(enabled_only=enabled_only)
    import json
    return Response(
        json.dumps(bundle, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=opscaner_cve_rules.json"}
    )


@cve_bp.route("/api/cve/import", methods=["POST"])
def import_rules():
    """Imports CVE rules from a standard JSON payload."""
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400
    overwrite = request.args.get("overwrite", "true").lower() in ("true", "1")
    try:
        summary = import_cve_rules_json(data, overwrite=overwrite)
        return jsonify({"status": "ok", "summary": summary})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@cve_bp.route("/api/cve/test-rule", methods=["POST"])
def test_rule_endpoint():
    """Tests a dynamic rule specification against a target URL on demand."""
    data = request.get_json(silent=True) or {}
    rule = data.get("rule")
    target_url = data.get("target_url")
    if not rule or not isinstance(rule, dict):
        return jsonify({"status": "error", "message": "Missing 'rule' dict in request body"}), 400
    if not target_url or not isinstance(target_url, str):
        return jsonify({"status": "error", "message": "Missing 'target_url' in request body"}), 400
    
    try:
        result = asyncio.run(test_single_rule(rule, target_url))
        return jsonify({"status": "ok", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
