"""
Test Target Mock Endpoints
Provides developer test routes (/test-lab/*) for verifying scanner detection
and CVE mapping across legacy PHP, patched PHP, vulnerable Node.js, and safe Node.js.
"""

from flask import Blueprint, jsonify

test_bp = Blueprint("test_lab", __name__)


@test_bp.route("/test-lab/php56")
def test_php56():
    resp = jsonify({"status": "ok", "app": "HR Portal Legacy", "php": "5.6.40"})
    resp.headers["X-Powered-By"] = "PHP/5.6.40"
    resp.headers["Server"] = "Apache/2.4.6 (CentOS) PHP/5.6.40"
    resp.set_cookie("PHPSESSID", "s83jd82hd82hd823jd82")
    return resp


@test_bp.route("/test-lab/php74")
def test_php74():
    resp = jsonify({"status": "ok", "app": "Intranet E-Document", "php": "7.4.33"})
    resp.headers["X-Powered-By"] = "PHP/7.4.33"
    resp.headers["Server"] = "nginx/1.18.0"
    resp.set_cookie("PHPSESSID", "k20d73h19dn28f73hs92")
    return resp


@test_bp.route("/test-lab/php83")
def test_php83():
    resp = jsonify({"status": "ok", "app": "Official ThaiCERT Portal", "php": "8.3.8"})
    resp.headers["X-Powered-By"] = "PHP/8.3.8"
    resp.headers["Server"] = "nginx/1.24.0"
    return resp


@test_bp.route("/test-lab/node20-vuln")
def test_node20_vuln():
    resp = jsonify({
        "status": "ok",
        "app": "Internal Node.js Microservice",
        "node": "v20.18.0",
        "framework": "Express 4.19",
        "brotli": True,
        "cve": "CVE-2026-111497 (Brotli decoder vulnerability / Node2Shell)",
        "eol": "24 Mar 2026"
    })
    resp.headers["X-Powered-By"] = "Express"
    resp.headers["X-Node-Version"] = "20.18.0"
    resp.headers["Content-Encoding"] = "br"
    resp.set_cookie("connect.sid", "s%3A839482938472.demo_session_token")
    return resp


@test_bp.route("/test-lab/node22-vuln")
def test_node22_vuln():
    resp = jsonify({
        "status": "ok",
        "app": "Modern Next.js SSR Portal",
        "node": "v22.12.0",
        "framework": "Next.js 14",
        "brotli": True,
        "cve": "CVE-2026-111497 (Node2Shell)"
    })
    resp.headers["X-Powered-By"] = "Next.js"
    resp.headers["X-Node-Version"] = "22.12.0"
    resp.headers["Content-Encoding"] = "br"
    return resp


@test_bp.route("/test-lab/node22-safe")
def test_node22_safe():
    resp = jsonify({
        "status": "ok",
        "app": "ThaiCERT Secure API",
        "node": "v22.23.4",
        "framework": "NestJS",
        "status_note": "Patched against Node2Shell"
    })
    resp.headers["X-Powered-By"] = "NestJS"
    resp.headers["X-Node-Version"] = "22.23.4"
    return resp


@test_bp.route("/test-lab/node24-safe")
def test_node24_safe():
    resp = jsonify({
        "status": "ok",
        "app": "Enterprise Data Hub",
        "node": "v24.22.1",
        "framework": "Express 5.0",
        "status_note": "Patched against Node2Shell"
    })
    resp.headers["X-Powered-By"] = "Express"
    resp.headers["X-Node-Version"] = "24.22.1"
    return resp
