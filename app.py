"""
OPScaner - Web Application Vulnerability Scanner & Network Auditor
Standardized according to ThaiCERT & NCSA Thailand Security Verification Guidelines.

Architecture & Directory Structure:
  ├── core/            # Network discovery, SemVer engine, and CVE database
  │   ├── semver.py
  │   ├── database.py
  │   └── network.py
  ├── audit/           # Deep security evaluators, session chains, and probes
  │   ├── php_audit.py
  │   ├── node_audit.py
  │   ├── nginx_audit.py
  │   ├── thaicert_rules.py
  │   └── probe_audit.py
  ├── reports/         # TLP:AMBER A4 Report Builder & PDF Engine
  │   ├── assets.py
  │   ├── amber_builder.py
  │   └── pdf_engine.py
  ├── api/             # HTTP route controllers & blueprints
  │   ├── scan_routes.py
  │   ├── report_routes.py
  │   └── test_routes.py
  ├── fonts/           # Official Thai SarabunPSK TrueType fonts
  └── GUI.html         # Modern web application frontend
"""

import os
import sys
import secrets
import threading
import time
import webbrowser
from flask import Flask, send_from_directory, request

from api.scan_routes import scan_bp
from api.report_routes import report_bp
from api.profile_routes import profile_bp
from api.cve_routes import cve_bp
from core.update_checker import start_daily_update_worker

# Backward compatibility re-exports for external scripts / tests
from core.semver import parse_semver, in_range
from core.database import NGINX_VULN, NGINX_CVE_DESCS, CVE_DATABASE
from core.network import (
    OUI_DATABASE,
    resolve_device_details,
    get_fast_latency,
    is_valid_unicast_host,
    get_live_lan_hosts,
    is_ignored_interface,
    detect_host_network,
    get_host_network_info,
    get_docker_gateway,
    parse_target_hosts,
)
from audit.php_audit import evaluate_php_security, evaluate_security_chains
from audit.node_audit import evaluate_node_security
from audit.nginx_audit import evaluate_nginx_security, collect_target_cves
from audit.thaicert_rules import classify_thaicert_groups
from audit.probe_audit import probe_lfi_prerequisite, check_tcp_port, probe_endpoint
from reports.amber_builder import build_amber_advisory_html
from reports.pdf_engine import generate_amber_pdf

is_production = os.environ.get("OPSCANER_ENV", "production").lower() == "production"

# Initialize Flask App
app = Flask(__name__, static_folder=".")

# Secure secret key configuration
configured_secret = os.environ.get("FLASK_SECRET", "").strip()
if not configured_secret or configured_secret in ("supersecretkey123", "secret", "change_me"):
    app.secret_key = secrets.token_hex(32)
else:
    app.secret_key = configured_secret

# Configurable CORS & Security Headers
allowed_origins_env = os.environ.get("OPSCANER_CORS_ORIGINS", "").strip()
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
elif not is_production:
    allowed_origins = ["*"]
else:
    allowed_origins = [
        "http://127.0.0.1:5050",
        "http://localhost:5050",
        "http://0.0.0.0:5050",
        "tauri://localhost",
        "http://tauri.localhost",
        "http://localhost:1420"
    ]


@app.after_request
def add_security_headers(response):
    # Dynamic CORS origin handling
    origin = request.headers.get("Origin")
    if "*" in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = "*"
    elif origin and (origin in allowed_origins or not allowed_origins):
        response.headers["Access-Control-Allow-Origin"] = origin
    elif not origin and allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = allowed_origins[0]

    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    # Production security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


@app.route("/api/<path:subpath>", methods=["OPTIONS"])
def handle_options(subpath):
    return "", 200


# Resolve frozen bundle base directory for PyInstaller standalone executables
BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
DIST_DIR = os.path.join(BASE_DIR, "thaicert-scanner", "dist")


# Static Frontend Routes (Svelte + Vite + Tailwind + Tauri)
@app.route("/")
def index():
    if os.path.isdir(DIST_DIR) and os.path.isfile(os.path.join(DIST_DIR, "index.html")):
        return send_from_directory(DIST_DIR, "index.html")
    if os.path.isfile(os.path.join(BASE_DIR, "GUI.html")):
        return send_from_directory(BASE_DIR, "GUI.html")
    return "Frontend bundle not found. Please build thaicert-scanner.", 404


@app.route("/assets/<path:filename>")
def serve_dist_assets(filename):
    if os.path.isdir(DIST_DIR):
        return send_from_directory(os.path.join(DIST_DIR, "assets"), filename)
    return "", 404


@app.route("/favicon.png")
def serve_favicon():
    if os.path.isdir(DIST_DIR) and os.path.isfile(os.path.join(DIST_DIR, "favicon.png")):
        return send_from_directory(DIST_DIR, "favicon.png")
    pub_dir = os.path.join(BASE_DIR, "thaicert-scanner", "public")
    if os.path.isfile(os.path.join(pub_dir, "favicon.png")):
        return send_from_directory(pub_dir, "favicon.png")
    return "", 404


@app.route("/fonts/<path:filename>")
def serve_font(filename):
    return send_from_directory(os.path.join(BASE_DIR, "fonts"), filename)


# Register Blueprints
app.register_blueprint(scan_bp)
app.register_blueprint(report_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(cve_bp)

# Start background update checker worker
try:
    start_daily_update_worker()
except Exception:
    pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    url = f"http://127.0.0.1:{port}"
    print(f"============================================================")
    print(f"  OPScaner - Web Vulnerability Scanner & Security Auditor   ")
    print(f"  ThaiCERT & NCSA Thailand Security Audit Framework         ")
    print(f"============================================================")
    print(f"[*] Starting local audit server: {url}")
    print(f"[*] Opening default browser...")

    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="0.0.0.0", port=port, debug=False)
