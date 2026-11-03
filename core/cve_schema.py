"""
OPScaner - Standard Vulnerability & Payload Schema (ภาษากลาง)
Extensible JSON/YAML Specification for Web, Network L4, Linux OS, and Android Security Testing.
Standardized according to ThaiCERT / NCSA 8-Group Attack Surface Hierarchy.
"""

import re
from typing import Dict, List, Optional, Tuple, Any

# Valid target types across IT infrastructure, Cloud, OS, and Mobile
VALID_TARGET_TYPES = ("web", "network_l4", "linux_os", "android")
VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

DEFAULT_CVE_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "CVE-2024-4577",
        "cve_id": "CVE-2024-4577",
        "name": "PHP-CGI Windows Argument Injection RCE",
        "description": "ช่องโหว่ Argument Injection บน PHP-CGI Windows สั่งรันโค้ดระยะไกลได้โดยไม่ต้องผ่านการยืนยันตัวตน (CVSS 9.8)",
        "target_type": "web",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cwe": "CWE-78",
        "thaicert_group": 6,
        "is_enabled": True,
        "trigger": {
            "method": "POST",
            "path": "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3D1+-d+auto_prepend_file%3Dphp://input",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "body": "<?php echo 'THAICERT_RCE_VERIFIED_'.(7*7); ?>",
            "timeout": 2.0
        },
        "matchers": [
            { "type": "status", "values": [200] },
            { "type": "body_regex", "regex": r"THAICERT_RCE_VERIFIED_49" }
        ],
        "remediation": "อัปเดต PHP เป็นเวอร์ชัน 8.2.20+ หรือ 8.3.8+ หรือปิดการใช้งาน PHP-CGI บน IIS/Apache",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
            "https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/"
        ]
    },
    {
        "rule_id": "CVE-2026-97205",
        "cve_id": "CVE-2026-97205",
        "name": "NGINX SSI Memory Corruption (Buffer Overflow)",
        "description": "ช่องโหว่หน่วยความจำบนโมดูล Server-Side Includes (SSI) ของ NGINX ทำให้เกิด Heap Out-of-bounds Write และ Memory Corruption (CVSS 8.5)",
        "target_type": "web",
        "severity": "High",
        "cvss_score": 8.5,
        "cwe": "CWE-787",
        "thaicert_group": 1,
        "is_enabled": True,
        "trigger": {
            "method": "GET",
            "path": "/",
            "headers": {
                "Range": "bytes=0-100, -1"
            },
            "timeout": 1.5
        },
        "matchers": [
            { "type": "banner_regex", "regex": r"nginx/(?:1\.(?:1[0-9]|2[0-4])\.[0-9]+|1\.25\.[0-3])" },
            { "type": "header_regex", "header": "server", "regex": r"nginx" }
        ],
        "remediation": "ปิดใช้งาน SSI (ssi off;) ใน nginx.conf หรืออัปเกรด NGINX เป็นเวอร์ชันล่าสุด",
        "references": [
            "https://nginx.org/en/security_advisories.html"
        ]
    },
    {
        "rule_id": "CVE-2026-15176",
        "cve_id": "CVE-2026-15176",
        "name": "NGINX Alias Path Traversal (Off-by-slash)",
        "description": "การตั้งค่า Alias Directives ผิดพลาด (Off-by-slash) เปิดโอกาสให้ผู้โจมตีเข้าถึงไฟล์นอกรูทของเว็บแอปพลิเคชันได้ (Directory Traversal)",
        "target_type": "web",
        "severity": "High",
        "cvss_score": 8.1,
        "cwe": "CWE-22",
        "thaicert_group": 1,
        "is_enabled": True,
        "trigger": {
            "method": "GET",
            "path": "/static../nginx.conf",
            "timeout": 1.5
        },
        "matchers": [
            { "type": "status", "values": [200] },
            { "type": "body_regex", "regex": r"http\s*\{|events\s*\{|server\s*\{" }
        ],
        "remediation": "ตรวจสอบการกำหนดค่า location และ alias ใน nginx.conf ให้ลงท้ายด้วยเครื่องหมายสแลช (/) เสมอ",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-15176"
        ]
    },
    {
        "rule_id": "CVE-2026-109618",
        "cve_id": "CVE-2026-109618",
        "name": "PHP 8.2/8.3 Zend var_unserializer Use-After-Free",
        "description": "ช่องโหว่ความจำระดับลึกบน Zend Engine ในฟังก์ชัน var_unserialize() ขณะยกเลิก Serialized Object ซ้อน ส่งผลให้เกิด Use-After-Free (CVSS 9.8)",
        "target_type": "web",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cwe": "CWE-416",
        "thaicert_group": 2,
        "is_enabled": True,
        "trigger": {
            "method": "POST",
            "path": "/",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "body": "data=O:8:\"DateTime\":0:{}",
            "timeout": 2.0
        },
        "matchers": [
            { "type": "header_regex", "header": "x-zend-engine-asan", "regex": r"use-after-free|heap-use-after-free" }
        ],
        "remediation": "อัปเดต PHP Runtime เป็น 8.2.35+ หรือ 8.3.36+ และหลีกเลี่ยงการใช้ unserialize() กับข้อมูลที่ไม่ปลอดภัย",
        "references": [
            "https://bugs.php.net"
        ]
    },
    {
        "rule_id": "EXPOSURE-ENV-SECRETS",
        "cve_id": "CWE-200-ENV",
        "name": "Exposed .env Configuration Credentials",
        "description": "ไฟล์คอนฟิกระบบ .env เปิดเผยสู่สาธารณะโดยไม่มีการบล็อกสิทธิ์ เสี่ยงต่อการรั่วไหลฐานข้อมูล Secret Keys และ Credential Credentials",
        "target_type": "web",
        "severity": "High",
        "cvss_score": 7.5,
        "cwe": "CWE-200",
        "thaicert_group": 1,
        "is_enabled": True,
        "trigger": {
            "method": "GET",
            "path": "/.env",
            "timeout": 1.2
        },
        "matchers": [
            { "type": "status", "values": [200] },
            { "type": "body_regex", "regex": r"APP_KEY=|DB_PASSWORD=|APP_ENV=|AWS_SECRET|JWT_SECRET" },
            { "type": "negative_canary", "enabled": True }
        ],
        "remediation": "ตั้งค่า Web Server (Nginx/Apache) ให้ปฏิเสธการเข้าถึงไฟล์ดอท (.env) โดยส่ง HTTP 403 หรือ 404",
        "references": [
            "https://cwe.mitre.org/data/definitions/200.html"
        ]
    },
    {
        "rule_id": "EXPOSURE-GIT-CONFIG",
        "cve_id": "CWE-200-GIT",
        "name": "Exposed .git Repository Configuration & Source Code",
        "description": "โฟลเดอร์ .git เปิดเผยสู่สาธารณะ ผู้โจมตีสามารถดาวน์โหลด Source Code และ Commit History ขององค์กรได้ทั้งหมด",
        "target_type": "web",
        "severity": "High",
        "cvss_score": 7.5,
        "cwe": "CWE-200",
        "thaicert_group": 1,
        "is_enabled": True,
        "trigger": {
            "method": "GET",
            "path": "/.git/config",
            "timeout": 1.2
        },
        "matchers": [
            { "type": "status", "values": [200] },
            { "type": "body_regex", "regex": r"\[core\]|repositoryformatversion" },
            { "type": "negative_canary", "enabled": True }
        ],
        "remediation": "ลบหรือบล็อกการเข้าถึงโฟลเดอร์ .git บน Web Server ทันที (location ~ /\\.git { deny all; })",
        "references": [
            "https://cwe.mitre.org/data/definitions/200.html"
        ]
    },
    {
        "rule_id": "DOCKER-ENGINE-DAEMON-API",
        "cve_id": "CWE-306-DOCKER",
        "name": "Docker Engine Daemon Remote API Unauthenticated",
        "description": "Docker Daemon API (พอร์ต 2375/2376) เปิดสู่เครือข่ายโดยไม่มีการยืนยันตัวตน ผู้โจมตีสามารถสร้างคอนเทนเนอร์และยึดสิทธิ์ Host Root ได้",
        "target_type": "web",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cwe": "CWE-306",
        "thaicert_group": 5,
        "is_enabled": True,
        "trigger": {
            "method": "GET",
            "path": "/containers/json",
            "timeout": 1.5
        },
        "matchers": [
            { "type": "status", "values": [200] },
            { "type": "body_regex", "regex": r"\"Id\":|\"Image\":|\"Names\":" },
            { "type": "negative_canary", "enabled": True }
        ],
        "remediation": "เปิดใช้งาน TLS Client Authentication สำหรับ Docker API หรือปิดการ Binding พอร์ต 2375 สู่สาธารณะ",
        "references": [
            "https://docs.docker.com/engine/security/protect-access/"
        ]
    },
    {
        "rule_id": "ANDROID-ADB-PORT-5555",
        "cve_id": "ANDROID-SEC-001",
        "name": "Android ADB Remote Debug Port 5555 Exposed",
        "description": "ตรวจพบพอร์ต Android Debug Bridge (ADB 5555) เปิดสู่เครือข่ายภายนอกโดยไม่มีรหัสผ่าน ผู้โจมตีสามารถสั่ง Shell ขโมยข้อมูล หรือติดตั้ง Malicious APK ได้ทันที",
        "target_type": "android",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cwe": "CWE-284",
        "thaicert_group": 4,
        "is_enabled": True,
        "trigger": {
            "target_port": 5555,
            "probe_type": "tcp_banner"
        },
        "matchers": [
            { "type": "port_open", "port": 5555 },
            { "type": "banner_regex", "regex": r"CNXN|device::|auth|ro\.product" }
        ],
        "remediation": "ปิดการใช้งาน Wireless Debugging / ADB over Network ใน Developer Options ของอุปกรณ์ Android",
        "references": [
            "https://developer.android.com/tools/adb"
        ]
    }
]


def validate_cve_rule(rule_dict: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Validates that a rule dictionary conforms to the standard JSON schema."""
    if not isinstance(rule_dict, dict):
        return False, "Rule must be a JSON object (dict)"

    rule_id = str(rule_dict.get("rule_id", "")).strip()
    if not rule_id or len(rule_id) < 3:
        return False, "Missing or invalid 'rule_id' (minimum 3 characters)"

    cve_id = str(rule_dict.get("cve_id", "")).strip()
    if not cve_id:
        return False, "Missing 'cve_id'"

    name = str(rule_dict.get("name", "")).strip()
    if not name:
        return False, "Missing 'name'"

    target_type = str(rule_dict.get("target_type", "web")).strip().lower()
    if target_type not in VALID_TARGET_TYPES:
        return False, f"Invalid 'target_type': {target_type}. Must be one of {VALID_TARGET_TYPES}"

    severity = str(rule_dict.get("severity", "Medium")).strip().capitalize()
    if severity not in VALID_SEVERITIES:
        severity = "Medium"

    trigger = rule_dict.get("trigger")
    if not isinstance(trigger, dict):
        return False, "Missing or invalid 'trigger' object in rule specification"

    matchers = rule_dict.get("matchers")
    if not isinstance(matchers, list) or len(matchers) == 0:
        return False, "'matchers' must be a non-empty list of criteria"

    return True, None


def normalize_cve_rule(rule_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes and fills default values for a validated CVE rule."""
    rule_id = str(rule_dict.get("rule_id", "")).strip().upper()
    cve_id = str(rule_dict.get("cve_id", rule_id)).strip().upper()
    target_type = str(rule_dict.get("target_type", "web")).strip().lower()
    severity = str(rule_dict.get("severity", "Medium")).strip().capitalize()
    if severity not in VALID_SEVERITIES:
        severity = "Medium"

    cvss_score = 5.0
    try:
        cvss_score = float(rule_dict.get("cvss_score", 5.0))
    except (ValueError, TypeError):
        pass

    thaicert_group = 1
    try:
        g = int(rule_dict.get("thaicert_group", 1))
        if 1 <= g <= 8:
            thaicert_group = g
    except (ValueError, TypeError):
        pass

    return {
        "rule_id": rule_id,
        "cve_id": cve_id,
        "name": str(rule_dict.get("name", "")).strip(),
        "description": str(rule_dict.get("description", "")).strip(),
        "target_type": target_type,
        "severity": severity,
        "cvss_score": cvss_score,
        "cwe": str(rule_dict.get("cwe", "")).strip(),
        "thaicert_group": thaicert_group,
        "is_enabled": bool(rule_dict.get("is_enabled", True)),
        "trigger": rule_dict.get("trigger", {}),
        "matchers": rule_dict.get("matchers", []),
        "remediation": str(rule_dict.get("remediation", "")).strip(),
        "references": rule_dict.get("references", [])
    }
