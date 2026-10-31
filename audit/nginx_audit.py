"""
NGINX Security & Multi-Stack CVE Correlation Module
Evaluates NGINX version against SemVer ranges (Mainline & Stable)
and aggregates matched CVE findings across NGINX, PHP, and Node.js.
"""

import re
from typing import Tuple, List, Dict, Any
from core.semver import parse_semver, in_range
from core.database import NGINX_VULN, NGINX_CVE_DESCS

def evaluate_nginx_security(server_str: str, headers: dict = None):
    """
    Evaluates NGINX version against known CVEs using SemVer ranges.
    Returns: (overall_severity, matched_cves, summary_note)
    """
    headers = headers or {}
    s = (server_str or "").lower()
    if "nginx" not in s:
        return "Secure", [], "ไม่ใช่บริการ NGINX"
    
    # Extract version e.g. nginx/1.26.3
    m = re.search(r'nginx/(\d+\.\d+(?:\.\d+)?)', s)
    ver_str = m.group(1) if m else ""
    vt = parse_semver(ver_str)
    
    matched = []
    highest_sev = "Secure"
    sev_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Review Needed": 1, "Secure": 0}
    
    if vt:
        for cve_id, ranges in NGINX_VULN.items():
            in_vulnerable_range = any(in_range(vt, lo, hi) for lo, hi in ranges)
            if in_vulnerable_range:
                desc = NGINX_CVE_DESCS.get(cve_id, {})
                cve_sev = desc.get("severity", "Medium")
                matched.append({
                    "id": cve_id,
                    "cve": cve_id,
                    "name": desc.get("name"),
                    "category": "NGINX",
                    "severity": cve_sev,
                    "cvss": desc.get("cvss", 7.5),
                    "trigger": desc.get("trigger"),
                    "host_check": desc.get("host_check"),
                    "confirm_vuln": desc.get("confirm_vuln"),
                    "confirm_safe": desc.get("confirm_safe"),
                    "reason": f"NGINX {ver_str} อยู่ในช่วงเวอร์ชันที่ได้รับผลกระทบ"
                })
                if sev_weights.get(cve_sev, 0) > sev_weights.get(highest_sev, 0):
                    highest_sev = cve_sev
        
        if matched:
            cve_names = ", ".join(c["cve"] for c in matched[:3])
            note = f"NGINX {ver_str} ตรวจพบ {len(matched)} ช่องโหว่ ({cve_names}) ควรตรวจสอบคอนฟิกและอัปเดตเป็น 1.30.6+ หรือ 1.31.7+"
        else:
            note = f"NGINX {ver_str} ปลอดภัย (อยู่นอกช่วงความเสี่ยงของ CVE-2026)"
    else:
        highest_sev = "Review Needed"
        note = "ตรวจพบบริการ NGINX (ซ่อนเลขเวอร์ชัน) ควรตรวจสอบคำสั่ง 'nginx -v' บนเครื่อง"
        
    return highest_sev, matched, note

def collect_target_cves(is_php: bool, is_node: bool, v_php: str, v_node: str, php_ver: str, node_ver: str, has_brotli: bool, nginx_cves: list, has_lfi_active: bool = False, is_fpm: bool = False) -> list:
    """
    Aggregates all matched CVE findings across NGINX, PHP, and Node.js for a target.
    """
    cves = []
    
    # 1. Add NGINX CVEs if any
    if nginx_cves:
        cves.extend(nginx_cves)
        
    # 2. PHP CVE Mapping
    if is_php:
        # CVE-2024-4577 (Windows CGI Argument Injection - ThaiCERT Priority)
        if v_php in ("Critical", "Outdated"):
            cves.append({
                "id": "CVE-2024-4577",
                "cve": "CVE-2024-4577",
                "name": "ช่องโหว่ระดับวิกฤตประเภท Argument Injection บนสถาปัตยกรรม PHP CGI",
                "category": "PHP",
                "severity": "Critical",
                "cvss": 9.8,
                "reason": f"PHP ({php_ver}) ต่ำกว่าเกณฑ์แพตช์ 8.2.20+ / 8.3.8+ เสี่ยงต่อ CVE-2024-4577",
                "host_check": "php -v && (php -i | grep 'Server API')",
                "confirm_vuln": "PHP < 8.2.20 / 8.3.8 บน Windows CGI/FastCGI",
                "confirm_safe": "PHP ≥ 8.2.20 / 8.3.8 หรือรันบน Linux"
            })
        
        # CVE-2026-109618 & 109619 (PHP 8.2/8.3 UAF memory corruption)
        if "8.2" in str(php_ver) or "8.3" in str(php_ver):
            vt = parse_semver(php_ver)
            if vt and ((vt[0] == 8 and vt[1] == 2 and vt[2] < 35) or (vt[0] == 8 and vt[1] == 3 and vt[2] < 36)):
                cves.append({
                    "id": "CVE-2026-109618",
                    "cve": "CVE-2026-109618",
                    "name": "ช่องโหว่ระดับวิกฤตประเภท Use-After-Free จากเงื่อนไข OOM Multipart Bailout บน PHP",
                    "category": "PHP",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "reason": f"PHP {php_ver} ต่ำกว่าแพตช์ 8.2.35 / 8.3.36",
                    "host_check": "php -v",
                    "confirm_vuln": "php -v ต่ำกว่า 8.2.35 / 8.3.36 และ Server API เป็น FPM/Apache Handler",
                    "confirm_safe": "php -v ≥ 8.2.35 / 8.3.36"
                })
                cves.append({
                    "id": "CVE-2026-109619",
                    "cve": "CVE-2026-109619",
                    "name": "ช่องโหว่ระดับวิกฤตประเภท Stale Global State ผ่าน Session Upload Progress บน PHP",
                    "category": "PHP",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "reason": f"PHP {php_ver} ต่ำกว่าแพตช์ 8.2.35 / 8.3.36 ร่วมกับ upload_progress",
                    "host_check": "php -i | grep session.upload_progress",
                    "confirm_vuln": "session.upload_progress.enabled = On บน PHP < 8.2.35 / 8.3.36",
                    "confirm_safe": "session.upload_progress.enabled = Off หรือ PHP ≥ 8.2.35"
                })
                
        # CVE-2026-115560 (Session Upload Progress)
        if has_lfi_active:
            cves.append({
                "id": "CVE-2026-115560",
                "cve": "CVE-2026-115560",
                "name": "ช่องโหว่การสลับรูปแบบ Serializer ผ่าน Session Upload Progress บน PHP",
                "category": "PHP",
                "severity": "Medium-High",
                "cvss": 8.1,
                "reason": "ตรวจพบเงื่อนไข Session Upload Progress เสี่ยงต่อการสลับ serialize_handler",
                "host_check": "php -i | grep -E 'session.serialize_handler|session.upload_progress'",
                "confirm_vuln": "แอปสลับ serialize_handler ข้ามรูปแบบตอน runtime",
                "confirm_safe": "session.upload_progress.enabled = Off"
            })
            
        # CVE-2019-11043 (PHP-FPM underflow)
        if is_fpm and any(old in str(php_ver) for old in ["7.1", "7.2", "7.3"]):
            cves.append({
                "id": "CVE-2019-11043",
                "cve": "CVE-2019-11043",
                "name": "ช่องโหว่ระดับวิกฤตประเภท Buffer Underflow บน PHP-FPM FastCGI ร่วมกับ NGINX",
                "category": "PHP",
                "severity": "Critical",
                "cvss": 9.8,
                "reason": f"PHP-FPM {php_ver} ต่ำกว่า 7.3.11 เสี่ยงต่อ fastcgi_split_path_info underflow",
                "host_check": "php-fpm -v && (nginx -T 2>/dev/null | grep fastcgi_split_path_info)",
                "confirm_vuln": "PHP-FPM 7.1–7.3 ร่วมกับ NGINX fastcgi_split_path_info",
                "confirm_safe": "PHP ≥ 7.3.11 หรือ PHP 8.x"
            })

    # 3. Node.js CVE Mapping
    if is_node:
        if v_node in ("Critical", "High", "Outdated", "Warning") or (has_brotli and v_node in ("Critical", "High", "Warning")):
            cves.append({
                "id": "CVE-2026-111497",
                "cve": "CVE-2026-111497",
                "name": "ช่องโหว่การประมวลผล Brotli Decoder บนสภาพแวดล้อม Node.js",
                "alias": "Node2Shell",
                "category": "Node.js",
                "severity": "High",
                "cvss": 9.2,
                "confidence": "Likely" if has_brotli else "Conditional",
                "reason": f"Node.js ({node_ver}) ต่ำกว่าเวอร์ชันที่ระบุว่าได้รับแพตช์สำหรับ CVE-2026-111497 (NVD ระบุ CVSS 9.2 Critical ขณะที่ Node.js จัดเป็นระดับ High) อาจได้รับผลกระทบหากแอปพลิเคชันรับข้อมูล Brotli จากภายนอกและนำไปถอดรหัสด้วย node:zlib",
                "host_check": "node -v",
                "confirm_vuln": "Node.js < 22.23.4 / 24.22.1 / 26.12.1 หรือ EOL ร่วมกับมีการรับข้อมูล Brotli มาถอดรหัส",
                "confirm_safe": "อัปเดตเป็นรุ่นที่มีแพตช์อย่างน้อย 22.23.4, 24.22.1 หรือ 26.12.1 ตามสายเวอร์ชัน หรือรุ่นล่าสุดที่ผู้พัฒนาแนะนำ"
            })
        nv = parse_semver(node_ver)
        if nv and nv[0] <= 20:
            cves.append({
                "id": "CVE-2026-105482",
                "cve": "CVE-2026-105482",
                "name": "Node.js DNS NUL Domain Validation Bypass",
                "category": "Node.js",
                "severity": "High",
                "cvss": 7.5,
                "reason": f"Node.js {node_ver} ต่ำกว่า 20.19.2 (ช่องโหว่ DNS NUL c-ares)",
                "host_check": "node -v",
                "confirm_vuln": "Node.js < 20.19.2 / 22.15.1",
                "confirm_safe": "Node.js ≥ 20.19.2"
            })
            cves.append({
                "id": "CVE-2026-105483",
                "cve": "CVE-2026-105483",
                "name": "Node.js TLS Cert Validation (Unicode IP)",
                "category": "Node.js",
                "severity": "High",
                "cvss": 7.5,
                "reason": f"Node.js {node_ver} ต่ำกว่า 20.19.2 (ช่องโหว่ TLS Cert Validation)",
                "host_check": "node -v",
                "confirm_vuln": "Node.js < 20.19.2 / 22.15.1",
                "confirm_safe": "Node.js ≥ 20.19.2"
            })
            
    return cves

