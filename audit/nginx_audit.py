"""
NGINX Security & Multi-Stack CVE Correlation Module
Evaluates NGINX version against SemVer ranges (Mainline & Stable)
and aggregates matched CVE findings across NGINX, PHP, and Node.js.
"""

import re
from typing import Tuple, List, Dict, Any
from core.semver import parse_semver, in_range
from core.database import NGINX_VULN, NGINX_CVE_DESCS

def evaluate_nginx_security(server_str: str, headers: dict = None, hints: dict = None):
    """
    Evaluates NGINX version against known CVEs using SemVer ranges combined with
    behavioral precondition hints (SSI files, HTTP/3 QUIC UDP, alias rewrite traversal).
    Returns: (overall_severity, matched_cves, summary_note)
    """
    headers = headers or {}
    hints = hints or {}
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
                v_status = "SUSPECTED_RISK (NEEDS_LOCAL_VERIFICATION)"
                reason = f"NGINX {ver_str} อยู่ในช่วงเวอร์ชันที่ได้รับผลกระทบตามฐานข้อมูลช่องโหว่"

                # Behavioral Precondition Correlation
                if cve_id == "CVE-2026-97205":  # SSI
                    if hints.get("ssi_files"):
                        v_status = "PRECONDITION_IDENTIFIED"
                        reason = f"NGINX {ver_str} เสี่ยงต่อ SSI UAF + พบไฟล์ SSI ในระบบ ({', '.join(hints['ssi_files'][:2])})"
                    else:
                        v_status = "PRECONDITION_ABSENT"
                        reason = f"NGINX {ver_str} เข้าข่ายช่วงเสี่ยง แต่ไม่พบไฟล์ .shtml/.shtm จากการสำรวจภายนอก"
                        cve_sev = "Low"

                elif cve_id == "CVE-2026-15176":  # Alias Off-by-slash
                    if hints.get("alias_traversal_observed"):
                        v_status = "PRECONDITION_IDENTIFIED"
                        reason = f"NGINX {ver_str} + ตรวจพบพฤติกรรม alias path traversal: {hints.get('alias_evidence')}"
                    else:
                        v_status = "SUSPECTED_RISK"
                        reason = f"NGINX {ver_str} เสี่ยงเชิงโครงสร้าง แต่ไม่พบความผิดปกติของ alias rewrite จากการทดสอบเบื้องต้น"

                elif cve_id == "CVE-2026-95101":  # HTTP/3 QUIC
                    if hints.get("http3_udp_verified"):
                        v_status = "PRECONDITION_IDENTIFIED"
                        reason = f"NGINX {ver_str} + ยืนยันพอร์ต UDP 443 รองรับโปรโตคอล QUIC (HTTP/3)"
                    else:
                        v_status = "PRECONDITION_ABSENT"
                        reason = f"NGINX {ver_str} อยู่ในช่วงเสี่ยง แต่ไม่พบการตอบสนองของ QUIC UDP listener"
                        cve_sev = "Low"

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
                    "verification_status": v_status,
                    "reason": reason
                })
                if sev_weights.get(cve_sev, 0) > sev_weights.get(highest_sev, 0):
                    highest_sev = cve_sev
        
        if matched:
            cve_names = ", ".join(c["cve"] for c in matched[:3])
            note = f"NGINX {ver_str} ตรวจพบ {len(matched)} รายการประเมิน ({cve_names}) ควรตรวจสอบคอนฟิกและอัปเดตเป็น 1.30.6+ หรือ 1.31.7+"
        else:
            note = f"NGINX {ver_str} ปลอดภัย (อยู่นอกช่วงความเสี่ยงของ CVE-2026)"
    else:
        highest_sev = "Review Needed"
        note = "ตรวจพบบริการ NGINX (ซ่อนเลขเวอร์ชัน) ควรตรวจสอบคำสั่ง 'nginx -v' บนเครื่อง"
        
    return highest_sev, matched, note

def collect_target_cves(
    is_php: bool,
    is_node: bool,
    v_php: str,
    v_node: str,
    php_ver: str,
    node_ver: str,
    has_brotli: bool,
    nginx_cves: list,
    has_lfi_active: bool = False,
    is_fpm: bool = False,
    is_windows: bool = False,
    rce_confirmed: bool = False,
    rce_technique: str = "",
    rce_endpoint: str = "",
    extra_cves: list = None
) -> list:
    """
    Aggregates all matched CVE findings across NGINX, PHP, Node.js, and OS/Kernel for a target.
    Enforces strict OS boundaries (e.g. CVE-2024-4577 only applies to Windows),
    ensures finding-to-evidence coherence (e.g. Command Injection on .aspx is CWE-78, not PHP-CGI),
    and updates confidence/status when RCE is empirically confirmed.
    """
    cves = []
    
    # 1. Add NGINX CVEs if any
    if nginx_cves:
        cves.extend(nginx_cves)

    # 1.1 Add Extra CVEs (e.g. Linux Kernel CVE-2026-98432)
    if extra_cves:
        for ec in extra_cves:
            if ec and ec not in cves:
                cves.append(ec)

    # Coherence classification
    is_cgi_rce = bool(rce_confirmed and ("CVE-2024-4577" in rce_technique or "PHP-CGI" in rce_technique))
    is_session_rce = bool(rce_confirmed and ("Session Upload Progress" in rce_technique or "LFI" in rce_technique))
    is_cmd_inj = bool(rce_confirmed and ("Command Injection" in rce_technique or "CWE-78" in rce_technique or "cmd=" in (rce_endpoint or "") or ".aspx" in (rce_endpoint or "") or "Diagnostic" in rce_technique or "Web Shell" in rce_technique))

    # Dedicated Command Injection Finding (e.g. Web Shell, ASPX, or Diagnostic cmd parameter)
    if is_cmd_inj:
        cves.append({
            "id": "CWE-78",
            "cve": "CWE-78",
            "name": "ช่องโหว่ระดับวิกฤตประเภท OS Command Injection ผ่าน Web Application Endpoint",
            "category": "Web Application",
            "severity": "Critical",
            "cvss": 9.8,
            "reason": f"ตรวจพบและพิสูจน์ทราบการสั่งรันคำสั่งระบบ (Live RCE Proof) ผ่าน endpoint {rce_endpoint or 'เป้าหมาย'} สำเร็จ",
            "host_check": "ตรวจสอบซอร์สโค้ดและ endpoint ที่เรียกใช้ฟังก์ชันระบบภายนอก (เช่น Process.Start, exec, system)",
            "confirm_vuln": "อนุญาตให้ส่งคำสั่งระบบผ่านพารามิเตอร์โดยไม่มีการตรวจสอบสิทธิ์หรือกรองอักขระควบคุม",
            "confirm_safe": "ยกเลิกหรือจำกัดสิทธิ์การเข้าถึง endpoint สั่งการ และปรับปรุงมาใช้ Parameterized Execution API",
            "confidence": "Confirmed",
            "confirmed": True,
            "verification_status": "RCE_CONFIRMED"
        })
        
    # 2. PHP CVE Mapping
    if is_php:
        # CVE-2024-4577 (Windows CGI Argument Injection - STRICTLY Windows Only)
        if is_windows and v_php in ("Critical", "Outdated", "Lifecycle Risk (EOL)"):
            cves.append({
                "id": "CVE-2024-4577",
                "cve": "CVE-2024-4577",
                "name": "ช่องโหว่ระดับวิกฤตประเภท Argument Injection บนสถาปัตยกรรม PHP CGI (Windows)",
                "category": "PHP",
                "severity": "Critical",
                "cvss": 9.8,
                "cvss_version": "CVSS v3.1",
                "score_source": "PHP Group / NVD",
                "vendor_severity": "Critical",
                "verification_type": "Confirmed Vulnerability" if is_cgi_rce else "Conditional Finding",
                "evidence_confidence": "High (Empirical Callback)" if is_cgi_rce else "Medium (Observed Windows / CGI Fingerprint)",
                "reason": "ยืนยันผลการประเมินเชิงประจักษ์: ส่ง directives ผ่าน PHP-CGI Argument Injection และสั่งประมวลผลโค้ดสำเร็จ" if is_cgi_rce else f"PHP ({php_ver}) บนระบบปฏิบัติการ Windows เสี่ยงต่อ CVE-2024-4577 ผ่านการแปลง Best-fit mapping",
                "host_check": "php -v && (php -i | grep 'Server API')",
                "confirm_vuln": "PHP < 8.2.20 / 8.3.8 บน Windows CGI/FastCGI",
                "confirm_safe": "การแก้ไขถาวร: PHP ≥ 8.2.20 / 8.3.8 หรือย้ายสู่ Linux | มาตรการบรรเทา: mod_rewrite บล็อกอักขระ %AD",
                "confidence": "Confirmed" if is_cgi_rce else "Likely",
                "confirmed": is_cgi_rce,
                "verification_status": "RCE_CONFIRMED" if is_cgi_rce else "SUSPECTED_RISK"
            })
        
        # CVE-2026-109618 & 109619 (PHP 8.2/8.3 UAF memory corruption)
        if "8.2" in str(php_ver) or "8.3" in str(php_ver):
            vt = parse_semver(php_ver)
            if vt and ((vt[0] == 8 and vt[1] == 2 and vt[2] < 35) or (vt[0] == 8 and vt[1] == 3 and vt[2] < 36)):
                cves.append({
                    "id": "CVE-2026-109618",
                    "cve": "CVE-2026-109618",
                    "name": "ช่องโหว่ระดับวิกฤตประเภท Use-After-Free จากเงื่อนไข OOM Multipart Bailout บน PHP (CWE-416)",
                    "category": "PHP",
                    "severity": "Critical",
                    "cvss": 9.2,
                    "cvss_version": "CVSS v4.0",
                    "score_source": "PHP Security Advisory GHSA-w8hw-w9fx-j79w",
                    "vendor_severity": "Critical",
                    "verification_type": "Conditional Finding",
                    "evidence_confidence": "Medium (Observed PHP Version)",
                    "reason": f"PHP {php_ver} ต่ำกว่าแพตช์ 8.2.35 / 8.3.36",
                    "host_check": "php -v",
                    "confirm_vuln": "php -v ต่ำกว่า 8.2.35 / 8.3.36 และ Server API เป็น FPM/Apache Handler",
                    "confirm_safe": "การแก้ไขถาวร: php -v ≥ 8.2.35 / 8.3.36 | มาตรการบรรเทา: จำกัด post_max_size",
                    "confidence": "Likely",
                    "verification_status": "SUSPECTED_RISK"
                })
                cves.append({
                    "id": "CVE-2026-109619",
                    "cve": "CVE-2026-109619",
                    "name": "ช่องโหว่ระดับวิกฤตประเภท Stale Global State ผ่าน Session Upload Progress บน PHP (CWE-665)",
                    "category": "PHP",
                    "severity": "Critical",
                    "cvss": 9.2,
                    "cvss_version": "CVSS v4.0",
                    "score_source": "PHP Security Advisory GHSA-6wmf-4rv5-p3rp",
                    "vendor_severity": "Critical",
                    "verification_type": "Conditional Finding (Architectural Risk)",
                    "evidence_confidence": "Medium (Observed FastCGI Architecture)",
                    "reason": f"PHP {php_ver} ต่ำกว่าแพตช์ 8.2.35 / 8.3.36 ร่วมกับ upload_progress",
                    "host_check": "php -i | grep session.upload_progress",
                    "confirm_vuln": "session.upload_progress.enabled = On บน PHP < 8.2.35 / 8.3.36",
                    "confirm_safe": "การแก้ไขถาวร: PHP ≥ 8.2.35 / 8.3.36 | มาตรการบรรเทา: กำหนด pm.max_requests > 0 และปิด session.upload_progress",
                    "confidence": "Likely",
                    "verification_status": "SUSPECTED_RISK"
                })
                
        # CVE-2026-115560 (Session Upload Progress - CWE-98 / CWE-94)
        if has_lfi_active or is_session_rce:
            cves.append({
                "id": "CVE-2026-115560",
                "cve": "CVE-2026-115560",
                "name": "ช่องโหว่การสลับรูปแบบ Serializer ผ่าน Session Upload Progress (CWE-98 / CWE-94)",
                "category": "PHP",
                "severity": "Critical" if is_session_rce else "High",
                "cvss": 9.8 if is_session_rce else None,
                "cvss_version": "CVSS v3.1" if is_session_rce else "Pending Official NVD Scoring",
                "score_source": "Empirical Assessment" if is_session_rce else "PHP Security Advisory (2026-10-23)",
                "vendor_severity": "Advisory Workaround",
                "verification_type": "Confirmed Vulnerability" if is_session_rce else "Conditional Finding",
                "evidence_confidence": "High (Canary Execution)" if is_session_rce else "Medium (Observable LFI Vector)",
                "reason": "ยืนยันผลการประเมินเชิงประจักษ์: ตรวจพบ LFI และเซิร์ฟเวอร์ประมวลผลโค้ด Canary ใน Session Upload Progress สำเร็จ" if is_session_rce else "ตรวจพบเงื่อนไข Session Upload Progress เสี่ยงต่อการสลับ serialize_handler",
                "host_check": "php -i | grep -E 'session.serialize_handler|session.upload_progress'",
                "confirm_vuln": "แอปสลับ serialize_handler ข้ามรูปแบบตอน runtime หรือเปิดรับ LFI parameter สู่ session directory",
                "confirm_safe": "การแก้ไขถาวร: รอแพตช์ทางการ | มาตรการบรรเทา: ตั้ง session.upload_progress.enabled = Off ใน php.ini",
                "confirmed": is_session_rce,
                "confidence": "Confirmed" if is_session_rce else "Conditional",
                "verification_status": "RCE_CONFIRMED" if is_session_rce else "PRECONDITION_IDENTIFIED"
            })
            
        # CVE-2019-11043 (PHP-FPM underflow)
        if is_fpm and any(old in str(php_ver) for old in ["7.1", "7.2", "7.3"]):
            cves.append({
                "id": "CVE-2019-11043",
                "cve": "CVE-2019-11043",
                "name": "ช่องโหว่ระดับวิกฤตประเภท Buffer Underflow บน PHP-FPM FastCGI ร่วมกับ NGINX (CWE-124)",
                "category": "PHP",
                "severity": "Critical",
                "cvss": 9.8,
                "reason": f"PHP-FPM {php_ver} ต่ำกว่า 7.3.11 เสี่ยงต่อ fastcgi_split_path_info underflow",
                "host_check": "php-fpm -v && (nginx -T 2>/dev/null | grep fastcgi_split_path_info)",
                "confirm_vuln": "PHP-FPM 7.1–7.3 ร่วมกับ NGINX fastcgi_split_path_info",
                "confirm_safe": "PHP ≥ 7.3.11 หรือ PHP 8.x",
                "confidence": "Likely",
                "verification_status": "SUSPECTED_RISK"
            })

    # 3. Node.js CVE Mapping
    if is_node:
        if v_node in ("Critical", "High", "Outdated", "Warning") or (has_brotli and v_node in ("Critical", "High", "Warning")):
            cves.append({
                "id": "CVE-2026-111497",
                "cve": "CVE-2026-111497",
                "name": "ช่องโหว่การประมวลผล Brotli Decoder บนสภาพแวดล้อม Node.js (CWE-20 / Node2Shell)",
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
                "name": "Node.js DNS NUL Domain Validation Bypass (CWE-20)",
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
                "name": "Node.js TLS Cert Validation (Unicode IP / CWE-295)",
                "category": "Node.js",
                "severity": "High",
                "cvss": 7.5,
                "reason": f"Node.js {node_ver} ต่ำกว่า 20.19.2 (ช่องโหว่ TLS Cert Validation)",
                "host_check": "node -v",
                "confirm_vuln": "Node.js < 20.19.2 / 22.15.1",
                "confirm_safe": "Node.js ≥ 20.19.2"
            })
            
    return cves

