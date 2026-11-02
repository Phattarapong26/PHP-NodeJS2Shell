"""
Heuristic Archetype Classification Rules & Multi-Tier Evidence Engine
Classifies targets into 8 organizational archetype profiles tailored for typical Thai IT & web infrastructure:
1. เว็บไซต์และระบบภายในองค์กร (CMS / Internal Web)
2. ระบบหลังบ้านแอปมือถือ และ API (APIs / Frameworks)
3. Hosting Control Panel (cPanel, Plesk, DirectAdmin, Webmin)
4. ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance, Network, FW/VPN, IoT)
5. Container และ Docker Image (Docker, Registry, K8s)
6. Windows ที่มี PHP ติดตั้งอยู่ (CVE-2024-4577 Priority)
7. ระบบทดสอบ ระบบเก่า และระบบสำรอง (Dev, UAT, Staging, Backup)
8. ระบบที่ผู้ให้บริการภายนอกดูแล (Shared Hosting, Managed Cloud)

Features Tiered Evidence Hierarchy (adapted from VASCAN8GROUP):
- Tier 1: Passive Product & Service Fingerprinting (38 Signatures)
- Tier 2: Per-Group Targeted Exposure Checklists (GROUP_CHECKS)
- Tier 3: Soft-404 Anti-False-Positive Baseline Verification
- Tier 4: Edge / WAF / Blocked Surface Classification
"""

import re
import hashlib
import random
import string
from typing import Dict, Any, List, Optional, Tuple

THAICERT_GROUP_PROFILES = {
    1: {
        "group_id": 1,
        "name": "เว็บไซต์และระบบภายในองค์กร (CMS / Internal Web)",
        "sapi_typical": "Apache mod_php หรือ PHP-FPM หลัง Reverse Proxy (Nginx/Apache)",
        "worker_model": "Pre-fork Multi-Process (Apache) หรือ FastCGI Worker Process Pool (FPM)",
        "engine_shared_vulnerabilities": [
            "PHP Engine OOM Memory Exhaustion",
            "Session Upload Progress Poisoning (Chain A)",
            "Stale Global State via Worker Reuse (GHSA-6wmf-4rv5-p3rp)"
        ],
        "exploit_chain_mechanism": "PHP ประมวลผล request body และ multipart upload ที่ระดับ SAPI/Engine ก่อนเรียก application entry point ทำให้ middleware ไม่มีโอกาสกรอง request หากเกิด OOM หรือ stale state จะทำให้เกิดเงื่อนไขที่ worker ตกค้าง แต่การทำ RCE ต้องอาศัย upload route และ LFI ภายใน CMS",
        "prerequisites": [
            {"name": "Engine Body/Multipart Parsing", "condition": "ส่งผ่านก่อน CMS Router/Middleware", "status": "Met at Engine Level"},
            {"name": "Upload Route / Large Body Delivery", "condition": "ไม่ถูก Proxy Buffer สกัดกั้น", "status": "Conditional on Proxy"},
            {"name": "LFI Prerequisite", "condition": "ต้องมีจุด include/require ไฟล์เซสชัน", "status": "Required for RCE"}
        ],
        "impact_scope": "ความเสี่ยง RCE หากมี LFI ประกอบ หรือเกิดการปนเปื้อนข้อมูลเซสชัน (Session Poisoning) ใน /tmp",
        "mitigation": "ปิด session.upload_progress.enabled = Off, จำกัด post_max_size / memory_limit และอัปเดต PHP เป็นเวอร์ชันที่ได้รับการแพตช์",
        "confidence_default": "Conditional"
    },
    2: {
        "group_id": 2,
        "name": "ระบบหลังบ้านแอปมือถือ และ API (Frameworks & REST APIs)",
        "sapi_typical": "PHP-FPM, Nginx FastCGI, หรือ CLI Persistent Server (Swoole / RoadRunner)",
        "worker_model": "FastCGI Worker Pool Reuse (pm.max_requests=0) หรือ Persistent Memory State",
        "engine_shared_vulnerabilities": [
            "PHP Engine OOM via Large Request Body",
            "Stale Global State Persistence (GHSA-6wmf-4rv5-p3rp)",
            "Serializer Mismatch in Cache/Session Store"
        ],
        "exploit_chain_mechanism": "แอปพลิเคชัน Framework มี Middleware และ Routing แต่การ parse request body และ multipart เกิดขึ้นก่อนโค้ด Userland อย่างไรก็ตาม การโจมตี stale-state จำเป็นต้องมี endpoint ทำหน้าที่เป็น producer ทิ้งสถานะค้าง และ request ถัดไปต้องเข้า worker เดิมที่มี consumer อ่านสถานะก่อนถูกรีเซ็ต",
        "prerequisites": [
            {"name": "Pre-routing Body Parsing", "condition": "Engine ประมวลผล body ก่อน Framework Middleware", "status": "Met at Engine Level"},
            {"name": "Producer/Consumer Endpoints", "condition": "มี endpoint ที่ทิ้ง state และ endpoint ที่อ่าน state", "status": "Application-Dependent"},
            {"name": "Worker Reuse Hit", "condition": "Request ถัดไปเข้าถึง worker ตัวเดิมก่อนถูก recycle", "status": "Probabilistic / High Concurrency"}
        ],
        "impact_scope": "การปนเปื้อนข้อมูลข้ามคำขอ (Cross-request Data Contamination) หรือสิทธิ์หลุดในระดับเวิร์กเกอร์เดียวกัน",
        "mitigation": "กำหนด pm.max_requests = 500, แยก stateless API pool และไม่เก็บ mutable global state ข้ามคำขอ",
        "confidence_default": "Conditional"
    },
    3: {
        "group_id": 3,
        "name": "Hosting Control Panel (cPanel, Plesk, DirectAdmin)",
        "sapi_typical": "Internal Panel Daemon (cpsrvd, sw-engine) แยกจาก User Site PHP Pools",
        "worker_model": "แยก Process และ Unix Domain Socket ระหว่าง Management Panel กับ User Websites",
        "engine_shared_vulnerabilities": [
            "PHP Engine Vulnerabilities บนเวอร์ชันที่แชร์รันไทม์",
            "Local Privilege Escalation (กรณีแชร์ Socket/Process)"
        ],
        "exploit_chain_mechanism": "ไม่ใช่ exploit chain เดียวกันโดยอัตโนมัติ ต้องตรวจสอบว่า Control Panel ใช้ internal PHP binary แยกต่างหาก (เช่น /usr/local/cpanel/3rdparty/bin/php) หรือแชร์ PHP runtime กับเว็บไซต์ผู้ใช้ หากแยกกัน การโจมตีเว็บผู้ใช้จะไม่ส่งผลกระทบต่อสิทธิ์ของ Control Panel",
        "prerequisites": [
            {"name": "Shared Binary/Socket Analysis", "condition": "ต้องตรวจสอบว่าใช้ binary หรือ socket ร่วมกันหรือไม่", "status": "Inspection Required"},
            {"name": "Privilege Boundary Crossing", "condition": "ต้องข้ามผ่านข้อจำกัดสิทธิ์ user isolation / chroot", "status": "Strict Boundary"}
        ],
        "impact_scope": "หากแยกสิทธิ์สมบูรณ์: ผลกระทบจำกัดเฉพาะเว็บไซต์ผู้ใช้; หากแชร์ runtime: เสี่ยงต่อการยกระดับสิทธิ์สู่ระบบจัดการ",
        "mitigation": "บังคับแยก PHP service, binary และ user pool ระหว่างส่วนบริหารจัดการกับเว็บไซต์อย่างเด็ดขาด",
        "confidence_default": "Conditional"
    },
    4: {
        "group_id": 4,
        "name": "ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance, NAS, IoT)",
        "sapi_typical": "Embedded Web Server (Lighttpd, Boa, Go, C/Lua Embedded)",
        "worker_model": "Single-process หรือ Event-driven Embedded Architecture",
        "engine_shared_vulnerabilities": [
            "ไม่สามารถยืนยันความเสี่ยงจนกว่าจะพบ PHP Runtime จริงในระบบ"
        ],
        "exploit_chain_mechanism": "อุปกรณ์เครือข่ายและ IoT มักไม่ใช้ PHP เป็นเว็บเซิร์ฟเวอร์หลัก ห้ามสรุปว่ามีช่องโหว่ PHP engine จนกว่าจะทราบ PHP version, SAPI, และ exposure จริงของระบบ",
        "prerequisites": [
            {"name": "PHP Runtime Verification", "condition": "ต้องตรวจพบ PHP binary และโมดูลเว็บที่ทำงานอยู่จริง", "status": "Unverified"}
        ],
        "impact_scope": "ไม่มีผลกระทบ (Non-Applicable) หากอุปกรณ์ไม่ได้รันรันไทม์ PHP",
        "mitigation": "ตรวจสอบรายการ Service ที่เปิดใช้งานและปิดพอร์ตบริหารจัดการที่ไม่จำเป็นต่ออินเทอร์เน็ต",
        "confidence_default": "Unverified"
    },
    5: {
        "group_id": 5,
        "name": "Container และ Docker Image (Docker, K8s, Podman)",
        "sapi_typical": "Containerized PHP-FPM + Nginx Sidecar หรือ Apache mod_php ใน Base Image",
        "worker_model": "Containerized Worker Pool (Ephemeral Lifecycle ผูกกับอายุ Container)",
        "engine_shared_vulnerabilities": [
            "PHP Engine Memory Corruption ใน Base Image",
            "Transient Worker State Contamination"
        ],
        "exploit_chain_mechanism": "การรีสตาร์ท Container/Pod ช่วยล้าง transient stale state ชั่วคราวในหน่วยความจำ แต่ไม่ใช่การแก้ไขช่องโหว่ถาวร หากอิมเมจต้นทางยังเป็นเวอร์ชันที่มีช่องโหว่ เวิร์กเกอร์ใหม่ที่ถูกบูตขึ้นมาจะยังมีช่องโหว่เดิมพร้อมรับการโจมตีซ้ำ",
        "prerequisites": [
            {"name": "Image Layer Vulnerability", "condition": "Base Image บรรจุ PHP package ที่ยังไม่ได้รับการแพตช์", "status": "Persistent in Image"},
            {"name": "Worker Reuse Before Pod Termination", "condition": "การโจมตีต้องเกิดภายในวงรอบชีวิตของ Container", "status": "Ephemeral Window"}
        ],
        "impact_scope": "ความเสี่ยงการค้างสถานะในแรมระหว่างคำขอ และความเสี่ยงถาวรในระดับ Supply Chain ของคอนเทนเนอร์",
        "mitigation": "Rebuild อิมเมจใหม่ด้วย PHP Base Image ที่แพตช์แล้ว (PHP 8.2.20+ / 8.3.8+) และกำหนด Read-only Root Filesystem",
        "confidence_default": "Conditional"
    },
    6: {
        "group_id": 6,
        "name": "Windows ที่มี PHP ติดตั้งอยู่ (IIS, XAMPP, WampServer)",
        "sapi_typical": "PHP-CGI (CVE-2024-4577 Priority), IIS FastCGI, หรือ Apache mod_php บน Windows",
        "worker_model": "CGI Process-per-request หรือ IIS FastCGI Process Manager / Multi-thread",
        "engine_shared_vulnerabilities": [
            "CVE-2024-4577 (PHP-CGI Argument Injection via Unicode Best-fit)",
            "PHP Engine OOM Memory Exhaustion (หากใช้ FastCGI หรือ mod_php บน Windows)",
            "Stale State Worker Bugs"
        ],
        "exploit_chain_mechanism": "CVE-2024-4577 เป็น chain เฉพาะของ PHP-CGI บน Windows ผ่านกลไก Best-fit encoding แต่ไม่ได้แปลว่า Windows จะมีเฉพาะช่องโหว่นี้ หาก Windows รัน PHP ผ่าน FastCGI บน IIS หรือ mod_php บน XAMPP ช่องโหว่ระดับ PHP engine อื่นๆ ก็ยังคงมีผลกระทบตาม SAPI และเวอร์ชันจริง",
        "prerequisites": [
            {"name": "Windows SAPI Distinction", "condition": "แยกแยะว่าเป็น CGI, FastCGI หรือ mod_php", "status": "Determined by SAPI"},
            {"name": "Unicode Best-fit Mapping", "condition": "เฉพาะกรณี PHP-CGI บน Windows Code Page (เช่น Windows-874, CP932)", "status": "Prerequisite for CVE-2024-4577"}
        ],
        "impact_scope": "RCE โดยตรงหากเป็น PHP-CGI (CVE-2024-4577) หรือความเสี่ยงระดับ Engine Memory หากเป็น FastCGI/mod_php",
        "mitigation": "อัปเดต PHP เป็น 8.2.20+ / 8.3.8+ หลีกเลี่ยงการใช้โหมด CGI บน Windows และย้ายไปใช้ FastCGI ที่ตั้งค่าความปลอดภัยรัดกุม",
        "confidence_default": "Likely"
    },
    7: {
        "group_id": 7,
        "name": "ระบบทดสอบ ระบบเก่า และระบบสำรอง (Dev, UAT, Staging, DR, Snapshot)",
        "sapi_typical": "Standard SAPI ใน Debug Mode พร้อมเปิดเผยข้อผิดพลาดและข้อมูลระบบ",
        "worker_model": "Unmonitored Worker Processes (มักไม่มีการกำหนด pm.max_requests หรือ memory_limit)",
        "engine_shared_vulnerabilities": [
            "Information Disclosure (CWE-200 via display_errors=On / expose_php=On)",
            "Latent PHP Engine RCE เมื่อระบบกู้คืนสู่ Active State"
        ],
        "exploit_chain_mechanism": "ระบบเหล่านี้มักเปิดเผยข้อมูลคอนฟิก เส้นทางไฟล์ และ stack trace ออกมาโดยตรง นอกจากนี้ไฟล์สำรองหรือ snapshot หากเปิดเผยต่อเครือข่ายอาจเสี่ยงต่อข้อมูลรั่วไหล และหากถูก restore เป็นระบบที่เปิดใช้งานจริง จะกลับมาเป็น target ที่รัน PHP ที่มีช่องโหว่เดิมได้ทันที",
        "prerequisites": [
            {"name": "Network Exposure", "condition": "เข้าถึงได้จากภายนอกโดยไม่มี Network Segmentation", "status": "High Risk"},
            {"name": "Telemetry Leakage", "condition": "เปิดเผยพาธไฟล์และค่าสภาพแวดล้อมในข้อความ Error", "status": "Confirmed in Dev"}
        ],
        "impact_scope": "การรั่วไหลของข้อมูลความลับ (Information Disclosure) และความเสี่ยงแฝง (Latent Risk) เมื่อระบบถูกกู้คืน",
        "mitigation": "ปิดการเข้าถึงจากอินเทอร์เน็ตภายนอก, ปิด display_errors = Off และเข้ารหัสไฟล์สำรอง/Snapshot ทั้งหมด",
        "confidence_default": "Conditional"
    },
    8: {
        "group_id": 8,
        "name": "ระบบที่ผู้ให้บริการภายนอกดูแล (Shared Hosting, Cloud VM)",
        "sapi_typical": "Multi-tenant FastCGI Pools หรือ Shared Apache Worker Model",
        "worker_model": "Multi-tenant Pool Isolation (chroot, cgroups, CageFS หรือ Systemd Jail)",
        "engine_shared_vulnerabilities": [
            "Cross-tenant Stale Worker State Contamination",
            "PHP Engine Memory Leaks ข้ามเซสชันผู้ใช้"
        ],
        "exploit_chain_mechanism": "ระดับความเสี่ยงขึ้นกับ isolation ของผู้ให้บริการ การเข้าถึงข้ามบัญชีต้องพิสูจน์ว่า request ถัดไปถูกส่งเข้า PHP worker เดิมและมีสิทธิ์เข้าถึงข้อมูลของ tenant อื่นได้จริงหรือไม่ ไม่สามารถยืนยันความเสี่ยงได้หากยังไม่ทราบการตั้งค่า pool และ isolation จริง",
        "prerequisites": [
            {"name": "Multi-tenant Pool Boundary", "condition": "ประเมินว่าผู้ให้บริการแยก user pool หรือแชร์ worker", "status": "Provider-Dependent"},
            {"name": "Same Worker Request Routing", "condition": "คำขอจากผู้ใช้อื่นต้องถูก route เข้า worker ตัวเดิม", "status": "Conditional"}
        ],
        "impact_scope": "เสี่ยงต่อการรั่วไหลของข้อมูลข้ามบัญชี (Cross-account Data Leakage) หากไม่มี OS-level sandboxing",
        "mitigation": "แยก User Pool อย่างเด็ดขาดผ่าน PHP-FPM pool configuration และเปิดใช้ OS-level isolation (เช่น CageFS หรือ Docker sandboxing)",
        "confidence_default": "Conditional"
    }
}


def evaluate_group_architecture_matrix(
    groups: List[int],
    is_php: bool,
    php_version: str,
    server: str,
    has_lfi: bool = False,
    is_patched: bool = False,
    is_fpm: bool = False
) -> List[Dict[str, Any]]:
    """
    Evaluates the distinct exploit chain, prerequisites, SAPI, worker model,
    and impact for each matched ThaiCERT target group.
    Ensures scientific accuracy: acknowledges engine-level bug commonalities while distinguishing
    the unique exploit requirements and boundaries per system architecture.
    """
    matrix = []
    server_lower = (server or "").lower()
    is_win = "win" in server_lower or "microsoft" in server_lower

    for g_id in groups:
        profile = THAICERT_GROUP_PROFILES.get(g_id)
        if not profile:
            continue

        # Dynamic SAPI & Worker Model Inference
        if g_id == 6:
            sapi_detected = "PHP-CGI" if ("cgi" in server_lower or not is_fpm) else "IIS FastCGI"
            worker_model = "CGI Process per Request" if sapi_detected == "PHP-CGI" else "IIS FastCGI Process Manager"
            chains_applicable = ["CVE-2024-4577 (CGI Parameter Injection)"]
            if not is_patched:
                chains_applicable.append("PHP Engine OOM & Stale State (FastCGI/mod_php)")
            prereq_summary = "ตรงตามเงื่อนไข (Windows OS) — ตรวจสอบ SAPI และ Unicode Best-fit Code Page" if not is_patched else "ได้รับการแพตช์ (PHP 8.2.20+ / 8.3.8+)"
            exploitability = "Likely" if not is_patched else "Mitigated"
        elif g_id == 4:
            sapi_detected = "Embedded Web Server (Lighttpd/Go/C)" if not is_php else "Embedded PHP Runtime"
            worker_model = "Single-process / Event-driven"
            chains_applicable = ["None (Non-PHP Embedded)" if not is_php else "PHP Engine Memory Vulnerability"]
            prereq_summary = "เงื่อนไขไม่ตรงกัน: ไม่พบ PHP Runtime จริงในระบบ" if not is_php else "ต้องตรวจสอบเวอร์ชันและการเข้าถึงของ PHP"
            exploitability = "Not Applicable" if not is_php else "Conditional"
        elif g_id == 1:
            sapi_detected = "PHP-FPM / FastCGI" if is_fpm else ("Apache mod_php" if "apache" in server_lower else "Standard SAPI")
            worker_model = "FastCGI Worker Pool Reuse" if is_fpm else "Apache Pre-fork Multi-process"
            chains_applicable = ["Chain A (Upload Progress + LFI)", "Chain D (mod_php OOM)", "GHSA-6wmf-4rv5-p3rp (FPM Stale State)"]
            prereq_summary = "Engine Parsing เกิดก่อน CMS Router; แต่ขาด LFI Prerequisite ทำให้ห่วงโซ่ RCE ไม่ครบ" if not has_lfi else "ตรงตามเงื่อนไข: พบจุดเรียกไฟล์ LFI ร่วมกับ PHP Engine"
            exploitability = "Conditional" if not has_lfi else "Confirmed"
        elif g_id == 2:
            sapi_detected = "PHP-FPM Worker Pool" if is_fpm else "Standard FastCGI / Swoole"
            worker_model = "FastCGI Worker Reuse (pm.max_requests=0)"
            chains_applicable = ["GHSA-6wmf-4rv5-p3rp (Stale Global State)", "PHP Engine OOM via Body Parsing"]
            prereq_summary = "Engine Body Parsing เกิดก่อน Middleware; ต้องการ producer ทิ้ง state และ consumer อ่าน state ใน worker เดิม"
            exploitability = "Conditional"
        elif g_id == 3:
            sapi_detected = "Internal Panel Daemon (Isolated) vs User Site Pool"
            worker_model = "แยก Process และ Socket สิทธิ์ต่างกัน"
            chains_applicable = ["User Site PHP Chain (ไม่กระทบ Panel หากแยก Binary)"]
            prereq_summary = "ต้องตรวจสอบการแยก binary, socket และ privilege ของ Control Panel จาก user site"
            exploitability = "Conditional"
        elif g_id == 5:
            sapi_detected = "Containerized PHP-FPM / mod_php"
            worker_model = "Container Ephemeral Worker Pool"
            chains_applicable = ["Transient Worker State Contamination", "Base Image Engine Vulnerability"]
            prereq_summary = "การรีสตาร์ท Pod ล้างหน่วยความจำชั่วคราว แต่ Base Image ยังมีช่องโหว่เดิมถาวร"
            exploitability = "Conditional"
        elif g_id == 7:
            sapi_detected = "Debug / Development SAPI"
            worker_model = "Unmetered Worker Process"
            chains_applicable = ["Chain B (Environment Telemetry Leak)", "Latent RCE when restored to Active DR"]
            prereq_summary = "พบการเปิดเผยข้อมูลระบบ (CWE-200); ไฟล์สำรอง/Snapshot เสี่ยงข้อมูลรั่วไหลและเป็น target เมื่อกู้คืน"
            exploitability = "Conditional"
        elif g_id == 8:
            sapi_detected = "Multi-tenant FastCGI / Cloud VM"
            worker_model = "Multi-tenant Pool Boundary"
            chains_applicable = ["Cross-tenant Worker Contamination (กรณีแชร์ Pool)"]
            prereq_summary = "ขึ้นกับการแบ่งแยก Tenant Isolation ของผู้ให้บริการ ต้องพิสูจน์สิทธิ์และ worker socket จริง"
            exploitability = "Conditional"
        else:
            sapi_detected = "Standard SAPI"
            worker_model = "Standard Process Model"
            chains_applicable = ["Standard PHP Security Chains"]
            prereq_summary = "ประเมินตามพารามิเตอร์และเวอร์ชันของระบบ"
            exploitability = profile.get("confidence_default", "Conditional")

        matrix.append({
            "group_id": g_id,
            "group_name": profile["name"],
            "sapi_detected": sapi_detected,
            "worker_model": worker_model,
            "engine_shared_vulnerabilities": profile.get("engine_shared_vulnerabilities", []),
            "chains_applicable": chains_applicable,
            "exploit_chain_mechanism": profile.get("exploit_chain_mechanism", profile.get("risk_context", "")),
            "prerequisites": profile.get("prerequisites", []),
            "prerequisite_summary": prereq_summary,
            "exploitability": exploitability,
            "impact_scope": profile.get("impact_scope", ""),
            "mitigation": profile.get("mitigation", "")
        })

    return matrix


# ==============================================================================
# Tier 1 & Tier 2: Product Signatures, Edge / WAF, and Targeted Checklists
# Adapted from VASCAN8GROUP for Enterprise ThaiCERT Architecture Classification
# ==============================================================================

GROUP_NAMES = {
    1: "เว็บไซต์และระบบภายในองค์กร (CMS / Internal Web)",
    2: "ระบบหลังบ้านแอปมือถือ และ API (APIs / Frameworks)",
    3: "Hosting Control Panel (cPanel, Plesk, DirectAdmin, Webmin)",
    4: "ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance, Network, FW/VPN, IoT)",
    5: "Container และ Docker Image (Docker, Registry, K8s)",
    6: "Windows ที่มี PHP ติดตั้งอยู่ (IIS, XAMPP, WampServer)",
    7: "ระบบทดสอบ ระบบเก่า และระบบสำรอง (Dev, UAT, Staging, Backup)",
    8: "ระบบที่ผู้ให้บริการภายนอกดูแล (Shared Hosting, Managed Cloud)"
}

_LEGACY_RE = re.compile(
    r"(?:^|[.\-_])(dev|uat|stag|staging|test|qa|sandbox|sbx|old|legacy|beta|demo|backup|bak|tmp)(?:[.\-_]|$)",
    re.I,
)

_PANEL_PORTS = {2082, 2083, 2086, 2087, 2095, 2096, 2222, 8880, 10000, 20000}
_DOCKER_PORTS = {2375, 2376, 2379, 2380, 5000, 6443, 8001, 10250, 10255}
_APPLIANCE_PORTS = {541, 542, 554, 830, 2000, 4433, 4443, 4786, 7443, 8006, 8291, 8728, 8729, 9443, 10443, 37777, 49152}
_WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986, 8172, 8530}

# 38 Passive Product / Technology Signatures
PRODUCT_SIGNATURES = [
    # Group 4: Appliance / Network / FW-VPN / Surveillance
    ("Fortinet", "FortiGate / FortiOS", [4], re.compile(r"\b(?:fortigate|fortios|fortinet)\b|/remote/fgt_lang", re.I)),
    ("Palo Alto Networks", "GlobalProtect", [4], re.compile(r"global[ -]protect|palo alto networks|pan-os", re.I)),
    ("Cisco", "Cisco ASA / AnyConnect", [4], re.compile(r"cisco anyconnect|cisco ssl vpn|webvpn|\+csc[o0]e\+", re.I)),
    ("Citrix", "NetScaler / Citrix Gateway", [4], re.compile(r"netscaler|citrix adc|citrix gateway|/vpn/index\.html", re.I)),
    ("Ivanti", "Connect Secure / Pulse Secure", [4], re.compile(r"ivanti connect secure|pulse secure|dana-na|dslaunch", re.I)),
    ("SonicWall", "SonicOS / SSL-VPN", [4], re.compile(r"sonicwall|sonicos|sonicwall ssl-vpn", re.I)),
    ("MikroTik", "RouterOS / WebFig", [4], re.compile(r"mikrotik|routeros|webfig", re.I)),
    ("Check Point", "Gaia / Security Gateway", [4], re.compile(r"check point|checkpoint|gaia portal", re.I)),
    ("Juniper", "Junos / Secure Gateway", [4], re.compile(r"juniper networks|junos pulse|juniper secure connect", re.I)),
    ("Synology", "Synology DSM", [4], re.compile(r"synology|diskstation|\bdsm\b", re.I)),
    ("QNAP", "QNAP QTS", [4], re.compile(r"qnap|qts", re.I)),
    ("Hikvision", "Hikvision Camera / NVR", [4], re.compile(r"hikvision|web video server", re.I)),
    ("Dahua", "Dahua Camera / NVR", [4], re.compile(r"dahua", re.I)),
    ("Axis", "Axis Communications Device", [4], re.compile(r"axis communications|\baxis network\b", re.I)),
    
    # Group 3 & 8: Hosting Control Panels / Shared Hosting
    ("cPanel", "cPanel / WHM", [3, 8], re.compile(r"cpanel|webhost manager|\bwhm\b", re.I)),
    ("Plesk", "Plesk Panel", [3, 8], re.compile(r"plesk", re.I)),
    ("DirectAdmin", "DirectAdmin", [3, 8], re.compile(r"directadmin", re.I)),
    ("Webmin", "Webmin Panel", [3], re.compile(r"webmin|miniserv", re.I)),
    ("CyberPanel", "CyberPanel", [3, 8], re.compile(r"cyberpanel", re.I)),
    ("ISPConfig", "ISPConfig", [3, 8], re.compile(r"ispconfig", re.I)),

    # Group 1: CMS & Web Applications
    ("WordPress", "WordPress CMS", [1], re.compile(r"wordpress|wp-content|wp-includes|wp-json", re.I)),
    ("Drupal", "Drupal CMS", [1], re.compile(r"drupal|sites/default/files", re.I)),
    ("Joomla", "Joomla! CMS", [1], re.compile(r"joomla|/media/system/js/|/administrator/", re.I)),
    ("Moodle", "Moodle LMS", [1], re.compile(r"moodle|moodlesession", re.I)),
    ("Nextcloud", "Nextcloud", [1], re.compile(r"nextcloud|nc_same_site", re.I)),
    ("Apache", "Apache HTTP Server", [1], re.compile(r"apache(?: httpd|/\d| server)", re.I)),
    ("F5 NGINX", "NGINX / OpenResty", [1], re.compile(r"nginx|openresty", re.I)),

    # Group 2: APIs & Backend Frameworks
    ("Laravel", "Laravel Framework", [1, 2], re.compile(r"laravel|laravel_session|x-csrf-token", re.I)),
    ("Symfony", "Symfony Framework", [1, 2], re.compile(r"symfony|_profiler|_sf2", re.I)),
    ("CodeIgniter", "CodeIgniter Framework", [1, 2], re.compile(r"codeigniter|ci_session", re.I)),
    ("Yii", "Yii Framework", [1, 2], re.compile(r"yii framework|_csrf", re.I)),
    ("Express", "Node.js / Express", [2], re.compile(r"x-powered-by:\s*express|\bexpress\.js\b", re.I)),
    ("Spring", "Spring Boot", [2], re.compile(r"spring boot|whitelabel error page", re.I)),
    ("FastAPI", "FastAPI / Starlette", [2], re.compile(r"fastapi|starlette", re.I)),
    ("Django", "Django Framework", [2], re.compile(r"django|csrftoken", re.I)),
    ("Flask", "Flask / Werkzeug", [2], re.compile(r"werkzeug|flask", re.I)),
    ("Ruby", "Ruby on Rails", [2], re.compile(r"ruby on rails|actioncontroller", re.I)),

    # Group 5: Containers & Docker
    ("Docker", "Docker Engine API", [5], re.compile(r"docker-distribution|docker engine|docker daemon", re.I)),
    ("Harbor", "Harbor Container Registry", [5], re.compile(r"harbor container registry|goharbor", re.I)),
    ("Red Hat", "OpenShift", [5], re.compile(r"openshift", re.I)),
    ("Portainer", "Portainer Management", [5], re.compile(r"portainer", re.I)),
    ("Kubernetes", "Kubernetes / Kubelet", [5], re.compile(r"kubernetes dashboard|kubelet|kubernetes api", re.I)),
    ("Traefik", "Traefik Cloud Ingress", [5], re.compile(r"traefik", re.I)),

    # Group 6: Windows & PHP
    ("Microsoft", "IIS / ASP.NET", [6], re.compile(r"microsoft-iis|asp\.net|__viewstate|iis windows", re.I)),
    ("Microsoft", "Exchange / OWA", [6], re.compile(r"outlook web app|\bowa\b|exchange server", re.I)),
    ("Apache Friends", "XAMPP", [6, 7], re.compile(r"xampp", re.I)),
    ("WampServer", "WampServer", [6, 7], re.compile(r"wampserver", re.I)),
    ("Laragon", "Laragon Stack", [6, 7], re.compile(r"laragon", re.I)),

    # Group 7: Dev, Test & CI/CD
    ("Jenkins", "Jenkins CI/CD", [7], re.compile(r"\bjenkins\b|X-Jenkins", re.I)),
    ("GitLab", "GitLab Server", [7], re.compile(r"gitlab", re.I)),
    ("Grafana", "Grafana Labs", [7], re.compile(r"grafana", re.I)),

    # Group 8: Managed & Cloud Hosting
    ("LiteSpeed", "LiteSpeed Web Server", [8], re.compile(r"litespeed|lsws", re.I)),
    ("CloudLinux", "CloudLinux / CageFS", [8], re.compile(r"cloudlinux|cagefs", re.I)),
]

EDGE_SIGNATURES = [
    ("Cloudflare", "Cloudflare Edge CDN / WAF", re.compile(r"cf-ray|cf-mitigated|server:\s*cloudflare|cf_clearance", re.I)),
    ("Akamai", "Akamai Edge WAF", re.compile(r"akamai-ghost|x-akamai|akamai-grn|ak_bmsc", re.I)),
    ("Imperva", "Imperva Incapsula WAF", re.compile(r"x-iinfo|incap_ses|visid_incap|incapsula", re.I)),
    ("F5", "F5 BIG-IP / Advanced WAF", re.compile(r"x-wa-info|bigipserver|\bts[0-9a-f]{5,}\b|f5 networks", re.I)),
    ("Fortinet", "FortiWeb WAF", re.compile(r"fortiweb|fortiwafsid", re.I)),
    ("Sucuri", "Sucuri Cloud WAF", re.compile(r"x-sucuri|server:\s*sucuri", re.I)),
    ("ModSecurity", "ModSecurity WAF", re.compile(r"mod_security|modsecurity|noyb", re.I)),
    ("AWS", "AWS CloudFront WAF", re.compile(r"cloudfront|x-amz-cf-id", re.I)),
]

# Targeted Sensitive Path Checklists per 8 ThaiCERT Groups
GROUP_CHECKS = {
    1: [
        ("/.git/config", "Git Repository Exposure", "High", r"\[core\]|repositoryformatversion"),
        ("/.env", ".env Environment File Exposure", "High", r"APP_KEY|DB_PASSWORD|APP_ENV|="),
        ("/.svn/entries", "SVN Repository Exposure", "High", None),
        ("/server-status", "Apache mod_status Telemetry", "Medium", r"Apache Server Status|Server uptime"),
        ("/server-info", "Apache mod_info Telemetry", "Medium", r"Apache Server Information"),
        ("/phpinfo.php", "phpinfo() Debug Script", "Medium", r"PHP Version|phpinfo\(\)"),
        ("/info.php", "phpinfo() Debug Script", "Medium", r"PHP Version|phpinfo\(\)"),
        ("/composer.lock", "composer.lock Exposure", "Low", r"packages|content-hash"),
        ("/wp-login.php", "WordPress Admin Portal", "Info", r"WordPress|user_login"),
        ("/wp-json/", "WordPress REST API", "Info", r"\"namespaces\"|wp/v2"),
    ],
    2: [
        ("/swagger.json", "Swagger API Specification", "Medium", r"swagger|openapi"),
        ("/openapi.json", "OpenAPI Specification", "Medium", r"openapi|paths"),
        ("/swagger-ui.html", "Swagger UI Documentation", "Low", r"Swagger UI|swagger-ui"),
        ("/api-docs", "API Documentation Endpoint", "Low", r"swagger|openapi|api"),
        ("/graphql", "GraphQL Endpoint", "Medium", r"GraphQL|__schema|errors"),
        ("/graphiql", "GraphiQL Interactive Console", "Medium", r"GraphiQL|graphiql"),
        ("/_ignition/health-check", "Laravel Ignition Diagnostic", "High", r"ignition|health"),
        ("/_profiler", "Symfony Web Profiler", "High", r"Symfony Profiler|profiler"),
        ("/app_dev.php", "Symfony Dev Front-Controller", "High", r"Symfony|Whoops"),
    ],
    3: [
        ("/cpanel", "cPanel Management Login", "Info", r"cPanel"),
        ("/whm", "WHM WebHost Manager", "Info", r"WHM|WebHost Manager"),
        ("/login_up.php", "Plesk Control Panel Login", "Info", r"Plesk"),
        ("/phpmyadmin/", "phpMyAdmin Database Portal", "Medium", r"phpMyAdmin"),
        ("/webmail", "Webmail Interface", "Info", r"webmail|Roundcube|Horde"),
        ("/.cpanel", ".cpanel Directory Exposure", "Low", None),
    ],
    4: [
        ("/remote/login", "FortiGate SSL-VPN Portal", "Info", r"SSL-VPN|fortinet|/remote/"),
        ("/remote/fgt_lang", "FortiGate Endpoint", "Low", None),
        ("/global-protect/login.esp", "Palo Alto GlobalProtect VPN", "Info", r"GlobalProtect|global-protect"),
        ("/sslvpn/", "SSL-VPN Gateway", "Info", r"sslvpn|vpn|login"),
        ("/vpn/index.html", "Citrix NetScaler Gateway", "Info", r"Citrix|NetScaler|vpn"),
        ("/webfig/", "MikroTik WebFig Router Management", "Info", r"RouterOS|MikroTik|webfig"),
    ],
    5: [
        ("/v2/", "Docker Registry API V2", "High", r"registry|Docker-Distribution"),
        ("/v2/_catalog", "Docker Registry Catalog Exposure", "Critical", r"repositories"),
        ("/containers/json", "Docker Engine Daemon API Exposure", "Critical", r"\[|Id|Image"),
        ("/version", "Docker / K8s Engine Version", "Medium", r"ApiVersion|gitVersion|Version"),
        ("/info", "Docker Daemon Host Info", "High", r"Containers|Images|ServerVersion"),
        ("/pods", "Kubelet Pods Listing", "Critical", r"PodList|items"),
    ],
    6: [
        ("/phpinfo.php", "PHP-CGI / Windows phpinfo()", "Medium", r"PHP Version|Server API"),
        ("/dashboard/", "XAMPP Windows Control Dashboard", "Low", r"XAMPP"),
        ("/xampp/", "XAMPP Root Console", "Low", r"XAMPP"),
        ("/phpmyadmin/", "phpMyAdmin Database Manager", "Medium", r"phpMyAdmin"),
    ],
    7: [
        ("/backup.zip", "Full Site Backup Archive Exposure", "High", None),
        ("/backup.tar.gz", "Tar Gzip Backup Archive Exposure", "High", None),
        ("/db.sql", "Database SQL Dump Exposure", "High", None),
        ("/dump.sql", "SQL Database Dump Exposure", "High", None),
        ("/site.bak", "Site Backup File Exposure", "High", None),
        ("/web.config.bak", "web.config Backup Exposure", "High", None),
        ("/.gitlab-ci.yml", "GitLab CI/CD Pipeline Exposure", "Medium", r"stages|script|image"),
        ("/.env.dev", "Development Environment Secrets Exposure", "High", r"APP_KEY|DB_PASSWORD|="),
    ],
    8: [
        ("/cpanel", "Multi-tenant cPanel Portal", "Info", r"cPanel"),
        ("/webmail", "Shared Webmail Portal", "Info", r"webmail|Roundcube"),
        ("/phpmyadmin/", "phpMyAdmin Multi-tenant Portal", "Medium", r"phpMyAdmin"),
        ("/.well-known/", "ACME / PKI Discovery Directory", "Info", None),
    ]
}

# L2 / MAC Vendor to Device Category and Port Sweep Rules
DEVICE_RULES = [
    (r"fortinet", "firewall", "Firewall / VPN (FortiGate)", [4], [541, 4443, 8443, 10443]),
    (r"palo alto|sonicwall|watchguard|sophos|check ?point|barracuda|netgate|juniper|zyxel", "firewall", "Firewall / VPN", [4], [4433, 4443, 8443]),
    (r"routerboard|mikrotik", "network", "Router (MikroTik)", [4], [8291, 8728, 8729]),
    (r"hikvision|dahua|axis communications|hanwha|uniview", "camera", "IP Camera / NVR", [4], [554, 8000, 8554, 37777]),
    (r"synology|qnap|asustor|terramaster|buffalo", "nas", "NAS / Storage", [4], [5000, 5001, 8080]),
    (r"\bhp inc|\bbrother\b|\bcanon\b|seiko epson|kyocera|ricoh|xerox|lexmark", "printer", "Printer / MFP", [4], [631, 9100]),
    (r"cisco|aruba|ruckus|ubiquiti|tp-link|d-link|netgear|ruijie", "network", "Network Infrastructure", [4], [22, 23, 80, 443, 8080, 8443]),
]


def generate_random_canary_path(length: int = 24) -> str:
    """Generate random non-existent path to establish soft-404 baseline."""
    chars = string.ascii_lowercase + string.digits
    return "/_canary_" + "".join(random.choices(chars, k=length))


def verify_checklist_hit(status_code: int, content_bytes: bytes, text_body: str, signature_regex: Optional[str], baseline_info: dict) -> bool:
    """
    Prevents false positives on Single Page Applications (SPA) and catch-all servers.
    Validates that:
    1. HTTP status is 200, 301, 302, 401, or 403.
    2. Response length and MD5 hash differ from the soft-404 canary baseline.
    3. Body matches signature_regex if specified.
    """
    if status_code not in (200, 301, 302, 401, 403):
        return False

    base_len = baseline_info.get("len", -1)
    base_hash = baseline_info.get("hash", "")
    curr_len = len(content_bytes)
    curr_hash = hashlib.md5(content_bytes[:4096]).hexdigest()

    # If status is 200 on an SPA catch-all, length and hash will match the random canary path
    if status_code == 200 and base_len > 0:
        if abs(curr_len - base_len) < 32 and curr_hash == base_hash:
            return False

    # Signature verification
    if signature_regex:
        if not re.search(signature_regex, text_body, re.IGNORECASE):
            return False

    return True


def detect_edge_product(headers: dict, body: str = "") -> Optional[Dict[str, str]]:
    """Detect Edge WAF / CDN signatures from response headers and body."""
    headers_blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    sample = (headers_blob + " " + (body or "")[:12000]).lower()
    for vendor, product, signature in EDGE_SIGNATURES:
        match = signature.search(sample)
        if match:
            return {"vendor": vendor, "product": product, "evidence": match.group(0)[:100]}
    return None


def identify_products(headers: dict, body: str = "", server: str = "") -> List[Dict[str, Any]]:
    """Passively identify technologies and vendors from HTTP banners, headers and body."""
    headers_blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    sample = (server + " " + headers_blob + " " + (body or "")[:12000])
    detections = []
    seen = set()

    for vendor, product, groups, signature in PRODUCT_SIGNATURES:
        match = signature.search(sample)
        if match:
            key = (vendor, product)
            if key not in seen:
                seen.add(key)
                detections.append({
                    "vendor": vendor,
                    "product": product,
                    "groups": groups,
                    "evidence": match.group(0)[:100],
                    "confidence": "high" if signature.search(headers_blob) else "medium"
                })

    return detections


def classify_thaicert_groups(
    ip_or_host: str,
    server: str,
    headers: dict,
    body_text: str,
    cookies_str: str,
    port: int,
    is_php: bool,
    is_node: bool = False,
    cms_name: str = "",
    checklist_hits: Optional[List[Dict[str, Any]]] = None,
    products: Optional[List[Dict[str, Any]]] = None,
    oui_vendor: Optional[str] = None
) -> dict:
    """
    Tiered Evidence Classification of the target host into the 8 ThaiCERT / NCSA system groups.
    Prioritizes:
    1. Confirmed Exposure Checklist Hits (Verified Sensitive Files)
    2. High-Confidence Product Signatures (38 Signatures)
    3. Hardware / MAC OUI Device Rules (ARP L2 Intelligence)
    4. Hostname Patterns (Dev / UAT / Staging / Backup prefixes)
    5. Specific Management / Protocol Ports (Control Panel, Docker API, VPN, SMB/RDP)
    6. Contextual Service Fallbacks (PHP / Node / Web / Gateway)
    """
    server_lower = (server or "").lower()
    body_lower = (body_text or "").lower()
    headers_str = str(headers or {}).lower()
    cookies_lower = (cookies_str or "").lower()
    host_lower = (ip_or_host or "").lower()

    matched_groups: List[int] = []
    group_labels: List[str] = []
    group_evidence: List[str] = []
    group_details: List[Dict[str, Any]] = []
    seen_groups = set()

    def add_group(g_id: int, label_text: str, reason_text: str, source_type: str = "heuristic"):
        if g_id not in seen_groups and g_id in GROUP_NAMES:
            seen_groups.add(g_id)
            matched_groups.append(g_id)
            group_labels.append(label_text)
            group_evidence.append(reason_text)
            group_details.append({
                "id": g_id,
                "name": GROUP_NAMES[g_id],
                "reason": reason_text,
                "source": source_type
            })

    # --- Tier 1: Confirmed Checklist Hits (Definitive Proof) ---
    for hit in (checklist_hits or []):
        gid = hit.get("group_id") or hit.get("group")
        if gid and gid in GROUP_NAMES:
            add_group(
                gid,
                f"กลุ่ม {gid}: {GROUP_NAMES[gid]} ({hit.get('label', hit.get('path'))})",
                f"Checklist Hit: {hit.get('path')} - {hit.get('label')}",
                "checklist-verified"
            )

    # --- Tier 2: Product & Technology Signatures (High Confidence) ---
    inferred_products = products or identify_products(headers, body_text, server)
    for prod in inferred_products:
        for gid in prod.get("groups", []):
            add_group(
                gid,
                f"กลุ่ม {gid}: {GROUP_NAMES[gid]} ({prod['product']})",
                f"Product Signature: {prod['vendor']} {prod['product']} ({prod.get('evidence', '')})",
                "product-signature"
            )

    # --- Tier 3: Edge WAF / CDN Detection ---
    edge_info = detect_edge_product(headers, body_text)
    if edge_info:
        add_group(
            8,
            f"กลุ่ม 8: บริการภายนอก/Cloud ({edge_info['product']})",
            f"Edge Security: {edge_info['product']} ({edge_info['evidence']})",
            "edge-signature"
        )

    # --- Tier 4: MAC OUI / L2 Hardware Architecture ---
    if oui_vendor:
        for v_regex, cat, dev_title, dev_groups, _ in DEVICE_RULES:
            if re.search(v_regex, oui_vendor, re.IGNORECASE):
                for gid in dev_groups:
                    add_group(
                        gid,
                        f"กลุ่ม {gid}: {GROUP_NAMES[gid]} ({dev_title})",
                        f"MAC OUI (ARP): {oui_vendor} → {dev_title}",
                        "arp-oui"
                    )

    # --- Tier 5: Hostname & Subdomain Classification ---
    if _LEGACY_RE.search(host_lower):
        add_group(
            7,
            "กลุ่ม 7: ระบบทดสอบ/ระบบเก่า/สำรอง (Non-production Hostname)",
            f"Hostname Indicator: {ip_or_host} สื่อถึง dev/test/staging/old/backup",
            "hostname-pattern"
        )

    # --- Tier 6: Port-Based Surface Classification ---
    if port in _PANEL_PORTS:
        add_group(3, "กลุ่ม 3: Hosting Control Panel (Panel Port)", f"เปิดพอร์ตบริหารจัดการ Control Panel {port}", "port-signature")
    if port in _DOCKER_PORTS:
        add_group(5, "กลุ่ม 5: Container & Microservices (Docker/K8s Port)", f"เปิดพอร์ต Container/Registry API {port}", "port-signature")
    if port in _APPLIANCE_PORTS:
        add_group(4, "กลุ่ม 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance Port)", f"เปิดพอร์ตเฉพาะ Appliance/VPN {port}", "port-signature")
    if port in _WINDOWS_PORTS:
        add_group(6, "กลุ่ม 6: Windows PHP Stacks (Windows Port)", f"เปิดพอร์ตโครงสร้างพื้นฐาน Windows {port} (SMB/RDP/WinRM)", "port-signature")

    # --- Tier 7: Heuristic Framework / CMS Rules ---
    # Group 1: CMS & Internal Web Portals
    g1_markers = []
    if any(k in body_lower or k in headers_str for k in ["wp-content", "wp-json", "wp-includes", "wordpress", "corppress"]):
        g1_markers.append("WordPress / CMS")
    if any(k in body_lower or k in headers_str for k in ["drupal", "/sites/default/", "x-generator: drupal"]):
        g1_markers.append("Drupal")
    if any(k in body_lower or k in headers_str for k in ["joomla", "/administrator/"]):
        g1_markers.append("Joomla!")
    if any(k in body_lower or k in cookies_lower for k in ["moodle", "moodlesession"]):
        g1_markers.append("Moodle")
    if any(k in body_lower or k in headers_str for k in ["nextcloud", "nc_same_site"]):
        g1_markers.append("Nextcloud")
    if g1_markers or (is_php and any(k in cms_name.lower() for k in ["wordpress", "drupal", "joomla", "cms", "moodle"])):
        add_group(1, f"กลุ่ม 1: เว็บไซต์/ระบบภายใน ({', '.join(g1_markers) if g1_markers else 'CMS/Internal Web'})",
                  f"CMS Markers: {', '.join(g1_markers) if g1_markers else cms_name}", "web-marker")

    # Group 2: APIs & Backend Frameworks
    g2_markers = []
    if "laravel" in cookies_lower or "x-csrf-token" in headers_str or "laravel" in body_lower:
        g2_markers.append("Laravel Framework")
    if "symfony" in cookies_lower or "_sf2" in cookies_lower or "symfony" in headers_str:
        g2_markers.append("Symfony Framework")
    if "ci_session" in cookies_lower or "codeigniter" in body_lower:
        g2_markers.append("CodeIgniter")
    if "yii" in body_lower or "_csrf" in cookies_lower and "yii" in headers_str:
        g2_markers.append("Yii Framework")
    if "slim" in headers_str or "slim" in body_lower:
        g2_markers.append("Slim Framework")
    if any(k in host_lower for k in ["api.", "/api", "backend.", "mobile."]) or "application/json" in headers_str:
        g2_markers.append("REST API Endpoint")
    if g2_markers:
        add_group(2, f"กลุ่ม 2: หลังบ้านแอป & API ({', '.join(g2_markers)})",
                  f"API/Framework Markers: {', '.join(g2_markers)}", "framework-marker")

    # Group 6: Windows & IIS
    g6_markers = []
    if any(k in server_lower for k in ["microsoft-iis", "iis/"]):
        g6_markers.append("Windows IIS")
    if any(k in server_lower or k in body_lower for k in ["win32", "win64", "windows"]):
        g6_markers.append("Windows OS Architecture")
    if any(k in body_lower or k in server_lower for k in ["xampp", "/xampp/"]):
        g6_markers.append("XAMPP Stack")
    if any(k in body_lower or k in server_lower for k in ["wampserver", "/wamp/"]):
        g6_markers.append("WampServer")
    if any(k in body_lower or k in server_lower for k in ["laragon"]):
        g6_markers.append("Laragon Stack")
    if g6_markers:
        add_group(6, f"กลุ่ม 6: Windows PHP Stacks ({', '.join(g6_markers)})",
                  f"Windows Platform: {', '.join(g6_markers)}", "platform-marker")

    # Group 7: Test / Staging / Debug
    if any(k in body_lower for k in ["phpmyadmin", "debug mode", "app_env=local", "staging environment", "dms staging"]):
        add_group(7, "กลุ่ม 7: ระบบทดสอบ/ระบบเก่า/สำรอง (Debug/Staging Telemetry)", "Debug Mode / Staging Environment Telemetry", "telemetry-marker")

    # --- Tier 8: Intelligent Fallback Rules ---
    if not matched_groups:
        if is_php:
            add_group(1, "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (General PHP Web)", "General PHP Web Application", "fallback")
        elif is_node:
            if any(k in host_lower or k in headers_str for k in ["/api", "api.", "backend", "application/json"]):
                add_group(2, "กลุ่ม 2: ระบบหลังบ้านแอปมือถือ และ API (Node.js API)", "Node.js REST API Service", "fallback")
            else:
                add_group(1, "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (Node.js Web App)", "Node.js Web Application", "fallback")
        elif any(k in server_lower for k in ["microsoft-iis", "windows", "win32", "win64"]):
            add_group(6, "กลุ่ม 6: Windows Server Application", "Windows Operating Environment", "fallback")
        elif port in [3000, 5000, 5173, 8000, 8080, 8888, 4000]:
            add_group(7, f"กลุ่ม 7: ระบบทดสอบ/ระบบเก่า/สำรอง (Development Port {port})", f"Development/Staging Port {port}", "fallback")
        elif any(k in server_lower for k in ["apache", "nginx", "caddy", "litespeed", "lighttpd"]) or port in [80, 443, 8008, 8081]:
            if "application/json" in headers_str or "/api" in host_lower:
                add_group(2, "กลุ่ม 2: ระบบหลังบ้านแอปมือถือ และ API (Web API)", "REST Web API Service", "fallback")
            else:
                add_group(1, "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (Web Service)", "Web Application Service", "fallback")
        elif any(k in host_lower for k in [".1", ".254"]) or port in [53, 67, 161, 554]:
            add_group(4, "กลุ่ม 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Network Device / Gateway)", "Network Infrastructure Device", "fallback")
        else:
            add_group(1, "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (Web Service)", "General Web Service", "fallback")

    primary = group_labels[0] if group_labels else "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร"
    unique_groups = sorted(list(set(matched_groups)))
    arch_matrix = evaluate_group_architecture_matrix(
        groups=unique_groups,
        is_php=is_php,
        php_version="",
        server=server,
        has_lfi=False,
        is_patched=False,
        is_fpm=("fpm" in server_lower or "nginx" in server_lower)
    )

    return {
        "groups": unique_groups,
        "primary_group": primary,
        "group_labels": group_labels,
        "evidence": list(set(group_evidence)),
        "group_details": group_details,
        "edge_product": edge_info,
        "profiles": [THAICERT_GROUP_PROFILES[g] for g in unique_groups if g in THAICERT_GROUP_PROFILES],
        "architecture_matrix": arch_matrix
    }

