"""
ThaiCERT & NCSA Compliance Rules
Classifies targets into the 8 official ThaiCERT system groups:
1. เว็บไซต์และระบบภายในองค์กร (CMS / Internal Web)
2. ระบบหลังบ้านแอปมือถือ และ API
3. Hosting Control Panel
4. ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance, NAS, IoT/SCADA)
5. Container และ Docker Image
6. Windows ที่มี PHP ติดตั้งอยู่ (CVE-2024-4577 Priority)
7. ระบบทดสอบ ระบบเก่า และระบบสำรอง
8. ระบบที่ผู้ให้บริการภายนอกดูแล
"""

import re
from typing import Dict, Any, List

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


def classify_thaicert_groups(ip_or_host: str, server: str, headers: dict, body_text: str, cookies_str: str, port: int, is_php: bool, is_node: bool, cms_name: str) -> dict:
    """
    Classifies the target host into the 8 ThaiCERT / NCSA target system groups:
    1. เว็บไซต์และระบบภายในองค์กร (WordPress, Drupal, Joomla, Moodle, Nextcloud)
    2. ระบบหลังบ้านแอปมือถือ และ API (Laravel, Symfony, CodeIgniter, Yii, Slim, REST API)
    3. Hosting Control Panel (cPanel, Plesk, DirectAdmin, Webmin)
    4. ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Vendor Portal, Network Appliance, NAS, ระบบอุตสาหกรรม)
    5. Container และ Docker Image (Docker, Kubernetes, Podman, Microservices)
    6. Windows ที่มี PHP ติดตั้งอยู่ (Windows IIS, XAMPP, WampServer, Laragon - CVE-2024-4577 Priority)
    7. ระบบทดสอบ ระบบเก่า และระบบสำรอง (Development, UAT, Staging, DR, Snapshot, Lingering)
    8. ระบบที่ผู้ให้บริการภายนอกดูแล (Shared Hosting, Managed Hosting, Cloud VM, Outsourced)
    """
    server_lower = (server or "").lower()
    body_lower = (body_text or "").lower()
    headers_str = str(headers or {}).lower()
    cookies_lower = (cookies_str or "").lower()
    host_lower = (ip_or_host or "").lower()

    matched_groups = []
    group_labels = []
    group_evidence = []

    # --- Group 1: เว็บไซต์และระบบภายในองค์กร ---
    g1_markers = []
    if any(k in body_lower or k in headers_str for k in ["wp-content", "wp-json", "wp-includes", "wordpress"]):
        g1_markers.append("WordPress")
    if any(k in body_lower or k in headers_str for k in ["drupal", "/sites/default/", "x-generator: drupal"]):
        g1_markers.append("Drupal")
    if any(k in body_lower or k in headers_str for k in ["joomla", "/administrator/"]):
        g1_markers.append("Joomla!")
    if any(k in body_lower or k in cookies_lower for k in ["moodle", "moodlesession"]):
        g1_markers.append("Moodle")
    if any(k in body_lower or k in headers_str for k in ["nextcloud", "nc_same_site"]):
        g1_markers.append("Nextcloud")
    if g1_markers or (is_php and any(k in cms_name.lower() for k in ["wordpress", "drupal", "joomla", "cms", "moodle"])):
        matched_groups.append(1)
        name = f"กลุ่ม 1: เว็บไซต์/ระบบภายใน ({', '.join(g1_markers) if g1_markers else 'CMS/Internal Web'})"
        group_labels.append(name)
        group_evidence.extend(g1_markers or ["Internal Web / CMS Portal"])

    # --- Group 2: ระบบหลังบ้านแอปมือถือ และ API ---
    g2_markers = []
    if "laravel" in cookies_lower or "x-csrf-token" in headers_str or "laravel" in body_lower:
        g2_markers.append("Laravel Framework")
    if "symfony" in cookies_lower or "_sf2" in cookies_lower or "symfony" in headers_str:
        g2_markers.append("Symfony")
    if "ci_session" in cookies_lower or "codeigniter" in body_lower:
        g2_markers.append("CodeIgniter")
    if "yii" in body_lower or "_csrf" in cookies_lower and "yii" in headers_str:
        g2_markers.append("Yii Framework")
    if "slim" in headers_str or "slim" in body_lower:
        g2_markers.append("Slim Framework")
    if any(k in host_lower for k in ["api.", "/api", "backend.", "mobile."]) or "application/json" in headers_str:
        g2_markers.append("REST API Endpoint")
    if g2_markers:
        matched_groups.append(2)
        group_labels.append(f"กลุ่ม 2: หลังบ้านแอป & API ({', '.join(g2_markers)})")
        group_evidence.extend(g2_markers)

    # --- Group 3: Hosting Control Panel ---
    g3_markers = []
    if port in [2082, 2083, 2086, 2087] or "cpanel" in body_lower or "cpanel" in server_lower:
        g3_markers.append("cPanel")
    if port in [8443, 8880] or "plesk" in server_lower or "plesk" in headers_str:
        g3_markers.append("Plesk Panel")
    if port in [2222] or "directadmin" in body_lower or "directadmin" in server_lower:
        g3_markers.append("DirectAdmin")
    if port in [10000] or "webmin" in body_lower or "miniserv" in server_lower:
        g3_markers.append("Webmin Panel")
    if g3_markers:
        matched_groups.append(3)
        group_labels.append(f"กลุ่ม 3: Hosting Control Panel ({', '.join(g3_markers)})")
        group_evidence.extend(g3_markers)

    # --- Group 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance, NAS, IoT/SCADA) ---
    g4_markers = []
    if any(k in server_lower or k in body_lower for k in ["synology", "diskstation", "dsm", "qts", "qnap", "truenas"]):
        g4_markers.append("NAS Storage Appliance")
    if any(k in server_lower or k in body_lower for k in ["mikrotik", "webfig", "pfsense", "fortigate", "fortios", "openwrt", "unifi"]):
        g4_markers.append("Network Appliance / Router")
    if any(k in server_lower or k in body_lower for k in ["jetdirect", "canon", "ricoh", "xerox", "brother", "hikvision", "dahua"]):
        g4_markers.append("Vendor Device / Peripheral")
    if any(k in server_lower or k in body_lower for k in ["scada", "plc", "modbus", "siemens", "schneider"]):
        g4_markers.append("Industrial ICS/SCADA Web")
    if g4_markers:
        matched_groups.append(4)
        group_labels.append(f"กลุ่ม 4: อุปกรณ์สำเร็จรูป & Appliance ({', '.join(g4_markers)})")
        group_evidence.extend(g4_markers)

    # --- Group 5: Container และ Docker Image ---
    g5_markers = []
    if any(k in server_lower or k in headers_str for k in ["traefik", "k8s", "envoy", "kong", "ingress", "portainer"]):
        g5_markers.append("Kubernetes / Ingress Gateway")
    if any(k in host_lower for k in ["172.17.", "172.18.", "10.42.", "10.244."]) or port in [9000, 9443]:
        g5_markers.append("Docker / Container Network")
    if g5_markers:
        matched_groups.append(5)
        group_labels.append(f"กลุ่ม 5: Container & Microservices ({', '.join(g5_markers)})")
        group_evidence.extend(g5_markers)

    # --- Group 6: Windows ที่มี PHP ติดตั้งอยู่ (CVE-2024-4577 High Priority) ---
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
        matched_groups.append(6)
        group_labels.append(f"กลุ่ม 6: Windows PHP Stacks ({', '.join(g6_markers)})")
        group_evidence.extend(g6_markers)

    # --- Group 7: ระบบทดสอบ ระบบเก่า และระบบสำรอง (Dev, UAT, Staging, DR, Lingering) ---
    g7_markers = []
    if any(k in host_lower for k in ["dev.", "uat.", "test.", "stage.", "staging.", "dr.", "backup.", "old.", "lab."]):
        g7_markers.append("Non-production Hostname Prefix")
    if port in [3000, 5000, 5173, 4000, 8000, 8080, 8888, 8081, 18080]:
        g7_markers.append(f"Development Port {port}")
    if any(k in body_lower for k in ["phpmyadmin", "debug mode", "app_env=local", "staging environment"]):
        g7_markers.append("Debug / Admin Lingering Tool")
    if g7_markers:
        matched_groups.append(7)
        group_labels.append(f"กลุ่ม 7: ระบบทดสอบ/ระบบเก่า/สำรอง ({', '.join(g7_markers)})")
        group_evidence.extend(g7_markers)

    # --- Group 8: ระบบที่ผู้ให้บริการภายนอกดูแล (Cloud VM & Outsourced) ---
    g8_markers = []
    if any(k in server_lower or k in headers_str for k in ["cloudflare", "cloudfront", "fastly", "akamai"]):
        g8_markers.append("Edge Cloud CDN/Proxy")
    if any(k in host_lower for k in ["amazonaws.com", "googleusercontent.com", "azure.com", "digitalocean"]):
        g8_markers.append("Cloud Provider VM")
    if g8_markers:
        matched_groups.append(8)
        group_labels.append(f"กลุ่ม 8: บริการภายนอก/Cloud ({', '.join(g8_markers)})")
        group_evidence.extend(g8_markers)

    # Fallback if no specific group matched
    if not matched_groups:
        if is_php:
            matched_groups = [1]
            group_labels = ["กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (General PHP Web)"]
            group_evidence = ["General PHP Web Application"]
        else:
            matched_groups = [4]
            group_labels = ["กลุ่ม 4: ซอฟต์แวร์/อุปกรณ์ทั่วไปในเครือข่าย"]
            group_evidence = ["General Network Service"]

    primary = group_labels[0]
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
        "profiles": [THAICERT_GROUP_PROFILES[g] for g in unique_groups if g in THAICERT_GROUP_PROFILES],
        "architecture_matrix": arch_matrix
    }

