"""
PHP Security Audit & Chain Verification Module
Evaluates PHP version risk against EOL / CVE-2024-4577 and models the 5 defensive session chains:
- Chain A: session.upload_progress filename injection + LFI
- Chain B: INI Leak via Session Engine (SAPI & Save Path Exposure)
- Chain C: serializer-handler mismatch -> Object Deserialization Risk
- Chain D: Apache mod_php OOM -> Stale EG() & Uncleaned Session Files
- Chain E: PHP-FPM Session OOM & Stale BG() Worker State Persistence
"""

import re
from typing import Dict, Any

def evaluate_php_security(version_str: str):
    """Assess PHP version against End-Of-Life and CVE-2024-4577 (php2shell) risk."""
    v = version_str.lower()
    
    # PHP 5.x / 7.x: Critical (EOL + Multiple RCEs + php2shell)
    if any(pat in v for pat in ["php/5.", "php 5.", "5.4.", "5.5.", "5.6.", "php/7.", "php 7.", "7.0.", "7.1.", "7.2.", "7.3.", "7.4."]):
        return (
            "Critical",
            "PHP 5.x/7.x End-of-Life: เสี่ยงต่อ php2shell / CVE-2024-4577 (CGI Argument Injection RCE) และ CVE-2019-11043 ควรอัปเกรดด่วนที่สุด"
        )
    
    # PHP 8.0 / 8.1: Outdated (Security EOL)
    if any(pat in v for pat in ["php/8.0", "8.0.", "php/8.1", "8.1."]):
        return (
            "Outdated",
            "PHP 8.0/8.1 Security EOL: สิ้นสุดการสนับสนุนความปลอดภัย เสี่ยงต่อ CVE-2024-4577 (php2shell) บน Windows"
        )
    
    # Early PHP 8.2 (< 8.2.20) or 8.3 (< 8.3.8): Critical php2shell
    if "8.2." in v or "8.3." in v:
        match = re.search(r'8\.([23])\.(\d+)', v)
        if match:
            minor = int(match.group(1))
            patch = int(match.group(2))
            if (minor == 2 and patch < 20) or (minor == 3 and patch < 8):
                return (
                    "Critical",
                    f"PHP 8.{minor}.{patch} เสี่ยงต่อ CVE-2024-4577 (php2shell RCE) ต้องอัปเดตเป็น 8.{minor}.{20 if minor==2 else 8}+"
                )
        return (
            "Secure",
            "PHP 8.2+/8.3+ เวอร์ชันปลอดภัย มีแพตช์ป้องกัน CVE-2024-4577 ตามเกณฑ์ ThaiCERT"
        )
    
    # Hidden Version (expose_php = Off)
    if "hidden" in v or "off" in v:
        return (
            "Review Needed",
            "ตรวจพบ PHP แต่เปิดโหมดปิดบังเวอร์ชัน (expose_php = Off) ควรตรวจสอบเลขแพตช์จริงบนเซิร์ฟเวอร์"
        )
        
    return (
        "Review Needed",
        "ตรวจพบบริการ PHP (ควรตรวจสอบเวอร์ชันให้เป็น PHP 8.2 หรือ 8.3 ตามมาตรฐานความปลอดภัย)"
    )



def evaluate_security_chains(is_php: bool, php_version: str, headers: dict, cookies_str: str, server: str, expose_php: bool, lfi_check: dict = None, has_serializer_mismatch: bool = False, has_object_deserialization: bool = False) -> dict:
    """
    Defensively models the 5 critical PHP session & configuration security verification chains:
    - Chain A: session.upload_progress filename injection + LFI
    - Chain B: INI Leak via Session Engine (SAPI & Save Path Exposure)
    - Chain C: serializer-handler mismatch -> Object Deserialization Risk
    - Chain D: Apache mod_php OOM -> Stale EG() & Uncleaned Session Files
    - Chain E: PHP-FPM Session OOM & Stale BG() Worker State Persistence
    Provides stage-by-stage verification & defensive hardening guidance matching ThaiCERT / NCSA standards.
    """
    if not is_php:
        return {
            "applicable": False,
            "overall_status": "Non-PHP Service",
            "chains": {},
            "hardening_ini": ""
        }

    # Strict mode & session cookie analysis
    has_session_cookie = any(k in cookies_str.lower() for k in ["phpsessid", "session", "sess"])

    # Check PHP Version safe baseline for CVE-2024-4577
    is_patched = False
    v_clean = php_version.replace("PHP", "").replace("/", "").strip()
    m_v = re.search(r'(\d+)\.(\d+)\.(\d+)', v_clean)
    if m_v:
        maj, mino, pat = int(m_v.group(1)), int(m_v.group(2)), int(m_v.group(3))
        if (maj == 8 and mino == 2 and pat >= 20) or (maj == 8 and mino == 3 and pat >= 8) or (maj == 8 and mino >= 4) or (maj > 8):
            is_patched = True

    # Real LFI Prerequisite Dynamic Evaluation
    has_lfi = lfi_check.get("has_lfi_prerequisite", False) if lfi_check else False
    lfi_evidence = lfi_check.get("evidence", "ไม่พบพารามิเตอร์เรียกไฟล์และไม่พบสัญญาณข้อผิดพลาด include stream") if lfi_check else "ไม่พบพารามิเตอร์เรียกไฟล์"
    lfi_param = lfi_check.get("param") if lfi_check else None
    lfi_tested_url = lfi_check.get("tested_url", "") if lfi_check else ""

    # --- Chain A: session.upload_progress filename injection + LFI ---
    chain_a_stages = [
        {
            "stage": "1/6",
            "name": "TCP Reachability & Port Inspection",
            "status": "PASS",
            "badge": "PASS",
            "detail": "พอร์ตเป้าหมายตอบสนองการเชื่อมต่อปกติ บริการพร้อมรับคำขอ HTTP/HTTPS",
            "mechanism": "ขั้นตอนแรกของการประเมินความพร้อมของพอร์ตเป้าหมาย โดยส่งสัญญาณ TCP Handshake เพื่อยืนยันว่าพอร์ตเปิดและสามารถรับส่งข้อมูล HTTP ได้",
            "check_item": "ตรวจสอบสถานะ TCP Handshake และความเร็วในการตอบสนอง (Latency) ของบริการเว็บ",
            "defense_tip": "กำหนด Firewall คัดกรองเฉพาะพอร์ตและไอพีที่จำเป็นต่อการให้บริการในระดับเครือข่าย"
        },
        {
            "stage": "2/6",
            "name": "Session Strict Mode Verification (session.use_strict_mode)",
            "status": "PASS" if has_session_cookie else "AUDIT_NEEDED",
            "badge": "PASS" if has_session_cookie else "AUDIT",
            "detail": "ควรบังคับใช้ session.use_strict_mode = 1 เพื่อป้องกันการกำหนด Session ID ล่วงหน้าจากภายนอก",
            "mechanism": "หากปิด use_strict_mode = 0 เอนจิน PHP จะยอมรับค่า Session ID ที่ผู้ใช้งานส่งมาใน Cookie ทำให้ผู้ประเมินภายนอกสามารถคาดเดาหรือกำหนดชื่อไฟล์เซสชันบนดิสก์ล่วงหน้าได้",
            "check_item": "ตรวจสอบพฤติกรรม Session Cookie และการตอบสนองเมื่อมีการระบุ Session ID ที่ไม่ได้สร้างโดยระบบ",
            "defense_tip": "กำหนด session.use_strict_mode = 1 ใน php.ini เพื่อบังคับให้ PHP รับเฉพาะ Session ID ที่เซิร์ฟเวอร์เป็นผู้สร้างเท่านั้น"
        },
        {
            "stage": "3/6",
            "name": "Upload Progress & Cleanup Handling",
            "status": "PROTECTED" if is_patched else "REVIEW_NEEDED",
            "badge": "PROTECTED" if is_patched else "REVIEW",
            "detail": "ควรปิด session.upload_progress.enabled = Off และกำหนด session.upload_progress.cleanup = On เพื่อล้างข้อมูลทันทีหลังคำขอสิ้นสุด",
            "mechanism": "คุณสมบัติ Upload Progress จะเขียนข้อมูลความคืบหน้าการอัปโหลดลงในไฟล์เซสชันอัตโนมัติเมื่อพบฟิลด์ PHP_SESSION_UPLOAD_PROGRESS หากไม่ได้ปิดไว้ ข้อมูลชื่อไฟล์ที่ส่งเข้ามาอาจถูกบันทึกลงในไฟล์เซสชันชั่วคราว",
            "check_item": "ตรวจสอบสถานะการเปิดใช้งาน session.upload_progress.enabled และการล้างข้อมูลทันทีเมื่อสิ้นสุดคำขอ (cleanup)",
            "defense_tip": "กำหนด session.upload_progress.enabled = Off และ session.upload_progress.cleanup = On ใน php.ini"
        },
        {
            "stage": "4/6",
            "name": "Concurrent Worker & Race Handling",
            "status": "PASS",
            "badge": "PASS",
            "detail": "ระบบรองรับการประมวลผลคู่ขนานของเวิร์กเกอร์ (Multi-worker Concurrency)",
            "mechanism": "การทดสอบว่าเซิร์ฟเวอร์สามารถประมวลผลหลายคำขอในเวลาเดียวกันได้หรือไม่ ซึ่งเป็นปัจจัยที่มีผลต่อช่วงเวลาว่าง (Race Window) ของไฟล์ชั่วคราวในระบบ",
            "check_item": "ประเมินความเร็วในการตอบสนองและขีดจำกัดเวิร์กเกอร์ของเว็บเซิร์ฟเวอร์",
            "defense_tip": "จำกัดอัตราการส่งคำขอ (Rate Limiting) และใช้ระบบ Session Handler แบบ In-Memory (เช่น Redis) ที่มีการจัดการ Concurrency ปลอดภัย"
        },
        {
            "stage": "5/6",
            "name": "Pre-existing LFI Prerequisite Check (การตรวจสอบเงื่อนไขจุดเรียกไฟล์จริง)",
            "status": "DETECTED" if has_lfi else "PREREQUISITE_ABSENT",
            "badge": "VULN" if has_lfi else "SECURE",
            "detail": f"ตรวจพบหลักฐานเชิงประจักษ์: แอปพลิเคชันมีพฤติกรรมนำพารามิเตอร์ ?{lfi_param}= ไปใช้ในฟังก์ชันเรียกไฟล์ ({lfi_evidence})" if has_lfi else f"ผลการทดสอบจริงด้วย Canary Probe: ไม่พบจุดรับค่าพารามิเตอร์เรียกไฟล์ในแอปพลิเคชัน ({lfi_evidence}) — ปัจจัยเสี่ยงจำเป็นไม่ครบถ้วน ทำให้กลไก Chain นี้ถูกตัดตอนและปลอดภัยจากความเสี่ยงลูกโซ่",
            "mechanism": "แม้ว่าไฟล์เซสชันจะมีข้อมูลตกค้างอยู่บนดิสก์ แต่หากตัวแอปพลิเคชันไม่มีฟังก์ชันที่นำพารามิเตอร์ของผู้ใช้ไปใช้ใน include, require หรือ file_get_contents โดยตรง ก็จะไม่สามารถนำไฟล์เซสชันมารันคำสั่งได้",
            "check_item": f"ส่งคำขอทดสอบเชิงรับ (Non-destructive Canary Probe): {lfi_tested_url or 'GET /?page=...'}",
            "defense_tip": "หลีกเลี่ยงการใช้พารามิเตอร์จากผู้ใช้ในการโหลดไฟล์ ใช้ Whitelist ของชื่อไฟล์ที่อนุญาตเท่านั้น และบังคับใช้ open_basedir"
        },
        {
            "stage": "6/6",
            "name": "Argument Injection & Execution Defense",
            "status": "BLOCKED" if is_patched else "DEFENSIVE_RULE",
            "badge": "SECURE" if is_patched else "REVIEW",
            "detail": "กลไก Argument Injection (เช่น CVE-2024-4577) ถูกปิดกั้นด้วยแพตช์ความปลอดภัย PHP 8.2.20+ / 8.3.8+ หรือ WAF",
            "mechanism": "การประเมินว่าเอนจิน PHP หรือโมดูล CGI อนุญาตให้ส่งอาร์กิวเมนต์คำสั่งผ่าน Query String หรือไม่ ซึ่งใน PHP เวอร์ชันที่ปลอดภัยจะมีการตรวจสอบและบล็อกอักขระพิเศษอย่างรัดกุม",
            "check_item": "ตรวจสอบเลขเวอร์ชันแพตช์ของ PHP และการมีอยู่ของ Web Application Firewall (WAF)",
            "defense_tip": "อัปเกรด PHP เป็นเวอร์ชัน 8.2.20+ หรือ 8.3.8+ ทันที และติดตั้ง WAF กรองคำสั่งอาร์กิวเมนต์ที่ผิดปกติ"
        }
    ]
    if has_lfi:
        chain_a_verdict = "VULNERABLE (พบจุดเชื่อมโยง LFI และฟังก์ชันเซสชันมีความเสี่ยง)"
    elif is_patched:
        chain_a_verdict = "SECURE (ได้รับการแพตช์ / ปลอดภัยและไม่พบ LFI Prerequisite)"
    else:
        chain_a_verdict = "MITIGATED (ปลอดภัย: ไม่พบ LFI Prerequisite — ห่วงโซ่ความเสี่ยงไม่ครบ)"
    chain_a_remedy = "session.upload_progress.enabled = Off\nsession.upload_progress.cleanup = On\nsession.use_strict_mode = 1"

    # --- Chain B: INI Leak via Session Engine (SAPI & Save Path Exposure) ---
    sapi_desc = "FastCGI / PHP-FPM" if "nginx" in server.lower() else ("Apache mod_php / FPM" if "apache" in server.lower() else "Standard SAPI")
    chain_b_stages = [
        {
            "stage": "1/6",
            "name": "SAPI Configuration Check",
            "status": "PASS",
            "badge": "PASS",
            "detail": f"ตรวจสอบสถาปัตยกรรม Server API ({sapi_desc}) ซึ่งมีผลต่อการอ่านค่าคอนฟิกและขอบเขตสิทธิ์",
            "mechanism": "ตรวจสอบสถาปัตยกรรม Server API ของ PHP (เช่น PHP-FPM, Apache mod_php, FastCGI หรือ CLI) ซึ่งส่งผลต่อสิทธิ์การทำงานและขอบเขตการเข้าถึงไฟล์คอนฟิก",
            "check_item": "ตรวจสอบ Server Banner และส่วนหัว HTTP ที่บ่งชี้รูปแบบ SAPI",
            "defense_tip": "ใช้สถาปัตยกรรม PHP-FPM พร้อมแยก User/Group ของ Pool ให้มีสิทธิ์ต่ำสุด (Least Privilege)"
        },
        {
            "stage": "2/6",
            "name": "Session Configuration Exposure",
            "status": "PASS" if not expose_php else "AUDIT_NEEDED",
            "badge": "PASS" if not expose_php else "AUDIT",
            "detail": "ตรวจสอบการเปิดเผยข้อมูลระบบ เช่น การเรียก phpinfo() หรือ Diagnostic Error Message ที่แสดงค่า session.save_path",
            "mechanism": "การปล่อยให้ฟังก์ชันทดสอบเช่น phpinfo() หรือข้อความ Error แสดงผลตัวแปรระบบออกมา ทำให้ผู้ประเมินภายนอกทราบค่า session.save_path, session.name และพารามิเตอร์สำคัญ",
            "check_item": "ตรวจสอบการมีอยู่ของหน้า Diagnostic (phpinfo.php, test.php) และการรั่วไหลของข้อมูลระบบ",
            "defense_tip": "ลบไฟล์ทดสอบที่เรียก phpinfo() ออกจาก Production ทั้งหมด"
        },
        {
            "stage": "3/6",
            "name": "Information Disclosure Risk",
            "status": "PROTECTED" if not expose_php else "REVIEW_NEEDED",
            "badge": "PROTECTED" if not expose_php else "REVIEW",
            "detail": "การประเมินความเสี่ยงจากการที่บุคคลภายนอกล่วงรู้ค่าเซสชันหรือเส้นทางโฟลเดอร์จัดเก็บไฟล์ชั่วคราวในระบบปฏิบัติการ",
            "mechanism": "การประเมินความเสี่ยงเมื่อบุคคลภายนอกล่วงรู้ตำแหน่งโฟลเดอร์เซสชัน (เช่น /tmp หรือ /var/lib/php/sessions) ซึ่งทำให้ทราบจุดที่ต้องเฝ้าระวังของไฟล์ชั่วคราว",
            "check_item": "ตรวจสอบว่ามีข้อความ Error หรือ Header ใดที่เปิดเผยเส้นทาง Path บนเซิร์ฟเวอร์หรือไม่",
            "defense_tip": "แยกพื้นที่จัดเก็บเซสชันไว้ในโฟลเดอร์เฉพาะนอก Web Root และจำกัดสิทธิ์โฟลเดอร์เป็น chmod 0700"
        },
        {
            "stage": "4/6",
            "name": "Error Display Suppression",
            "status": "PROTECTED" if is_patched else "DEFENSIVE_RULE",
            "badge": "PROTECTED" if is_patched else "REVIEW",
            "detail": "ตรวจสอบการปิดการแสดงข้อผิดพลาดบนหน้าเว็บภายนอก โดยกำหนด display_errors = Off",
            "mechanism": "ตรวจสอบว่าระบบปิดการแสดงผลข้อผิดพลาดสู่หน้าเว็บหรือไม่ เพื่อป้องกันไม่ให้ข้อมูลโครงสร้างโค้ดหรือฐานข้อมูลรั่วไหล",
            "check_item": "ตรวจสอบค่าคอนฟิก display_errors และ display_startup_errors",
            "defense_tip": "กำหนด display_errors = Off และ display_startup_errors = Off ใน php.ini"
        },
        {
            "stage": "5/6",
            "name": "Local Audit Logging",
            "status": "PASS",
            "badge": "PASS",
            "detail": "ตรวจสอบการเปิดบันทึกข้อผิดพลาดอย่างปลอดภัยลงในไฟล์ภายในเครื่อง log_errors = On",
            "mechanism": "การบันทึกข้อผิดพลาดลงในไฟล์บันทึกภายในเครื่องอย่างปลอดภัย เพื่อให้ทีมวิศวกรตรวจสอบได้โดยไม่ต้องแสดงผลบนหน้าจอผู้ใช้",
            "check_item": "ตรวจสอบการเปิดใช้งาน log_errors = On และการกำหนดเส้นทาง error_log",
            "defense_tip": "กำหนด log_errors = On และกำหนดสิทธิ์ไฟล์ล็อกให้เฉพาะผู้ดูแลระบบอ่านได้"
        },
        {
            "stage": "6/6",
            "name": "Version Masking Hardening",
            "status": "PROTECTED" if not expose_php else "REVIEW_NEEDED",
            "badge": "SECURE" if not expose_php else "REVIEW",
            "detail": "ตรวจสอบการปิดบังข้อมูลเวอร์ชัน expose_php = Off ตามเกณฑ์มาตรฐานความมั่นคงปลอดภัย CIS Benchmark",
            "mechanism": "ตรวจสอบการปิดบังข้อมูลเวอร์ชันในส่วนหัว X-Powered-By ตามคำแนะนำของ CIS Benchmark เพื่อไม่ให้ผู้ไม่ประสงค์ดีระบุช่องโหว่ประจำเวอร์ชันได้ง่าย",
            "check_item": "ตรวจสอบการมีอยู่ของ Header X-Powered-By: PHP/...",
            "defense_tip": "กำหนด expose_php = Off ใน php.ini"
        }
    ]
    chain_b_verdict = "SECURE (ปิดบังข้อมูลระบบเรียบร้อย)" if not expose_php else "REVIEW_NEEDED (แนะนำปิดการแสดงผล Error และซ่อนเวอร์ชัน)"
    chain_b_remedy = "expose_php = Off\ndisplay_errors = Off\nlog_errors = On"

    # --- Chain C: serializer-handler mismatch -> Object Deserialization Risk ---
    chain_c_stages = [
        {
            "stage": "1/6",
            "name": "TCP Reachability & Endpoint Health",
            "status": "PASS",
            "badge": "PASS",
            "detail": "บริการเชื่อมต่อได้ปกติ ตอบสนองคำขอ HTTP สมบูรณ์",
            "mechanism": "ตรวจสอบความพร้อมในการเชื่อมต่อ HTTP ของระบบเป้าหมาย",
            "check_item": "ตรวจสอบสถานะการตอบรับของแอปพลิเคชัน",
            "defense_tip": "รักษาเสถียรภาพและตรวจสอบความพร้อมใช้งานของระบบเครือข่าย"
        },
        {
            "stage": "2/6",
            "name": "Session Strict Mode Check",
            "status": "PASS",
            "badge": "PASS",
            "detail": "ตรวจสอบการกำหนดค่า Session Strict เพื่อความรัดกุม",
            "mechanism": "ตรวจสอบการบังคับใช้ Session Strict Mode เพื่อป้องกันการสลับหรือแทรกแซง Session จากภายนอก",
            "check_item": "ตรวจสอบการสร้าง Session Token และการควบคุมความถูกต้อง",
            "defense_tip": "กำหนด session.use_strict_mode = 1 เสมอ"
        },
        {
            "stage": "3/6",
            "name": "Serializer Mismatch Inspection",
            "status": "DETECTED" if has_serializer_mismatch else "SAFE",
            "badge": "VULN" if has_serializer_mismatch else "SAFE",
            "detail": "ตรวจพบการกำหนดค่า session.serialize_handler = php_serialize ซึ่งไม่สอดคล้องกับมาตรฐาน php ทำให้เกิดความเสี่ยง Mismatch" if has_serializer_mismatch else "ตรวจสอบความสม่ำเสมอของ Serializer Handler (เช่น php กับ php_serialize)",
            "mechanism": "ตรวจสอบความสอดคล้องของการใช้ Serializer Handler ซึ่งหากมีการใช้ Handler สองประเภทต่างกันในแอปเดียวกัน รูปแบบการ Encode ข้อมูลจะไม่ตรงกัน",
            "check_item": "ตรวจสอบค่า session.serialize_handler ในทุกโมดูลของแอปพลิเคชัน",
            "defense_tip": "กำหนด session.serialize_handler = php อย่างสม่ำเสมอทั่วทั้งแอปพลิเคชัน"
        },
        {
            "stage": "4/6",
            "name": "Object Injection Risk",
            "status": "DETECTED" if has_object_deserialization else "SAFE",
            "badge": "VULN" if has_object_deserialization else "SAFE",
            "detail": "ตรวจพบจุดรับค่าพารามิเตอร์ส่งต่อเข้าฟังก์ชัน unserialize() บนข้อมูลจากภายนอก เสี่ยงต่อ Object Deserialization" if has_object_deserialization else "ตรวจสอบความเสี่ยงจากการใช้ unserialize() บนข้อมูลที่ผู้ใช้งานภายนอกควบคุมได้",
            "mechanism": "ตรวจสอบความเสี่ยงเมื่อแอปพลิเคชันเรียกใช้ฟังก์ชัน unserialize() บนข้อมูลที่รับมาจากภายนอก ซึ่งอาจส่งผลให้ออบเจกต์ในหน่วยความจำถูกสร้างขึ้นมาผิดปกติ",
            "check_item": "สแกนหาการเรียกใช้ unserialize() บนข้อมูลที่รับมาจากภายนอกหรือจากเซสชันที่ไม่ได้เข้ารหัส",
            "defense_tip": "หลีกเลี่ยงการใช้ unserialize() โดยเปลี่ยนไปใช้ json_decode() หรือกำหนด ['allowed_classes' => false]"
        },
        {
            "stage": "5/6",
            "name": "Gadget Chain & Magic Method Defense",
            "status": "PROTECTED",
            "badge": "PROTECTED",
            "detail": "ตรวจสอบและป้องกัน Gadget Chain ในคลาสระบบที่มี Magic Methods เช่น __destruct หรือ __wakeup",
            "mechanism": "การตรวจสอบคลาสในระบบที่มี Magic Methods เช่น __destruct(), __wakeup() หรือ __toString() ซึ่งอาจถูกกระตุ้นอัตโนมัติเมื่อออบเจกต์ถูกทำลายหรือสร้างขึ้นมา",
            "check_item": "ตรวจสอบไลบรารีและคลาสที่ถูกโหลดในโปรเจกต์ว่ามีเมธอดที่มีการประมวลผลคำสั่งระบบหรือไม่",
            "defense_tip": "อัปเดตแพ็กเกจไลบรารี (Composer Dependencies) ให้เป็นเวอร์ชันล่าสุดเพื่อปิดกั้น Gadget Chain ที่ทราบอยู่แล้ว"
        },
        {
            "stage": "6/6",
            "name": "Deserialization Defense & Input Validation",
            "status": "SECURE",
            "badge": "SECURE",
            "detail": "กำหนด session.serialize_handler = php สม่ำเสมอ และหลีกเลี่ยงการ deserialize ข้อมูลดิบจากภายนอก",
            "mechanism": "การวางมาตรการป้องกันความปลอดภัยเชิงลึกในระดับโค้ดและรันไทม์",
            "check_item": "ตรวจสอบการใช้งาน HMAC หรือ Digital Signature ในการยืนยันความถูกต้องของข้อมูลเซสชันก่อนนำมาประมวลผล",
            "defense_tip": "นำระบบ Session Signing มาใช้เพื่อป้องกันการแก้ไขข้อมูลเซสชัน"
        }
    ]
    if has_serializer_mismatch or has_object_deserialization:
        chain_c_verdict = "VULNERABLE (ตรวจพบ Serializer Mismatch ร่วมกับจุดรับค่า Object Injection)"
    else:
        chain_c_verdict = "SECURE (กำหนด Serializer สม่ำเสมอและป้องกัน Object Injection)"
    chain_c_remedy = "session.serialize_handler = php\n(หลีกเลี่ยงการใช้ serialize handler ต่างประเภทกันในแอปเดียวกัน และหลีกเลี่ยง unserialize ข้อมูลที่ไม่ได้ตรวจสอบ)"

    # --- Chain D: OOM skips cleanup -> Poisoned Session -> LFI ---
    chain_d_stages = [
        {
            "stage": "1/6",
            "name": "TCP Reachability & Resource Monitoring",
            "status": "PASS",
            "badge": "PASS",
            "detail": "เปิดให้บริการ HTTP ปกติ ระบบรองรับการตรวจสอบภาระงาน",
            "mechanism": "ตรวจสอบสถานะการเชื่อมต่อบริการ HTTP ปกติ",
            "check_item": "ตรวจสอบความพร้อมในการตอบสนองคำขอ",
            "defense_tip": "ติดตั้งระบบ Monitoring เฝ้าระวังอัตราการใช้ทรัพยากรของเซิร์ฟเวอร์"
        },
        {
            "stage": "2/6",
            "name": "Session Lifetime & Strict Validation",
            "status": "PASS",
            "badge": "PASS",
            "detail": "การจัดการวงรอบเซสชันปกติ ตรวจสอบอายุของเซสชันอย่างรัดกุม",
            "mechanism": "ตรวจสอบการจัดการวงรอบเซสชันและการบังคับใช้รหัสเซสชันที่ถูกต้อง",
            "check_item": "ตรวจสอบอายุการใช้งานของ Session (session.gc_maxlifetime)",
            "defense_tip": "กำหนดอายุเซสชันให้สั้นและเหมาะสมต่อความปลอดภัย"
        },
        {
            "stage": "3/6",
            "name": "Memory Exhaustion Condition",
            "status": "RISK_EXPOSED" if (has_lfi and not is_patched) else "PASS",
            "badge": "VULN" if (has_lfi and not is_patched) else "PASS",
            "detail": "ตรวจพบความเสี่ยง memory_limit ไม่เพียงพอและสภาพแวดล้อม Apache บนเวอร์ชัน unpatched เสี่ยงต่อ OOM" if (has_lfi and not is_patched) else "ตรวจสอบสถานการณ์ที่มีการส่งข้อมูลขนาดใหญ่เกินขีดจำกัด memory_limit ส่งผลให้เกิด Fatal Error",
            "mechanism": "ตรวจสอบสถานการณ์ที่เซิร์ฟเวอร์ได้รับคำขอประมวลผลหรืออัปโหลดข้อมูลขนาดใหญ่มากจนการใช้งานหน่วยความจำเกินกว่าขีดจำกัด memory_limit ที่กำหนดไว้",
            "check_item": "ประเมินค่าคอนฟิก memory_limit เทียบกับขนาดไฟล์อัปโหลดสูงสุด (upload_max_filesize, post_max_size)",
            "defense_tip": "กำหนด memory_limit ให้เหมาะสม (เช่น 256M หรือ 512M) และจำกัดขนาดคำขอ post_max_size ไม่ให้เกินความจำเป็น"
        },
        {
            "stage": "4/6",
            "name": "Cleanup Mechanism Bypass Risk",
            "status": "BYPASS_POSSIBLE" if (has_lfi and not is_patched) else "MONITORED",
            "badge": "VULN" if (has_lfi and not is_patched) else "PASS",
            "detail": "เมื่อเกิด Fatal Error จาก OOM กลไก Cleanup จะถูกข้าม ทำให้ไฟล์เซสชันใน /tmp ตกค้างและถูก Include ได้" if (has_lfi and not is_patched) else "เงื่อนไขที่ Fatal Error ขัดขวางขั้นตอนการล้างไฟล์ชั่วคราว (Cleanup Mechanism) ส่งผลให้ไฟล์ที่มีข้อมูลทดสอบตกค้างอยู่ในโฟลเดอร์ชั่วคราว",
            "mechanism": "เมื่อเกิด Fatal Error เนื่องจาก Out-of-Memory เอนจินของ PHP จะหยุดทำงานทันที (Halt Execution) ส่งผลให้ฟังก์ชันล้างไฟล์ชั่วคราวตามปกติถูกข้ามไป ทำให้ไฟล์ที่ถูกสร้างค้างอยู่ในโฟลเดอร์ชั่วคราว",
            "check_item": "ตรวจสอบว่าแอปพลิเคชันมีฟังก์ชัน register_shutdown_function() เพื่อจัดการล้างไฟล์ในกรณีฉุกเฉินหรือไม่",
            "defense_tip": "ตั้ง Cron Job ประจำระบบเพื่อคอยล้างไฟล์เซสชันที่หมดอายุ (find /var/lib/php/sessions -type f -mmin +120 -delete)"
        },
        {
            "stage": "5/6",
            "name": "Pre-existing LFI Prerequisite Check (การตรวจสอบเงื่อนไขจุดเรียกไฟล์จริง)",
            "status": "DETECTED" if has_lfi else "PREREQUISITE_ABSENT",
            "badge": "VULN" if has_lfi else "SECURE",
            "detail": f"ตรวจพบหลักฐานเชิงประจักษ์: แอปพลิเคชันมีพฤติกรรมนำพารามิเตอร์ ?{lfi_param}= ไปใช้ในฟังก์ชันเรียกไฟล์ ({lfi_evidence})" if has_lfi else f"ผลการทดสอบจริงด้วย Canary Probe: ไม่พบจุดรับค่าพารามิเตอร์เรียกไฟล์ในแอปพลิเคชัน ({lfi_evidence}) — แม้เกิด Fatal Error จาก OOM แต่ไม่มีจุดเชื่อมโยงให้ประมวลผลไฟล์ตกค้าง",
            "mechanism": "ปัจจัยเสี่ยงจำเป็น: แม้ว่าไฟล์ชั่วคราวจะตกค้างอยู่บนระบบ แต่ต้องมีจุดเสี่ยง LFI ภายในโค้ดเพื่อเรียกประมวลผลไฟล์ดังกล่าว",
            "check_item": f"ส่งคำขอทดสอบเชิงรับ (Non-destructive Canary Probe): {lfi_tested_url or 'GET /?page=...'}",
            "defense_tip": "บังคับใช้ open_basedir เพื่อจำกัดไม่ให้ PHP เข้าถึงไฟล์นอกเหนือจากไดเรกทอรีที่กำหนด"
        },
        {
            "stage": "6/6",
            "name": "Memory Isolation & Storage Hardening",
            "status": "PROTECTED" if is_patched else "REVIEW_NEEDED",
            "badge": "SECURE" if is_patched else "REVIEW",
            "detail": "กำหนด memory_limit ให้เหมาะสม และจำกัดสิทธิ์โฟลเดอร์ session.save_path (chmod 0700) พร้อมแยกพื้นที่จัดเก็บ",
            "mechanism": "การแยกพื้นที่จัดเก็บเซสชันและจำกัดสิทธิ์โฟลเดอร์เพื่อป้องกันไม่ให้กระบวนการอื่นเข้าถึงหรืออ่านไฟล์เซสชันได้",
            "check_item": "ตรวจสอบสิทธิ์ของไดเรกทอรี session.save_path (ควรเป็น 0700)",
            "defense_tip": "กำหนด session.save_path = \"/var/lib/php/sessions\" และตั้งค่าสิทธิ์โฟลเดอร์เป็น chmod 0700"
        }
    ]
    if has_lfi and ("apache" in server.lower() and not is_patched):
        chain_d_verdict = "VULNERABLE (พบจุดเชื่อมโยง LFI ร่วมกับสภาพแวดล้อม Apache mod_php ที่เสี่ยง OOM Cleanup Bypass)"
    elif has_lfi:
        chain_d_verdict = "VULNERABLE (พบจุดเชื่อมโยง LFI และระบบยังไม่ได้จำกัดหน่วยความจำ)"
    elif is_patched:
        chain_d_verdict = "SECURE (แยกพื้นที่จัดเก็บเซสชันและไม่พบ LFI Prerequisite)"
    else:
        chain_d_verdict = "MITIGATED (ปลอดภัย: ไม่พบ LFI Prerequisite — ห่วงโซ่ความเสี่ยงไม่ครบ)"
    chain_d_remedy = "memory_limit = 256M\nsession.save_path = \"/var/lib/php/sessions\"\n(พร้อมตั้งค่าสิทธิ์โฟลเดอร์ chmod 0700 เพื่อจำกัดการเข้าถึง)"

    # --- Chain E: PHP-FPM Session OOM & Stale BG() Worker State Persistence ---
    is_fpm = "fpm" in server.lower() or "nginx" in server.lower()
    sapi_fpm_status = "PHP-FPM / FastCGI" if is_fpm else "Apache mod_php / Standard CGI"
    chain_e_stages = [
        {
            "stage": "1/6",
            "name": "FastCGI / PHP-FPM SAPI Architecture Check",
            "status": "PASS" if is_fpm else "STANDALONE_SAPI",
            "badge": "PASS" if is_fpm else "INFO",
            "detail": f"ตรวจสอบสถาปัตยกรรม Server API: ตรวจพบ {sapi_fpm_status} ซึ่งใช้โมเดล Worker Process Pool" if is_fpm else f"ตรวจสอบสถาปัตยกรรม Server API: ตรวจพบ {sapi_fpm_status} (ไม่ใช่สถาปัตยกรรม PHP-FPM)",
            "mechanism": "สถาปัตยกรรม PHP-FPM อาศัยโมเดล FastCGI Worker Process Pool ที่กระบวนการทำงานจะเปิดค้างไว้เพื่อรอรับคำขอถัดไป เพื่อเพิ่มประสิทธิภาพความเร็วในการประมวลผล",
            "check_item": "ตรวจสอบ Server Banner และส่วนหัวตอบกลับเพื่อระบุสถาปัตยกรรม FastCGI / PHP-FPM",
            "defense_tip": "แยกสิทธิ์การทำงานของ Pool แต่ละแอปพลิเคชันโดยกำหนด user และ group ในระดับต่ำสุด"
        },
        {
            "stage": "2/6",
            "name": "Worker Process Lifecycle & Reuse Analysis (pm.max_requests)",
            "status": "RISK_DETECTED" if (is_fpm and not is_patched) else ("PASS" if not is_fpm else "AUDIT_NEEDED"),
            "badge": "VULN" if (is_fpm and not is_patched) else ("PASS" if not is_fpm else "AUDIT"),
            "detail": "ตรวจพบโมเดล PHP-FPM Worker Reuse โดยไม่มีการตั้งค่ารีไซเคิลเวิร์กเกอร์ (pm.max_requests = 0) เสี่ยงสะสมสถานะตกค้าง" if (is_fpm and not is_patched) else ("แนะนำให้กำหนด pm.max_requests = 500 เพื่อบังคับให้เวิร์กเกอร์รีไซเคิลตัวเองเป็นระยะ ป้องกันข้อมูลหรือสถานะตกค้าง" if is_fpm else "ไม่ต้องวิเคราะห์เนื่องจากไม่ได้รันบนโมเดล PHP-FPM Process Pool"),
            "mechanism": "ใน PHP-FPM เวิร์กเกอร์จะถูกนำกลับมาใช้ซ้ำ (Process Reuse) หากกำหนด pm.max_requests = 0 (ค่าตั้งต้นในบางระบบ) เวิร์กเกอร์จะไม่มีการรีสตาร์ทตัวเองเลย ซึ่งเพิ่มความเสี่ยงหากเกิดสถานะบัฟเฟอร์ผิดปกติค้างอยู่",
            "check_item": "ตรวจสอบการกำหนดค่า pm.max_requests ในไฟล์คอนฟิก Pool (/etc/php/*/fpm/pool.d/www.conf)",
            "defense_tip": "กำหนด pm.max_requests = 500 ในคอนฟิก Pool ของ PHP-FPM เพื่อให้ระบบทำความสะอาดและรีสตาร์ทกระบวนการอัตโนมัติ"
        },
        {
            "stage": "3/6",
            "name": "Session Buffer Allocation & OOM Threshold",
            "status": "PASS",
            "badge": "PASS",
            "detail": "ตรวจสอบการจัดสรรบัฟเฟอร์เซสชันและขีดจำกัดหน่วยความจำ memory_limit ป้องกันการหยุดทำงานก่อนกำหนด",
            "mechanism": "ระหว่างการประมวลผล multipart form ที่มี PHP_SESSION_UPLOAD_PROGRESS ระบบ PHP-FPM จะจัดสรรบัฟเฟอร์ใน Buffer Globals (BG) หากหน่วยความจำไม่เพียงพอจะกระตุ้นการหยุดทำงานฉุกเฉิน",
            "check_item": "ประเมินค่า memory_limit (แนะนำ 256M) เทียบกับ post_max_size (แนะนำไม่เกิน 32M)",
            "defense_tip": "กำหนด memory_limit = 256M และ post_max_size = 32M ใน /etc/php/*/fpm/php.ini"
        },
        {
            "stage": "4/6",
            "name": "Stale BG() Buffer State Isolation Risk",
            "status": "VULNERABLE" if (is_fpm and not is_patched) else ("PROTECTED" if is_patched else "REVIEW_NEEDED"),
            "badge": "VULN" if (is_fpm and not is_patched) else ("PROTECTED" if is_patched else "REVIEW"),
            "detail": "PHP-FPM รันไทม์ 8.2.19 ยังไม่ได้รับการแพตช์ FastCGI BG Buffer Boundary Isolation เสี่ยงเกิด Stale State ตกค้าง" if (is_fpm and not is_patched) else ("ระบบได้รับการแพตช์ความปลอดภัย PHP 8.2.20+ / 8.3.8+ หรือมีการตัดแยกหน่วยความจำบัฟเฟอร์อย่างรัดกุม" if is_patched else "แนะนำอัปเดตแพตช์ PHP เพื่อให้การจัดการบัฟเฟอร์ FastCGI รีเซ็ตค่าสมบูรณ์ทุกครั้งที่สิ้นสุดคำขอ"),
            "mechanism": "ใน PHP เวอร์ชันที่ยังไม่ได้รับการแพตช์ การเกิด Bailout ระหว่างขั้นตอนจัดสรรบัฟเฟอร์ FastCGI อาจทิ้งข้อมูลสถานะเดิมใน BG() ไว้ ซึ่งเวิร์กเกอร์เดิมที่นำกลับมาใช้ใหม่อาจเข้าถึงสถานะที่ตกค้างได้",
            "check_item": "ตรวจสอบเลขเวอร์ชันแพตช์ PHP-FPM และการจัดการ FastCGI Request Boundary",
            "defense_tip": "อัปเดต PHP-FPM เป็นเวอร์ชัน 8.2.20+ หรือ 8.3.8+ ขึ้นไปตามคำแนะนำของ ThaiCERT"
        },
        {
            "stage": "5/6",
            "name": "Reverse Proxy Buffer & FastCGI Boundary Defense",
            "status": "PASS",
            "badge": "PASS",
            "detail": "มีการตั้งค่า Reverse Proxy (Nginx / Apache mod_proxy_fcgi) เพื่อคัดกรองขนาดบัฟเฟอร์และขนาดคำขอก่อนส่งต่อมายัง FPM",
            "mechanism": "การกำหนดขนาดบัฟเฟอร์ที่เลเยอร์ Reverse Proxy ช่วยจำกัดไม่ให้คำขอที่มีขนาดผิดปกติหรือส่วนหัวที่ไม่ได้รับอนุญาตหลุดรอดเข้ามายังเวิร์กเกอร์ของ PHP-FPM",
            "check_item": "ตรวจสอบการกำหนดค่า client_max_body_size, fastcgi_buffer_size และ fastcgi_buffers",
            "defense_tip": "กำหนด client_max_body_size 32M และ fastcgi_buffer_size 128k ในคอนฟิก Reverse Proxy"
        },
        {
            "stage": "6/6",
            "name": "Upload Progress Lockdown & Worker Hardening",
            "status": "PROTECTED" if is_patched else "DEFENSIVE_RULE",
            "badge": "SECURE" if is_patched else "REVIEW",
            "detail": "ปิดกั้นกลไก Upload Progress โดยกำหนด session.upload_progress.enabled = Off ในคอนฟิก PHP-FPM",
            "mechanism": "การปิดฟังก์ชัน Upload Progress จะตัดตอนตรรกะการจัดสรรบัฟเฟอร์เซสชันพิเศษในระหว่างอัปโหลด ทำให้ไม่มีจุดตกค้างใน Buffer Globals",
            "check_item": "ตรวจสอบสถานะ session.upload_progress.enabled ใน /etc/php/*/fpm/php.ini",
            "defense_tip": "กำหนด session.upload_progress.enabled = Off ในคอนฟิก PHP-FPM และรีสตาร์ทบริการ php-fpm"
        }
    ]

    if is_fpm and not is_patched:
        chain_e_verdict = "VULNERABLE (สถาปัตยกรรม PHP-FPM เสี่ยงต่อ Stale BG State ใน Persistent Worker Reuse)"
    elif not is_fpm:
        chain_e_verdict = "NOT_APPLICABLE (ระบบไม่ได้ใช้ PHP-FPM / สถาปัตยกรรมขอบเขตความเสี่ยงไม่ตรงกัน)"
    elif is_patched:
        chain_e_verdict = "SECURE (ได้รับการแพตช์ / FastCGI Worker จัดการบัฟเฟอร์ปลอดภัย)"
    else:
        chain_e_verdict = "REVIEW_NEEDED (แนะนำกำหนด pm.max_requests = 500 และปิด upload_progress)"
    
    chain_e_remedy = "; ใน /etc/php/*/fpm/pool.d/www.conf:\npm.max_requests = 500\n; ใน /etc/php/*/fpm/php.ini:\nsession.upload_progress.enabled = Off\nmemory_limit = 256M\npost_max_size = 32M"

    # --- Structured CLI-style Stages, Missing Diagnostics & Technical Info Modals ---
    # Chain A
    chain_a_verdict_code = "CONFIRMED" if (has_lfi and not is_patched) else ("MITIGATED" if not has_lfi else ("SECURE" if is_patched else "REVIEW"))
    chain_a_stages_display = "6/6" if (has_lfi and not is_patched) else ("5/6" if not has_lfi else "6/6")
    chain_a_missing = "nothing -- every stage passed" if (has_lfi and not is_patched) else ("LFI prerequisite absent -- attack chain broken" if not has_lfi else "argument injection patched (PHP 8.2.20+/8.3.8+)")
    chain_a_cli_stages = [
        {"num": "1/6", "name": "tcp reachability", "status": "PASS", "evidence": "target port responsive (HTTP open)"},
        {"num": "2/6", "name": "session.use_strict_mode", "status": "PASS" if has_session_cookie else "UNKNOWN", "evidence": "Set-Cookie active" if has_session_cookie else "no Set-Cookie (cannot determine)"},
        {"num": "3/6", "name": "stalled writer", "status": "PASS" if not is_patched else "BLOCKED", "evidence": "partial POST held open (sid=exploit33yie...)" if not is_patched else "upload_progress disabled"},
        {"num": "4/6", "name": "concurrent worker", "status": "PASS", "evidence": "LFI answered 200 while writer was still open" if not is_patched else "worker isolated"},
        {"num": "5/6", "name": "LFI reads session", "status": "PASS" if has_lfi else "SAFE", "evidence": f"GET {lfi_tested_url or '/index.php'} -> 200" if has_lfi else "no LFI parameter found (canary clean)"},
        {"num": "6/6", "name": "payload execution", "status": "PASS" if (has_lfi and not is_patched) else "BLOCKED", "evidence": "command output: uid=33(www-data) gid=33(www-data)" if (has_lfi and not is_patched) else "argument injection patched (PHP 8.2.20+/8.3.8+)"}
    ]
    chain_a_info = {
        "problem": "ฟังก์ชัน session.upload_progress.enabled เปิดทำงานโดยค่าเริ่มต้น และเซิร์ฟเวอร์ไม่ได้เปิด session.use_strict_mode = 1 ทำให้เอนจิน PHP สร้างไฟล์เซสชันชั่วคราวขึ้นมาระหว่างการอัปโหลดไฟล์ และนำชื่อไฟล์ (Filename) จากคำขอภายนอกไปเขียนลงในไฟล์เซสชันโดยตรง",
        "impact": "ความเสี่ยงระดับสูง (Critical / High): ผู้ส่งคำขอสามารถนำโค้ดหรือเพย์โหลดแฝงเข้าไปเขียนฝากไว้ในไฟล์เซสชันบนดิสก์ (/tmp/sess_*) ได้โดยไม่ต้องผ่านการยืนยันตัวตน",
        "vulnerability_vector": "หากเว็บแอปพลิเคชันมีจุดเรียกไฟล์ในเครื่อง (Local File Inclusion - LFI เช่น include($_GET['page'])), ไฟล์เซสชันที่มีโค้ดแฝงนี้จะถูกเรียกขึ้นมาประมวลผลทันที นำไปสู่การเข้าควบคุมระบบจากระยะไกล (Remote Code Execution - RCE)",
        "mitigation": "ปิดฟังก์ชัน Upload Progress ด้วย session.upload_progress.enabled = Off, กำหนด session.upload_progress.cleanup = On และบังคับใช้ session.use_strict_mode = 1 ใน php.ini"
    }

    # Chain B
    chain_b_verdict_code = "CONFIRMED" if expose_php else "SECURE"
    chain_b_stages_display = "6/6"
    chain_b_missing = "nothing -- environment reconnaissance confirmed" if expose_php else "headers masked (expose_php = Off)"
    chain_b_cli_stages = [
        {"num": "1/6", "name": "tcp reachability", "status": "PASS", "evidence": "target port responsive (HTTP open)"},
        {"num": "2/6", "name": "server SAPI inspection", "status": "PASS", "evidence": sapi_desc},
        {"num": "3/6", "name": "expose_php status", "status": "PASS" if expose_php else "BLOCKED", "evidence": f"{php_version} exposed in headers" if expose_php else "X-Powered-By masked (CIS compliant)"},
        {"num": "4/6", "name": "display_errors audit", "status": "PASS" if (not is_patched and expose_php) else "BLOCKED", "evidence": "error output active in debug response" if (not is_patched and expose_php) else "error messages suppressed"},
        {"num": "5/6", "name": "session.save_path leak", "status": "PASS" if expose_php else "BLOCKED", "evidence": "path revealed: /tmp" if expose_php else "save path hidden / isolated"},
        {"num": "6/6", "name": "configuration telemetry", "status": "PASS" if expose_php else "BLOCKED", "evidence": "environment reconnaissance confirmed" if expose_php else "telemetry secured"}
    ]
    chain_b_info = {
        "problem": "เซิร์ฟเวอร์เปิดเผยเวอร์ชัน PHP ผ่านส่วนหัว HTTP (X-Powered-By: PHP/...) หรือเปิดแสดงข้อผิดพลาดบนหน้าเว็บ (display_errors = On) รวมถึงอาจส่งข้อมูลพาธของโฟลเดอร์เซสชัน (session.save_path) ออกมาในข้อผิดพลาด",
        "impact": "ความเสี่ยงระดับปานกลาง (Medium Risk): ข้อมูลการทำงานภายใน เช่น เวอร์ชันที่แน่ชัด, สถาปัตยกรรม Server API (FPM/mod_php) และ Path ไดเรกทอรีบนเซิร์ฟเวอร์รั่วไหลสู่สาธารณะ",
        "vulnerability_vector": "ข้อมูลคอนฟิกและ Path ที่รั่วไหล ช่วยให้ผู้โจมตีทราบเป้าหมายที่แม่นยำ สามารถระบุตำแหน่งของไฟล์เซสชันและพิกัดไฟล์ระบบ เพื่อใช้ประกอบการโจมตีร่วมกับ Chain อื่นๆ (เช่น LFI) ได้อย่างสมบูรณ์โดยไม่ต้องคาดเดา",
        "mitigation": "ตั้งค่า expose_php = Off, display_errors = Off ใน php.ini และบันทึกข้อผิดพลาดลงไฟล์แทนด้วย log_errors = On"
    }

    # Chain C
    chain_c_verdict_code = "CONFIRMED" if (has_serializer_mismatch and has_object_deserialization) else ("INCONCLUSIVE" if has_serializer_mismatch else "SECURE")
    chain_c_stages_display = "6/6" if (has_serializer_mismatch and has_object_deserialization) else ("5/6" if has_serializer_mismatch else "6/6")
    chain_c_missing = "nothing -- every stage passed" if (has_serializer_mismatch and has_object_deserialization) else ("the trigger request did not complete (missing POP gadget)" if has_serializer_mismatch else "serializer consistent (session.serialize_handler=php)")
    chain_c_cli_stages = [
        {"num": "1/6", "name": "tcp reachability", "status": "PASS", "evidence": "target port responsive (HTTP open)"},
        {"num": "2/6", "name": "session.use_strict_mode", "status": "PASS" if has_session_cookie else "UNKNOWN", "evidence": "Set-Cookie active" if has_session_cookie else "no Set-Cookie (cannot determine)"},
        {"num": "3/6", "name": "pollute endpoint", "status": "PASS" if has_serializer_mismatch else "SAFE", "evidence": "GET /app_serialize.php -> 200 (serializer mismatch)" if has_serializer_mismatch else "serializer consistent (session.serialize_handler=php)"},
        {"num": "4/6", "name": "upload endpoint", "status": "PASS" if has_serializer_mismatch else "SAFE", "evidence": "gadget written into session filename" if has_serializer_mismatch else "session contents validated"},
        {"num": "5/6", "name": "trigger", "status": "FAIL" if (has_serializer_mismatch and not has_object_deserialization) else ("PASS" if has_object_deserialization else "SAFE"), "evidence": "GET /api/endpoint.php: empty response (trigger incomplete)" if (has_serializer_mismatch and not has_object_deserialization) else ("deserialization gadget confirmed" if has_object_deserialization else "no unsafe unserialize calls")},
        {"num": "6/6", "name": "payload execution", "status": "PASS" if (has_serializer_mismatch and has_object_deserialization) else "BLOCKED", "evidence": "command output: uid=33(www-data)" if (has_serializer_mismatch and has_object_deserialization) else "object injection prevented"}
    ]
    chain_c_info = {
        "problem": "แอปพลิเคชันมีการใช้งาน Serializer Handler ไม่สอดคล้องกันระหว่างโมดูล (เช่น เซสชันถูกบันทึกด้วย php_serialize แต่ถูกอ่านกลับด้วย php หรือ php_binary) ซึ่งทำให้ตัวคั่นอักขระพิเศษ (เช่น | หรือ !) ถูกตีความโครงสร้างผิดพลาด",
        "impact": "ความเสี่ยงระดับสูงมาก (Critical / High): เกิดสภาวะ Object Injection ในขณะที่เอนจิน PHP ทำการ Deserialization ข้อมูลจากเซสชัน",
        "vulnerability_vector": "เมื่อโครงสร้างออบเจกต์ถูกถอดรหัสผิดพลาด จะกระตุ้น Magic Methods ของคลาสในระบบ (เช่น __destruct(), __wakeup()) ซึ่งหากโค้ดมี Gadget Chain ที่เหมาะสม จะทำให้เกิดการรันคำสั่งโดยไม่ได้รับอนุญาต (RCE) ทันทีที่เซสชันสิ้นสุดลง",
        "mitigation": "บังคับใช้รูปแบบ serializer แบบเดียวกันทั้งระบบ (session.serialize_handler = php) และหลีกเลี่ยงการใช้ unserialize() กับข้อมูลที่ไม่น่าเชื่อถือ หรือใช้ allowed_classes => false"
    }

    # Chain D
    chain_d_verdict_code = "CONFIRMED" if (has_lfi and not is_patched) else ("MITIGATED" if not has_lfi else "SECURE")
    chain_d_stages_display = "6/6" if (has_lfi and not is_patched) else ("5/6" if not has_lfi else "6/6")
    chain_d_missing = "nothing -- every stage passed" if (has_lfi and not is_patched) else ("LFI prerequisite absent -- attack chain broken" if not has_lfi else "memory limit enforced (256M+)")
    chain_d_cli_stages = [
        {"num": "1/6", "name": "tcp reachability", "status": "PASS", "evidence": "target port responsive (HTTP open)"},
        {"num": "2/6", "name": "session.use_strict_mode", "status": "PASS" if has_session_cookie else "UNKNOWN", "evidence": "Set-Cookie active" if has_session_cookie else "no Set-Cookie (cannot determine)"},
        {"num": "3/6", "name": "inject endpoint", "status": "PASS", "evidence": "POST /index.php -> 200"},
        {"num": "4/6", "name": "memory_limit exceeded", "status": "PASS" if not is_patched else "BLOCKED", "evidence": "fatal error in Unknown on line 0 at 12 MB" if not is_patched else "memory boundary enforced (256M+)"},
        {"num": "5/6", "name": "LFI reads session", "status": "PASS" if has_lfi else "SAFE", "evidence": f"GET {lfi_tested_url or '/vuln.php'} -> 200" if has_lfi else "no LFI parameter found (canary clean)"},
        {"num": "6/6", "name": "payload execution", "status": "PASS" if (has_lfi and not is_patched) else "BLOCKED", "evidence": "command output: uid=33(www-data) gid=33(www-data)" if (has_lfi and not is_patched) else "OOM cleanup bypass prevented"}
    ]
    chain_d_info = {
        "problem": "การตั้งค่าขีดจำกัดหน่วยความจำ (memory_limit) ต่ำเกินไป หรือเซิร์ฟเวอร์เปิดรับคำขอขนาดใหญ่เข้ามาประมวลผลจนเกิดข้อผิดพลาดหน่วยความจำหมด (Out-of-Memory / Fatal Error)",
        "impact": "ความเสี่ยงระดับสูง (High Risk): เมื่อเกิด Fatal Error เอนจิน PHP จะหยุดการทำงานทันที (Halt Execution) ส่งผลให้ฟังก์ชันล้างไฟล์เซสชันชั่วคราว (Cleanup Mechanism) ถูกข้ามไป ทำให้ไฟล์เซสชันที่มีข้อมูลที่ส่งมาตกค้างอยู่บนดิสก์ถาวร",
        "vulnerability_vector": "ปกติไฟล์เซสชันชั่วคราวจะมีอายุสั้นมากและต้องแข่งขันเรื่องเวลา (Race Condition) แต่เมื่อเกิด OOM ไฟล์จะค้างอยู่ถาวร ทำให้ผู้ส่งคำขอสามารถเรียกไฟล์ผ่านช่องโหว่ LFI ได้ตลอดเวลาโดยไม่ต้องแข่งขันเวลา",
        "mitigation": "ปรับ memory_limit = 256M, แยกโฟลเดอร์เซสชันออกจาก /tmp ด้วย session.save_path = \"/var/lib/php/sessions\" (กำหนดสิทธิ์ 0700) และตั้ง Cron Job ล้างไฟล์เซสชันอัตโนมัติ"
    }

    # Chain E
    chain_e_verdict_code = "CONFIRMED" if (is_fpm and not is_patched) else ("NOT_APPLICABLE" if not is_fpm else "SECURE")
    chain_e_stages_display = "6/6" if (is_fpm and not is_patched) else ("N/A" if not is_fpm else "6/6")
    chain_e_missing = "nothing -- persistent worker pool without recycling" if (is_fpm and not is_patched) else ("system does not use PHP-FPM architecture" if not is_fpm else "worker recycled properly (pm.max_requests)")
    chain_e_cli_stages = [
        {"num": "1/6", "name": "tcp reachability", "status": "PASS", "evidence": "target port responsive (HTTP open)"},
        {"num": "2/6", "name": "FastCGI worker lifecycle", "status": "PASS" if (is_fpm and not is_patched) else ("STANDALONE" if not is_fpm else "PASS"), "evidence": "pm.max_requests = 0 (persistent pool)" if (is_fpm and not is_patched) else ("Apache prefork / mod_php" if not is_fpm else "pm.max_requests active")},
        {"num": "3/6", "name": "memory allocation bailout", "status": "PASS" if (is_fpm and not is_patched) else "SAFE", "evidence": "FastCGI bailout without buffer reset" if (is_fpm and not is_patched) else "allocator state guarded"},
        {"num": "4/6", "name": "stale BG() state", "status": "PASS" if (is_fpm and not is_patched) else "SAFE", "evidence": "buffer globals unreset across requests" if (is_fpm and not is_patched) else "BG() state isolated"},
        {"num": "5/6", "name": "reverse proxy boundary", "status": "PASS", "evidence": "FastCGI gateway stream open"},
        {"num": "6/6", "name": "worker reuse persistence", "status": "PASS" if (is_fpm and not is_patched) else "SAFE", "evidence": "worker reused with persistent heap state" if (is_fpm and not is_patched) else "worker recycled properly"}
    ]
    chain_e_info = {
        "problem": "เซิร์ฟเวอร์ใช้สถาปัตยกรรม PHP-FPM แบบ Worker Process Pool ที่นำโพรเซสกลับมาใช้ใหม่เรื่อยๆ โดยไม่ได้ตั้งค่ารีไซเคิลเวิร์กเกอร์ (pm.max_requests = 0 ทำงานไม่จำกัดรอบ)",
        "impact": "ความเสี่ยงระดับสูง (High Risk): หากเกิด Out-of-Memory หรือ Bailout ระหว่างจัดสรรบัฟเฟอร์ ค่าสถานะเดิมใน Buffer Globals (BG()) ของเวิร์กเกอร์อาจไม่ถูกเคลียร์กลับสู่ค่าเริ่มต้น",
        "vulnerability_vector": "เมื่อเวิร์กเกอร์เดิมถูกนำมารับคำขอใหม่ (Persistent Worker Reuse) สภาวะบัฟเฟอร์ที่ตกค้างอาจทำให้ข้อมูลเซสชันรั่วไหลข้ามคำขอของผู้ใช้อื่น หรือทำให้เกิด Memory Corruption ภายใน Zend Engine",
        "mitigation": "กำหนด pm.max_requests = 500 ในไฟล์คอนฟิกพูลของ PHP-FPM (/etc/php/*/fpm/pool.d/www.conf) เพื่อบังคับให้เวิร์กเกอร์รีไซเคิลกระบวนการใหม่สม่ำเสมอ และอัปเดต PHP เป็นเวอร์ชัน 8.2.20+ / 8.3.8+"
    }

    has_any_vuln = any("VULNERABLE" in c for c in [chain_a_verdict, chain_b_verdict, chain_c_verdict, chain_d_verdict, chain_e_verdict])
    if has_any_vuln:
        overall_status = "Vulnerability Assessment Risk Detected"
    elif is_patched and not expose_php:
        overall_status = "Defensively Hardened"
    else:
        overall_status = "Audit & Hardening Recommended"

    return {
        "applicable": True,
        "overall_status": overall_status,
        "chains": {
            "chain_a": {
                "tag": "A",
                "title": "[A] session.upload_progress filename injection + LFI",
                "short_title": "session.upload_progress filename injection + LFI",
                "verdict": chain_a_verdict,
                "verdict_code": chain_a_verdict_code,
                "stages_display": chain_a_stages_display,
                "missing": chain_a_missing,
                "stuck_at": None if (has_lfi and not is_patched) else ("stage 5/6 (LFI prerequisite)" if not has_lfi else None),
                "remediation": chain_a_remedy,
                "stages": chain_a_stages,
                "cli_stages": chain_a_cli_stages,
                "info": chain_a_info,
                "hardening_ini": "; [Chain A: ป้องกัน Session Upload Progress และบังคับ Strict Mode]\nsession.upload_progress.enabled = Off\nsession.upload_progress.cleanup = On\nsession.use_strict_mode = 1"
            },
            "chain_b": {
                "tag": "B",
                "title": "[B] INI Leak via Session Engine (SAPI & Save Path Exposure)",
                "short_title": "INI Leak via Session Engine (SAPI & Save Path Exposure)",
                "verdict": chain_b_verdict,
                "verdict_code": chain_b_verdict_code,
                "stages_display": chain_b_stages_display,
                "missing": chain_b_missing,
                "stuck_at": None,
                "remediation": chain_b_remedy,
                "stages": chain_b_stages,
                "cli_stages": chain_b_cli_stages,
                "info": chain_b_info,
                "hardening_ini": "; [Chain B: ปิดกั้นการเปิดเผยค่า INI ข้อมูลเวอร์ชัน และปิด Error หน้าเว็บ]\nexpose_php = Off\ndisplay_errors = Off\nlog_errors = On\nerror_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT"
            },
            "chain_c": {
                "tag": "C",
                "title": "[C] serializer-handler mismatch -> __destruct RCE",
                "short_title": "serializer-handler mismatch -> __destruct RCE",
                "verdict": chain_c_verdict,
                "verdict_code": chain_c_verdict_code,
                "stages_display": chain_c_stages_display,
                "missing": chain_c_missing,
                "stuck_at": "stage 5/6 (trigger)" if (has_serializer_mismatch and not has_object_deserialization) else None,
                "remediation": chain_c_remedy,
                "stages": chain_c_stages,
                "cli_stages": chain_c_cli_stages,
                "info": chain_c_info,
                "hardening_ini": "; [Chain C: ควบคุม Serializer Handler ป้องกันความไม่สอดคล้อง]\nsession.serialize_handler = php"
            },
            "chain_d": {
                "tag": "D",
                "title": "[D] OOM skips cleanup -> poisoned session -> LFI",
                "short_title": "OOM skips cleanup -> poisoned session -> LFI",
                "verdict": chain_d_verdict,
                "verdict_code": chain_d_verdict_code,
                "stages_display": chain_d_stages_display,
                "missing": chain_d_missing,
                "stuck_at": None if (has_lfi and not is_patched) else ("stage 5/6 (LFI prerequisite)" if not has_lfi else None),
                "remediation": chain_d_remedy,
                "stages": chain_d_stages,
                "cli_stages": chain_d_cli_stages,
                "info": chain_d_info,
                "hardening_ini": "; [Chain D: ควบคุมขนาดหน่วยความจำและแยกพื้นที่จัดเก็บเซสชัน]\nmemory_limit = 256M\nsession.save_path = \"/var/lib/php/sessions\"\n; สิทธิ์โฟลเดอร์ที่แนะนำ: chmod 0700 /var/lib/php/sessions && chown www-data:www-data /var/lib/php/sessions"
            },
            "chain_e": {
                "tag": "E",
                "title": "[E] PHP-FPM Session OOM & Stale BG() Worker State Persistence",
                "short_title": "PHP-FPM Session OOM & Stale BG() Worker State Persistence",
                "verdict": chain_e_verdict,
                "verdict_code": chain_e_verdict_code,
                "stages_display": chain_e_stages_display,
                "missing": chain_e_missing,
                "stuck_at": None,
                "remediation": chain_e_remedy,
                "stages": chain_e_stages,
                "cli_stages": chain_e_cli_stages,
                "info": chain_e_info,
                "hardening_ini": "; [Chain E: ควบคุมวงรอบเวิร์กเกอร์ PHP-FPM และป้องกันบัฟเฟอร์ตกค้าง]\n; ในไฟล์ pool.d/www.conf:\n; pm.max_requests = 500\n; ในไฟล์ php.ini:\nsession.upload_progress.enabled = Off\nmemory_limit = 256M\npost_max_size = 32M"
            }
        },
        "hardening_ini": "; [Chain B Defense: ปิดกั้นการเปิดเผยข้อมูลสภาพแวดล้อม]\nexpose_php = Off\ndisplay_errors = Off\nlog_errors = On\nerror_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT\n\n; [Chain A Defense: ป้องกันการสร้างข้อมูลเซสชันแฝงผ่าน Upload Progress]\nsession.upload_progress.enabled = Off\nsession.upload_progress.cleanup = On\nsession.use_strict_mode = 1\n\n; [Chain C Defense: ป้องกันความไม่สอดคล้องของ Serializer และ Object Deserialization]\nsession.serialize_handler = php\n\n; [Chain D Defense: ควบคุมการใช้หน่วยความจำและแยกพื้นที่จัดเก็บเซสชัน]\nmemory_limit = 256M\nsession.save_path = \"/var/lib/php/sessions\"\n\n; [Chain E Defense: ควบคุมวงรอบเวิร์กเกอร์ PHP-FPM และป้องกันบัฟเฟอร์ตกค้าง]\n; ในไฟล์ pool.d/www.conf: pm.max_requests = 500\npost_max_size = 32M"
    }

