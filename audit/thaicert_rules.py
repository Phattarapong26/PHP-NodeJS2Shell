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
        "sapi_evaluation": "ประเมิน SAPI (Apache mod_php vs PHP-FPM) และ Request Buffering",
        "risk_context": "ในหลายกรณี PHP จะ parse request body และ multipart upload ก่อนเรียก application entry point ทำให้ middleware อาจไม่มีโอกาสกรอง request ที่ทำให้เกิดปัญหาระดับ engine ได้ อย่างไรก็ตามต้องยืนยันตาม SAPI และ configuration จริง",
        "confidence_default": "Conditional"
    },
    2: {
        "group_id": 2,
        "name": "ระบบหลังบ้านแอปมือถือ และ API (Frameworks & REST APIs)",
        "sapi_evaluation": "ประเมินตาม SAPI และเส้นทาง Request ลำดับการประมวลผลก่อนเข้า Router",
        "risk_context": "Framework Routing จัดการในระดับ Application Logic แต่ข้อผิดพลาดระดับ Engine Parsing เกิดก่อนเข้า Router จึงต้องประเมินพฤติกรรมการรับส่งข้อมูลจริง",
        "confidence_default": "Conditional"
    },
    3: {
        "group_id": 3,
        "name": "Hosting Control Panel (cPanel, Plesk, DirectAdmin)",
        "sapi_evaluation": "ตรวจสอบ process, SAPI, pool, socket และ privilege แยกกัน",
        "risk_context": "บางระบบแยก PHP ระหว่างตัวจัดการกับเว็บไซต์ แต่บางระบบอาจแชร์ binary หรือ service ร่วมกัน ไม่ควรสมมติว่าแยกกันเสมอ แต่การแชร์ก็ไม่ได้แปลว่าจะเข้าถึง worker state ได้ทันที ต้องตรวจสอบสิทธิ์และ socket จริง",
        "confidence_default": "Conditional"
    },
    4: {
        "group_id": 4,
        "name": "ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance, NAS, IoT)",
        "sapi_evaluation": "ยืนยันความมีอยู่ของ PHP Runtime ก่อนประเมิน",
        "risk_context": "อุปกรณ์ฮาร์ดแวร์มักใช้ Web Server แบบ Embedded (C/Lua/Go) ห้ามสรุปว่ามีช่องโหว่ PHP หากไม่พบ PHP Runtime จริงในระบบ",
        "confidence_default": "Unverified"
    },
    5: {
        "group_id": 5,
        "name": "Container และ Docker Image (Docker, K8s, Podman)",
        "sapi_evaluation": "ประเมิน Image Layer และ Deployment Configuration",
        "risk_context": "การ restart container ช่วยล้าง worker state ชั่วคราว แต่ไม่ใช่การแก้ช่องโหว่ถาวร ต้องอัปเดต PHP package/runtime ให้เป็นรุ่นที่ patched ใน image หรือ deployment configuration",
        "confidence_default": "Conditional"
    },
    6: {
        "group_id": 6,
        "name": "Windows ที่มี PHP ติดตั้งอยู่ (IIS, XAMPP, WampServer)",
        "sapi_evaluation": "ประเมิน SAPI (FastCGI vs CGI vs mod_php) และเลขเวอร์ชันจริง",
        "risk_context": "CVE-2024-4577 เป็นช่องโหว่สำคัญของ PHP-CGI บน Windows แต่การประเมินช่องโหว่ระดับ engine อื่นๆ ต้องพิจารณาตาม SAPI และเวอร์ชันจริง ไม่ควรใช้ OS เป็นตัวตัดสินเพียงอย่างเดียว",
        "confidence_default": "Likely"
    },
    7: {
        "group_id": 7,
        "name": "ระบบทดสอบ ระบบเก่า และระบบสำรอง (Dev, UAT, Staging, DR, Snapshot)",
        "sapi_evaluation": "ประเมิน Network Exposure สิทธิ์การเข้าถึง และการนำไปใช้งาน",
        "risk_context": "ไฟล์สำรองหรือ snapshot หากเปิดเผยต่อเครือข่ายอาจเสี่ยงต่อข้อมูลรั่วไหล และหากถูก restore เป็นระบบที่เปิดใช้งานจริง จะกลับมาเป็น target ที่รัน PHP ได้",
        "confidence_default": "Conditional"
    },
    8: {
        "group_id": 8,
        "name": "ระบบที่ผู้ให้บริการภายนอกดูแล (Shared Hosting, Cloud VM)",
        "sapi_evaluation": "ประเมินระดับ Tenant Isolation, Pool Boundaries และ Worker Permissions",
        "risk_context": "ระดับความเสี่ยงขึ้นกับ isolation ของผู้ให้บริการ การเข้าถึงข้ามบัญชีต้องพิสูจน์ว่า request ไปถึง PHP worker เดิมและมีสิทธิ์ใด",
        "confidence_default": "Conditional"
    }
}


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
    return {
        "groups": unique_groups,
        "primary_group": primary,
        "group_labels": group_labels,
        "evidence": list(set(group_evidence)),
        "profiles": [THAICERT_GROUP_PROFILES[g] for g in unique_groups if g in THAICERT_GROUP_PROFILES]
    }

