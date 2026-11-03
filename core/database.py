"""
Core Vulnerability and CVE Catalog Database
Contains SemVer vulnerability ranges and actionable verification criteria
across PHP, Node.js, and NGINX stacks conforming to ThaiCERT & NCSA standards.
"""

# NGINX Vulnerability Version Ranges (Dual-range: stable branch <= 1.30.5 + mainline 1.31.0 - 1.31.6)
NGINX_VULN = {
    "CVE-2026-15176": [((0, 1, 29), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
    "CVE-2026-93479": [((1, 30, 0), (1, 30, 5)), ((1, 31, 2), (1, 31, 6))],
    "CVE-2026-97205": [((0, 8, 11), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
    "CVE-2026-95101": [((1, 25, 0), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
    "CVE-2026-97629": [((1, 23, 2), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
    "CVE-2021-23017": [((0, 6, 18), (1, 20, 0)), ((1, 21, 0), (1, 21, 0))],
}

NGINX_CVE_DESCS = {
    "CVE-2026-15176": {
        "name": "NGINX Heap Buffer Overflow (alias + rewrite)",
        "category": "NGINX",
        "severity": "Critical",
        "cvss": 9.2,
        "cvss_version": "CVSS v4.0",
        "trigger": "alias + rewrite + $request_filename",
        "host_check": "nginx -T 2>/dev/null | grep -B5 -A15 'alias' || echo 'ไม่พบ alias'",
        "confirm_vuln": "พบบล็อก location ที่มีทั้ง alias และ rewrite $request_filename บน NGINX < 1.30.6 / 1.31.7",
        "confirm_safe": "การแก้ไขถาวร: อัปเกรดเป็น NGINX ≥ 1.30.6 / 1.31.7 | มาตรการบรรเทา: ปรับแก้คอนฟิกไม่ใช้ alias ร่วมกับ rewrite $request_filename"
    },
    "CVE-2026-93479": {
        "name": "NGINX Heap Buffer Overflow (map + regex)",
        "category": "NGINX",
        "severity": "Critical",
        "cvss": 9.2,
        "cvss_version": "CVSS v4.0",
        "trigger": "map regex + capture vars",
        "host_check": "nginx -T 2>/dev/null | grep -B3 -A10 'map.*~' || echo 'ไม่พบ map regex'",
        "confirm_vuln": "พบคำสั่ง map regex capture ตัวแปรไปประกอบพาธไฟล์บน NGINX < 1.30.6 / 1.31.7",
        "confirm_safe": "การแก้ไขถาวร: อัปเกรดเป็น NGINX ≥ 1.30.6 / 1.31.7 | มาตรการบรรเทา: หลีกเลี่ยง regex capture ในคำสั่ง map"
    },
    "CVE-2026-97205": {
        "name": "NGINX Use-After-Free (AIO + SSI)",
        "category": "High",
        "severity": "High",
        "cvss": 8.1,
        "cvss_version": "CVSS v3.1",
        "trigger": "aio on + ssi on",
        "host_check": "nginx -T 2>/dev/null | grep -E 'aio\\s+on|ssi\\s+on' || echo 'ไม่พบ aio/ssi'",
        "confirm_vuln": "พบบรรทัด aio on และ ssi on เปิดพร้อมกันบน NGINX < 1.30.6 / 1.31.7",
        "confirm_safe": "การแก้ไขถาวร: อัปเกรดเป็น NGINX ≥ 1.30.6 / 1.31.7 | มาตรการบรรเทา: ปิดใช้งาน ssi off หรือ aio off หากไม่จำเป็น"
    },
    "CVE-2026-95101": {
        "name": "NGINX Request Body Injection (HTTP/3)",
        "category": "NGINX",
        "severity": "Medium",
        "cvss": 6.5,
        "cvss_version": "CVSS v3.1",
        "trigger": "listen quic / http3 on",
        "host_check": "nginx -T 2>/dev/null | grep -E 'listen.*quic|http3\\s+on' || echo 'ไม่พบ HTTP/3'",
        "confirm_vuln": "เปิดใช้งาน HTTP/3 QUIC บน NGINX 1.25.0–1.30.5 / 1.31.0–1.31.6",
        "confirm_safe": "การแก้ไขถาวร: อัปเกรดเป็น NGINX ≥ 1.30.6 / 1.31.7 | มาตรการบรรเทา: ปิด HTTP/3 ชั่วคราว"
    },
    "CVE-2026-97629": {
        "name": "NGINX Session Forgery (TLS tickets)",
        "category": "NGINX",
        "severity": "Medium",
        "cvss": 6.5,
        "cvss_version": "CVSS v3.1",
        "trigger": "ssl_session_tickets on",
        "host_check": "nginx -T 2>/dev/null | grep ssl_session_ticket || echo 'ไม่พบการตั้งค่า ticket'",
        "confirm_vuln": "เปิดใช้ TLS Session Tickets บน NGINX 1.23.2–1.30.5 / 1.31.0–1.31.6",
        "confirm_safe": "การแก้ไขถาวร: อัปเกรดเป็น NGINX ≥ 1.30.6 / 1.31.7 | มาตรการบรรเทา: ระบุ ssl_session_tickets off;"
    },
    "CVE-2021-23017": {
        "name": "NGINX 1-byte Memory Overwrite in DNS resolver",
        "category": "NGINX",
        "severity": "High",
        "cvss": 7.7,
        "cvss_version": "CVSS v3.1",
        "trigger": "resolver directive",
        "host_check": "nginx -T 2>/dev/null | grep resolver || echo 'ไม่พบ directive resolver'",
        "confirm_vuln": "พบ directive resolver ในคอนฟิกบน NGINX < 1.20.1 / 1.21.0",
        "confirm_safe": "การแก้ไขถาวร: อัปเกรดเป็น NGINX ≥ 1.20.1 / 1.21.0 | มาตรการบรรเทา: ปิด directive resolver หากไม่จำเป็น"
    }
}

# COMPREHENSIVE CVE DATABASE CATALOG (16 ช่องโหว่สำคัญ)
CVE_DATABASE = [
    {
        "id": "CVE-2024-4577",
        "category": "PHP",
        "severity": "Critical",
        "cvss": 9.8,
        "name": "PHP CGI Argument Injection (php2shell / Windows Best-Fit)",
        "desc": "Best-Fit Character Encoding Mapping บน Windows อนุญาตให้ผู้โจมตี Bypass ตัวกรองและส่งอาร์กิวเมนต์ CGI สู่ php.exe เพื่อรันคำสั่ง OS",
        "patched": "PHP 8.1.29 / 8.2.20 / 8.3.8+",
        "host_check": "php -v && (php -i | grep -E 'Server API|System')",
        "confirm_vuln": "รัน PHP บน Windows ในโหมด CGI/FastCGI และ PHP ต่ำกว่า 8.1.29 / 8.2.20 / 8.3.8",
        "confirm_safe": "รันบน Linux หรือ PHP-FPM/CLI หรืออัปเกรดเป็น 8.2.20+ / 8.3.8+"
    },
    {
        "id": "CVE-2026-111497",
        "category": "Node.js",
        "severity": "Critical",
        "cvss": 9.2,
        "name": "Node.js Brotli Out-of-bounds Write (Node2Shell RCE)",
        "desc": "ความผิดพลาดในตัวถอดรหัส Google Brotli ใน node:zlib ทำให้อ่าน/เขียนทะลุขอบเขตหน่วยความจำและรันโค้ดอันตราย (RCE)",
        "patched": "Node.js 22.23.4 / 24.22.1 / 26.12.1+",
        "host_check": "node -v",
        "confirm_vuln": "Node.js < 22.23.4 / 24.22.1 / 26.12.1 หรือเวอร์ชัน EOL (<= 20.x, 25.x) เปิดรับ Brotli Decompression",
        "confirm_safe": "อัปเดตเป็น Node.js 22.23.4+, 24.22.1+ หรือ 26.12.1+ เรียบร้อยแล้ว"
    },
    {
        "id": "CVE-2026-109618",
        "category": "PHP",
        "severity": "Critical",
        "cvss": 9.8,
        "name": "PHP Use-After-Free (OOM bailout multipart)",
        "desc": "Memory corruption เมื่อ PHP ประมวลผล multipart + Out-of-Memory — ทำงานก่อนระดับแอปพลิเคชันโค้ด",
        "patched": "PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+",
        "host_check": "php -v && (php -i | grep 'Server API')",
        "confirm_vuln": "php -v ต่ำกว่า 8.2.35 / 8.3.36 และ Server API เป็น FPM/FastCGI หรือ Apache Handler",
        "confirm_safe": "อัปเกรด PHP เป็น 8.2.35+ หรือ 8.3.36+ เรียบร้อยแล้ว"
    },
    {
        "id": "CVE-2026-109619",
        "category": "PHP",
        "severity": "Critical",
        "cvss": 9.8,
        "cvss_version": "CVSS v3.1",
        "name": "PHP Use-After-Free (stale global state in session)",
        "desc": "Global state ไม่รีเซ็ตหลัง fatal error ทำให้ session.upload_progress อ้างอิงหน่วยความจำที่ถูก Free ไปแล้ว",
        "patched": "การแก้ไขถาวร: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ | มาตรการบรรเทาความเสี่ยง: กำหนด pm.max_requests และปิด session.upload_progress",
        "host_check": "php -i | grep session.upload_progress",
        "confirm_vuln": "session.upload_progress.enabled = On ร่วมกับ PHP ต่ำกว่า 8.2.35 / 8.3.36",
        "confirm_safe": "อัปเกรดเวอร์ชัน PHP หรือปิด session.upload_progress.enabled = 0 และระบุ pm.max_requests > 0"
    },
    {
        "id": "CVE-2026-115560",
        "category": "PHP",
        "severity": "Medium-High",
        "cvss": 8.1,
        "name": "PHP Session Upload Progress Injection",
        "desc": "การสลับ serialize_handler ข้ามรูปแบบตอน runtime ร่วมกับ upload_progress เปิดใช้งาน นำไปสู่ Session Injection และ RCE",
        "patched": "ยังไม่มีแพตช์ตรง — ป้องกันด้วย session.upload_progress.enabled = Off",
        "host_check": "php -i | grep -E 'session.serialize_handler|session.upload_progress'",
        "confirm_vuln": "แอปสลับ serialize_handler เป็น php_serialize ขณะที่ upload_progress เปิด On",
        "confirm_safe": "ตั้ง session.upload_progress.enabled = Off ใน php.ini"
    },
    {
        "id": "CVE-2026-15176",
        "category": "NGINX",
        "severity": "Critical",
        "cvss": 9.8,
        "name": "NGINX Heap Buffer Overflow (alias + rewrite)",
        "desc": "การใช้ directive alias ร่วมกับ rewrite $request_filename ในบล็อก location ทำให้เกิด Heap Buffer Overflow นำไปสู่ RCE",
        "patched": "NGINX 1.30.6+ / 1.31.7+",
        "host_check": "nginx -T 2>/dev/null | grep -B5 -A15 'alias'",
        "confirm_vuln": "พบบล็อก location มีทั้ง alias และ rewrite $request_filename บน nginx < 1.30.6 / 1.31.7",
        "confirm_safe": "ไม่พบ alias คู่กับ rewrite หรือ NGINX ≥ 1.30.6 / 1.31.7"
    },
    {
        "id": "CVE-2026-93479",
        "category": "NGINX",
        "severity": "Critical",
        "cvss": 9.8,
        "name": "NGINX Heap Buffer Overflow (map + regex)",
        "desc": "การใช้ map regex ร่วมกับตัวแปร regex capture ($1, $2) ก่อนส่งเข้า output ทำให้เกิด Heap Corruption",
        "patched": "NGINX 1.30.6+ / 1.31.7+",
        "host_check": "nginx -T 2>/dev/null | grep -B3 -A10 'map.*~'",
        "confirm_vuln": "พบคำสั่ง map regex capture ตัวแปรประกอบชื่อไฟล์บน nginx < 1.30.6 / 1.31.7",
        "confirm_safe": "ไม่พบ map regex หรือ NGINX ≥ 1.30.6 / 1.31.7"
    },
    {
        "id": "CVE-2026-97205",
        "category": "NGINX",
        "severity": "Critical",
        "cvss": 9.8,
        "name": "NGINX Use-After-Free (AIO + SSI)",
        "desc": "การเปิดใช้งาน aio on ร่วมกับ ssi on และมีการใช้ SSI include virtual ทำให้เกิด Use-After-Free",
        "patched": "NGINX 1.30.6+ / 1.31.7+",
        "host_check": "nginx -T 2>/dev/null | grep -E 'aio\\s+on|ssi\\s+on'",
        "confirm_vuln": "พบบรรทัด aio on และ ssi on เปิดพร้อมกันบน nginx < 1.30.6 / 1.31.7",
        "confirm_safe": "ไม่เปิด aio และ ssi พร้อมกัน หรือ NGINX ≥ 1.30.6 / 1.31.7"
    },
    {
        "id": "CVE-2026-95101",
        "category": "NGINX",
        "severity": "Medium",
        "cvss": 6.5,
        "name": "NGINX Request Body Injection (HTTP/3)",
        "desc": "ข้อบกพร่องใน HTTP/3 QUIC ทำให้ Request Body Injection สามารถข้ามข้อจำกัด client_max_body_size",
        "patched": "NGINX 1.30.6+ / 1.31.7+",
        "host_check": "nginx -T 2>/dev/null | grep -E 'listen.*quic|http3\\s+on'",
        "confirm_vuln": "เปิดใช้งาน HTTP/3 QUIC บน NGINX 1.25.0–1.30.5 / 1.31.0–1.31.6",
        "confirm_safe": "ไม่เปิด HTTP/3 หรือ NGINX ≥ 1.30.6 / 1.31.7"
    },
    {
        "id": "CVE-2026-97629",
        "category": "NGINX",
        "severity": "Medium",
        "cvss": 6.5,
        "name": "NGINX Session Forgery (TLS tickets)",
        "desc": "TLS Session ticket key ไม่ initialize ร่วมกันข้าม worker ทำให้เกิด Session Forgery",
        "patched": "NGINX 1.30.6+ / 1.31.7+",
        "host_check": "nginx -T 2>/dev/null | grep ssl_session_ticket",
        "confirm_vuln": "เปิดใช้ TLS Session Tickets บน NGINX 1.23.2–1.30.5 / 1.31.0–1.31.6",
        "confirm_safe": "ระบุ ssl_session_tickets off หรือ NGINX ≥ 1.30.6 / 1.31.7"
    },
    {
        "id": "CVE-2026-105482",
        "category": "Node.js",
        "severity": "High",
        "cvss": 7.5,
        "name": "Node.js DNS NUL Domain Validation Bypass",
        "desc": "ชื่อโดเมนที่มีอักขระ NUL ทำให้การตรวจปลายทางผิดพลาด และข้ามข้อจำกัดการเข้าถึงในไลบรารี c-ares",
        "patched": "Node.js 18.20.8 / 20.19.2 / 22.15.1 / 23.11.1+",
        "host_check": "node -v",
        "confirm_vuln": "Node.js ต่ำกว่า 18.20.8 / 20.19.2 / 22.15.1",
        "confirm_safe": "อัปเดตเป็นรุ่นที่แก้ไขแล้ว"
    },
    {
        "id": "CVE-2026-105483",
        "category": "Node.js",
        "severity": "High",
        "cvss": 7.5,
        "name": "Node.js TLS Cert Validation (Unicode IP)",
        "desc": "การใช้ IP รูปแบบ Unicode ทำให้ระบบยอมรับใบรับรองเซิร์ฟเวอร์ที่ไม่ถูกต้อง",
        "patched": "Node.js 20.19.2 / 22.15.1+",
        "host_check": "node -v",
        "confirm_vuln": "Node.js ต่ำกว่า 20.19.2 / 22.15.1",
        "confirm_safe": "อัปเดตเป็นรุ่นที่แก้ไขแล้ว"
    },
    {
        "id": "CVE-2026-106069",
        "category": "Node.js",
        "severity": "High",
        "cvss": 7.5,
        "name": "Node.js TLS Endpoint Identity Bypass",
        "desc": "IP รูปแบบไม่มาตรฐานทำให้หลีกเลี่ยงการตรวจสอบตัวตนเซิร์ฟเวอร์ในโมดูล TLS",
        "patched": "Node.js 20.19.2 / 22.15.1+",
        "host_check": "node -v",
        "confirm_vuln": "Node.js ต่ำกว่า 20.19.2 / 22.15.1",
        "confirm_safe": "อัปเดตเป็นรุ่นที่แก้ไขแล้ว"
    },
    {
        "id": "CVE-2019-11043",
        "category": "PHP",
        "severity": "Critical",
        "cvss": 9.8,
        "name": "PHP-FPM FastCGI Underflow RCE",
        "desc": "Pointer underflow ใน fpm_main.c เมื่อใช้ร่วมกับ NGINX fastcgi_split_path_info นำไปสู่การรันคำสั่ง Arbitrary Code Execution",
        "patched": "PHP 7.1.33 / 7.2.24 / 7.3.11 หรือ PHP 8.x+",
        "host_check": "php-fpm -v && (nginx -T | grep fastcgi_split_path_info)",
        "confirm_vuln": "PHP-FPM 7.1–7.3 ร่วมกับ NGINX ที่ใช้ fastcgi_split_path_info",
        "confirm_safe": "PHP ≥ 7.3.11 หรือ PHP 8.x"
    },
    {
        "id": "CVE-2021-23017",
        "category": "NGINX",
        "severity": "High",
        "cvss": 7.7,
        "cvss_version": "CVSS v3.1",
        "name": "NGINX 1-byte Memory Overwrite in DNS resolver",
        "desc": "ข้อผิดพลาด 1-byte memory overwrite ในโมดูล DNS resolver เมื่อประมวลผลคำตอบ DNS ที่ผิดปกติ",
        "patched": "NGINX 1.20.1 / 1.21.0+",
        "host_check": "nginx -v && (nginx -T | grep resolver)",
        "confirm_vuln": "NGINX < 1.20.1 และมีการตั้งค่า directive resolver",
        "confirm_safe": "NGINX ≥ 1.20.1 หรือไม่มี directive resolver"
    },
    {
        "id": "CVE-2022-31626",
        "category": "PHP",
        "severity": "High",
        "cvss": 7.5,
        "name": "PHP mysqlnd Buffer Overflow",
        "desc": "Buffer overflow ในไดรเวอร์ mysqlnd เมื่อรับแพ็กเก็ตตอบกลับที่ผิดปกติจากเซิร์ฟเวอร์ฐานข้อมูล",
        "patched": "PHP 7.4.30 / 8.0.20 / 8.1.7+",
        "host_check": "php -m | grep mysqlnd && php -v",
        "confirm_vuln": "พบ mysqlnd บน PHP < 7.4.30 / 8.0.20 / 8.1.7",
        "confirm_safe": "PHP ≥ 8.1.7 หรือ PHP 8.2+"
    }
]

import json
import os

def load_cve_feed_updates(feed_path: str = None) -> int:
    """
    Dynamically loads updated CVE advisory records from an external JSON feed file
    (e.g., synchronized from NVD, OSV, or ThaiCERT feed) without altering code.
    """
    path = feed_path or os.environ.get("OPSCANER_CVE_FEED_PATH")
    if not path and os.path.exists("cve_feed.json"):
        path = "cve_feed.json"
    
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                feed = json.load(f)
                if isinstance(feed, list):
                    existing_ids = {item.get("id") for item in CVE_DATABASE}
                    added = 0
                    for entry in feed:
                        if isinstance(entry, dict) and entry.get("id"):
                            if entry["id"] in existing_ids:
                                for i, old in enumerate(CVE_DATABASE):
                                    if old.get("id") == entry["id"]:
                                        CVE_DATABASE[i] = entry
                                        break
                            else:
                                CVE_DATABASE.append(entry)
                                existing_ids.add(entry["id"])
                                added += 1
                    return added
        except Exception:
            pass
    return 0

# Attempt initial feed load if feed file exists
load_cve_feed_updates()
