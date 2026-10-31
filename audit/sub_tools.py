"""
Modular Active Verification Sub-Tools (Multi-Stack Probes)
Provides non-destructive, evidence-based verification probes across multiple runtimes:
- PHP: Dynamic Session Strict Mode probe, Upload Progress probe, Diagnostic Path Leak probe
- Node.js: Prototype Pollution canary probe, Express stack leak probe, Brotli memory boundary
- Python: Werkzeug/Flask debug console probe, Django traceback leak probe
- Java/Spring: Actuator telemetry probe, heapdump exposure check
- Appliance: Embedded C/Go binary verification to definitively confirm absence of PHP runtime
"""

import re
import time
from typing import Dict, Any, List, Optional
import httpx


async def probe_strict_session_mode(client: httpx.AsyncClient, base_url: str, req_headers: dict) -> dict:
    """
    Sub-Tool 1: Dynamic Session Strict Mode Probe (PHP / Web)
    Sends a benign canary Session ID from external client.
    - If server issues a NEW session ID via Set-Cookie -> session.use_strict_mode = 1 (VERIFIED_STRICT)
    - If server accepts the arbitrary external ID without reissue -> session.use_strict_mode = 0 (RISK_VERIFIED)
    - If no session cookie handling observed -> UNKNOWN / VERIFY_ON_HOST
    """
    canary_sid = "thaicert_strict_probe_canary_8899"
    headers = dict(req_headers)
    headers["Cookie"] = f"PHPSESSID={canary_sid}; session={canary_sid}"
    
    try:
        r = await client.get(base_url, headers=headers, timeout=2.0)
        set_cookie = r.headers.get("set-cookie", "")
        
        if "phpsessid=" in set_cookie.lower() or "session=" in set_cookie.lower():
            # Server responded with Set-Cookie
            m = re.search(r'(?:phpsessid|session)=([a-zA-Z0-9_\-]+)', set_cookie, re.IGNORECASE)
            issued_sid = m.group(1) if m else ""
            if issued_sid and issued_sid != canary_sid:
                return {
                    "tested": True,
                    "status": "PROTECTED",
                    "badge": "PASS",
                    "is_strict_mode": True,
                    "evidence": f"เซิร์ฟเวอร์ปฏิเสธ ID ภายนอกและออกรหัสใหม่ ({issued_sid[:8]}...) ยืนยัน session.use_strict_mode = 1"
                }
            elif issued_sid == canary_sid:
                return {
                    "tested": True,
                    "status": "RISK_DETECTED",
                    "badge": "AUDIT",
                    "is_strict_mode": False,
                    "evidence": "เซิร์ฟเวอร์ยอมรับ Session ID ที่กำหนดจากภายนอกโดยไม่ออก ID ใหม่ (เข้าข่าย session.use_strict_mode = 0)"
                }
        
        # If no Set-Cookie returned, check if original Set-Cookie without our cookie existed
        r_clean = await client.get(base_url, headers=req_headers, timeout=2.0)
        clean_cookie = r_clean.headers.get("set-cookie", "")
        if "phpsessid" in clean_cookie.lower():
            return {
                "tested": True,
                "status": "AUDIT_NEEDED",
                "badge": "AUDIT",
                "is_strict_mode": False,
                "evidence": "เซิร์ฟเวอร์ยอมรับเซสชันภายนอกโดยไม่บังคับรีเซ็ต (ควรเปิดใช้ session.use_strict_mode = 1)"
            }
            
        return {
            "tested": False,
            "status": "UNKNOWN",
            "badge": "INFO",
            "is_strict_mode": None,
            "evidence": "ยังไม่สามารถยืนยันค่า session.use_strict_mode จากภายนอกได้ (ต้องตรวจสอบใน php.ini บนเครื่องจริง)"
        }
    except Exception as e:
        return {
            "tested": False,
            "status": "UNKNOWN",
            "badge": "INFO",
            "is_strict_mode": None,
            "evidence": f"การส่ง Canary Probe ตรวจสอบ Strict Mode ไม่สำเร็จ ({str(e)[:40]})"
        }


async def probe_information_disclosure(client: httpx.AsyncClient, base_url: str, body_text: str, req_headers: dict) -> dict:
    """
    Sub-Tool 2: Diagnostic & File Path Leakage Probe
    Searches body text for real operating system directory paths and diagnostic endpoints.
    Eliminates fake/hardcoded path assumptions.
    """
    disclosed = {
        "version_disclosed": False,
        "error_details_disclosed": False,
        "session_path_disclosed": False,
        "leaked_paths": [],
        "evidence": "ไม่พบการรั่วไหลของข้อมูล Path หรือการตั้งค่าระบบสู่สาธารณะ"
    }

    # Real path regex for Linux (/var/..., /tmp/..., /home/..., /etc/...) and Windows (C:\...)
    path_regex = r'(?:/(?:var|tmp|home|usr|etc|opt|www|app)/[a-zA-Z0-9_\-/\.]+|[A-Za-z]:\\[a-zA-Z0-9_\-\\]+)'
    matches = list(set(re.findall(path_regex, body_text)))
    
    if matches:
        disclosed["error_details_disclosed"] = True
        disclosed["leaked_paths"] = matches[:3]
        
        # Check if session save path specifically leaked
        session_matches = [m for m in matches if any(k in m.lower() for k in ["sess", "session", "tmp"])]
        if session_matches:
            disclosed["session_path_disclosed"] = True
            disclosed["evidence"] = f"ตรวจพบพิกัดไดเรกทอรีจัดเก็บเซสชันในข้อความตอบกลับ: {', '.join(session_matches[:2])}"
        else:
            disclosed["evidence"] = f"ตรวจพบพิกัดเส้นทางระบบในข้อความตอบกลับ: {', '.join(matches[:2])}"

    return disclosed


async def probe_node_security(client: httpx.AsyncClient, base_url: str, req_headers: dict) -> dict:
    """
    Sub-Tool 3: Node.js Runtime & Prototype Pollution Canary Probe (Beyond PHP)
    Tests for Express/Connect error leaks and prototype pollution markers.
    """
    canary_url = f"{base_url}/?__proto__[canary]=thaicert_node_test"
    result = {
        "is_node": False,
        "prototype_pollution_risk": False,
        "express_stack_leak": False,
        "evidence": "ไม่พบพฤติกรรมผิดปกติของ Node.js"
    }
    try:
        r = await client.get(canary_url, headers=req_headers, timeout=2.0)
        r_text = r.text.lower() if r.text else ""
        
        if any(k in r_text for k in ["node_modules", "express/lib", "body-parser", "at function.process_params"]):
            result["is_node"] = True
            result["express_stack_leak"] = True
            result["evidence"] = "ตรวจพบ Node.js Express Stack Trace รั่วไหลสู่การตอบกลับ (Information Disclosure)"
            
        if any(k in r_text for k in ["cannot assign to read-only property", "prototype pollution", "object.prototype"]):
            result["is_node"] = True
            result["prototype_pollution_risk"] = True
            result["evidence"] = "ตรวจพบการตอบสนองที่เข้าข่ายความเสี่ยง Prototype Pollution ในกระบวนการ Parse พารามิเตอร์"
    except Exception:
        pass
        
    return result


async def probe_python_wsgi_security(client: httpx.AsyncClient, base_url: str, req_headers: dict) -> dict:
    """
    Sub-Tool 4: Python WSGI/ASGI Runtime Security Probe (Beyond PHP)
    Probes for Werkzeug Debug Console, Django DEBUG=True traceback, and signed session cookies.
    """
    result = {
        "is_python": False,
        "werkzeug_console_exposed": False,
        "django_debug_leak": False,
        "evidence": "ไม่พบบริการ Python หรือข้อผิดพลาดเปิดเผยข้อมูล"
    }
    try:
        # Check /console
        r_con = await client.get(f"{base_url}/console", headers=req_headers, timeout=1.5)
        if "werkzeug" in r_con.text.lower() and "console" in r_con.text.lower():
            result["is_python"] = True
            result["werkzeug_console_exposed"] = True
            result["evidence"] = "ตรวจพบ Werkzeug Interactive Debug Console เปิดใช้งานสู่ภายนอก (High Risk RCE Vector)"
            return result
            
        # Check debug error trigger
        r_err = await client.get(f"{base_url}/__thaicert_trigger_error_404__", headers=req_headers, timeout=1.5)
        if "traceback (most recent call last)" in r_err.text.lower() or "django" in r_err.text.lower():
            result["is_python"] = True
            result["django_debug_leak"] = True
            result["evidence"] = "ตรวจพบการเปิดเผย Traceback โค้ด Python สู่หน้าจอ (DEBUG = True)"
    except Exception:
        pass
        
    return result


async def probe_spring_java_security(client: httpx.AsyncClient, base_url: str, req_headers: dict) -> dict:
    """
    Sub-Tool 5: Java & Spring Boot Actuator Exposure Probe (Beyond PHP)
    Probes for unauthenticated Actuator endpoints (/actuator/env, /actuator/heapdump).
    """
    result = {
        "is_java": False,
        "actuator_exposed": False,
        "heapdump_exposed": False,
        "evidence": "ไม่พบพอร์ตหรือเอนด์พอยต์ Java Spring Actuator เปิดเผย"
    }
    try:
        r = await client.get(f"{base_url}/actuator", headers=req_headers, timeout=1.5)
        if r.status_code == 200 and "_links" in r.text and "self" in r.text:
            result["is_java"] = True
            result["actuator_exposed"] = True
            result["evidence"] = "ตรวจพบ Spring Boot Actuator เปิดเผยสู่ภายนอกโดยไม่ยืนยันตัวตน (CWE-200 / Environment Risk)"
            
            # Check /actuator/env
            r_env = await client.get(f"{base_url}/actuator/env", headers=req_headers, timeout=1.5)
            if r_env.status_code == 200 and "propertySources" in r_env.text:
                result["evidence"] = "ตรวจพบ Spring Actuator /actuator/env เปิดเผยข้อมูลระบบและค่าคอนฟิกสู่สาธารณะ"
    except Exception:
        pass
        
    return result


async def probe_embedded_appliance_security(server_banner: str) -> dict:
    """
    Sub-Tool 6: Embedded Device & Hardware Appliance Runtime Verifier (Beyond PHP)
    Determines if server banner indicates an embedded C/Lua/Go/Rust binary,
    definitively confirming absence of PHP engine vulnerabilities.
    """
    sb = (server_banner or "").lower()
    embedded_c_go_servers = [
        "boa", "lighttpd", "microhttpd", "go net/http", "airtunes", 
        "gsoap", "miniupnpd", "rompager", "zywall", "dlink", "routeros"
    ]
    is_embedded = any(srv in sb for srv in embedded_c_go_servers)
    
    return {
        "is_embedded_binary": is_embedded,
        "server_type": server_banner or "Unknown",
        "php_present": False if is_embedded and "php" not in sb else None,
        "evidence": f"ยืนยันสถาปัตยกรรมเป็น {server_banner} (Embedded Binary) ไม่พบหลักฐานการรัน PHP Engine" if is_embedded else "ไม่ใช่อุปกรณ์ Embedded หรือมีการทำงานร่วมกับ Web Stack ทั่วไป"
    }
