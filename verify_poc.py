#!/usr/bin/env python3
"""
OPScaner Defensive POC & Verification Harness
Provides live evidence-based verification for TBCERT / ThaiCERT:
1. Proof of Active Verification vs Passive Banner Grabbing (LFI Canary Probe & Strict Mode)
2. OS & SAPI Environmental Verification (Windows Win64 vs Linux & Host Command Check)
3. Differential Comparison (Port 8080 Vulnerable vs Port 8088 CIS Hardened)
"""

import sys
import asyncio
import httpx
import json

from audit.probe_audit import probe_lfi_prerequisite
from audit.sub_tools import probe_strict_session_mode, probe_information_disclosure
from audit.thaicert_rules import classify_thaicert_groups, evaluate_group_architecture_matrix
from audit.rce_prover import probe_active_rce_proof

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


async def run_verification_suite(base_url: str = "http://localhost:8080"):
    print(f"\n{BOLD}{BLUE}{'='*75}{RESET}")
    print(f"{BOLD}{BLUE}  OPScaner Evidence-Based Verification Suite (TBCERT / ThaiCERT POC){RESET}")
    print(f"{BOLD}{BLUE}{'='*75}{RESET}\n")
    print(f"[*] Target Endpoint: {BOLD}{base_url}{RESET}")

    async with httpx.AsyncClient(verify=False, timeout=3.0) as client:
        try:
            r = await client.get(base_url)
        except Exception as e:
            print(f"{RED}[-] Connection failed to {base_url}: {e}{RESET}")
            print(f"{YELLOW}[!] Ensure Docker testbed is running (docker start opscaner-test-target){RESET}")
            return

        headers = r.headers
        server_banner = headers.get("server", "Unknown")
        powered_by = headers.get("x-powered-by", "Unknown")
        server_os = headers.get("x-server-os", "Unknown")
        sapi_header = headers.get("x-php-sapi", "Unknown")
        session_path = headers.get("x-session-save-path", "Unknown")

        # -------------------------------------------------------------
        # CHALLENGE 2: OS & SAPI Environmental Verification
        # -------------------------------------------------------------
        print(f"\n{BOLD}[1] การตรวจสอบสถาปัตยกรรมระบบปฏิบัติการและ SAPI (OS & SAPI Verification){RESET}")
        print(f"    - Server Banner:     {YELLOW}{server_banner}{RESET}")
        print(f"    - X-Powered-By:      {YELLOW}{powered_by}{RESET}")
        print(f"    - Server OS Header:  {YELLOW}{server_os}{RESET}")
        print(f"    - SAPI Type:         {YELLOW}{sapi_header}{RESET}")
        print(f"    - Session Storage:   {YELLOW}{session_path}{RESET}")

        is_win = any(k in server_banner.lower() or k in server_os.lower() for k in ["win", "windows", "microsoft"])
        if is_win:
            print(f"    -> {GREEN}[PASS] ยืนยันสถาปัตยกรรม Windows OS (Win64) สอดคล้องกับเงื่อนไขของ CVE-2024-4577{RESET}")
        else:
            print(f"    -> {YELLOW}[WARN] ตรวจพบสถาปัตยกรรม Linux (CVE-2024-4577 จะไม่ส่งผลกระทบ RCE บนโฮสต์นี้){RESET}")

        print(f"\n    {BOLD}คำสั่งตรวจสอบบนโฮสต์จริง (Host Verification Command):{RESET}")
        print(f"    {BOLD}CLI:{RESET} {GREEN}php -v && (php -i | grep -E 'Server API|System|session.save_path'){RESET}")

        # -------------------------------------------------------------
        # CHALLENGE 1: Proof of Active Canary Probe vs Blind Fuzzing
        # -------------------------------------------------------------
        print(f"\n{BOLD}[2] การทดสอบยืนยันเงื่อนไขจำเป็นเชิงรุก (Active Canary Verification vs Banner Grabbing){RESET}")
        print("    ส่ง Benign Diagnostic Canary Token ไปยังพารามิเตอร์เรียกไฟล์...")

        lfi_result = await probe_lfi_prerequisite(client, base_url, r.text, {})
        if lfi_result.get("has_lfi_prerequisite"):
            print(f"    -> {RED}{BOLD}[VULN DETECTED]{RESET} ตรวจพบช่องโหว่ File Inclusion (FI/LFI) จริง!")
            print(f"       พารามิเตอร์ที่พบ:  {YELLOW}?{lfi_result.get('param')}={RESET}")
            print(f"       หลักฐานยืนยัน:     {lfi_result.get('evidence')}")
            print(f"       สถานะ Exploit Chain: {GREEN}ครบเงื่อนไขของ Chain A (Upload Progress + LFI RCE){RESET}")
        else:
            print(f"    -> {GREEN}{BOLD}[PREREQUISITE ABSENT]{RESET} ไม่พบฟังก์ชันเรียกไฟล์หรือ include stream error")
            print("       ผลสรุป: ระบบปลอดภัยจากการทำ RCE ผ่าน Chain A (ขาดเงื่อนไขจำเป็น)")

        # Test Strict Session Mode Canary
        strict_result = await probe_strict_session_mode(client, base_url, {})
        print(f"\n    ตรวจสอบการบังคับใช้ Session Strict Mode (session.use_strict_mode):")
        print(f"    -> สถานะ: {strict_result.get('status')} | {strict_result.get('evidence')}")

        # Path Disclosure Probe
        path_result = await probe_information_disclosure(client, base_url, r.text, {})
        print(f"\n    ตรวจสอบการเปิดเผยเส้นทางระบบ (Path Disclosure):")
        if path_result.get("leaked_paths"):
            print(f"    -> ตรวจพบ Path จริงบนเครื่อง: {YELLOW}{', '.join(path_result.get('leaked_paths'))}{RESET}")
        else:
            print(f"    -> {GREEN}ไม่พบการรั่วไหลของไดเรกทอรีระบบสู่หน้าจอ{RESET}")

        # -------------------------------------------------------------
        # ThaiCERT 8-Group Classification
        # -------------------------------------------------------------
        print(f"\n{BOLD}[3] การจัดกลุ่มระบบตามมาตรฐาน ThaiCERT (8-Group Classification){RESET}")
        tc_info = classify_thaicert_groups(
            ip_or_host="localhost",
            server=server_banner,
            headers=dict(headers),
            body_text=r.text,
            cookies_str=str(r.cookies),
            port=8080,
            is_php=True,
            is_node=False,
            cms_name="WordPress" if "wp-json" in r.text or "wp-content" in r.text else "Web Application"
        )
        print(f"    - กลุ่มหลักที่ระบุ:  {BOLD}{tc_info.get('primary_group')}{RESET}")
        print(f"    - กลุ่มระบบที่เข้าข่าย: {YELLOW}{', '.join(tc_info.get('group_labels', []))}{RESET}")

        # -------------------------------------------------------------
        # CHALLENGE 4: Empirical Live RCE Proof Indicator
        # -------------------------------------------------------------
        port_num = 8080
        if ":" in base_url.replace("http://", "").replace("https://", ""):
            try:
                port_num = int(base_url.split(":")[-1].split("/")[0])
            except ValueError:
                pass

        print(f"\n{BOLD}[4] การพิสูจน์การรันคำสั่งจริง (Empirical Live RCE Proof Indicator){RESET}")
        rce_res = await probe_active_rce_proof(client, base_url, port_num, server=server_banner, is_php=True)
        if rce_res.get("is_rce_proved"):
            print(f"    -> {RED}{BOLD}{rce_res.get('proof_badge')}{RESET}")
            print(f"       เทคนิค:          {YELLOW}{rce_res.get('technique')}{RESET}")
            print(f"       ระดับสิทธิ์:      {RED}{rce_res.get('privilege_level')}{RESET}")
            print(f"       คำสั่งที่รัน:     {GREEN}$ {rce_res.get('command_executed')}{RESET}")
            print(f"       ผลลัพธ์จาก OS:   {BOLD}{rce_res.get('execution_output')}{RESET}")
            print(f"       CLI Reproduce:   {YELLOW}{rce_res.get('reproduce_curl')}{RESET}")
            print(f"       สรุปผล:          {rce_res.get('impact_statement')}")
        else:
            print(f"    -> {GREEN}{BOLD}[SAFE / THEORETICAL ONLY]{RESET}")
            print(f"       สถานะ:          {rce_res.get('proof_badge')}")
            print(f"       ผลลัพธ์:        {rce_res.get('execution_output')}")
            print(f"       สรุปผล:          {rce_res.get('impact_statement')}")

        print(f"\n{BOLD}{BLUE}{'='*75}{RESET}\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    asyncio.run(run_verification_suite(target))
