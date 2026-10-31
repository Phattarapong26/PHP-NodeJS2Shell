#!/usr/bin/env python3
"""
OPScaner Security Audit Toolkit (CLI Edition)
Enterprise-grade, Non-destructive Vulnerability & Architecture Assessment CLI.
Compliant with ThaiCERT & NCSA Guidelines (8 Target Groups & Safe Canary Verification).

Usage:
    python3 audit_cli.py -t http://localhost:8080
    python3 audit_cli.py -t 192.168.1.41 -p 80
    python3 audit_cli.py -t http://localhost:8080 --export-report
"""

import argparse
import asyncio
import getpass
import json
import sys
import time
from urllib.parse import urlparse
import httpx

from audit.probe_audit import probe_endpoint
from core.network import is_public_target
from reports.amber_builder import build_amber_advisory_html


# ANSI Colors for Terminal
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"
C_WHITE = "\033[97m"
C_BG_RED = "\033[41m\033[97m"
C_BG_AMBER = "\033[43m\033[30m"


def print_banner():
    banner = f"""{C_CYAN}{C_BOLD}
  ╔════════════════════════════════════════════════════════════════════╗
  ║       OPScaner — ThaiCERT & NCSA Security Audit Toolkit (CLI)      ║
  ║         Context-Aware Precision Scanner & Architecture Matrix      ║
  ║          Safe Active Verification • Zero Mock • Multi-Stack        ║
  ╚════════════════════════════════════════════════════════════════════╝{C_RESET}
"""
    print(banner)


def parse_target(target_str: str, default_port: int = 80):
    """Parses URL or host:port into (host, port, scheme)"""
    if "://" in target_str:
        u = urlparse(target_str)
        scheme = u.scheme or "http"
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if scheme == "https" else default_port)
    else:
        if ":" in target_str:
            parts = target_str.split(":")
            host = parts[0]
            port = int(parts[1])
            scheme = "https" if port == 443 else "http"
        else:
            host = target_str
            port = default_port
            scheme = "https" if port == 443 else "http"
    return host, port, scheme


async def run_cli_audit(
    target: str,
    port_override: int,
    export_report: bool,
    output_json: str,
    active_rce: bool = False,
    i_own_this_target: bool = False,
    operator: str = ""
):
    host, port, scheme = parse_target(target, default_port=port_override or 80)
    target_url = f"{scheme}://{host}:{port}"
    operator = operator or getpass.getuser()

    # --- SAFETY GATE CHECK ---
    if active_rce:
        is_public = is_public_target(host)
        if is_public and not i_own_this_target:
            print(f"\n{C_RED}{C_BOLD}╔══════════════════════════════════════════════════════════════════════╗{C_RESET}")
            print(f"{C_RED}{C_BOLD}║                [!] SAFETY GATE ACTIVATED: PUBLIC TARGET              ║{C_RESET}")
            print(f"{C_RED}{C_BOLD}╚══════════════════════════════════════════════════════════════════════╝{C_RESET}")
            print(f"{C_YELLOW}เป้าหมาย '{host}' เป็น IP สาธารณะ หรือ โดเมนภายนอกเครือข่ายท้องถิ่น{C_RESET}")
            print(f"{C_YELLOW}การเปิดโหมด --active-rce จะส่ง Live Canary & PoC Payload เพื่อทดสอบการรันโค้ดจริง{C_RESET}")
            print(f"{C_WHITE}ท่านต้องเป็นเจ้าของระบบ หรือได้รับหนังสืออนุญาตเป็นลายลักษณ์อักษรตาม พ.ร.บ.คอมพิวเตอร์ฯ{C_RESET}\n")
            try:
                confirm = input(f"{C_WHITE}พิมพ์ '{C_RED}{C_BOLD}YES{C_RESET}{C_WHITE}' เพื่อยืนยันสิทธิ์และดำเนินการต่อ: {C_RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                confirm = "NO"

            if confirm != "YES":
                print(f"\n{C_YELLOW}[!] Safety Gate: ยกเลิก Active RCE โดยผู้ใช้งาน — ดำเนินการเฉพาะ Safe Passive Audit{C_RESET}\n")
                active_rce = False
            else:
                print(f"\n{C_GREEN}[✓] Safety Gate: ยืนยันสิทธิ์เรียบร้อย — เริ่มต้นการทดสอบ Active RCE Verification...{C_RESET}\n")

    print(f"{C_WHITE}[*] กำลังเริ่มต้นตรวจสอบเป้าหมาย:{C_RESET} {C_BOLD}{target_url}{C_RESET}")
    print(f"{C_WHITE}[*] โหมดการตรวจสอบ:{C_RESET} {C_RED + C_BOLD + 'Active RCE PoC Enabled' if active_rce else C_GREEN + 'Safe Passive & Heuristic Inspection'}{C_RESET}")
    print(f"{C_WHITE}[*] ขั้นตอนที่ 1:{C_RESET} Pre-flight TCP Handshake & Layer-7 Fingerprinting...")

    t0 = time.time()
    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
        result = await probe_endpoint(
            client,
            host,
            port,
            allow_active_rce=active_rce,
            operator=operator
        )

    duration = time.time() - t0

    if not result:
        print(f"\n{C_RED}[!] ไม่สามารถเชื่อมต่อเป้าหมาย {target_url} ได้ (Connection Timed out / Port Closed){C_RESET}\n")
        return

    # Extract Findings & Evidence
    da = result.get("deep_audit", {})
    web_server = result.get("webServer") or "Unknown"
    cms_name = result.get("cms") or "Web Application"
    primary_group = result.get("primary_group") or "Unclassified"
    groups = result.get("thaicert_groups") or []
    group_labels = result.get("group_labels") or []
    matched_cves = result.get("matched_cves") or []
    sec_chains = result.get("security_chains", {}).get("chains", {})
    sub_tools = da.get("sub_tools", {})

    print(f"{C_GREEN}[+] การเชื่อมต่อสำเร็จ! ใช้เวลาประเมิน {duration:.2f} วินาที{C_RESET}\n")

    # Target Profile Summary Card
    print(f"{C_BOLD}═══ [ข้อมูลระบบและสถาปัตยกรรมที่ตรวจพบ] ════════════════════════════════{C_RESET}")
    print(f"  • {C_WHITE}เป้าหมาย (Host):{C_RESET}        {C_CYAN}{result.get('ip')}:{port}{C_RESET}")
    print(f"  • {C_WHITE}เว็บเซิร์ฟเวอร์ (Server):{C_RESET} {C_YELLOW}{web_server}{C_RESET}")
    if result.get("php"):
        print(f"  • {C_WHITE}PHP Runtime:{C_RESET}            {C_RED if '8.2.19' in str(result.get('php')) or result.get('vulnerability') == 'Critical' else C_GREEN}{result.get('php')}{C_RESET}")
    if result.get("node"):
        print(f"  • {C_WHITE}Node.js Runtime:{C_RESET}        {C_CYAN}{result.get('node')}{C_RESET}")
    print(f"  • {C_WHITE}CMS / Framework:{C_RESET}        {C_MAGENTA}{cms_name}{C_RESET}")
    print(f"  • {C_WHITE}ระบบป้องกัน (WAF):{C_RESET}      {result.get('waf')}")
    print(f"  • {C_WHITE}กลุ่มระบบ ThaiCERT:{C_RESET}     {C_BOLD}{primary_group}{C_RESET}")
    if len(group_labels) > 1:
        for gl in group_labels[1:]:
            print(f"                           ↳ {gl}")

    # Sub-tools & Non-Destructive Active Canaries
    print(f"\n{C_BOLD}═══ [ผลการทดสอบ Active Verification Canaries (Safe Probes)] ════════════{C_RESET}")
    
    # 1. LFI Canary
    lfi_res = None
    probe_steps = da.get("probe_steps") or []
    for step in probe_steps:
        if isinstance(step, dict) and "LFI" in step.get("step", ""):
            lfi_res = step
            break
    if lfi_res:
        status_color = C_RED if lfi_res.get("status") == "warn" else C_GREEN
        print(f"  [1] LFI Dynamic Canary:      {status_color}{lfi_res.get('desc')}{C_RESET}")
    else:
        # Check from probe_log text
        for log_line in result.get("probe_log", []):
            if "LFI" in str(log_line):
                status_color = C_RED if "DETECTED" in str(log_line) or "warn" in str(log_line).lower() else C_GREEN
                print(f"  [1] LFI Dynamic Canary:      {status_color}{log_line}{C_RESET}")
                lfi_res = True
                break
        if not lfi_res:
            print(f"  [1] LFI Dynamic Canary:      {C_GREEN}ไม่พบพารามิเตอร์เรียกไฟล์เสี่ยง (Prerequisite Absent){C_RESET}")

    # 2. Strict Session Mode
    strict_tool = sub_tools.get("strict_mode_probe")
    if strict_tool and strict_tool.get("tested"):
        st_color = C_GREEN if strict_tool.get("is_strict_mode") else C_YELLOW
        print(f"  [2] Session Strict Mode:     {st_color}{strict_tool.get('evidence')}{C_RESET}")
    else:
        print(f"  [2] Session Strict Mode:     {C_WHITE}ไม่ได้จัดการคุกกี้เซสชันจากภายนอก (ตรวจสอบใน php.ini){C_RESET}")

    # 3. Path & Boundary Leakage
    info_tool = sub_tools.get("info_disclosure_probe")
    if info_tool and info_tool.get("error_details_disclosed"):
        print(f"  [3] Path Disclosure Leak:    {C_YELLOW}{info_tool.get('evidence')}{C_RESET}")
    else:
        print(f"  [3] Path Disclosure Leak:    {C_GREEN}ไม่พบการรั่วไหลของ Path ระบบสู่สาธารณะ{C_RESET}")

    # Exploit Chains Assessment
    if sec_chains:
        print(f"\n{C_BOLD}═══ [การประเมินห่วงโซ่การโจมตี (Security Exploit Chains A-E)] ══════════{C_RESET}")
        for c_key, c_val in sec_chains.items():
            code = c_val.get("verdict_code")
            title = c_val.get("short_title") or c_val.get("title")
            stages = c_val.get("stages_display", "-")
            color = C_RED if code in ("VULN", "ARCHITECTURAL_RISK") else (C_YELLOW if code in ("CONDITIONAL", "REVIEW", "AUDIT") else C_GREEN)
            print(f"  • {C_BOLD}{title}{C_RESET}")
            print(f"    - สถานะ: {color}{c_val.get('verdict')}{C_RESET} (ผ่านเงื่อนไข: {stages})")
            if c_val.get("remediation"):
                first_rem = c_val.get("remediation").splitlines()[0]
                print(f"    - แนวทางแก้ไข: {C_CYAN}{first_rem}{C_RESET}")

    # RCE Proof & Cryptographic Evidence Card
    rce_info = da.get("rce_proof") or {}
    rce_status = rce_info.get("proof_status", "PROBING_DISABLED_BY_SAFETY_GATE")
    rce_tech = rce_info.get("technique", "-")
    rce_cmd = rce_info.get("command_executed")
    rce_out = rce_info.get("execution_output")
    rce_trail = rce_info.get("audit_trail")

    print(f"\n{C_BOLD}═══ [ผลการพิสูจน์ทราบ RCE / LFI Verification (PoC Evidence)] ══════════════{C_RESET}")
    if rce_status == "RCE_CONFIRMED":
        print(f"  {C_BG_RED} 🔥 RCE CONFIRMED (ยืนยันช่องโหว่การรันโค้ดระดับคำสั่ง) {C_RESET}")
        print(f"  • {C_WHITE}เทคนิคการขยายผล:{C_RESET}     {C_RED}{rce_tech}{C_RESET}")
        print(f"  • {C_WHITE}คำสั่ง/Canary ที่รัน:{C_RESET} {C_YELLOW}{rce_cmd}{C_RESET}")
        print(f"  • {C_WHITE}ผลลัพธ์เชิงประจักษ์:{C_RESET}  {C_WHITE}{rce_out}{C_RESET}")
        print(f"  • {C_WHITE}ระดับสิทธิ์ที่ได้รับ:{C_RESET}  {C_RED}{rce_info.get('privilege_level')}{C_RESET}")
        print(f"  • {C_WHITE}Endpoint ทดสอบ:{C_RESET}     {C_CYAN}{rce_info.get('exploit_endpoint')}{C_RESET}")
    elif rce_status == "CANARY_CONFIRMED":
        print(f"  {C_BG_AMBER} ⚠️ CANARY CONFIRMED (ยืนยัน LFI สำเร็จ - อ่านไฟล์เซสชันได้) {C_RESET}")
        print(f"  • {C_WHITE}ผลการประเมิน:{C_RESET}        {C_YELLOW}Canary reflected in session file (PHP execution neutralized){C_RESET}")
        print(f"  • {C_WHITE}ข้อสรุปทางเทคนิค:{C_RESET}    {C_WHITE}เป็น Arbitrary File Read ผ่านเซสชัน แต่ไม่เกิดการ Execute โค้ด{C_RESET}")
    elif rce_status == "CONFIRMED_LFI":
        print(f"  {C_BG_AMBER} ⚠️ LFI / ARBITRARY FILE READ CONFIRMED (CWE-22 / CWE-98) {C_RESET}")
        print(f"  • {C_WHITE}ไฟล์ระบบที่อ่านได้:{C_RESET}  {C_YELLOW}{rce_info.get('exploit_endpoint')}{C_RESET}")
        print(f"  • {C_WHITE}ข้อสรุปทางเทคนิค:{C_RESET}    {C_WHITE}อ่าน /etc/passwd ได้จริง (ยังไม่ยืนยัน RCE){C_RESET}")
    elif rce_status == "PROBING_DISABLED_BY_SAFETY_GATE":
        print(f"  {C_GREEN}🛡️ SAFETY GATE ACTIVE: การทดสอบ Active RCE ถูกระงับไว้โดยค่าเริ่มต้น{C_RESET}")
        print(f"  • {C_WHITE}คำแนะนำ:{C_RESET}              หากต้องการทดสอบ PoC ให้ระบุ {C_CYAN}--active-rce{C_RESET}")
    else:
        print(f"  {C_GREEN}✓ NOT CONFIRMED: ไม่พบหลักฐานการเกิด RCE หรือช่องทางส่งต่อคำสั่งควบคุม{C_RESET}")

    if rce_trail:
        print(f"\n  {C_CYAN}{C_BOLD}[Tamper-Evident Evidence Digest & Integrity Hash (SHA-256)]{C_RESET}")
        print(f"  • {C_WHITE}ผู้ทดสอบ (Operator):{C_RESET}  {rce_trail.get('operator')}")
        print(f"  • {C_WHITE}เวลา (Timestamp UTC):{C_RESET} {rce_trail.get('timestamp_utc')}")
        print(f"  • {C_WHITE}Payload SHA-256:{C_RESET}     {C_YELLOW}{rce_trail.get('payload_sha256')}{C_RESET}")
        print(f"  • {C_WHITE}Evidence SHA-256:{C_RESET}    {C_GREEN}{rce_trail.get('evidence_sha256')}{C_RESET}")

    # Matched CVEs
    print(f"\n{C_BOLD}═══ [รายการข้อค้นพบช่องโหว่ความมั่นคงปลอดภัย (CVE Ledger)] ═══════════════{C_RESET}")
    if matched_cves:
        for c in matched_cves:
            cve_id = c.get("id") or c.get("cve")
            cve_name = c.get("name")
            sev = c.get("severity")
            cvss = c.get("cvss")
            sev_color = C_RED if sev == "Critical" else (C_YELLOW if sev == "High" else C_BLUE)
            print(f"  {sev_color}[!] ค้นพบ {cve_id} {cve_name}{C_RESET}")
            print(f"      ระดับความรุนแรง: {sev_color}{sev} (CVSS: {cvss}){C_RESET} | เหตุผล: {c.get('reason')}")
            print(f"      คำสั่งตรวจบนเครื่อง: {C_WHITE}`{c.get('host_check')}`{C_RESET}")
    else:
        print(f"  {C_GREEN}✓ ไม่พบรายการ CVE ที่ตรงกับเงื่อนไขความเสี่ยงตามขอบเขตที่ตรวจสอบ{C_RESET}")

    # Summary Verdict
    overall_sev = result.get("vulnerability") or "Secure"
    sev_bg = C_BG_RED if overall_sev in ("Critical", "High") else (C_BG_AMBER if overall_sev in ("Medium", "Warning") else C_GREEN)
    print(f"\n{C_BOLD}═══ [สรุปผลการประเมินความเสี่ยงภาพรวม] ═════════════════════════════════════{C_RESET}")
    print(f"  ระดับความเสี่ยง: {sev_bg} {overall_sev} {C_RESET}")
    print(f"  คำแนะนำหลัก:   {result.get('cveNote') or 'ติดตามการอัปเดตแพตช์ความปลอดภัยตามรอบเวลาปกติ'}")

    # Export Report if requested
    if export_report:
        report_data = {
            "target": target_url,
            "hosts": [result]
        }
        report_html = build_amber_advisory_html(report_data)
        out_filename = f"NCSA_Advisory_TLPAMBER_{host.replace('.', '_')}_{port}.html"
        with open(out_filename, "w", encoding="utf-8") as f:
            f.write(report_html)
        print(f"\n{C_GREEN}[+] บันทึกรายงานทางการ สกมช. (TLP:AMBER HTML) เรียบร้อยที่:{C_RESET} {C_BOLD}{out_filename}{C_RESET}")

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"{C_GREEN}[+] บันทึกผลการตรวจเชิงเทคนิค (JSON Telemetry) ที่:{C_RESET} {C_BOLD}{output_json}{C_RESET}")

    print(f"\n{C_CYAN}════════════════════════════════════════════════════════════════════════{C_RESET}\n")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="OPScaner ThaiCERT/NCSA Security Audit CLI Toolkit")
    parser.add_argument("-t", "--target", required=True, help="Target URL or Host (e.g., http://localhost:8080, 192.168.1.41)")
    parser.add_argument("-p", "--port", type=int, default=None, help="Port override (default: 80 or 443)")
    parser.add_argument("--active-rce", action="store_true", help="Enable active LFI-to-RCE and canary verification probes")
    parser.add_argument("--i-own-this-target", action="store_true", help="Affirm that you own or have explicit authorization to test this target")
    parser.add_argument("--operator", type=str, default="", help="Auditor / Operator name for cryptographic audit trail")
    parser.add_argument("--export-report", action="store_true", help="Generate official ThaiCERT TLP:AMBER advisory HTML report")
    parser.add_argument("--json", type=str, default=None, help="Save JSON telemetry output to specified file")

    args = parser.parse_args()
    asyncio.run(run_cli_audit(
        target=args.target,
        port_override=args.port,
        export_report=args.export_report,
        output_json=args.json,
        active_rce=args.active_rce,
        i_own_this_target=args.i_own_this_target,
        operator=args.operator
    ))


if __name__ == "__main__":
    main()
