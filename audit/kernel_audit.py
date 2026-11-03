"""
OPScaner - Linux Kernel & MPTCP Behavioral Precondition Evaluator
Focuses on Linux Kernel TCP Use-After-Free (CVE-2026-98432, CVSS 9.8).

Mechanisms:
1. Passive OS Fingerprinting (TTL, Banner, HTTP headers) to rule out Windows.
2. Active MPTCP Listener Probe on exposed TCP ports (22, 80, 443, 8080, etc.).
3. Container Host-Kernel Correlation (Docker/K8s shared kernel evaluation).
4. EDR / Security Agent Host-Check Matrix.
"""

import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

# Common listening ports evaluated for kernel TCP stack exposure
KERNEL_PROBE_PORTS = [80, 443, 8080, 8443, 22, 3306, 5432, 6379, 27017, 8087, 8086]

# Standard EDR / Endpoint Protection Process Signatures for Host Audits
EDR_SIGNATURES = [
    ("CrowdStrike Falcon", "falcon-sensor"),
    ("SentinelOne", "sentinelone"),
    ("Microsoft Defender for Endpoint", "mdatp"),
    ("Wazuh Agent", "wazuh-agent"),
    ("Sophos Intercept X", "sophos-spl"),
    ("Trend Micro Deep Security", "ds_agent"),
    ("Palo Alto Cortex XDR", "trapsd"),
    ("Carbon Black Cloud", "cbagentd"),
    ("Kaspersky Endpoint Security", "kesl")
]


def probe_mptcp_capability(host: str, port: int, timeout: float = 2.0) -> Optional[bool]:
    """
    Probes if a TCP listener on host:port negotiates MPTCP (MultiPath TCP).
    Returns:
      True  -> MPTCP-ACTIVE (listener accepts MPTCP handshake, primary attack vector)
      False -> PLAIN-TCP (listener falls back to standard TCP)
      None  -> UNKNOWN (scanner environment does not support MPTCP socket / timeout)
    """
    # IPPROTO_MPTCP is protocol 262 on Linux 5.6+
    IPPROTO_MPTCP = getattr(socket, "IPPROTO_MPTCP", 262)
    SOL_MPTCP = 284
    MPTCP_INFO = 1

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
    except (AttributeError, OSError):
        # Platform or kernel does not support native MPTCP socket creation
        return None

    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        try:
            info = sock.getsockopt(SOL_MPTCP, MPTCP_INFO, 16)
            if info and len(info) >= 16:
                return True
        except OSError:
            pass
        return False
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe_mptcp_listeners(host: str, open_ports: List[int], timeout: float = 2.0) -> Dict[int, str]:
    """
    Concurrently probes open TCP ports on target host for MPTCP capability.
    Returns: {port: 'MPTCP-ACTIVE' | 'PLAIN-TCP' | 'UNKNOWN'}
    """
    results = {}
    if not open_ports:
        return results

    candidate_ports = [p for p in open_ports if p in KERNEL_PROBE_PORTS or p < 10000][:6]
    if not candidate_ports:
        candidate_ports = open_ports[:4]

    def _worker(p):
        res = probe_mptcp_capability(host, p, timeout=timeout)
        if res is True:
            return p, "MPTCP-ACTIVE"
        elif res is False:
            return p, "PLAIN-TCP"
        return p, "UNKNOWN"

    try:
        with ThreadPoolExecutor(max_workers=min(len(candidate_ports), 6)) as executor:
            for p, st in executor.map(_worker, candidate_ports):
                results[p] = st
    except Exception:
        pass

    return results


def evaluate_cve_2026_98432(
    is_windows: bool,
    server: str,
    open_ports: List[int],
    mptcp_results: Dict[int, str],
    is_container: bool = False
) -> Tuple[Optional[dict], str]:
    """
    Evaluates CVE-2026-98432 (Linux Kernel IPv4 TCP Use-After-Free, CVSS 9.8).
    Strictly enforces OS boundary: returns None / N/A for Windows hosts.
    Returns: (finding_dict_or_none, summary_note)
    """
    server_low = (server or "").lower()
    if is_windows or any(k in server_low for k in ["iis", "windows", "win32", "win64"]):
        return None, "ไม่ใช่ระบบปฏิบัติการ Linux (Windows) — ไม่เข้าข่าย CVE-2026-98432"

    # If all network ports are closed and this is not a container audit, no network vector exists
    if not is_container and not open_ports and not mptcp_results:
        return None, "พอร์ตเครือข่ายปิดทั้งหมด — ไม่พบเวกเตอร์ความเสี่ยงระดับเครือข่าย (CVE-2026-98432)"

    mptcp_active_ports = [p for p, st in mptcp_results.items() if st == "MPTCP-ACTIVE"]
    plain_tcp_ports = [p for p, st in mptcp_results.items() if st == "PLAIN-TCP"]

    container_note = " (ตรวจสอบระดับ Host/Node: Container แชร์เคอร์เนลเดียวกันกับเครื่องแม่ข่ายจริง)" if is_container else ""

    if mptcp_active_ports:
        confidence = "Likely"
        status = "LIKELY_VULNERABLE (MPTCP-ACTIVE)"
        reason = f"ตรวจพบพอร์ต {mptcp_active_ports} เจรจา MPTCP สำเร็จ (เวกเตอร์กระตุ้น race condition บนเคอร์เนล Linux พร้อมใช้งาน)"
        note = f"🔴 ตรวจพบ MPTCP-ACTIVE บนพอร์ต {mptcp_active_ports}: เข้าข่ายเวกเตอร์ช่องโหว่ CVE-2026-98432{container_note}"
    elif plain_tcp_ports:
        confidence = "Conditional"
        status = "CONDITIONAL (PLAIN-TCP / NEEDS_KERNEL_AUDIT)"
        reason = f"เซิร์ฟเวอร์ตอบรับ TCP ปกติบนพอร์ต {plain_tcp_ports} หากเคอร์เนล Linux ต่ำกว่าแพตช์ (kernel 4.4+) จะยังคงเข้าข่าย"
        note = f"🟡 ระบบรันบน Linux (PLAIN-TCP): ควรตรวจสอบ uname -r บนเครื่องจริง{container_note}"
    else:
        confidence = "Conditional"
        status = "CONDITIONAL (NEEDS_LOCAL_VERIFICATION)"
        reason = "ตรวจพบสภาพแวดล้อม Linux ควรตรวจสอบเวอร์ชันเคอร์เนลผ่านคำสั่ง uname -r บนเครื่องจริง"
        note = f"⚪ ตรวจพบสภาพแวดล้อม Linux: ควรตรวจสอบเคอร์เนลบนเครื่อง{container_note}"

    finding = {
        "id": "CVE-2026-98432",
        "cve": "CVE-2026-98432",
        "name": f"ช่องโหว่ระดับวิกฤตประเภท Use-After-Free บน Linux Kernel IPv4 TCP (CWE-416 / CVE-2026-98432){container_note}",
        "category": "OS / Kernel",
        "severity": "Critical",
        "cvss": 9.8,
        "confidence": confidence,
        "verification_status": status,
        "reason": reason,
        "host_check": "cat /etc/os-release && uname -r && ps aux | grep -iE 'falcon|sentinel|wazuh|edr|defender'",
        "confirm_vuln": "เคอร์เนล Linux ≥ 4.4 ที่ยังไม่ได้รับแพตช์ commit e3f33b0a1d89 ('ipv4: free inet_opt and ireq_opt after RCU grace period')",
        "confirm_safe": "อัปเดต Linux Kernel เป็นรุ่นที่มีแพตช์แก้ไขล่าสุด หรือปิดการใช้งาน MPTCP/IPv4 options ที่ไม่จำเป็น"
    }

    return finding, note
