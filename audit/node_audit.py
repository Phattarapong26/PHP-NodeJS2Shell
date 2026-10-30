"""
Node.js Security Audit Module
Assesses Node.js version against EOL schedules and Node2Shell / Brotli RCE (CVE-2026-111497).
"""

import re
from typing import Tuple

def evaluate_node_security(version_str: str, has_brotli: bool = False):
    """
    Assess Node.js version against EOL and Node2Shell / HTTP2Shell (CVE-2026-111497, CVSS 9.2 in Brotli).
    Rules:
    - 26.x: EOL 30 Apr 2029 -> Patched in 26.12.1+ (< 26.12.1 is Critical)
    - 24.x: EOL 30 Apr 2028 -> Patched in 24.22.1+ (< 24.22.1 is Critical)
    - 22.x: EOL 30 Apr 2027 -> Patched in 22.23.4+ (< 22.23.4 is Critical)
    - 25.x: EOL 1 Jun 2026 -> No patch (Critical, upgrade to 24.x/26.x)
    - 20.x and older: EOL 30 Apr 2026 -> No patch (Critical, upgrade to 22.x/24.x)
    """
    v = version_str.lower()
    
    # Extract version numbers e.g. 20.18.0, v22.12.0, 24.22.1, 26.11.0
    match = re.search(r'(?:node(?:\.js)?/|v)?(\d+)\.(\d+)(?:\.(\d+))?', v)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) is not None else 0

        # Node 20.x and older (18.x, 16.x, 14.x...): EOL 30 Apr 2026 -> No patch
        if major <= 20:
            return (
                "Critical",
                f"Node.js v{major}.{minor}.{patch} (EOL สิ้นสุด 30 เม.ย. 2026): ไม่มีแพตช์ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเกรดเป็น 22.x หรือ 24.x ทันที"
            )

        # Node 25.x: EOL 1 Jun 2026 -> No patch
        if major == 25:
            return (
                "Critical",
                f"Node.js v{major}.{minor}.{patch} (EOL สิ้นสุด 1 มิ.ย. 2026): ไม่มีแพตช์ Node2Shell / CVE-2026-111497 ควรอัปเกรดข้ามรุ่นเป็น 24.x หรือ 26.x ทันที"
            )

        # Node 22.x: Patched in 22.23.4+ (EOL 30 Apr 2027)
        if major == 22:
            if (minor < 23) or (minor == 23 and patch < 4):
                return (
                    "Critical",
                    f"Node.js v{major}.{minor}.{patch} เสี่ยงต่อ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเดตเป็น 22.23.4 ขึ้นไป"
                )
            else:
                return (
                    "Secure",
                    f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับแพตช์แก้ไข Node2Shell (CVE-2026-111497) แล้ว (รองรับถึง 30 เม.ย. 2027)"
                )

        # Node 24.x: Patched in 24.22.1+ (EOL 30 Apr 2028)
        if major == 24:
            if (minor < 22) or (minor == 22 and patch < 1):
                return (
                    "Critical",
                    f"Node.js v{major}.{minor}.{patch} เสี่ยงต่อ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเดตเป็น 24.22.1 ขึ้นไป"
                )
            else:
                return (
                    "Secure",
                    f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับแพตช์แก้ไข Node2Shell (CVE-2026-111497) แล้ว (รองรับถึง 30 เม.ย. 2028)"
                )

        # Node 26.x: Patched in 26.12.1+ (EOL 30 Apr 2029)
        if major == 26:
            if (minor < 12) or (minor == 12 and patch < 1):
                return (
                    "Critical",
                    f"Node.js v{major}.{minor}.{patch} เสี่ยงต่อ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเดตเป็น 26.12.1 ขึ้นไป"
                )
            else:
                return (
                    "Secure",
                    f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับแพตช์แก้ไข Node2Shell (CVE-2026-111497) แล้ว (รองรับถึง 30 เม.ย. 2029)"
                )

        # Newer versions (major > 26)
        return (
            "Secure",
            f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับการแก้ไขช่องโหว่ Brotli เรียบร้อย"
        )

    # If version couldn't be extracted from headers/cookies
    if has_brotli:
        return (
            "Warning",
            "ตรวจพบบริการ Node.js เปิดใช้การบีบอัด Brotli (เสี่ยงต่อ Node2Shell / CVE-2026-111497 หากเวอร์ชันต่ำกว่า 22.23.4 / 24.22.1 / 26.12.1)"
        )

    return (
        "Review Needed",
        "ตรวจพบบริการ Node.js (ควรตรวจสอบให้แน่ใจว่าอัปเดตเป็น 22.23.4+, 24.22.1+ หรือ 26.12.1+ เพื่อป้องกัน Node2Shell)"
    )

