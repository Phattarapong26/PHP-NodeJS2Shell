"""
Node.js Security Audit Module
Assesses Node.js version against EOL schedules and the Brotli decoder vulnerability (CVE-2026-111497),
often referenced in threat intelligence reports as "Node2Shell".

Adheres to NCSA / ThaiCERT and NIST SP 800-115 defensive verification standards:
- Separates version vulnerability status from application-level decoder exposure.
- Distinguishes NVD CVSS 9.2 (Critical) from Node.js official Security Release rating (High).
- Avoids unconditional "Secure" claims based purely on version string.
- Accurately tracks Node.js official release & EOL milestones.
- Strictly avoids misleading aliases such as "HTTP2Shell".
"""

import re
from typing import Dict, Any, Tuple, Optional, List


# Node.js Release Schedules & EOL Milestones
# Source: Node.js Official Releases (https://nodejs.org/en/about/previous-releases)
NODE_RELEASE_SCHEDULE: Dict[int, Dict[str, Any]] = {
    20: {
        "eol": "24 มีนาคม 2026",
        "status": "EOL",
        "lts_name": "Iron (LTS)",
        "min_patch": None,  # No upstream patch for CVE-2026-111497 in 20.x
        "is_eol": True
    },
    22: {
        "eol": "30 เมษายน 2027",
        "status": "Maintenance LTS",
        "lts_name": "Jod (LTS)",
        "min_patch": (22, 23, 4),
        "min_patch_str": "22.23.4",
        "is_eol": False
    },
    24: {
        "eol": "30 เมษายน 2028",
        "status": "Active LTS",
        "lts_name": "Krypton (LTS)",
        "min_patch": (24, 22, 1),
        "min_patch_str": "24.22.1",
        "is_eol": False
    },
    25: {
        "eol": "31 มีนาคม 2026",
        "status": "EOL (Current/Odd)",
        "lts_name": "Current",
        "min_patch": None,
        "is_eol": True
    },
    26: {
        "eol": "30 เมษายน 2029",
        "status": "Active LTS",
        "lts_name": "Lithium (LTS)",
        "min_patch": (26, 12, 1),
        "min_patch_str": "26.12.1",
        "is_eol": False
    }
}


class NodeAuditResult(tuple):
    """
    Subclasses tuple (severity, note) for seamless backward compatibility
    with existing code: `vuln, note = evaluate_node_security(...)`
    while exposing structured metadata via `.details` and `.as_dict()`.
    """
    def __new__(cls, severity: str, note: str, details: Optional[Dict[str, Any]] = None):
        return super().__new__(cls, (severity, note))

    def __init__(self, severity: str, note: str, details: Optional[Dict[str, Any]] = None):
        self.severity = severity
        self.note = note
        self.details = details or {}

    def as_dict(self) -> Dict[str, Any]:
        return self.details


def evaluate_node_security(
    version_str: str,
    has_brotli: bool = False,
    accepts_untrusted_brotli: Optional[bool] = None,
    uses_node_zlib_decompress: Optional[bool] = None
) -> NodeAuditResult:
    """
    Assess Node.js version against EOL and the Brotli decoder vulnerability (CVE-2026-111497).
    
    Evaluates in two distinct dimensions:
    1. Version status: Is the detected version in an affected range or unmaintained EOL?
    2. Exposure status: Does the application decompress untrusted Brotli input via `node:zlib`?

    Returns a NodeAuditResult that unpacks as (severity, note) for backward compatibility
    and provides structured details via .details.
    """
    v = (version_str or "").lower().strip()

    has_brotli_runtime = bool(has_brotli)
    accepts_untrusted_brotli_input = accepts_untrusted_brotli
    uses_node_zlib_brotli_decompress = uses_node_zlib_decompress

    # Exposure status assessment
    if accepts_untrusted_brotli_input is True and uses_node_zlib_brotli_decompress is True:
        exposure_status = "Exposed Brotli Decoder (Untrusted Input + node:zlib decompress)"
    elif accepts_untrusted_brotli_input is True:
        exposure_status = "Untrusted Brotli Input Observed (Decoder invocation unverified)"
    elif has_brotli_runtime:
        exposure_status = "Brotli Runtime Supported (Application decompression path unverified)"
    else:
        exposure_status = "Brotli Exposure Absent / Not Observed"

    # Extract version numbers e.g. 20.18.0, v22.12.0, 24.22.1, 26.11.0
    match = re.search(r'(?:node(?:\.js)?/|v)?(\d+)\.(\d+)(?:\.(\d+))?', v)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) is not None else 0
        detected_version = f"{major}.{minor}.{patch}"

        # Node 20.x and older: EOL 24 March 2026
        if major <= 20:
            version_status = "Affected / End-of-Life"
            is_exposed = bool(accepts_untrusted_brotli_input or uses_node_zlib_brotli_decompress)
            severity = "High" if is_exposed else "Outdated"
            confidence = "Likely" if is_exposed else "Conditional"
            note = (
                f"Node.js v{detected_version} สิ้นสุดการสนับสนุนแล้ว (EOL: 24 มี.ค. 2026) "
                f"จึงอาจไม่มีแพตช์ความปลอดภัยจากโครงการหลักสำหรับช่องโหว่ Brotli decoder (CVE-2026-111497) "
                f"ควรวางแผนอัปเกรดและตรวจสอบสถานะแพตช์จากผู้จัดจำหน่ายระบบปฏิบัติการที่ใช้งานจริง"
            )
            rec = "วางแผนอัปเกรดเป็น Node.js 22.x (Active LTS) หรือ 24.x (Active LTS) และตรวจสอบแพตช์จากผู้จัดจำหน่าย"
            evidence = [
                f"ตรวจพบ Node.js เวอร์ชัน {detected_version}",
                "รุ่นสิ้นสุดการสนับสนุน (EOL: 24 มีนาคม 2026)",
                f"สถานะ Exposure: {exposure_status}"
            ]
            details = {
                "severity": severity,
                "confidence": confidence,
                "version_status": version_status,
                "exposure_status": exposure_status,
                "cve": "CVE-2026-111497",
                "cve_title": "ช่องโหว่ Brotli decoder ใน Node.js (CVE-2026-111497)",
                "alias": "Node2Shell",
                "severity_nvd": "Critical (CVSS 9.2)",
                "severity_vendor": "High (Node.js Security Release)",
                "severity_note": "ระดับความรุนแรงตามแหล่งอ้างอิงอาจแตกต่างกัน โดย NVD ระบุ CVSS 9.2 (Critical) ขณะที่ประกาศทางการของ Node.js จัดเป็นระดับ High ทั้งนี้ความเสี่ยงต่อระบบจริงขึ้นกับ exposure และการใช้งาน decoder",
                "has_brotli_runtime": has_brotli_runtime,
                "accepts_untrusted_brotli_input": accepts_untrusted_brotli_input,
                "uses_node_zlib_brotli_decompress": uses_node_zlib_brotli_decompress,
                "evidence": evidence,
                "recommendation": rec
            }
            return NodeAuditResult(severity, note, details)

        # Node 25.x: EOL 31 March 2026 (Odd-numbered Current release)
        if major == 25:
            version_status = "Affected / End-of-Life"
            is_exposed = bool(accepts_untrusted_brotli_input or uses_node_zlib_brotli_decompress)
            severity = "High" if is_exposed else "Outdated"
            confidence = "Likely" if is_exposed else "Conditional"
            note = (
                f"Node.js v{detected_version} สิ้นสุดการสนับสนุนแล้ว (EOL: 31 มี.ค. 2026) "
                f"และไม่อยู่ในสายรุ่นที่มี security release จากโครงการหลักสำหรับช่องโหว่ Brotli decoder (CVE-2026-111497) "
                f"ควรวางแผนอัปเกรดข้ามรุ่นเป็น 24.x หรือ 26.x และตรวจสอบแพตช์จากผู้จัดจำหน่ายที่ใช้งานจริง"
            )
            rec = "อัปเกรดข้ามรุ่นเป็น Node.js 24.x หรือ 26.x ซึ่งเป็นสาย LTS ที่มีแพตช์สนับสนุน"
            evidence = [
                f"ตรวจพบ Node.js เวอร์ชัน {detected_version}",
                "รุ่น Current สิ้นสุดการสนับสนุน (EOL: 31 มีนาคม 2026)",
                f"สถานะ Exposure: {exposure_status}"
            ]
            details = {
                "severity": severity,
                "confidence": confidence,
                "version_status": version_status,
                "exposure_status": exposure_status,
                "cve": "CVE-2026-111497",
                "cve_title": "ช่องโหว่ Brotli decoder ใน Node.js (CVE-2026-111497)",
                "alias": "Node2Shell",
                "severity_nvd": "Critical (CVSS 9.2)",
                "severity_vendor": "High (Node.js Security Release)",
                "severity_note": "ระดับความรุนแรงตามแหล่งอ้างอิงอาจแตกต่างกัน โดย NVD ระบุ CVSS 9.2 (Critical) ขณะที่ประกาศทางการของ Node.js จัดเป็นระดับ High ทั้งนี้ความเสี่ยงต่อระบบจริงขึ้นกับ exposure และการใช้งาน decoder",
                "has_brotli_runtime": has_brotli_runtime,
                "accepts_untrusted_brotli_input": accepts_untrusted_brotli_input,
                "uses_node_zlib_brotli_decompress": uses_node_zlib_brotli_decompress,
                "evidence": evidence,
                "recommendation": rec
            }
            return NodeAuditResult(severity, note, details)

        # Supported LTS lines: Node 22, 24, 26
        if major in (22, 24, 26):
            sched = NODE_RELEASE_SCHEDULE[major]
            min_p = sched["min_patch"]
            min_p_str = sched["min_patch_str"]
            eol_str = sched["eol"]

            is_below_patch = (minor < min_p[1]) or (minor == min_p[1] and patch < min_p[2])

            if is_below_patch:
                version_status = "Affected range"
                is_exposed = bool(accepts_untrusted_brotli_input or uses_node_zlib_brotli_decompress)
                severity = "High"
                confidence = "Likely" if is_exposed else "Conditional"
                note = (
                    f"Node.js v{detected_version} ต่ำกว่าเวอร์ชันที่ Node.js ระบุว่าได้รับแพตช์สำหรับช่องโหว่ Brotli decoder "
                    f"(CVE-2026-111497 หรือที่มีการเรียกในบางรายงานว่า “Node2Shell”) จึงอาจได้รับผลกระทบ "
                    f"หากแอปพลิเคชันรับข้อมูล Brotli จากภายนอกและนำไปถอดรหัสด้วยโมดูลที่เกี่ยวข้อง "
                    f"ควรอัปเดตเป็นรุ่นที่มีแพตช์อย่างน้อย {min_p_str} ตามสายเวอร์ชัน หรือใช้รุ่นล่าสุดที่ผู้พัฒนาแนะนำ"
                )
                rec = f"อัปเดต Node.js เป็นรุ่นที่มีแพตช์อย่างน้อย {min_p_str} หรือรุ่นล่าสุดที่ผู้พัฒนาแนะนำ (รองรับถึง {eol_str})"
                evidence = [
                    f"ตรวจพบ Node.js เวอร์ชัน {detected_version} (ต่ำกว่าเกณฑ์แพตช์ {min_p_str})",
                    f"สถานะ Exposure: {exposure_status}",
                    f"สาย LTS: {sched['lts_name']} (EOL: {eol_str})"
                ]
            else:
                version_status = "Patched range based on version"
                severity = "Patched for this CVE"
                confidence = "Hardened"
                note = (
                    f"Node.js v{detected_version} อยู่ที่หรือสูงกว่าเวอร์ชันที่มีแพตช์สำหรับ CVE-2026-111497 "
                    f"จากข้อมูลเวอร์ชันที่ตรวจพบ ทั้งนี้ยังต้องตรวจสอบการใช้งาน Brotli และเส้นทางการประมวลผลข้อมูลของแอปพลิเคชัน "
                    f"(ไม่พบว่าอยู่ในช่วงเวอร์ชันที่ได้รับผลกระทบจาก CVE นี้ตามฐานข้อมูลปัจจุบัน)"
                )
                rec = f"คงสถานะอัปเดต Node.js ในสาย {sched['lts_name']} อย่างต่อเนื่อง (รองรับถึง {eol_str})"
                evidence = [
                    f"ตรวจพบ Node.js เวอร์ชัน {detected_version} (อยู่ที่หรือสูงกว่าเกณฑ์แพตช์ {min_p_str})",
                    "ไม่พบว่าอยู่ในช่วงเวอร์ชันที่ได้รับผลกระทบจาก CVE-2026-111497",
                    f"สถานะ Exposure: {exposure_status}"
                ]

            details = {
                "severity": severity,
                "confidence": confidence,
                "version_status": version_status,
                "exposure_status": exposure_status,
                "cve": "CVE-2026-111497",
                "cve_title": "ช่องโหว่ Brotli decoder ใน Node.js (CVE-2026-111497)",
                "alias": "Node2Shell",
                "severity_nvd": "Critical (CVSS 9.2)",
                "severity_vendor": "High (Node.js Security Release)",
                "severity_note": "ระดับความรุนแรงตามแหล่งอ้างอิงอาจแตกต่างกัน โดย NVD ระบุ CVSS 9.2 (Critical) ขณะที่ประกาศทางการของ Node.js จัดเป็นระดับ High ทั้งนี้ความเสี่ยงต่อระบบจริงขึ้นกับ exposure และการใช้งาน decoder",
                "has_brotli_runtime": has_brotli_runtime,
                "accepts_untrusted_brotli_input": accepts_untrusted_brotli_input,
                "uses_node_zlib_brotli_decompress": uses_node_zlib_brotli_decompress,
                "evidence": evidence,
                "recommendation": rec
            }
            return NodeAuditResult(severity, note, details)

        # Newer versions (major > 26): Do NOT assume unconditionally safe!
        version_status = "Newer release / Evaluation needed"
        severity = "Review Needed"
        confidence = "Unverified"
        note = (
            f"ตรวจพบ Node.js รุ่นใหม่กว่าช่วงที่กฎนี้ครอบคลุม (v{detected_version}) "
            f"ต้องตรวจสอบ release advisory ของผู้พัฒนาเพิ่มเติมเพื่อยืนยันสถานะความปลอดภัย"
        )
        rec = "ตรวจสอบประกาศความปลอดภัยทางการและ release changelog ของเวอร์ชันดังกล่าวจาก Node.js"
        evidence = [
            f"ตรวจพบ Node.js เวอร์ชัน {detected_version} (เกินกว่าขอบเขตกฎ v26.x)",
            f"สถานะ Exposure: {exposure_status}"
        ]
        details = {
            "severity": severity,
            "confidence": confidence,
            "version_status": version_status,
            "exposure_status": exposure_status,
            "cve": "CVE-2026-111497",
            "cve_title": "ช่องโหว่ Brotli decoder ใน Node.js (CVE-2026-111497)",
            "alias": "Node2Shell",
            "severity_nvd": "Critical (CVSS 9.2)",
            "severity_vendor": "High (Node.js Security Release)",
            "severity_note": "ระดับความรุนแรงตามแหล่งอ้างอิงอาจแตกต่างกัน โดย NVD ระบุ CVSS 9.2 (Critical) ขณะที่ประกาศทางการของ Node.js จัดเป็นระดับ High ทั้งนี้ความเสี่ยงต่อระบบจริงขึ้นกับ exposure และการใช้งาน decoder",
            "has_brotli_runtime": has_brotli_runtime,
            "accepts_untrusted_brotli_input": accepts_untrusted_brotli_input,
            "uses_node_zlib_brotli_decompress": uses_node_zlib_brotli_decompress,
            "evidence": evidence,
            "recommendation": rec
        }
        return NodeAuditResult(severity, note, details)

    # If version couldn't be extracted from headers/cookies
    if has_brotli_runtime:
        version_status = "Unknown version"
        severity = "Review Needed"
        confidence = "Unverified"
        note = (
            "ตรวจพบบริการ Node.js และพบความเป็นไปได้ในการประมวลผล Brotli "
            "แต่ยังไม่สามารถยืนยันเวอร์ชันและเส้นทางการประมวลผลได้ "
            "ควรตรวจสอบเวอร์ชันจริง การใช้งาน node:zlib และแหล่งที่มาของข้อมูลที่นำไปถอดรหัสก่อนประเมินผลกระทบต่อ CVE-2026-111497"
        )
        rec = "ตรวจสอบเวอร์ชัน Node.js จริงบนโฮสต์ด้วยคำสั่ง node -v และตรวจสอบการใช้งาน Brotli decoder"
        evidence = [
            "ตรวจพบบริการ Node.js แต่ไม่พบข้อมูลเวอร์ชันในส่วนหัว HTTP",
            "ตรวจพบการเปิดใช้งานหรือรองรับการบีบอัด Brotli ในส่วนหัว",
            "สถานะ Exposure: Decompression unverified"
        ]
    else:
        version_status = "Unknown version"
        severity = "Review Needed"
        confidence = "Unverified"
        note = (
            "ตรวจพบบริการ Node.js (ควรตรวจสอบเวอร์ชันจริงกับประกาศของ Node.js "
            "และอัปเดตเป็นรุ่นที่มีแพตช์สำหรับ CVE-2026-111497 โดยพิจารณาร่วมกับการใช้งาน Brotli และการเปิดรับข้อมูลจากภายนอก)"
        )
        rec = "ตรวจสอบเวอร์ชัน Node.js ด้วยคำสั่ง node -v และอัปเดตเป็นรุ่น LTS ที่ได้รับการสนับสนุน"
        evidence = [
            "ตรวจพบบริการ Node.js แต่ไม่พบข้อมูลเวอร์ชันในส่วนหัว HTTP",
            "ไม่พบหลักฐานการใช้งานหรือรับส่งข้อมูล Brotli"
        ]

    details = {
        "severity": severity,
        "confidence": confidence,
        "version_status": version_status,
        "exposure_status": exposure_status,
        "cve": "CVE-2026-111497",
        "cve_title": "ช่องโหว่ Brotli decoder ใน Node.js (CVE-2026-111497)",
        "alias": "Node2Shell",
        "severity_nvd": "Critical (CVSS 9.2)",
        "severity_vendor": "High (Node.js Security Release)",
        "severity_note": "ระดับความรุนแรงตามแหล่งอ้างอิงอาจแตกต่างกัน โดย NVD ระบุ CVSS 9.2 (Critical) ขณะที่ประกาศทางการของ Node.js จัดเป็นระดับ High ทั้งนี้ความเสี่ยงต่อระบบจริงขึ้นกับ exposure และการใช้งาน decoder",
        "has_brotli_runtime": has_brotli_runtime,
        "accepts_untrusted_brotli_input": accepts_untrusted_brotli_input,
        "uses_node_zlib_brotli_decompress": uses_node_zlib_brotli_decompress,
        "evidence": evidence,
        "recommendation": rec
    }
    return NodeAuditResult(severity, note, details)
