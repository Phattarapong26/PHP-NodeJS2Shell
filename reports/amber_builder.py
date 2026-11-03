"""
TLP:AMBER Security Advisory Builder - Evidence-based Assessment Format
Produces standardized A4 security advisories in HTML,
complying with FIRST TLP v2.0, 18pt/16pt typography,
strict page-break controls, table repeating headers, and code hardening blueprints.
NO LLM DEPENDENCY - 100% Deterministic Technical Narrative Generator.
"""

import html
import io
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from .assets import NCSA_LOGO_B64, SURVEY_QR_PNG_B64

try:
    from audit.thaicert_rules import THAICERT_GROUP_PROFILES
except Exception:
    THAICERT_GROUP_PROFILES = {}


def get_ncsa_logo_png_data_uri() -> str:
    """Convert WebP Logo to PNG Data URI for 100% compatibility in Chromium and WebViews."""
    if not NCSA_LOGO_B64:
        return ""
    try:
        from PIL import Image
        import base64
        raw = NCSA_LOGO_B64
        if "," in raw:
            raw = raw.split(",", 1)[1]
        img_bytes = base64.b64decode(raw)
        im = Image.open(io.BytesIO(img_bytes))
        out = io.BytesIO()
        im.save(out, format="PNG")
        png_b64 = base64.b64encode(out.getvalue()).decode("ascii")
        return f"data:image/png;base64,{png_b64}"
    except Exception:
        return NCSA_LOGO_B64


def get_tlp_amber_traffic_light_html() -> str:
    """Generate official FIRST TLP v2.0 TLP:AMBER traffic light widget without borders."""
    return """
    <div class="ncsa-tlp-container">
      <div class="ncsa-tlp-pill" style="background: #f59e0b; color: #0f172a; font-weight: 800; font-size: 11px; letter-spacing: 0.5px; padding: 2px 8px; border-radius: 2px; text-align: center; min-width: 82px; margin-bottom: 3px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        TLP:AMBER
      </div>
      <div class="ncsa-tlp-lights-box" style="background: #334155; border: none; border-radius: 6px; padding: 3px 8px; display: flex; gap: 5px; align-items: center; justify-content: center;">
        <span class="ncsa-tlp-circle" style="background: #64748b; width: 12px; height: 12px; border-radius: 50%; border: none; display: inline-block; box-sizing: border-box;"></span>
        <span class="ncsa-tlp-circle" style="background: #f59e0b; width: 12px; height: 12px; border-radius: 50%; border: none; display: inline-block; box-sizing: border-box;"></span>
        <span class="ncsa-tlp-circle" style="background: #64748b; width: 12px; height: 12px; border-radius: 50%; border: none; display: inline-block; box-sizing: border-box;"></span>
      </div>
    </div>
    """


def get_ncsa_header_banner_html() -> str:
    """Generate official NCSA Thailand Letterhead Banner without borders."""
    logo_src = get_ncsa_logo_png_data_uri()
    tlp_widget = get_tlp_amber_traffic_light_html()
    return f"""
    <div class="ncsa-header-banner">
      <div class="ncsa-header-left">
        <img class="ncsa-logo-img" src="{logo_src}" alt="NCSA Thailand" />
        <div class="ncsa-header-text">
          <div class="ncsa-agency-name">รายงานประเมินความมั่นคงปลอดภัยไซเบอร์ (อ้างอิงแนวทาง TLP:AMBER)</div>
          <div class="ncsa-agency-addr">Cybersecurity Technical Assessment Report | อ้างอิงแนวทาง FIRST TLP v2.0 และกรอบการประเมินเชิงเทคนิค</div>
          <div class="ncsa-agency-contact">เอกสารสำหรับผู้ดูแลระบบและทีมงานเทคนิคที่เกี่ยวข้องตามความจำเป็นในการปฏิบัติงาน (Need-to-know)</div>
        </div>
      </div>
      <div class="ncsa-header-right">
        {tlp_widget}
      </div>
    </div>
    """


def get_watermark_svg_data_uri() -> str:
    """Generate subtle, diagonal watermark SVG with red text as data URI for report sheets (zero border lines)."""
    import base64
    svg = """<svg xmlns='http://www.w3.org/2000/svg' width='680' height='420' viewBox='0 0 680 420'>
  <style>
    .wm-txt {
      font-family: 'TH SarabunPSK', 'TH Sarabun New', 'Segoe UI', Tahoma, sans-serif;
      font-size: 22px;
      font-weight: bold;
      fill: #dc2626;
      opacity: 0.06;
      letter-spacing: 1.2px;
    }
    .wm-sub {
      font-family: -apple-system, BlinkMacSystemFont, 'SF Mono', Consolas, monospace;
      font-size: 11px;
      font-weight: 700;
      fill: #b91c1c;
      opacity: 0.05;
      letter-spacing: 2.5px;
    }
  </style>
  <g transform='rotate(-24 340 210)'>
    <text x='340' y='203' text-anchor='middle' class='wm-txt'>เอกสารลับจากระบบของฝ่ายปฏิบัติการ ThaiCERT</text>
    <text x='340' y='223' text-anchor='middle' class='wm-sub'>CONFIDENTIAL • THAICERT OPERATIONAL LICENSE</text>
  </g>
</svg>"""
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def get_css_styles() -> str:
    """Official Thai Government & NCSA Typography CSS with NO BORDERS throughout the report."""
    wm_uri = get_watermark_svg_data_uri()
    css = """
    @font-face {
      font-family: 'TH Sarabun PSK';
      src: local('TH SarabunPSK'), local('THSarabunPSK'), local('TH Sarabun PSK'), local('TH Sarabun New'),
           url('/fonts/THSarabunNew.ttf') format('truetype');
      font-weight: normal;
      font-style: normal;
    }
    @font-face {
      font-family: 'TH Sarabun PSK';
      src: local('TH SarabunPSK Bold'), local('THSarabunPSK-Bold'), local('TH Sarabun PSK Bold'), local('TH Sarabun New Bold'),
           url('/fonts/THSarabunNew Bold.ttf') format('truetype');
      font-weight: bold;
      font-style: normal;
    }

    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }

    body {
      background: #0b101b;
      margin: 0;
      padding: 0;
      font-family: 'TH SarabunPSK', 'TH Sarabun PSK', sans-serif !important;
      color: #000;
    }

    /* Print / Preview Toolbar (no-print) */
    .adv-toolbar {
      background: #080d1a;
      border: none;
      color: #f8fafc;
      padding: 10px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 1000;
      box-shadow: 0 4px 18px rgba(0,0,0,0.6);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13.5px;
    }

    .adv-toolbar-title {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      color: #eaf6ff;
    }

    .adv-toolbar-badge {
      background: #f59e0b;
      color: #0f172a;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.5px;
      font-family: 'SF Mono', Consolas, monospace;
    }

    .adv-toolbar-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    .adv-btn {
      padding: 6px 14px;
      border-radius: 7px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: none;
      transition: all 0.18s ease-in-out;
    }

    .adv-btn-primary {
      background: linear-gradient(135deg, #d97706, #f59e0b);
      color: #0f172a;
      box-shadow: 0 0 12px rgba(245, 158, 11, 0.25);
    }
    .adv-btn-primary:hover {
      background: linear-gradient(135deg, #b45309, #d97706);
      box-shadow: 0 0 16px rgba(245, 158, 11, 0.45);
      transform: translateY(-1px);
    }

    .adv-btn-outline {
      background: rgba(245, 158, 11, 0.15);
      color: #fde68a;
    }
    .adv-btn-outline:hover {
      background: rgba(245, 158, 11, 0.25);
      color: #fff;
    }

    /* A4 Paper Sheets Screen Simulation */
    .a4-paper-sheet {
      font-family: 'TH SarabunPSK', 'TH Sarabun PSK', sans-serif !important;
      font-size: 16pt;
      line-height: 1.4;
      color: #000000;
      background-color: #ffffff;
      background-image: url("__WATERMARK_DATA_URI__");
      background-repeat: repeat;
      background-position: center center;
      background-size: 680px 420px;
      box-sizing: border-box;
      border: none !important;
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }

    @media screen {
      .sheets-container {
        padding: 32px 0 60px;
        display: flex;
        flex-direction: column;
        align-items: center;
      }

      .a4-paper-sheet {
        width: 210mm;
        min-height: 297mm;
        margin: 0 auto 30px auto;
        padding: 18mm 20mm 24mm 20mm;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.45);
        border: none !important;
        border-radius: 4px;
        position: relative;
      }
    }

    /* NCSA Official Letterhead Banner (No Border) */
    .ncsa-header-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 8px;
      margin-bottom: 14px;
      border: none !important;
      border-bottom: none !important;
      width: 100%;
      box-sizing: border-box;
    }

    .ncsa-header-left {
      display: flex;
      align-items: center;
      gap: 12px;
      flex: 1;
      min-width: 0;
    }

    .ncsa-logo-img {
      height: 44px;
      width: auto;
      object-fit: contain;
      display: block;
      flex-shrink: 0;
      border: none !important;
    }

    .ncsa-header-text {
      display: flex;
      flex-direction: column;
      justify-content: center;
      flex: 1;
      min-width: 0;
    }

    .ncsa-agency-name {
      font-size: 12pt;
      font-weight: bold;
      color: #000000;
      line-height: 1.25;
      margin-bottom: 2px;
      white-space: nowrap;
      letter-spacing: -0.2px;
    }

    .ncsa-agency-addr,
    .ncsa-agency-contact {
      font-size: 8.8pt;
      color: #000000;
      line-height: 1.25;
      white-space: nowrap;
      letter-spacing: -0.1px;
    }

    .ncsa-header-right {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      justify-content: center;
      margin-left: 12px;
      flex-shrink: 0;
    }

    /* Document Title: 18pt Bold (Only this main title is 18pt) */
    .adv-doc-title {
      font-size: 18pt !important;
      font-weight: bold !important;
      color: #0f172a;
      text-align: center;
      margin-top: 6px;
      margin-bottom: 4px;
      line-height: 1.3;
      break-after: avoid !important;
      page-break-after: avoid !important;
    }

    .adv-doc-meta {
      font-size: 16pt !important;
      color: #64748b;
      text-align: center;
      margin-bottom: 14px;
      break-after: avoid !important;
      page-break-after: avoid !important;
    }

    /* TLP Notice Banner: 16pt Normal, No Border */
    .adv-tlp-rule-box {
      background: rgba(245, 158, 11, 0.08);
      border: none !important;
      border-left: none !important;
      border-radius: 6px;
      padding: 10px 14px;
      margin-bottom: 16px;
      font-size: 16pt !important;
      line-height: 1.35;
      color: #78350f;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    /* Typography Standards: All Headings = 16pt Bold, Body/Content = 16pt Normal */
    .adv-heading {
      font-size: 16pt !important;
      font-weight: bold !important;
      margin-top: 18px;
      margin-bottom: 8px;
      color: #0f172a;
      line-height: 1.35;
      break-after: avoid !important;
      page-break-after: avoid !important;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-subhead {
      font-size: 16pt !important;
      font-weight: bold !important;
      color: #0f172a;
      margin: 14px 0 6px 0;
      break-after: avoid !important;
      page-break-after: avoid !important;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    /* Narrative Paragraphs: 16pt Thai 1.25cm indent */
    .adv-para {
      font-size: 16pt !important;
      font-weight: normal;
      text-align: justify;
      text-justify: inter-cluster;
      text-indent: 1.25cm;
      line-height: 1.4;
      margin: 0 0 8px 0;
      color: #1e293b;
      word-break: break-word;
      orphans: 4 !important;
      widows: 4 !important;
      break-inside: auto;
      page-break-inside: auto;
    }

    /* Lists */
    .adv-list {
      margin: 6px 0 10px 0;
      padding: 0;
      list-style: none;
    }

    .adv-list li {
      font-size: 16pt !important;
      line-height: 1.4;
      margin-bottom: 5px;
      padding-left: 1.25cm;
      text-indent: -0.45cm;
      text-align: left !important;
      orphans: 4 !important;
      widows: 4 !important;
    }

    .adv-list li::before {
      content: "• ";
      font-weight: bold;
      color: #d97706;
    }

    /* Tables: Strictly NO BORDER, Clean Zebra Striping */
    .adv-table-wrap {
      overflow-x: auto;
      margin: 8px 0 14px 0;
      border: none !important;
    }

    .adv-table {
      width: 100%;
      border-collapse: collapse;
      margin: 8px 0 14px 0;
      border: none !important;
      font-size: 16pt !important;
      break-inside: auto;
      page-break-inside: auto;
    }

    .adv-table thead {
      display: table-header-group !important;
      border: none !important;
    }

    .adv-table thead tr {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      border: none !important;
    }

    .adv-table th {
      border: none !important;
      padding: 6px 8px;
      font-size: 16pt !important;
      font-weight: bold !important;
      text-align: center;
      background: #fef3c7;
      color: #78350f;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-table tbody {
      display: table-row-group !important;
      border: none !important;
    }

    .adv-table tr {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      border: none !important;
    }

    .adv-table td {
      border: none !important;
      padding: 5px 8px;
      font-size: 16pt !important;
      color: #334155;
      vertical-align: middle;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-table tbody tr:nth-child(even) {
      background: #f8fafc;
    }

    /* Device Block & Findings: Soft Backgrounds, Strictly NO BORDER */
    .adv-device-block {
      margin-bottom: 24px;
      padding: 14px 18px;
      background: #f8fafc;
      border: none !important;
      border-radius: 8px;
      break-inside: auto;
      page-break-inside: auto;
    }

    .adv-finding-item {
      margin-top: 10px;
      margin-bottom: 14px;
      padding: 12px 14px;
      background: #ffffff;
      border: none !important;
      border-radius: 6px;
      break-inside: auto;
      page-break-inside: auto;
    }

    .adv-finding-head {
      display: flex;
      align-items: baseline;
      gap: 10px;
      margin-bottom: 4px;
      break-after: avoid !important;
      page-break-after: avoid !important;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      border: none !important;
    }

    .adv-item-title {
      font-size: 16pt !important;
      font-weight: bold !important;
      color: #0f172a;
      line-height: 1.35;
    }

    .adv-item-badge-crit {
      background: #dc2626;
      color: #fff;
      font-size: 11pt;
      font-weight: bold;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-block;
      border: none !important;
    }
    .adv-item-badge-high {
      background: #ea580c;
      color: #fff;
      font-size: 11pt;
      font-weight: bold;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-block;
      border: none !important;
    }
    .adv-item-badge-med {
      background: #f59e0b;
      color: #0f172a;
      font-size: 11pt;
      font-weight: bold;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-block;
      border: none !important;
    }
    .adv-item-badge-sec {
      background: #16a34a;
      color: #fff;
      font-size: 11pt;
      font-weight: bold;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-block;
      border: none !important;
    }

    /* Code Box: Dark, Rounded, Strictly NO BORDER */
    .adv-code-box {
      background: #0f172a !important;
      color: #f8fafc !important;
      padding: 8px 12px !important;
      border-radius: 6px !important;
      border: none !important;
      margin: 8px 0 12px 0 !important;
      overflow-x: auto !important;
      text-indent: 0 !important;
      font-family: 'JetBrains Mono', Menlo, Consolas, Monaco, monospace !important;
      font-size: 10pt !important;
      line-height: 1.4 !important;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }
    .adv-code-box pre {
      margin: 0 !important;
      padding: 0 !important;
      background: transparent !important;
      border: none !important;
      font-family: inherit !important;
      font-size: inherit !important;
      color: inherit !important;
      text-indent: 0 !important;
      white-space: pre-wrap !important;
      word-break: break-all !important;
    }

    /* Screen simulation footer */
    .sheet-footer {
      position: absolute;
      bottom: 10mm;
      left: 20mm;
      right: 20mm;
      font-size: 11pt;
      color: #707070;
      border: none !important;
      font-family: 'TH SarabunPSK', 'TH Sarabun PSK', sans-serif !important;
    }
    .sheet-footer-line {
      display: none !important;
      border: none !important;
    }
    .sheet-footer-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      line-height: 1.2;
      border: none !important;
    }
    .sheet-footer-left {
      flex: 1;
      text-align: left;
      font-size: 9.5pt;
      color: #707070;
    }
    .sheet-footer-center {
      flex: 1;
      text-align: center;
      font-size: 11pt;
      letter-spacing: 0.5px;
    }
    .sheet-footer-right {
      flex: 1;
      text-align: right;
      font-size: 10.5pt;
      color: #707070;
      letter-spacing: 0.5px;
    }

    /* Print & PDF Layout Rules */
    @page {
      size: A4 portrait;
      margin: 18mm 20mm 22mm 20mm;
    }

    @media print {
      html, body {
        background: #ffffff !important;
        color: #0f172a !important;
        margin: 0 !important;
        padding: 0 !important;
        width: 100% !important;
        display: block !important;
        overflow: visible !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .no-print, .adv-toolbar {
        display: none !important;
      }

      .sheets-container {
        display: block !important;
        padding: 0 !important;
        margin: 0 !important;
        width: 100% !important;
        overflow: visible !important;
      }

      .a4-paper-sheet {
        display: block !important;
        width: 100% !important;
        max-width: 100% !important;
        min-height: auto !important;
        height: auto !important;
        margin: 0 !important;
        padding: 0 !important;
        box-shadow: none !important;
        border: none !important;
        border-radius: 0 !important;
        background-color: #ffffff !important;
        background-image: url("__WATERMARK_DATA_URI__") !important;
        background-repeat: repeat !important;
        background-position: center center !important;
        background-size: 680px 420px !important;
        position: static !important;
        overflow: visible !important;
        page-break-after: auto !important;
        break-after: auto !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .page-break-section {
        break-before: page !important;
        page-break-before: always !important;
      }

      #sheet-references, #sheet-survey {
        break-before: page !important;
        page-break-before: always !important;
        break-inside: avoid !important;
        page-break-inside: avoid !important;
      }

      .adv-heading, .adv-subhead {
        break-after: avoid !important;
        page-break-after: avoid !important;
        break-inside: avoid !important;
        page-break-inside: avoid !important;
      }

      .adv-para {
        orphans: 4 !important;
        widows: 4 !important;
      }

      .adv-table tr {
        break-inside: avoid !important;
        page-break-inside: avoid !important;
      }

      .adv-code-box {
        break-inside: avoid !important;
        page-break-inside: avoid !important;
      }
    }
    """
    return css.replace("__WATERMARK_DATA_URI__", wm_uri)


def build_amber_advisory_html(scan_report_data: Dict[str, Any]) -> str:
    """
    Builds a complete, professional TLP:AMBER A4 Security Advisory HTML.
    Groups findings by physical/logical device (IP), eliminates multi-page boilerplate loops,
    and adheres strictly to zero borders across all tables, cards, and sections.
    """
    now = datetime.now()
    date_str = f"{now.day} {['มกราคม','กุมภาพันธ์','มีนาคม','เมษายน','พฤษภาคม','มิถุนายน','กรกฎาคม','สิงหาคม','กันยายน','ตุลาคม','พฤศจิกายน','ธันวาคม'][now.month-1]} พ.ศ. {now.year + 543}"
    ref_id = f"NCSA-AMBER-{now.year}-{int(now.timestamp()) % 10000:04d}"

    target_scope = scan_report_data.get("target") or scan_report_data.get("target_id") or scan_report_data.get("subnet") or "ระบบสารสนเทศเป้าหมาย"
    hosts_list = scan_report_data.get("hosts", [])
    if not hosts_list and "deep_audit" in scan_report_data:
        hosts_list = [scan_report_data]

    # Group hosts_list by unique IP address to treat each physical/logical host as one device
    hosts_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for h in hosts_list:
        ip = h.get("ip") or h.get("target_id") or "-"
        hosts_by_ip.setdefault(ip, []).append(h)

    total_scanned = len(hosts_by_ip) if len(hosts_by_ip) > 0 else len(hosts_list)
    crit_count = 0
    high_count = 0
    med_count = 0
    safe_count = 0

    all_matched_cves = []
    
    # Calculate summary counts per unique host
    for ip, p_hosts in hosts_by_ip.items():
        host_has_crit = False
        host_has_high = False
        host_has_med = False

        for h in p_hosts:
            v_php = h.get("vulnerability")
            v_node = h.get("vulnerabilityNode")
            da = h.get("deep_audit") or {}
            v_nginx = (da.get("nginx_audit") or {}).get("severity", "Secure")
            rce_p = h.get("rce_proof") or da.get("rce_proof") or {}
            rce_st = rce_p.get("proof_status", "")

            cves = h.get("matched_cves") or []
            for c in cves:
                c_id = c.get("id") or c.get("cve")
                if c_id and c_id not in [x.get("id") or x.get("cve") for x in all_matched_cves]:
                    all_matched_cves.append(c)

            if rce_p.get("is_rce_proved") or rce_st == "RCE_CONFIRMED" or "Critical" in [v_php, v_node, v_nginx]:
                host_has_crit = True
            elif rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI") or "High" in [v_php, v_node, v_nginx]:
                host_has_high = True
            elif "Medium" in [v_php, v_node, v_nginx] or "Warning" in [v_php, v_node]:
                host_has_med = True

        if host_has_crit:
            crit_count += 1
        elif host_has_high:
            high_count += 1
        elif host_has_med:
            med_count += 1
        else:
            safe_count += 1

    has_any_risk = (crit_count + high_count + med_count) > 0

    header_banner = get_ncsa_header_banner_html()
    css_styles = get_css_styles()

    # Table rows for Attack Surface Ledger (Organized concisely by unique IP)
    table_rows_html = ""
    for idx, (h_ip, p_hosts) in enumerate(hosts_by_ip.items(), 1):
        # Collect all ports for this IP
        all_ports = []
        for h in p_hosts:
            for p in (h.get("ports") or [h.get("port")]):
                if p and p not in all_ports:
                    all_ports.append(p)
        h_ports = ", ".join(str(p) for p in sorted(all_ports)) if all_ports else "-"
        
        # Determine Device Name and Technology Stack
        dev_name = ""
        web_srvs = []
        macs = []
        primary_groups = []
        host_highest_sev = "ปลอดภัย (Secure)"
        host_badge_cls = "adv-item-badge-sec"

        for h in p_hosts:
            if not dev_name and h.get("device_name"):
                dev_name = h.get("device_name")
            ws = h.get("webServer") or h.get("server") or ""
            if ws and ws not in web_srvs and "ไม่มี web service" not in ws.lower():
                web_srvs.append(ws)
            m = h.get("mac")
            if m and m not in macs and m != "LAN Device":
                macs.append(m)
            
            da = h.get("deep_audit") or {}
            grp = da.get("primary_group")
            if grp and grp not in primary_groups and "ไม่สามารถระบุ" not in grp:
                primary_groups.append(grp)

            # Check severity
            v_php = h.get("vulnerability")
            v_node = h.get("vulnerabilityNode")
            v_nginx = (da.get("nginx_audit") or {}).get("severity")
            rce_p = h.get("rce_proof") or da.get("rce_proof") or {}
            rce_st = rce_p.get("proof_status", "")

            if rce_p.get("is_rce_proved") or rce_st == "RCE_CONFIRMED":
                host_highest_sev = "วิกฤต (Critical - RCE Confirmed)"
                host_badge_cls = "adv-item-badge-crit"
            elif "Critical" in [v_php, v_node, v_nginx] and "Critical" not in host_highest_sev:
                host_highest_sev = "วิกฤต (Critical)"
                host_badge_cls = "adv-item-badge-crit"
            elif (rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI") or "High" in [v_php, v_node, v_nginx]) and "Critical" not in host_highest_sev:
                host_highest_sev = "สูง (High - LFI Confirmed)" if rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI") else "สูง (High)"
                host_badge_cls = "adv-item-badge-high"
            elif ("Medium" in [v_php, v_node, v_nginx] or "Warning" in [v_php, v_node]) and host_highest_sev == "ปลอดภัย (Secure)":
                host_highest_sev = "ปานกลาง (Medium)"
                host_badge_cls = "adv-item-badge-med"

        first_h = p_hosts[0]
        if not dev_name or dev_name in ["LAN Client", "DHCP Host", "General Host"]:
            combined_srv = " ".join(web_srvs).lower()
            if "airtunes" in combined_srv or "apple" in combined_srv:
                dev_name = "Apple Inc. (AirPlay Device)"
            elif "gsoap" in combined_srv:
                dev_name = "อุปกรณ์สำเร็จรูป / IoT (gSOAP)"
            elif "mikrotik" in combined_srv:
                dev_name = "MikroTik Router Appliance"
            elif "express" in combined_srv or any(h.get("is_node") for h in p_hosts):
                dev_name = "Node.js Application Server"
            elif any(h.get("is_php") for h in p_hosts):
                dev_name = "PHP Web Server"
            elif web_srvs:
                dev_name = web_srvs[0]
            else:
                dev_name = "อุปกรณ์เครือข่ายภายใน (LAN Device)"

        tech_parts = []
        for h in p_hosts:
            if h.get("php") and f"PHP {h.get('php')}" not in tech_parts:
                tech_parts.append(f"PHP {h.get('php')}")
            if h.get("node") and f"Node.js {h.get('node')}" not in tech_parts:
                tech_parts.append(f"Node.js {h.get('node')}")
        for ws in web_srvs:
            if ws not in tech_parts and ws != dev_name:
                tech_parts.append(ws)
        tech_str = " · ".join(tech_parts)

        mac_badge = f'<div style="font-size: 13pt; color: #94a3b8; font-family: monospace;">MAC: {html.escape(macs[0])}</div>' if macs else ""
        service_badge = f'<div style="font-size: 15pt; color: #475569; margin-top: 1px;">บริการ: <code style="font-size: 13pt; background: #f1f5f9; padding: 1px 4px; border-radius: 3px; border: none; font-family: monospace;">{html.escape(tech_str)}</code></div>' if tech_str else ""

        dev_service_cell = f"""
        <div>
          <div style="font-weight: bold; color: #0f172a; font-size: 16pt;">{html.escape(dev_name)}</div>
          {service_badge}
          {mac_badge}
        </div>
        """

        grp_str = " | ".join(primary_groups) if primary_groups else "ไม่สามารถระบุกลุ่มระบบได้จากข้อมูลที่มี (Unclassified)"

        table_rows_html += f"""
        <tr>
          <td style="text-align: center;">{idx}</td>
          <td><strong>{html.escape(h_ip)}</strong></td>
          <td style="text-align: center;"><code>{html.escape(h_ports)}</code></td>
          <td>{dev_service_cell}</td>
          <td>{html.escape(grp_str)}</td>
          <td style="text-align: center;"><span class="{host_badge_cls}">{host_highest_sev}</span></td>
        </tr>
        """

    # In-Depth Findings Sections (Organized by Unique Physical/Logical Device)
    vulnerable_devices_html = ""
    vuln_device_count = 0

    for ip, p_hosts in hosts_by_ip.items():
        # Check if this physical host has any vulnerabilities or actionable findings
        host_is_vuln = False
        host_rce_active = False
        host_rce_status = ""
        host_max_sev = "ปลอดภัย (Secure)"
        host_badge_cls = "adv-item-badge-sec"

        for h in p_hosts:
            da = h.get("deep_audit") or {}
            cves = h.get("matched_cves") or []
            chains = (da.get("security_chains") or {}).get("chains") or (h.get("security_chains") or {}).get("chains") or {}
            rce_p = h.get("rce_proof") or da.get("rce_proof") or {}
            rce_st = rce_p.get("proof_status", "")

            if rce_p.get("is_rce_proved") or rce_st == "RCE_CONFIRMED":
                host_rce_active = True
                host_rce_status = "RCE_CONFIRMED"
                host_is_vuln = True
                host_max_sev = "ระดับวิกฤต (Critical - RCE Confirmed)"
                host_badge_cls = "adv-item-badge-crit"
            elif rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI"):
                host_is_vuln = True
                if "Critical" not in host_max_sev:
                    host_max_sev = "ระดับสูง (High - LFI Confirmed)"
                    host_badge_cls = "adv-item-badge-high"

            v_php = h.get("vulnerability")
            v_node = h.get("vulnerabilityNode")
            v_nginx = (da.get("nginx_audit") or {}).get("severity")

            if "Critical" in [v_php, v_node, v_nginx]:
                host_is_vuln = True
                if "Critical" not in host_max_sev:
                    host_max_sev = "ระดับวิกฤต (Critical)"
                    host_badge_cls = "adv-item-badge-crit"
            elif "High" in [v_php, v_node, v_nginx]:
                host_is_vuln = True
                if host_max_sev in ("ปลอดภัย (Secure)", "ระดับปานกลาง (Medium)"):
                    host_max_sev = "ระดับสูง (High)"
                    host_badge_cls = "adv-item-badge-high"
            elif "Medium" in [v_php, v_node, v_nginx] or "Warning" in [v_php, v_node]:
                host_is_vuln = True
                if host_max_sev == "ปลอดภัย (Secure)":
                    host_max_sev = "ระดับปานกลาง (Medium)"
                    host_badge_cls = "adv-item-badge-med"

            if bool(cves):
                host_is_vuln = True

            has_actionable_chains = any(
                c_val.get("verdict_code") in ("CONFIRMED", "VULN", "REVIEW", "AUDIT", "ARCHITECTURAL_RISK", "INFO_DISCLOSURE")
                for c_val in chains.values()
            ) if chains else False
            if has_actionable_chains:
                host_is_vuln = True

        # STRICT FILTER: Do not list safe hosts in the vulnerability findings section
        if not host_is_vuln:
            continue

        vuln_device_count += 1

        # Determine Device Hostname / Category
        dev_name = ""
        for h in p_hosts:
            if h.get("device_name") and h.get("device_name") not in ["LAN Client", "DHCP Host", "General Host"]:
                dev_name = h.get("device_name")
                break
        if not dev_name:
            dev_name = f"เซิร์ฟเวอร์หลัก ({ip})"

        # All ports on this host
        all_ports = []
        for h in p_hosts:
            for p in (h.get("ports") or [h.get("port")]):
                if p and p not in all_ports:
                    all_ports.append(p)
        ports_str = ", ".join(str(p) for p in sorted(all_ports))

        # Tech stack summary
        tech_summary_parts = []
        for h in p_hosts:
            if h.get("php_version") and f"PHP {h.get('php_version')}" not in tech_summary_parts:
                tech_summary_parts.append(f"PHP {h.get('php_version')}")
            if h.get("runtime_version") and f"Node.js {h.get('runtime_version')}" not in tech_summary_parts:
                tech_summary_parts.append(f"Node.js {h.get('runtime_version')}")
            ws = h.get("webServer") or h.get("server") or (h.get("deep_audit") or {}).get("nginx_audit", {}).get("server")
            if ws and ws not in tech_summary_parts and "ไม่มี" not in str(ws).lower():
                tech_summary_parts.append(str(ws))
        tech_summary = ", ".join(tech_summary_parts) if tech_summary_parts else "Web & Application Server"

        # Unique ThaiCERT Group Profiles for this Host (Consolidated, no multi-page repetitive matrix)
        host_groups: Dict[int, Dict[str, Any]] = {}
        for h in p_hosts:
            port_val = (h.get("ports") or [h.get("port")])[0] if (h.get("ports") or [h.get("port")]) else None
            da = h.get("deep_audit") or {}
            matrix = h.get("architecture_matrix") or da.get("architecture_matrix") or []
            for m in matrix:
                gid = m.get("group_id")
                if gid not in host_groups:
                    profile = THAICERT_GROUP_PROFILES.get(gid, {})
                    host_groups[gid] = {
                        "name": m.get("group_name") or profile.get("name") or f"กลุ่ม {gid}",
                        "sapi": m.get("sapi_detected") or profile.get("sapi_typical") or "มาตรฐาน",
                        "worker": m.get("worker_model") or profile.get("worker_model") or "Standard Process",
                        "impact": m.get("impact_scope") or profile.get("impact_scope") or "ขอบเขตผลกระทบต่อระบบ",
                        "exploitability": m.get("exploitability") or "Conditional",
                        "ports": [port_val] if port_val else []
                    }
                else:
                    if port_val and port_val not in host_groups[gid]["ports"]:
                        host_groups[gid]["ports"].append(port_val)

        # Build compact ThaiCERT classification summary for this host
        matrix_summary_html = ""
        if host_groups:
            matrix_rows = ""
            for gid, ginfo in host_groups.items():
                g_ports_str = f" (พอร์ต: {', '.join(str(p) for p in ginfo['ports'])})" if ginfo["ports"] else ""
                conf_label = "ยืนยันผลกระทบแล้ว" if ginfo["exploitability"] == "Confirmed" else ("มีความเป็นไปได้สูง" if ginfo["exploitability"] == "Likely" else "ขึ้นกับเงื่อนไขเฉพาะ")
                matrix_rows += f"""
                <div style="margin-bottom: 6px; padding: 6px 10px; background: #f8fafc; border-radius: 4px; font-size: 15pt;">
                  <strong>กลุ่ม {gid}: {html.escape(ginfo['name'])}</strong>{g_ports_str} — สถาปัตยกรรม <code>{html.escape(str(ginfo['sapi']))}</code> / <code>{html.escape(str(ginfo['worker']))}</code> (สถานะ: <span style="color: #0369a1; font-weight: bold;">{conf_label}</span>)
                </div>
                """
            matrix_summary_html = f"""
            <div style="margin-top: 10px; margin-bottom: 14px; padding: 10px 14px; background: #ffffff; border-radius: 6px;">
              <div style="font-size: 16pt; font-weight: bold; color: #0f172a; margin-bottom: 6px;">
                การจัดกลุ่มสถาปัตยกรรมและความเสี่ยงของระบบ (ThaiCERT Classification):
              </div>
              {matrix_rows}
            </div>
            """

        # Now, render findings for each port of this host that has actionable vulnerabilities
        host_port_findings_html = ""
        for h in p_hosts:
            port_val = (h.get("ports") or [h.get("port")])[0] if (h.get("ports") or [h.get("port")]) else None
            da = h.get("deep_audit") or {}
            cves = h.get("matched_cves") or []
            chains = (da.get("security_chains") or {}).get("chains") or (h.get("security_chains") or {}).get("chains") or {}
            rce_proof = h.get("rce_proof") or da.get("rce_proof") or {}
            rce_is_active = bool(rce_proof.get("is_rce_proved"))
            rce_status_val = rce_proof.get("proof_status", "")
            
            v_p = h.get("vulnerability")
            v_n = h.get("vulnerabilityNode")
            nx_audit = da.get("nginx_audit", {})
            v_nx = nx_audit.get("severity", "Secure")

            has_actionable_c = any(
                c_val.get("verdict_code") in ("CONFIRMED", "VULN", "REVIEW", "AUDIT", "ARCHITECTURAL_RISK", "INFO_DISCLOSURE")
                for c_val in chains.values()
            ) if chains else False

            port_has_findings = (
                rce_is_active
                or rce_status_val in ("RCE_CONFIRMED", "CANARY_CONFIRMED", "CONFIRMED_LFI")
                or any(s in ("Critical", "High", "Medium", "Warning") for s in [v_p, v_n, v_nx])
                or bool(cves)
                or has_actionable_c
            )

            if not port_has_findings:
                continue

            port_service_name = h.get("webServer") or h.get("server") or nx_audit.get("server") or "Web Service"

            # 1. Live Proof (RCE / LFI) - NO BORDER
            proof_html = ""
            if rce_proof.get("is_rce_proved") or rce_status_val in ("RCE_CONFIRMED", "CANARY_CONFIRMED", "CONFIRMED_LFI"):
                is_rce = rce_proof.get("is_rce_proved") or rce_status_val == "RCE_CONFIRMED"
                box_bg = "#fff5f5" if is_rce else "#fefce8"
                title_color = "#991b1b" if is_rce else "#854d0e"
                badge_text = "[RCE CONFIRMED]" if is_rce else ("[CANARY CONFIRMED]" if rce_status_val == "CANARY_CONFIRMED" else "[LFI CONFIRMED]")
                header_title = "หลักฐานเชิงประจักษ์ยืนยันการรันคำสั่งควบคุมระบบ (Live RCE Proof)" if is_rce else "หลักฐานเชิงประจักษ์ยืนยันช่องโหว่ LFI / Arbitrary File Read"
                
                trail = rce_proof.get("audit_trail") or {}
                trail_html = ""
                if trail:
                    trail_html = f"""
                    <div style="margin-top: 8px; padding-top: 6px; font-size: 8.5pt; color: #94a3b8;">
                      <div><b>Tamper-Evident Evidence Digest:</b> Operator: {html.escape(trail.get('operator', '-'))} | UTC: {html.escape(trail.get('timestamp_utc', '-'))}</div>
                      <div style="word-break: break-all;"><b>SHA-256:</b> <span style="color: #4ade80;">{html.escape(trail.get('evidence_sha256', '-'))}</span></div>
                    </div>
                    """

                proof_html = f"""
                <div style="margin-top: 10px; margin-bottom: 12px; padding: 12px 16px; background: {box_bg}; border-radius: 6px;">
                  <div style="font-size: 16pt; font-weight: bold; color: {title_color}; margin-bottom: 4px;">
                    {header_title} บนพอร์ต {html.escape(str(port_val or '-'))}
                  </div>
                  <p class="adv-para" style="color: #451a03; margin-bottom: 8px;">
                    {html.escape(rce_proof.get('impact_statement', ''))} (เทคนิค: <b>{html.escape(rce_proof.get('technique', ''))}</b> | ระดับสิทธิ์: <b>{html.escape(rce_proof.get('privilege_level', ''))}</b>)
                  </p>
                  <div class="adv-code-box" style="margin: 0;">
                    <div style="color: #94a3b8; font-size: 9pt; padding-bottom: 4px; margin-bottom: 6px;">
                      $ {html.escape(rce_proof.get('command_executed', 'canary execution'))} &nbsp;&nbsp;<span style="color: {'#f87171' if is_rce else '#facc15'}; font-weight: bold;">{badge_text}</span> &nbsp;&nbsp;เวลา: {html.escape(rce_proof.get('verified_at', ''))}
                    </div>
                    <div style="color: #4ade80; font-weight: bold;">
                      {html.escape(rce_proof.get('execution_output', ''))}
                    </div>
                    {f'<div style="color: #f59e0b; font-size: 9pt; margin-top: 6px; padding-top: 4px;">คำสั่งทดสอบจริง (CLI): {html.escape(rce_proof.get("reproduce_curl", ""))}</div>' if rce_proof.get("reproduce_curl") else ''}
                    {trail_html}
                  </div>
                </div>
                """

            # 2. Architectural Preconditions (NO BORDER)
            br_pre = da.get("brotli_preconditions") or {}
            nx_pre = da.get("nginx_preconditions") or {}
            precond_rows = ""
            if br_pre:
                br_status = "ยอมรับและถอดรหัสบิตสตรีมเข้า (Active Decompression Confirmed)" if br_pre.get("brotli_request_accepted") else "ปฏิเสธ / ไม่พบการใช้งาน"
                precond_rows += f"""<tr><td style="padding: 4px 8px; font-weight: bold; width: 35%; color: #475569;">Brotli Stream Processing (CVE-2026-111497):</td><td style="padding: 4px 8px; color: #0f172a;">{html.escape(br_status)}</td></tr>"""
            if nx_pre:
                h3_status = "ยืนยันพอร์ต UDP 443 ผ่านแพ็กเก็ต RFC 9000 (Active QUIC Listener Confirmed)" if nx_pre.get("http3_udp_verified") else "ไม่พบการตอบสนองของ QUIC UDP บนพอร์ต 443"
                alias_status = f"ตรวจพบพฤติกรรม Traversal: {nx_pre.get('alias_evidence')}" if nx_pre.get("alias_traversal_observed") else "ปกติ (ไม่พบความผิดปกติจากคำขอ /dir../ เทียบกับ Baseline)"
                ssi_status = f"พบไฟล์: {', '.join(nx_pre.get('ssi_files', []))}" if nx_pre.get("ssi_files") else "ไม่พบไฟล์ .shtml/.shtm บนระบบ"
                precond_rows += f"""
                    <tr><td style="padding: 4px 8px; font-weight: bold; color: #475569;">HTTP/3 QUIC UDP Transport:</td><td style="padding: 4px 8px; color: #0f172a;">{html.escape(h3_status)}</td></tr>
                    <tr><td style="padding: 4px 8px; font-weight: bold; color: #475569;">NGINX Alias Path Traversal:</td><td style="padding: 4px 8px; color: #0f172a;">{html.escape(alias_status)}</td></tr>
                    <tr><td style="padding: 4px 8px; font-weight: bold; color: #475569;">SSI Directive Exposure:</td><td style="padding: 4px 8px; color: #0f172a;">{html.escape(ssi_status)}</td></tr>
                """
            precond_html = ""
            if precond_rows:
                precond_html = f"""
                <div style="margin-top: 8px; margin-bottom: 12px; padding: 10px 14px; background: #ffffff; border-radius: 6px;">
                  <div style="font-size: 15pt; font-weight: bold; color: #1e293b; margin-bottom: 4px;">
                    ตารางประเมินเงื่อนไขจำเป็นทางสถาปัตยกรรม (Architectural Preconditions) พอร์ต {html.escape(str(port_val or '-'))}:
                  </div>
                  <table style="width: 100%; font-size: 15pt; border-collapse: collapse; border: none;">
                    {precond_rows}
                  </table>
                </div>
                """

            # 3. Matched CVEs for this port (NO BORDER)
            cves_html = ""
            for c in cves:
                cve_id = c.get("id") or c.get("cve") or "CVE-VULN"
                cve_name = c.get("name") or "ช่องโหว่ความมั่นคงปลอดภัย"
                cve_sev = c.get("severity") or "High"
                cvss = c.get("cvss") or 7.5
                cat = c.get("category") or "Web Stack"
                reason = c.get("reason") or c.get("desc") or "ตรวจพบเวอร์ชันซอฟต์แวร์ที่ตรงกับเงื่อนไขความเสี่ยง"
                host_check = c.get("host_check") or "php -v || node -v || nginx -v"
                confirm_vuln = c.get("confirm_vuln") or "พบเวอร์ชันอยู่ในช่วงที่ได้รับผลกระทบ"
                confirm_safe = c.get("confirm_safe") or "อัปเดตเป็นเวอร์ชันที่ได้รับแพตช์ความปลอดภัยล่าสุด"

                sev_th_map = {
                    "Critical": "ระดับวิกฤต (Critical)",
                    "High": "ระดับสูง (High)",
                    "Medium": "ระดับปานกลาง (Medium)",
                    "Low": "ระดับต่ำ (Low)",
                    "Warning": "ระดับควรเฝ้าระวัง (Warning)"
                }
                cve_sev_th = sev_th_map.get(cve_sev, f"ระดับ {cve_sev}")
                cve_conf = c.get("confidence") or ("Confirmed" if c.get("confirmed") else "Conditional")

                cves_html += f"""
                <div class="adv-finding-item">
                  <div style="font-size: 16pt; font-weight: bold; color: #0f172a; margin-bottom: 4px;">
                    ข้อค้นพบ: {html.escape(cve_id)} — {html.escape(cve_name)}
                  </div>
                  <div style="font-size: 15pt; color: #334155; margin-bottom: 8px; background: #f8fafc; padding: 6px 12px; border-radius: 4px;">
                    <strong>ระดับความรุนแรง:</strong> {cve_sev_th} &nbsp;|&nbsp; 
                    <strong>คะแนน CVSS:</strong> {cvss} &nbsp;|&nbsp;
                    <strong>ความเชื่อมั่น:</strong> <span style="font-weight: bold; color: #0284c7;">{html.escape(cve_conf)}</span> &nbsp;|&nbsp;
                    <strong>หมวดหมู่:</strong> {html.escape(cat)}
                  </div>
                  <p class="adv-para">
                    จากการตรวจสอบบริการบนพอร์ต {html.escape(str(port_val or '-'))} พบว่า {html.escape(reason)} จัดเป็นข้อค้นพบ {cve_sev_th} โดยมีเงื่อนไขผลกระทบ: {html.escape(confirm_vuln)}
                  </p>
                  <div class="adv-code-box">
                    <div style="font-size: 15pt; color: #94a3b8; font-weight: bold; margin-bottom: 4px;">คำสั่งสำหรับผู้ดูแลระบบใช้ตรวจสอบจริงบนเครื่อง (Host-Check):</div>
                    <pre><code>{html.escape(host_check)}</code></pre>
                  </div>
                  <div class="adv-code-box">
                    <div style="font-size: 15pt; color: #94a3b8; font-weight: bold; margin-bottom: 4px;">แนวทางแก้ไขและเกณฑ์ความปลอดภัยที่แนะนำ:</div>
                    <pre><code># คำแนะนำ: อัปเดตซอฟต์แวร์ {html.escape(cat)} ให้เป็นไปตามเกณฑ์ความปลอดภัย
# เกณฑ์ความปลอดภัยที่แนะนำ: {html.escape(confirm_safe)}
# ควรสำรองข้อมูลและทดสอบในสภาพแวดล้อม Staging ก่อนปรับปรุงระบบจริง</code></pre>
                  </div>
                </div>
                """

            # If no specific CVEs matched but port has a critical/high/outdated runtime status (e.g. EOL PHP 7.4)
            if not cves and (v_p in ("Critical", "High", "Medium", "Warning") or v_n in ("Critical", "High", "Medium", "Warning")):
                rt_version = h.get("runtime_version") or h.get("php_version") or h.get("node_version") or "ไม่ระบุเวอร์ชัน"
                note_text = h.get("cveNote") or f"ตรวจพบการเปิดให้บริการซอฟต์แวร์เวอร์ชันที่มีความเสี่ยงหรือสิ้นสุดการสนับสนุน ({rt_version})"
                h_check = (h.get("deep_audit") or {}).get("host_verify_cmd") or "php -v || node -v"
                safe_crit = (h.get("deep_audit") or {}).get("safe_criteria") or "อัปเกรดเป็นเวอร์ชันล่าสุดที่ได้รับการสนับสนุนอย่างเป็นทางการ"

                sev_label = "ระดับวิกฤต (Critical)" if (v_p == "Critical" or v_n == "Critical") else ("ระดับสูง (High)" if (v_p == "High" or v_n == "High") else "ระดับควรเฝ้าระวัง (Warning / Outdated)")

                cves_html += f"""
                <div class="adv-finding-item">
                  <div style="font-size: 16pt; font-weight: bold; color: #0f172a; margin-bottom: 4px;">
                    ข้อค้นพบ: สถานะซอฟต์แวร์และการหมดอายุการสนับสนุน ({html.escape(rt_version)})
                  </div>
                  <div style="font-size: 15pt; color: #334155; margin-bottom: 8px; background: #f8fafc; padding: 6px 12px; border-radius: 4px;">
                    <strong>ระดับความรุนแรง:</strong> {sev_label} &nbsp;|&nbsp;
                    <strong>สถานะ:</strong> สิ้นสุดระยะสนับสนุน (End-of-Life / EOL)
                  </div>
                  <p class="adv-para">
                    {html.escape(note_text)}
                  </p>
                  <div class="adv-code-box">
                    <div style="font-size: 15pt; color: #94a3b8; font-weight: bold; margin-bottom: 4px;">คำสั่งสำหรับผู้ดูแลระบบใช้ตรวจสอบจริงบนเครื่อง (Host-Check):</div>
                    <pre><code>{html.escape(h_check)}</code></pre>
                  </div>
                  <div class="adv-code-box">
                    <div style="font-size: 15pt; color: #94a3b8; font-weight: bold; margin-bottom: 4px;">แนวทางแก้ไขและเกณฑ์ความปลอดภัยที่แนะนำ:</div>
                    <pre><code># คำแนะนำ: วางแผนปรับปรุงและอัปเกรดซอฟต์แวร์เป็นเวอร์ชันที่ยังได้รับการบำรุงรักษา
# เกณฑ์ความปลอดภัยที่แนะนำ: {html.escape(safe_crit)}</code></pre>
                  </div>
                </div>
                """

            # 4. Session Chains / PHP Hardening (NO BORDER)
            session_html = ""
            if chains:
                for c_key, c_val in chains.items():
                    c_verdict_code = c_val.get("verdict_code")
                    if c_verdict_code in ("CONFIRMED", "VULN", "REVIEW", "AUDIT", "ARCHITECTURAL_RISK"):
                        c_title = c_val.get("title") or "Security Hardening Chain"
                        c_verdict = c_val.get("verdict") or "ตรวจพบข้อควรระวังในการตั้งค่า"
                        c_remedy = c_val.get("remediation") or "ปรับปรุงค่าคอนฟิกตามแนวทาง CIS Benchmark"
                        c_ini = c_val.get("hardening_ini") or "; ปรับแต่งคอนฟิกเพื่อความมั่นคงปลอดภัย"
                        
                        session_html += f"""
                        <div class="adv-finding-item">
                          <div style="font-size: 16pt; font-weight: bold; color: #0f172a; margin-bottom: 4px;">
                            ข้อควรระวังด้านการตั้งค่า: {html.escape(c_title)}
                          </div>
                          <div style="font-size: 15pt; color: #334155; margin-bottom: 8px; background: #f8fafc; padding: 6px 12px; border-radius: 4px;">
                            <strong>สถานะ:</strong> {html.escape(c_val.get('confidence', 'Conditional'))} &nbsp;|&nbsp;
                            <strong>รหัสการประเมิน:</strong> <code>{html.escape(c_verdict_code)}</code>
                          </div>
                          <p class="adv-para">
                            {html.escape(c_verdict)} แนะนำให้ผู้ดูแลระบบตรวจสอบ {html.escape(c_remedy)}
                          </p>
                          <div class="adv-code-box">
                            <div style="font-size: 15pt; color: #94a3b8; font-weight: bold; margin-bottom: 4px;">แนวทางการตั้งค่า php.ini ที่แนะนำ:</div>
                            <pre><code>{html.escape(c_ini)}</code></pre>
                          </div>
                        </div>
                        """

            # Combine port section
            host_port_findings_html += f"""
            <div style="margin-top: 14px; margin-bottom: 16px; padding: 12px 14px; background: #f1f5f9; border-radius: 6px;">
              <div style="font-size: 16pt; font-weight: bold; color: #0f172a; margin-bottom: 6px;">
                พอร์ตบริการ: <code>{html.escape(str(port_val or '-'))}</code> — {html.escape(port_service_name)}
              </div>
              {proof_html}
              {precond_html}
              {cves_html}
              {session_html}
            </div>
            """

        # Assemble Full Device Block (NO BORDER)
        vulnerable_devices_html += f"""
        <div class="adv-device-block">
          <div style="font-size: 16pt; font-weight: bold; color: #0f172a; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <span>อุปกรณ์ที่พบความเสี่ยงลำดับที่ {vuln_device_count}: {html.escape(dev_name)} ({html.escape(ip)})</span>
            <div><span class="{host_badge_cls}">{host_max_sev}</span></div>
          </div>
          
          <div style="font-size: 16pt; color: #334155; margin-bottom: 10px; background: #ffffff; padding: 8px 14px; border-radius: 6px;">
            <div><strong>ที่อยู่ IP:</strong> <code>{html.escape(ip)}</code> &nbsp;|&nbsp; <strong>พอร์ตบริการที่เปิด:</strong> <code>{html.escape(ports_str)}</code> &nbsp;|&nbsp; <strong>บริการ:</strong> {html.escape(tech_summary)}</div>
          </div>

          {matrix_summary_html}
          {host_port_findings_html}
        </div>
        """

    if not vulnerable_devices_html:
        vulnerable_devices_html = """
        <div class="adv-finding-item">
          <p class="adv-para" style="text-align: center; color: #16a34a; font-weight: bold; margin: 24px 0;">
            ✓ จากการตรวจสอบตามขอบเขตและวิธีการที่กำหนด ยังไม่พบหลักฐานของข้อค้นพบระดับวิกฤต (Critical) หรือระดับสูง (High) บนอุปกรณ์ใดในเครือข่าย
            <br><span style="font-size: 16pt; color: #475569; font-weight: normal;">(ผลดังกล่าวไม่ใช่การรับรองว่าระบบปลอดภัยทั้งหมด ผู้ดูแลระบบควรติดตามแพตช์และทบทวนการตั้งค่าตามรอบระยะเวลาที่เหมาะสม)</span>
          </p>
        </div>
        """

    survey_qr_img = f"data:image/png;base64,{SURVEY_QR_PNG_B64}" if SURVEY_QR_PNG_B64 else ""
    total_vulns = crit_count + high_count + med_count

    if not has_any_risk:
        exec_summary_html = f"""
      <div class="adv-heading">สรุปผลการประเมินภาพรวมความปลอดภัยเชิงรุก</div>
      <p class="adv-para">
        รายงานฉบับนี้จัดทำขึ้นเพื่อแจ้งผลการตรวจสอบความมั่นคงปลอดภัยสำหรับผู้ดูแลระบบ โดยจากการตรวจสอบระบบสารสนเทศและบริการเครือข่ายในวง IP <code>{html.escape(target_scope)}</code> (รวมทั้งสิ้น <strong>{total_scanned}</strong> ระบบ) อ้างอิงตามเกณฑ์มาตรฐานความปลอดภัยสากลและข้อมูลช่องโหว่ (CVE)
      </p>
      <p class="adv-para">
        ผลการตรวจสอบพบว่า <strong>ระบบทั้งหมดอยู่ในสถานะปลอดภัย (Clean &amp; Secure)</strong> โดยไม่พบช่องโหว่ความเสี่ยงระดับวิกฤต (Critical), ระดับสูง (High) หรือระดับปานกลาง (Medium) บนบริการที่เปิดให้เข้าถึงได้ อุปกรณ์ส่วนใหญ่เป็นเครื่องลูกข่ายภายในและอุปกรณ์เครือข่ายที่มีการปิดกั้นพอร์ตบริการด้วยไฟร์วอลล์อย่างถูกต้อง
      </p>
      <p class="adv-para">
        ทางทีมงานขอแนะนำให้ผู้ดูแลระบบรักษาระดับการป้องกันตามมาตรฐานความปลอดภัย (Cyber Hygiene) อย่างต่อเนื่อง โดยหมั่นตรวจสอบการเปิดเผยพอร์ตบริการและอัปเดตระบบตามรอบการบำรุงรักษาปกติ
      </p>
        """
        page2_heading = "สรุปผลการประเมินความปลอดภัยทางเทคนิค"
        page2_content = f"""
      <p class="adv-para">
        จากการประเมินและตรวจสอบบริการเครือข่ายเชิงลึก ไม่พบพอร์ตหรือบริการเว็บแอปพลิเคชันที่มีช่องโหว่ความเสี่ยงระดับวิกฤตหรือระดับสูงเปิดให้บริการสู่เครือข่ายภายนอก
      </p>

      <div style="margin-top: 14px; margin-bottom: 20px; padding: 18px 22px; background: #f0fdf4; border-radius: 8px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
          <span style="font-size: 18pt; color: #16a34a;">✓</span>
          <span style="font-size: 16pt; font-weight: bold; color: #166534;">ผลการตรวจประเมิน: ระบบอยู่ในสถานะปลอดภัย ไม่พบช่องโหว่ความเสี่ยงระดับวิกฤตหรือระดับสูง</span>
        </div>
        <div style="font-size: 16pt; color: #1e293b; line-height: 1.6;">
          <p style="margin: 0 0 8px 0;"><strong>ผลสรุปการตรวจประเมินทางเทคนิคสำหรับระบบในขอบเขต:</strong></p>
          <ul style="margin: 0 0 12px 18px; padding: 0;">
            <li><b>Remote Code Execution (RCE):</b> ไม่พบจุดรับคำสั่งหรือพฤติกรรมที่เสี่ยงต่อการถูกสั่งรันโค้ดจากระยะไกล</li>
            <li><b>Web Stack Vulnerabilities:</b> ไม่พบช่องโหว่ความรุนแรงสูงใน PHP, Node.js หรือ Web Server Services</li>
            <li><b>Network Perimeter:</b> อุปกรณ์ลูกข่ายส่วนใหญ่มีการปิดกั้นพอร์ตบริการ หรือตั้งค่าไฟร์วอลล์อย่างถูกต้อง</li>
          </ul>
          <p style="margin: 0; color: #15803d; font-size: 16pt;">
            💡 <b>ข้อเสนอแนะในการกำกับดูแล:</b> ควรรักษามาตรฐานความมั่นคงปลอดภัย (Cyber Hygiene) ต่อเนื่อง โดยหมั่นอัปเดตระบบปฏิบัติการ ซอฟต์แวร์ และตรวจสอบการเปิดเผยพอร์ตเครือข่ายภายนอกเป็นประจำ
          </p>
        </div>
      </div>
        """
    else:
        if crit_count == total_vulns and crit_count > 0:
            vuln_breakdown = "ซึ่งทั้งหมดอยู่ในระดับวิกฤต (Critical)"
        elif high_count == total_vulns and high_count > 0:
            vuln_breakdown = "ซึ่งทั้งหมดอยู่ในระดับสูง (High)"
        elif med_count == total_vulns and med_count > 0:
            vuln_breakdown = "ซึ่งทั้งหมดอยู่ในระดับปานกลาง (Medium)"
        else:
            breakdown_parts = []
            if crit_count > 0:
                breakdown_parts.append(f"ระดับวิกฤต (Critical) <strong>{crit_count}</strong> รายการ")
            if high_count > 0:
                breakdown_parts.append(f"ระดับสูง (High) <strong>{high_count}</strong> รายการ")
            if med_count > 0:
                breakdown_parts.append(f"ระดับปานกลาง (Medium) <strong>{med_count}</strong> รายการ")
            vuln_breakdown = f"โดยแบ่งเป็น {', '.join(breakdown_parts)}"

        safe_tail = f" ส่วนอีก <strong>{safe_count}</strong> ระบบที่เหลือยังไม่พบสัญญาณความเสี่ยงตามเงื่อนไขที่กำหนด" if safe_count > 0 else ""

        exec_summary_html = f"""
      <div class="adv-heading">สรุปผลการประเมินภาพรวมความเสี่ยงเชิงรุก</div>
      <p class="adv-para">
        รายงานฉบับนี้จัดทำขึ้นเพื่อแจ้งข้อค้นพบทางเทคนิคและแนวทางแก้ไขสำหรับผู้ดูแลระบบ โดยจากการตรวจสอบระบบสารสนเทศและบริการเครือข่ายในวง IP <code>{html.escape(target_scope)}</code> (รวมทั้งสิ้น <strong>{total_scanned}</strong> ระบบ) อ้างอิงตามเกณฑ์มาตรฐานความปลอดภัยสากล ข้อมูลช่องโหว่ (CVE) และเอกสารอ้างอิงจากผู้พัฒนา
      </p>
      <p class="adv-para">
        ผลการตรวจสอบพบช่องโหว่ทั้งหมด <strong>{total_vulns}</strong> รายการ {vuln_breakdown}{safe_tail}
      </p>
      <p class="adv-para">
        ทางทีมงานขอแนะนำให้ผู้ดูแลระบบเร่งตรวจสอบและดำเนินการแก้ไขตามลำดับความสำคัญ โดยควรเน้นไปที่ระบบที่มีหลักฐานยืนยันช่องโหว่ชัดเจน และเป็นระบบที่เชื่อมต่อหรือเปิดให้เข้าถึงได้จากเครือข่ายภายนอกก่อนเป็นอันดับแรก
      </p>
        """
        page2_heading = "รายละเอียดข้อค้นพบทางเทคนิคและแนวทางการแก้ไขจำแนกตามอุปกรณ์"
        page2_content = f"""
      <p class="adv-para">
        ส่วนนี้นำเสนอรายละเอียดเชิงเทคนิคของข้อค้นพบและช่องโหว่ความมั่นคงปลอดภัยโดยจำแนกตามอุปกรณ์ที่ตรวจพบ เพื่อให้ผู้ดูแลระบบเห็นภาพรวมความเสี่ยงและรายละเอียดเฉพาะของแต่ละอุปกรณ์อย่างชัดเจน พร้อมการจัดกลุ่มตามเกณฑ์ ThaiCERT สถาปัตยกรรมระบบ คำสั่งตรวจสอบจริงบนเครื่อง (Host-Check) และแนวทางการแก้ไขที่เหมาะสมกับอุปกรณ์นั้นๆ
      </p>

      {vulnerable_devices_html}
        """

    return f"""<!DOCTYPE html>
<html lang="th">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>เอกสารแจ้งเตือนความมั่นคงปลอดภัยไซเบอร์ (TLP:AMBER) - {ref_id}</title>
  <link rel="stylesheet" href="/fonts/fonts.css">
  <style>
{css_styles}
  </style>
</head>
<body>

  <!-- Print & Preview Toolbar -->
  <div class="adv-toolbar no-print">
    <div class="adv-toolbar-title">
      <span class="adv-toolbar-badge">TLP:AMBER</span>
      <span>รายงานประเมินความมั่นคงปลอดภัยไซเบอร์ (TLP:AMBER)</span>
    </div>
    <div class="adv-toolbar-actions">
      <button class="adv-btn adv-btn-primary" onclick="window.print()">
        🖨️ พิมพ์ / บันทึกเป็น PDF
      </button>
      <a href="/api/report/pdf" target="_blank" class="adv-btn adv-btn-outline">
        ⬇️ ดาวน์โหลด PDF ตรงจากเซิร์ฟเวอร์
      </a>
    </div>
  </div>

  <div class="sheets-container">

    <!-- PAGE 1: Letterhead, Title, Executive Summary, Attack Surface -->
    <div class="a4-paper-sheet" id="sheet-page-1">
      {header_banner}

      <div class="adv-doc-title">รายงานประเมินความมั่นคงปลอดภัยไซเบอร์</div>
      <div class="adv-doc-meta">
        รหัสอ้างอิง: {ref_id} &nbsp;|&nbsp; วันที่: {date_str} &nbsp;|&nbsp; ขอบเขต: {html.escape(target_scope)}
      </div>

      <div class="adv-tlp-rule-box">
        <strong>ข้อกำหนดการเผยแพร่ TLP:AMBER:</strong> เอกสารนี้ใช้สำหรับผู้รับและหน่วยงานที่เกี่ยวข้องตามความจำเป็นในการปฏิบัติงาน ผู้รับสามารถแบ่งปันต่อภายในหน่วยงานของตนและแก่ผู้เกี่ยวข้องที่จำเป็นต้องใช้ข้อมูลเพื่อป้องกัน แก้ไข หรือประเมินความเสี่ยง ทั้งนี้ต้องไม่เผยแพร่ต่อสาธารณะ และไม่ส่งต่อไปยังผู้ที่ไม่เกี่ยวข้องกับการดำเนินงาน
      </div>

      {exec_summary_html}

      <div class="adv-subhead">ตารางสรุปรายการอุปกรณ์และบริการเครือข่ายที่ตรวจพบ</div>
      <div class="adv-table-wrap">
        <table class="adv-table">
          <thead>
            <tr>
              <th style="width: 35px;">#</th>
              <th style="width: 125px;">เป้าหมาย (IP / Host)</th>
              <th style="width: 75px;">พอร์ตบริการ</th>
              <th>ประเภทอุปกรณ์ / บริการที่ตรวจพบ</th>
              <th style="width: 175px;">กลุ่มระบบ (ThaiCERT Classification)</th>
              <th style="width: 120px;">สถานะความเสี่ยง</th>
            </tr>
          </thead>
          <tbody>
            {table_rows_html}
          </tbody>
        </table>
      </div>

      <div class="sheet-footer no-print">
        <div class="sheet-footer-line"></div>
        <div class="sheet-footer-row">
          <div class="sheet-footer-left">รายงานประเมินความมั่นคงปลอดภัยไซเบอร์</div>
          <div class="sheet-footer-center">TLP:AMBER ●</div>
          <div class="sheet-footer-right">1 | P a g e</div>
        </div>
      </div>
    </div>

    <!-- PAGE 2+: Technical Findings & Hardening Blueprints -->
    <div class="a4-paper-sheet page-break-section" id="sheet-page-2">
      <div class="adv-heading">{page2_heading}</div>
      {page2_content}

      <div class="sheet-footer no-print">
        <div class="sheet-footer-line"></div>
        <div class="sheet-footer-row">
          <div class="sheet-footer-left">รายงานประเมินความมั่นคงปลอดภัยไซเบอร์</div>
          <div class="sheet-footer-center">TLP:AMBER ●</div>
          <div class="sheet-footer-right">2 | P a g e</div>
        </div>
      </div>
    </div>

    <!-- PAGE 3: References & Incident Coordination (Independent Standalone Page) -->
    <div class="a4-paper-sheet page-break-section" id="sheet-references">
      <div class="adv-heading">เอกสารอ้างอิงและช่องทางการประสานงานรับมือเหตุการณ์ความมั่นคงปลอดภัย</div>
      
      <p class="adv-para">
        การตรวจประเมินและจัดทำรายงานฉบับนี้ ดำเนินการโดยอ้างอิงตามกรอบมาตรฐานความมั่นคงปลอดภัยสารสนเทศและแนวปฏิบัติสากล ได้แก่:
      </p>
      <ul class="adv-list">
        <li><b>NIST SP 800-115:</b> Technical Guide to Information Security Testing and Assessment (กรอบการตรวจประเมินและทดสอบช่องโหว่)</li>
        <li><b>ThaiCERT Advisory &amp; Guidance:</b> แนวปฏิบัติการบริหารจัดการและรับมือช่องโหว่ความมั่นคงปลอดภัยบนเว็บแอปพลิเคชัน</li>
        <li><b>CIS Benchmarks:</b> Center for Internet Security (แนวทางการตั้งค่าความมั่นคงปลอดภัยระบบแม่ข่าย Nginx, PHP และ Node.js)</li>
        <li><b>National Vulnerability Database (NVD/NIST):</b> ฐานข้อมูลรายการช่องโหว่และความเสี่ยงสากล (Common Vulnerabilities and Exposures)</li>
        <li><b>FIRST Standards:</b> Traffic Light Protocol (TLP) Version 2.0 มาตรฐานการจำแนกชั้นความลับและการแลกเปลี่ยนข้อมูลไซเบอร์</li>
      </ul>

      <div class="adv-heading" style="margin-top: 18px;">ช่องทางการประสานงานรับมือเหตุการณ์ความมั่นคงปลอดภัยไซเบอร์</div>
      <p class="adv-para">
        หากหน่วยงานของท่านตรวจพบเหตุการณ์ภัยคุกคามทางไซเบอร์ หรือประสงค์ขอรับคำปรึกษาทางเทคนิคเพิ่มเติม สามารถประสานงานฝ่ายปฏิบัติการได้ตามช่องทางดังต่อไปนี้:
      </p>

      <div style="margin: 10px 0 16px 0; padding: 14px 18px; background: #f8fafc; border-radius: 8px; font-size: 16pt;">
        <div style="font-weight: bold; color: #0f172a; margin-bottom: 6px;">
          ศูนย์ประสานการรักษาความมั่นคงปลอดภัยระบบคอมพิวเตอร์แห่งชาติ (ThaiCERT / สกมช.)
        </div>
        <table style="width: 100%; font-size: 16pt; border-collapse: collapse; border: none; line-height: 1.4;">
          <tr>
            <td style="width: 28%; font-weight: bold; color: #475569; padding: 3px 0; border: none;">เว็บไซต์หลัก:</td>
            <td style="padding: 3px 0; border: none;"><a href="https://www.ncsa.or.th" target="_blank" style="color: #0284c7; text-decoration: underline;">https://www.ncsa.or.th</a></td>
          </tr>
          <tr>
            <td style="font-weight: bold; color: #475569; padding: 3px 0; border: none;">อีเมลรับแจ้งเหตุ:</td>
            <td style="padding: 3px 0; border: none;"><a href="mailto:incident@thaicert.or.th" style="color: #0284c7; text-decoration: underline;">incident@thaicert.or.th</a></td>
          </tr>
          <tr>
            <td style="font-weight: bold; color: #475569; padding: 3px 0; border: none;">อีเมลประสานงาน:</td>
            <td style="padding: 3px 0; border: none;"><a href="mailto:saraban@ncsa.or.th" style="color: #0284c7; text-decoration: underline;">saraban@ncsa.or.th</a></td>
          </tr>
          <tr>
            <td style="font-weight: bold; color: #475569; padding: 3px 0; border: none;">สายด่วนรับแจ้งเหตุ:</td>
            <td style="padding: 3px 0; border: none;"><strong>02-143-7777</strong> (ในวันและเวลาราชการ)</td>
          </tr>
        </table>
      </div>

      <div class="sheet-footer no-print">
        <div class="sheet-footer-line"></div>
        <div class="sheet-footer-row">
          <div class="sheet-footer-left">รายงานประเมินความมั่นคงปลอดภัยไซเบอร์</div>
          <div class="sheet-footer-center">TLP:AMBER ●</div>
          <div class="sheet-footer-right">3 | P a g e</div>
        </div>
      </div>
    </div>

    <!-- PAGE 4: System Satisfaction Evaluation & Feedback Survey (Independent Standalone Page) -->
    <div class="a4-paper-sheet page-break-section" id="sheet-survey">
      <div class="adv-heading">แบบประเมินความพึงพอใจของระบบ</div>

      <p class="adv-para">
        เพื่อการพัฒนาและยกระดับประสิทธิภาพของระบบประเมินความมั่นคงปลอดภัยไซเบอร์ (OPScaner) รวมถึงการให้บริการข้อมูลทางเทคนิคของฝ่ายปฏิบัติการ ขอความอนุเคราะห์ผู้ดูแลระบบและผู้เกี่ยวข้องร่วมตอบแบบประเมินความพึงพอใจผ่านระบบอิเล็กทรอนิกส์
      </p>

      <div style="margin: 16px auto; max-width: 480px; text-align: center; border-radius: 8px; padding: 16px 20px; background: #f8fafc;">
        <div style="font-size: 16pt; font-weight: bold; color: #0f172a; margin-bottom: 4px;">สแกนคิวอาร์โค้ดเพื่อทำแบบประเมินความพึงพอใจ</div>
        <p class="adv-para" style="text-indent: 0; text-align: center; margin-bottom: 12px; color: #475569;">
          ผู้รับเอกสารสามารถใช้สมาร์ตโฟนสแกน QR Code ด้านล่างนี้เพื่อเข้าสู่แบบประเมินและส่งข้อเสนอแนะ
        </p>
        {"<div style='margin-bottom: 10px;'><img src='" + survey_qr_img + "' style='width: 115px; height: 115px; border: none; padding: 4px; border-radius: 6px; background: #ffffff; display: inline-block;' alt='Survey QR' /></div>" if survey_qr_img else ""}
        <div style="font-size: 16pt; color: #1e293b; line-height: 1.35;">
          <strong>ลิงก์ทำแบบประเมินออนไลน์:</strong> <br>
          <a href="https://www.ncsa.or.th/survey" target="_blank" style="color: #0284c7; text-decoration: underline; font-weight: bold;">https://www.ncsa.or.th/survey</a>
        </div>
      </div>

      <div class="adv-heading" style="margin-top: 16px;">หัวข้อและประเด็นในการประเมิน</div>
      <ul class="adv-list">
        <li>ความถูกต้องและความแม่นยำของผลการตรวจประเมินทางเทคนิค (Detection Precision)</li>
        <li>ความชัดเจนและความเป็นประโยชน์ของคำแนะนำในการแก้ไขปัญหา (Remediation Guidance)</li>
        <li>ความสะดวกในการใช้งานระบบและการออกรายงานมาตรฐานทางการ (Report Usability)</li>
        <li>ข้อเสนอแนะเพิ่มเติมสำหรับการพัฒนาขีดความสามารถของเครื่องมือในอนาคต</li>
      </ul>

      <p class="adv-para" style="margin-top: 14px;">
        ข้อมูลและข้อคิดเห็นของท่านจะถูกนำไปใช้เพื่อยกระดับคุณภาพของเครื่องมือและการปฏิบัติงานด้านความมั่นคงปลอดภัยไซเบอร์ ทางทีมงานขอขอบพระคุณในความร่วมมือเป็นอย่างยิ่ง
      </p>

      <div class="sheet-footer no-print">
        <div class="sheet-footer-line"></div>
        <div class="sheet-footer-row">
          <div class="sheet-footer-left">รายงานประเมินความมั่นคงปลอดภัยไซเบอร์</div>
          <div class="sheet-footer-center">TLP:AMBER ●</div>
          <div class="sheet-footer-right">4 | P a g e</div>
        </div>
      </div>
    </div>

  </div>

</body>
</html>
"""
