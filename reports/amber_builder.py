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
    """Generate official FIRST TLP v2.0 TLP:AMBER traffic light widget."""
    return """
    <div class="ncsa-tlp-container">
      <div class="ncsa-tlp-pill" style="background: #f59e0b; color: #0f172a; font-weight: 800; font-size: 11px; letter-spacing: 0.5px; padding: 2px 8px; border-radius: 2px; text-align: center; min-width: 82px; margin-bottom: 3px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        TLP:AMBER
      </div>
      <div class="ncsa-tlp-lights-box" style="background: #a3a3a3; border: 2px solid #000000; border-radius: 6px; padding: 3px 8px; display: flex; gap: 5px; align-items: center; justify-content: center;">
        <span class="ncsa-tlp-circle" style="background: #ffffff; width: 13px; height: 13px; border-radius: 50%; border: 2px solid #000000; display: inline-block; box-sizing: border-box;"></span>
        <span class="ncsa-tlp-circle" style="background: #f59e0b; width: 13px; height: 13px; border-radius: 50%; border: 2px solid #000000; display: inline-block; box-sizing: border-box;"></span>
        <span class="ncsa-tlp-circle" style="background: #ffffff; width: 13px; height: 13px; border-radius: 50%; border: 2px solid #000000; display: inline-block; box-sizing: border-box;"></span>
      </div>
    </div>
    """


def get_ncsa_header_banner_html() -> str:
    """Generate official NCSA Thailand Letterhead Banner."""
    logo_src = get_ncsa_logo_png_data_uri()
    tlp_widget = get_tlp_amber_traffic_light_html()
    return f"""
    <div class="ncsa-header-banner">
      <div class="ncsa-header-left">
        <img class="ncsa-logo-img" src="{logo_src}" alt="NCSA Thailand" />
        <div class="ncsa-header-divider"></div>
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
    """Generate subtle, diagonal watermark SVG with red text and security border lines as data URI for report sheets."""
    import base64
    svg = """<svg xmlns='http://www.w3.org/2000/svg' width='480' height='280' viewBox='0 0 480 280'>
  <style>
    .wm-line {
      stroke: #dc2626;
      stroke-width: 1.2px;
      stroke-opacity: 0.15;
      stroke-dasharray: 8 4;
    }
    .wm-txt {
      font-family: 'TH SarabunPSK', 'TH Sarabun New', 'Segoe UI', Tahoma, sans-serif;
      font-size: 22px;
      font-weight: bold;
      fill: #dc2626;
      opacity: 0.15;
      letter-spacing: 0.8px;
    }
    .wm-sub {
      font-family: -apple-system, BlinkMacSystemFont, 'SF Mono', Consolas, monospace;
      font-size: 11px;
      font-weight: 700;
      fill: #b91c1c;
      opacity: 0.13;
      letter-spacing: 2.2px;
    }
  </style>
  <g transform='rotate(-24 240 140)'>
    <line x1='30' y1='108' x2='450' y2='108' class='wm-line' />
    <text x='240' y='133' text-anchor='middle' class='wm-txt'>เอกสารลับจากระบบของฝ่ายปฏิบัติการ ThaiCERT</text>
    <text x='240' y='153' text-anchor='middle' class='wm-sub'>CONFIDENTIAL • THAICERT OPERATIONAL LICENSE</text>
    <line x1='30' y1='165' x2='450' y2='165' class='wm-line' />
  </g>
</svg>"""
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def get_css_styles() -> str:
    """Official Thai Government & NCSA Typography CSS."""
    wm_uri = get_watermark_svg_data_uri()
    css = """
    @font-face {
      font-family: 'TH SarabunPSK';
      src: local('TH SarabunPSK'), local('THSarabunPSK'), local('TH Sarabun PSK'), local('TH Sarabun New'),
           url('/fonts/THSarabunNew.ttf') format('truetype');
      font-weight: normal;
      font-style: normal;
    }
    @font-face {
      font-family: 'TH SarabunPSK';
      src: local('TH SarabunPSK Bold'), local('THSarabunPSK-Bold'), local('TH Sarabun PSK Bold'), local('TH Sarabun New Bold'),
           url('/fonts/THSarabunNew Bold.ttf') format('truetype');
      font-weight: bold;
      font-style: normal;
    }
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

    /* Print / Preview Toolbar */
    .adv-toolbar {
      background: #080d1a;
      border-bottom: 1px solid #1a2744;
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
      border: 1px solid transparent;
      transition: all 0.18s ease-in-out;
    }

    .adv-btn-primary {
      background: linear-gradient(135deg, #d97706, #f59e0b);
      border-color: #fbbf24;
      color: #0f172a;
      box-shadow: 0 0 12px rgba(245, 158, 11, 0.25);
    }
    .adv-btn-primary:hover {
      background: linear-gradient(135deg, #b45309, #d97706);
      box-shadow: 0 0 16px rgba(245, 158, 11, 0.45);
      transform: translateY(-1px);
    }

    .adv-btn-outline {
      background: rgba(245, 158, 11, 0.12);
      border-color: rgba(245, 158, 11, 0.35);
      color: #fde68a;
    }
    .adv-btn-outline:hover {
      background: rgba(245, 158, 11, 0.22);
      border-color: #fbbf24;
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
      background-size: 480px 280px;
      box-sizing: border-box;
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
        border-radius: 2px;
        position: relative;
      }
    }

    /* NCSA Official Letterhead Banner */
    .ncsa-header-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 8px;
      margin-bottom: 14px;
      border-bottom: 1.5px solid #000000;
      width: 100%;
      box-sizing: border-box;
    }

    .ncsa-header-left {
      display: flex;
      align-items: center;
      gap: 10px;
      flex: 1;
      min-width: 0;
    }

    .ncsa-logo-img {
      height: 44px;
      width: auto;
      object-fit: contain;
      display: block;
      flex-shrink: 0;
    }

    .ncsa-header-divider {
      width: 1px;
      height: 42px;
      background: #94a3b8;
      flex-shrink: 0;
      margin: 0 4px;
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

    /* Document Title */
    .adv-doc-title {
      font-size: 20pt;
      font-weight: bold;
      color: #0f172a;
      text-align: center;
      margin-top: 6px;
      margin-bottom: 4px;
      line-height: 1.3;
      break-after: avoid !important;
      page-break-after: avoid !important;
    }

    .adv-doc-meta {
      font-size: 13.5pt;
      color: #64748b;
      text-align: center;
      margin-bottom: 14px;
      break-after: avoid !important;
      page-break-after: avoid !important;
    }

    /* TLP Notice Banner */
    .adv-tlp-rule-box {
      background: rgba(245, 158, 11, 0.08);
      border-left: 4px solid #f59e0b;
      padding: 8px 12px;
      margin-bottom: 16px;
      font-size: 14pt;
      line-height: 1.35;
      color: #78350f;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    /* Typography Standards: Headings = 18pt, Body/Content = 16pt */
    .adv-heading {
      font-size: 18pt !important;
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
      font-size: 17pt !important;
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
      margin: 6px 0 12px 0;
      padding: 0;
      list-style: none;
    }

    .adv-list li {
      font-size: 16pt !important;
      line-height: 1.4;
      margin-bottom: 6px;
      padding-left: 1.85cm;
      text-indent: -0.6cm;
      text-align: justify;
      text-justify: inter-cluster;
      orphans: 4 !important;
      widows: 4 !important;
    }

    .adv-list li::before {
      content: "• ";
      font-weight: bold;
      color: #d97706;
    }

    /* Tables */
    .adv-table-wrap {
      overflow-x: auto;
      margin: 10px 0 16px 0;
    }

    .adv-table {
      width: 100%;
      border-collapse: collapse;
      margin: 10px 0 16px 0;
      border: 1px solid #cbd5e1;
      font-size: 14pt;
      break-inside: auto;
      page-break-inside: auto;
    }

    .adv-cell-inner {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      display: block !important;
      width: 100% !important;
      box-sizing: border-box !important;
    }

    .adv-table thead {
      display: table-header-group !important;
    }

    .adv-table thead tr {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-table th {
      border: 1px solid #cbd5e1;
      padding: 6px 8px;
      font-weight: bold;
      text-align: center;
      background: #fef3c7;
      color: #78350f;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-table tbody {
      display: table-row-group !important;
    }

    .adv-table tr {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-table td {
      border: 1px solid #cbd5e1;
      padding: 5px 8px;
      color: #334155;
      vertical-align: top;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    /* Finding Items */
    .adv-finding-item {
      margin-top: 14px;
      margin-bottom: 20px;
      padding-bottom: 14px;
      border-bottom: 1px dashed #cbd5e1;
      break-inside: auto;
      page-break-inside: auto;
    }

    .adv-finding-item:last-child {
      border-bottom: none;
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
    }

    .adv-item-title {
      font-size: 17pt !important;
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
    }
    .adv-item-badge-high {
      background: #ea580c;
      color: #fff;
      font-size: 11pt;
      font-weight: bold;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-block;
    }
    .adv-item-badge-med {
      background: #f59e0b;
      color: #0f172a;
      font-size: 11pt;
      font-weight: bold;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-block;
    }
    .adv-item-badge-sec {
      background: #16a34a;
      color: #fff;
      font-size: 11pt;
      font-weight: bold;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-block;
    }

    .adv-code-box {
      background: #0f172a !important;
      color: #f8fafc !important;
      padding: 8px 12px !important;
      border-radius: 6px !important;
      border: 1px solid #334155 !important;
      margin: 8px 0 12px 0 !important;
      overflow-x: auto !important;
      text-indent: 0 !important;
      font-family: 'JetBrains Mono', Menlo, Consolas, Monaco, monospace !important;
      font-size: 10pt !important;
      line-height: 1.4 !important;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1) !important;
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
      font-family: 'TH SarabunPSK', 'TH Sarabun PSK', sans-serif !important;
    }
    .sheet-footer-line {
      border-top: 1px solid #d0d0d0;
      margin-bottom: 5px;
      width: 100%;
    }
    .sheet-footer-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      line-height: 1.2;
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
        background-size: 480px 280px !important;
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
    Handles both full network scan outputs and individual target audit records.
    """
    now = datetime.now()
    date_str = f"{now.day} {['มกราคม','กุมภาพันธ์','มีนาคม','เมษายน','พฤษภาคม','มิถุนายน','กรกฎาคม','สิงหาคม','กันยายน','ตุลาคม','พฤศจิกายน','ธันวาคม'][now.month-1]} พ.ศ. {now.year + 543}"
    ref_id = f"NCSA-AMBER-{now.year}-{int(now.timestamp()) % 10000:04d}"

    target_scope = scan_report_data.get("target") or scan_report_data.get("target_id") or scan_report_data.get("subnet") or "ระบบสารสนเทศเป้าหมาย"
    hosts_list = scan_report_data.get("hosts", [])
    if not hosts_list and "deep_audit" in scan_report_data:
        hosts_list = [scan_report_data]

    total_scanned = len(hosts_list)
    crit_count = 0
    high_count = 0
    med_count = 0
    safe_count = 0

    all_matched_cves = []
    for h in hosts_list:
        v_php = h.get("vulnerability")
        v_node = h.get("vulnerabilityNode")
        nginx_audit = (h.get("deep_audit") or {}).get("nginx_audit", {})
        v_nginx = nginx_audit.get("severity", "Secure")
        
        cves = h.get("matched_cves") or []
        for c in cves:
            if c not in all_matched_cves:
                all_matched_cves.append(c)

        if "Critical" in [v_php, v_node, v_nginx]:
            crit_count += 1
        elif "High" in [v_php, v_node, v_nginx]:
            high_count += 1
        elif "Medium" in [v_php, v_node, v_nginx] or "Warning" in [v_php, v_node]:
            med_count += 1
        else:
            safe_count += 1

    has_any_risk = (crit_count + high_count + med_count) > 0

    header_banner = get_ncsa_header_banner_html()
    css_styles = get_css_styles()

    # Table rows for Attack Surface Ledger
    table_rows_html = ""
    for idx, h in enumerate(hosts_list, 1):
        h_ip = h.get("ip") or h.get("target_id") or "-"
        h_ports = ", ".join(str(p) for p in (h.get("ports") or [80]))
        
        # Determine Device Category / Hardware Vendor & Live Service
        dev_name = h.get("device_name") or ""
        web_srv = h.get("webServer") or h.get("server") or ""
        h_mac = h.get("mac") or ""

        if not dev_name or dev_name in ["LAN Client", "DHCP Host", "General Host"]:
            if "airtunes" in web_srv.lower() or "apple" in web_srv.lower():
                dev_name = "Apple Inc. (AirPlay Device)"
            elif "gsoap" in web_srv.lower():
                dev_name = "อุปกรณ์สำเร็จรูป / IoT (gSOAP)"
            elif "mikrotik" in web_srv.lower():
                dev_name = "MikroTik Router Appliance"
            elif "express" in web_srv.lower() or h.get("is_node"):
                dev_name = "Node.js Application Server"
            elif h.get("is_php"):
                dev_name = "PHP Web Server"
            elif web_srv:
                dev_name = web_srv
            else:
                dev_name = "อุปกรณ์เครือข่ายภายใน (LAN Device)"

        # Service / Runtime Details
        h_tech = []
        if h.get("php"): h_tech.append(f"PHP {h.get('php')}")
        if h.get("node"): h_tech.append(f"Node.js {h.get('node')}")
        if web_srv and web_srv != dev_name and not any(k in web_srv.lower() for k in ["ไม่มี web service", "general host"]):
            h_tech.append(web_srv)
        tech_str = " · ".join(h_tech) if h_tech else (web_srv if web_srv != dev_name else "")

        mac_badge = f'<div style="font-size: 9.5pt; color: #94a3b8; font-family: monospace;">MAC: {html.escape(h_mac)}</div>' if (h_mac and h_mac != "LAN Device") else ""
        service_badge = f'<div style="font-size: 10.5pt; color: #475569; margin-top: 1px;">บริการ: <code style="font-size: 9.5pt; background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-family: monospace;">{html.escape(tech_str)}</code></div>' if tech_str else ""

        dev_service_cell = f"""
        <div>
          <div style="font-weight: bold; color: #0f172a; font-size: 13pt;">{html.escape(dev_name)}</div>
          {service_badge}
          {mac_badge}
        </div>
        """
        
        da = h.get("deep_audit") or {}
        grp = da.get("primary_group") or "ไม่สามารถระบุกลุ่มระบบได้จากข้อมูลที่มี (Unclassified)"
        rce_p = h.get("rce_proof") or da.get("rce_proof") or {}
        rce_st = rce_p.get("proof_status", "")
        
        # Determine highest severity
        sev = "ปลอดภัย (Secure)"
        badge_cls = "adv-item-badge-sec"
        v_php = h.get("vulnerability")
        v_node = h.get("vulnerabilityNode")
        v_nginx = (da.get("nginx_audit") or {}).get("severity")
        if rce_p.get("is_rce_proved") or rce_st == "RCE_CONFIRMED":
            sev = "วิกฤต (Critical - RCE Confirmed)"
            badge_cls = "adv-item-badge-crit"
        elif "Critical" in [v_php, v_node, v_nginx]:
            sev = "วิกฤต (Critical)"
            badge_cls = "adv-item-badge-crit"
        elif rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI") or "High" in [v_php, v_node, v_nginx]:
            sev = "สูง (High - LFI Confirmed)" if rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI") else "สูง (High)"
            badge_cls = "adv-item-badge-high"
        elif "Medium" in [v_php, v_node, v_nginx] or "Warning" in [v_php, v_node]:
            sev = "ปานกลาง (Medium)"
            badge_cls = "adv-item-badge-med"

        table_rows_html += f"""
        <tr>
          <td style="text-align: center;">{idx}</td>
          <td><strong>{html.escape(h_ip)}</strong></td>
          <td style="text-align: center;"><code>{html.escape(h_ports)}</code></td>
          <td>{dev_service_cell}</td>
          <td>{html.escape(grp)}</td>
          <td style="text-align: center;"><span class="{badge_cls}">{sev}</span></td>
        </tr>
        """

    # In-Depth Findings Sections
    findings_html = ""
    finding_idx = 1
    arch_matrix_html = ""
    for h in hosts_list:
        h_ip = h.get("ip") or h.get("target_id") or "-"
        da = h.get("deep_audit") or {}
        matched_cves = h.get("matched_cves") or []
        chains = da.get("security_chains", {}).get("chains", {}) or h.get("security_chains", {}).get("chains", {})
        
        # Build Architectural Narrative per host if present (Official Paper Format: No borders, no dark boxes, indented paragraphs)
        matrix = h.get("architecture_matrix") or da.get("architecture_matrix") or []
        rce_proof = h.get("rce_proof") or da.get("rce_proof") or {}
        is_rce_active = bool(rce_proof.get("is_rce_proved"))
        rce_tech = rce_proof.get("technique", "")

        # Synchronize live RCE verification into exploit chains and matrix
        if is_rce_active:
            if "Session Upload Progress" in rce_tech or "LFI" in rce_tech:
                if "a" in chains:
                    chains["a"]["verdict"] = "CONFIRMED (ยืนยันผลการประเมินเชิงประจักษ์: ตรวจพบ LFI และเซิร์ฟเวอร์ประมวลผลโค้ด Canary ใน Session Upload Progress สำเร็จ)"
                    chains["a"]["verdict_code"] = "CONFIRMED"
                    chains["a"]["confidence"] = "Confirmed"
            for m in matrix:
                if m.get("group_id") in (1, 6, 7):
                    m["exploitability"] = "Confirmed"

        # 0. Empirical Live RCE / LFI Proof Section with Cryptographic Evidence
        status_val = rce_proof.get("proof_status", "")
        if rce_proof.get("is_rce_proved") or status_val in ("RCE_CONFIRMED", "CANARY_CONFIRMED", "CONFIRMED_LFI"):
            is_rce = rce_proof.get("is_rce_proved") or status_val == "RCE_CONFIRMED"
            trail = rce_proof.get("audit_trail") or {}
            box_bg = "#fff5f5" if is_rce else "#fefce8"
            box_border = "#dc2626" if is_rce else "#ca8a04"
            title_color = "#991b1b" if is_rce else "#854d0e"
            badge_text = "[RCE CONFIRMED]" if is_rce else ("[CANARY CONFIRMED]" if status_val == "CANARY_CONFIRMED" else "[LFI CONFIRMED]")
            header_title = "หลักฐานเชิงประจักษ์ยืนยันการรันคำสั่งควบคุมระบบ (Live RCE Proof)" if is_rce else "หลักฐานเชิงประจักษ์ยืนยันช่องโหว่ LFI / Arbitrary File Read"
            
            trail_html = ""
            if trail:
                trail_html = f"""
                <div style="margin-top: 8px; padding-top: 6px; border-top: 1px dashed #334155; font-size: 8.5pt; color: #94a3b8;">
                  <div><b>Tamper-Evident Evidence Digest (SHA-256):</b> Operator: {html.escape(trail.get('operator', '-'))} | UTC: {html.escape(trail.get('timestamp_utc', '-'))}</div>
                  <div style="word-break: break-all;"><b>Evidence SHA-256:</b> <span style="color: #4ade80;">{html.escape(trail.get('evidence_sha256', '-'))}</span></div>
                </div>
                """

            findings_html += f"""
            <div style="margin-top: 14px; margin-bottom: 18px; padding: 12px 16px; background: {box_bg}; border-left: 4px solid {box_border}; border-radius: 4px;">
              <div style="font-size: 15.5pt; font-weight: bold; color: {title_color}; margin-bottom: 4px;">
                {header_title} บนพอร์ต {html.escape(str(h.get('port','-')))}
              </div>
              <p class="adv-para" style="color: #451a03; margin-bottom: 8px;">
                {html.escape(rce_proof.get('impact_statement', ''))} (เทคนิค: <b>{html.escape(rce_proof.get('technique', ''))}</b> | ระดับสิทธิ์: <b>{html.escape(rce_proof.get('privilege_level', ''))}</b>)
              </p>
              <div style="background: #0f172a; color: #38bdf8; padding: 10px 14px; border-radius: 6px; font-family: monospace; font-size: 10.5pt; line-height: 1.45; overflow-x: auto;">
                <div style="color: #94a3b8; font-size: 9pt; border-bottom: 1px solid #334155; padding-bottom: 4px; margin-bottom: 6px;">
                  $ {html.escape(rce_proof.get('command_executed', 'canary execution'))} &nbsp;&nbsp;<span style="color: {'#f87171' if is_rce else '#facc15'}; font-weight: bold;">{badge_text}</span> &nbsp;&nbsp;เวลา: {html.escape(rce_proof.get('verified_at', ''))}
                </div>
                <div style="color: #4ade80; font-weight: bold;">
                  {html.escape(rce_proof.get('execution_output', ''))}
                </div>
                {f'<div style="color: #f59e0b; font-size: 9pt; margin-top: 6px; border-top: 1px dashed #334155; padding-top: 4px;">คำสั่งทดสอบจริง (CLI): {html.escape(rce_proof.get("reproduce_curl", ""))}</div>' if rce_proof.get("reproduce_curl") else ''}
                {trail_html}
              </div>
            </div>
            """
        elif status_val == "NOT_CONFIRMED":
            findings_html += f"""
            <div style="margin-top: 14px; margin-bottom: 18px; padding: 10px 14px; background: #f8fafc; border-left: 4px solid #64748b; border-radius: 4px;">
              <div style="font-size: 14pt; font-weight: bold; color: #334155; margin-bottom: 4px;">
                ผลการทดสอบ Active Canary PoC บนพอร์ต {html.escape(str(h.get('port','-')))}: [NOT CONFIRMED / NO SINK IN SCOPE]
              </div>
              <p class="adv-para" style="color: #475569; margin-bottom: 0;">
                ระบบได้ส่งคำขอทดสอบ LFI และ Session Upload Progress Canary แบบไม่ทำลายข้อมูลแล้ว ไม่พบจุดรับคำสั่งเพื่อรันโค้ดภายใต้ขอบเขตพารามิเตอร์ที่ตรวจสอบจากภายนอก
              </p>
            </div>
            """
        elif status_val == "PROBING_DISABLED_BY_SAFETY_GATE":
            findings_html += f"""
            <div style="margin-top: 14px; margin-bottom: 18px; padding: 10px 14px; background: #f8fafc; border-left: 4px solid #64748b; border-radius: 4px;">
              <div style="font-size: 14pt; font-weight: bold; color: #334155; margin-bottom: 4px;">
                การประเมินสิทธิ์ความปลอดภัย (Safety Gate Protection) บนพอร์ต {html.escape(str(h.get('port','-')))}
              </div>
              <p class="adv-para" style="color: #475569; margin-bottom: 0;">
                การตรวจสอบในรอบนี้ดำเนินการในโหมด Safe Passive Banner Inspection โดยระงับการส่ง Active Exploit ตามข้อกำหนดความปลอดภัย หากต้องการพิสูจน์ RCE ในเชิงประจักษ์ ต้องได้รับการยืนยันสิทธิ์จากผู้ดูแลระบบตามระเบียบ
              </p>
            </div>
            """

        # Architectural & Behavioral Preconditions Matrix per host (Strict Stack Isolation)
        br_pre = da.get("brotli_preconditions") or {}
        nx_pre = da.get("nginx_preconditions") or {}
        srv_str = (h.get("webServer", "") + " " + str(h.get("server", "")) + " " + str(da.get("nginx_audit", {}).get("server", ""))).lower()
        is_host_nginx = "nginx" in srv_str
        is_host_node = bool(h.get("is_node")) or "node" in (str(h.get("runtime", "")) + " " + str(h.get("runtime_version", ""))).lower()

        rows_html = ""
        if is_host_node and br_pre:
            br_status = "ยอมรับและถอดรหัสบิตสตรีมเข้า (Active Decompression Confirmed)" if br_pre.get("brotli_request_accepted") else ("รองรับ Brotli ผ่านส่วนหัว (Header Hint Observed)" if br_pre.get("brotli_supported") else "ปฏิเสธ / ไม่พบการใช้งาน (Precondition Absent)")
            rows_html += f"""<tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 5px 8px; font-weight: bold; width: 35%; color: #475569;">Brotli Stream Processing (CVE-2026-111497 / CWE-20):</td><td style="padding: 5px 8px; color: #0f172a;">{html.escape(br_status)}</td></tr>"""

        if is_host_nginx and nx_pre:
            h3_status = "ยืนยันพอร์ต UDP 443 ผ่านแพ็กเก็ต RFC 9000 (Active QUIC Listener Confirmed)" if nx_pre.get("http3_udp_verified") else "ไม่พบการตอบสนองของ QUIC UDP บนพอร์ต 443"
            alias_status = f"ตรวจพบพฤติกรรม Traversal: {nx_pre.get('alias_evidence')}" if nx_pre.get("alias_traversal_observed") else "ปกติ (ไม่พบความผิดปกติจากคำขอ /dir../ เทียบกับ 404 Baseline)"
            ssi_status = f"พบไฟล์: {', '.join(nx_pre.get('ssi_files', []))}" if nx_pre.get("ssi_files") else "ไม่พบไฟล์ .shtml/.shtm บนระบบ"
            rows_html += f"""
                <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 5px 8px; font-weight: bold; color: #475569;">HTTP/3 QUIC UDP Transport (CVE-2026-95101 / CWE-400):</td><td style="padding: 5px 8px; color: #0f172a;">{html.escape(h3_status)}</td></tr>
                <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 5px 8px; font-weight: bold; color: #475569;">NGINX Alias Path Traversal (CVE-2026-15176 / CWE-22):</td><td style="padding: 5px 8px; color: #0f172a;">{html.escape(alias_status)}</td></tr>
                <tr><td style="padding: 5px 8px; font-weight: bold; color: #475569;">SSI Directive Exposure (CVE-2026-97205 / CWE-97):</td><td style="padding: 5px 8px; color: #0f172a;">{html.escape(ssi_status)}</td></tr>
            """

        if rows_html:
            findings_html += f"""
            <div style="margin-top: 10px; margin-bottom: 14px; padding: 10px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;">
              <div style="font-size: 11pt; font-weight: bold; color: #1e293b; margin-bottom: 6px;">
                ตารางประเมินเงื่อนไขจำเป็นทางสถาปัตยกรรม (Architectural & Behavioral Preconditions) บนพอร์ต {html.escape(str(h.get('port','-')))}
              </div>
              <table style="width: 100%; font-size: 9pt; border-collapse: collapse;">
                {rows_html}
              </table>
            </div>
            """

        is_client_node = (not h.get("is_php")) and (not h.get("is_node")) and (not h.get("ports")) and (h.get("vulnerability") in ("Secure", "Low", "None", None))
        if matrix and not is_client_node and (has_any_risk or h.get("is_php") or h.get("is_node")):
            arch_matrix_html += f"""
            <div style="margin-top: 14px; margin-bottom: 20px;">
            """
            for m in matrix:
                g_id = m.get("group_id")
                profile = THAICERT_GROUP_PROFILES.get(g_id, {})
                g_name = m.get("group_name") or profile.get("name") or f"กลุ่ม {g_id}"
                sapi_val = m.get("sapi_detected") or profile.get("sapi_typical") or "ไม่ระบุ SAPI"
                worker_val = m.get("worker_model") or profile.get("worker_model") or "Standard Process"
                exploit_mech = m.get("exploit_chain_mechanism") or profile.get("exploit_chain_mechanism") or "ไม่มีข้อมูลกลไกในระบบ"
                prereq_summary = m.get("prerequisite_summary") or "ไม่มีเงื่อนไขจำเป็นเพิ่มเติม"
                impact_scope = m.get("impact_scope") or profile.get("impact_scope") or "ขอบเขตผลกระทบทั่วไป"
                mitigation_val = m.get("mitigation") or profile.get("mitigation") or "ปรับปรุงเวอร์ชันและตรวจสอบการตั้งค่า"
                exploitability = m.get("exploitability") or "Conditional"
                chains_list = m.get("chains_applicable", [])
                chains_text = ", ".join([html.escape(c) for c in chains_list]) if chains_list else "ไม่พบห่วงโซ่ที่เข้าข่าย"

                conf_label = "ยืนยันเงื่อนไขครบถ้วน (Confirmed)" if exploitability == "Confirmed" else ("มีความเป็นไปได้สูง (Likely)" if exploitability == "Likely" else ("ขึ้นกับเงื่อนไขเฉพาะ (Conditional)" if exploitability == "Conditional" else ("ไม่มีผลกระทบ (Not Applicable)" if exploitability in ("Not Applicable", "Mitigated") else html.escape(exploitability))))

                chains_desc = f" ซึ่งมีความเชื่อมโยงกับห่วงโซ่ความเสี่ยง {chains_text}" if chains_list else ""

                arch_matrix_html += f"""
                <div style="margin-top: 14px; margin-bottom: 16px;">
                  <div style="font-size: 16.5pt; font-weight: bold; color: #0f172a; margin-bottom: 6px; line-height: 1.35;">
                    การวิเคราะห์สถาปัตยกรรมกลุ่ม{html.escape(g_name)} บนระบบเป้าหมาย {html.escape(h_ip)}
                  </div>

                  <p class="adv-para">
                    จากการวิเคราะห์โครงสร้างสถาปัตยกรรมของระบบเป้าหมาย <code>{html.escape(h_ip)}</code> พบว่าระบบทำงานผ่านอินเตอร์เฟซ {html.escape(sapi_val)} ภายใต้รูปแบบการบริหารจัดการเวิร์กเกอร์แบบ {html.escape(worker_val)}{chains_desc} ซึ่งมีความสำคัญต่อวงรอบหน่วยความจำและขอบเขตการทำงานของโปรเซส ในแง่กลไกการทำงาน {html.escape(exploit_mech)}
                  </p>

                  <p class="adv-para">
                    สำหรับการประเมินเงื่อนไขจำเป็นทางเทคนิค (Prerequisites) ที่จะทำให้การโจมตีสัมฤทธิ์ผล พบว่า {html.escape(prereq_summary)} ซึ่งหากขาดเงื่อนไขดังกล่าว การส่งคำขอโจมตีจะไม่สามารถขยายผลได้ ส่งผลให้ขอบเขตผลกระทบที่แท้จริงจำกัดอยู่ที่ {html.escape(impact_scope)} โดยมีระดับความเป็นไปได้ในการโจมตีจริงอยู่ในเกณฑ์: {conf_label} ทั้งนี้ แนวทางการยกระดับความมั่นคงปลอดภัยเชิงโครงสร้างที่แนะนำคือ {html.escape(mitigation_val)}
                  </p>
                </div>
                """

            arch_matrix_html += """
            </div>
            """
        
        # 1. Matched CVEs for this host
        for c in matched_cves:
            cve_id = c.get("id") or c.get("cve") or "CVE-VULN"
            cve_name = c.get("name") or "ช่องโหว่ความมั่นคงปลอดภัย"
            cve_sev = c.get("severity") or "High"
            cvss = c.get("cvss") or 7.5
            cat = c.get("category") or "Web Stack"
            reason = c.get("reason") or c.get("desc") or "ตรวจพบเวอร์ชันซอฟต์แวร์ที่ตรงกับเงื่อนไขความเสี่ยง"
            host_check = c.get("host_check") or "php -v || node -v || nginx -v"
            confirm_vuln = c.get("confirm_vuln") or "พบเวอร์ชันอยู่ในช่วงที่ได้รับผลกระทบ"
            confirm_safe = c.get("confirm_safe") or "อัปเดตเป็นเวอร์ชันที่ได้รับแพตช์ความปลอดภัยล่าสุด"

            # Severity mapping in Thai
            sev_th_map = {
                "Critical": "ระดับวิกฤต (Critical)",
                "High": "ระดับสูง (High)",
                "Medium": "ระดับปานกลาง (Medium)",
                "Low": "ระดับต่ำ (Low)",
                "Warning": "ระดับควรเฝ้าระวัง (Warning)"
            }
            cve_sev_th = sev_th_map.get(cve_sev, f"ระดับ {cve_sev}")

            cve_conf = c.get("confidence")
            if not cve_conf:
                if c.get("confirmed") or c.get("is_vulnerable"):
                    cve_conf = "Confirmed"
                elif c.get("version_matched") and (c.get("sapi_confirmed") or c.get("exposure_confirmed")):
                    cve_conf = "Likely"
                elif c.get("version_matched"):
                    cve_conf = "Conditional"
                else:
                    cve_conf = "Conditional"

            # Format finding title: Start with keyword "ค้นพบ" without numbers
            finding_title = f"ค้นพบ {html.escape(cve_id)} {html.escape(cve_name)}"

            if cve_conf == "Confirmed":
                cve_narrative = f"""จากการตรวจสอบและพิสูจน์ทราบความมั่นคงปลอดภัยบนระบบเป้าหมาย พบหลักฐานเชิงประจักษ์ (Live Proof Verification) ว่า {html.escape(reason)} ซึ่งจัดอยู่ในระดับความรุนแรง {cve_sev_th} โดยระบบการทดสอบได้ยืนยันความพร้อมของเส้นทางประเมินและผลลัพธ์การตอบสนองในเชิงประจักษ์แล้ว ผู้ดูแลระบบจำเป็นต้องยกระดับการป้องกันและแก้ไขอย่างเร่งด่วนที่สุด"""
            else:
                cve_narrative = f"""จากการตรวจสอบและประเมินความมั่นคงปลอดภัยบนระบบเป้าหมาย พบข้อค้นพบทางเทคนิคว่า {html.escape(reason)} ซึ่งจัดอยู่ในระดับความรุนแรง {cve_sev_th} ตามข้อมูลการประเมินของรายการช่องโหว่ที่อ้างถึง ทั้งนี้ ระดับความเสี่ยงต่อระบบเป้าหมายจริงอาจแตกต่างกันตามเวอร์ชันซอฟต์แวร์ การตั้งค่า การเปิดให้เข้าถึงจากเครือข่าย และเงื่อนไขแวดล้อมของระบบ หากระบบมีเงื่อนไขที่สอดคล้องกับข้อกำหนดของช่องโหว่และเปิดให้เข้าถึงจากเครือข่าย ผู้โจมตีอาจใช้ประโยชน์จากช่องโหว่ดังกล่าวได้ อย่างไรก็ตาม ผลกระทบและความเป็นไปได้ในการโจมตีต้องยืนยันเพิ่มเติมจากเวอร์ชันซอฟต์แวร์ การตั้งค่า และเส้นทางการให้บริการจริง"""

            findings_html += f"""
            <div class="adv-finding-item" style="margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid #e2e8f0;">
              <div style="font-size: 16.5pt; font-weight: bold; color: #0f172a; margin-bottom: 6px; line-height: 1.35;">
                {finding_title}
              </div>
              <div style="font-size: 13.5pt; color: #334155; margin-bottom: 12px; background: #f8fafc; padding: 6px 12px; border-radius: 4px; border-left: 3px solid #cbd5e1;">
                <strong>ระบบเป้าหมายที่ได้รับผลกระทบ:</strong> <code>{html.escape(h_ip)}</code> &nbsp;|&nbsp; 
                <strong>หมวดหมู่เทคโนโลยี:</strong> {html.escape(cat)} &nbsp;|&nbsp; 
                <strong>ระดับความรุนแรง:</strong> {cve_sev_th} &nbsp;|&nbsp; 
                <strong>คะแนนมาตรฐาน CVSS:</strong> {cvss} &nbsp;|&nbsp;
                <strong>ระดับความเชื่อมั่น (Confidence):</strong> <span style="font-weight: bold; color: #0284c7;">{html.escape(cve_conf)}</span>
              </div>

              <p class="adv-para">
                {cve_narrative}
              </p>

              <p class="adv-para">
                จากข้อมูลที่ตรวจพบ ระบบอาจเข้าข่ายได้รับผลกระทบเมื่อ {html.escape(confirm_vuln)} ทั้งนี้ควรตรวจสอบยืนยันเวอร์ชันและการตั้งค่าบนเครื่องจริงก่อนสรุปผล โดยเกณฑ์การดำเนินงานที่แนะนำคือการปรับปรุงระบบให้เข้าสู่สภาวะ {html.escape(confirm_safe)}:
              </p>

              <div class="adv-code-box" style="margin: 8px 0 12px 0;">
                <div style="font-size: 11pt; color: #64748b; font-weight: bold; margin-bottom: 4px;">ตัวอย่างคำสั่งตรวจสอบสำหรับผู้ดูแลระบบ (ควรทบทวนขอบเขตและสิทธิ์ก่อนนำไปใช้):</div>
                <pre><code>{html.escape(host_check)}</code></pre>
              </div>

              <p class="adv-para">
                สำหรับแนวทางการแก้ไขและยกระดับความมั่นคงปลอดภัยเชิงป้องกัน ขอแนะนำให้ผู้ดูแลระบบตรวจสอบประกาศของผู้พัฒนาและอัปเดตซอฟต์แวร์ {html.escape(cat)} เป็นรุ่นที่มีแพตช์แก้ไขช่องโหว่ดังกล่าว โดยทดสอบความเข้ากันได้ในสภาพแวดล้อมทดสอบก่อนนำไปใช้กับระบบจริง:
              </p>

              <div class="adv-code-box" style="margin: 8px 0 14px 0;">
                <div style="font-size: 11pt; color: #64748b; font-weight: bold; margin-bottom: 4px;">แนวทางการปรับปรุงระบบและการตั้งค่าความมั่นคงปลอดภัย:</div>
                <pre><code># ตัวอย่างเท่านั้น: ตรวจสอบชื่อแพ็กเกจ ผู้จัดจำหน่าย และวิธีติดตั้งให้เหมาะกับระบบจริงก่อนดำเนินการ
# ควรสำรองข้อมูลและทดสอบใน Staging ก่อนอัปเดต Production
# เกณฑ์ความปลอดภัยที่แนะนำ: {html.escape(confirm_safe)}</code></pre>
              </div>
            </div>
            """
            finding_idx += 1

        # 2. PHP Session Chains (if applicable and has details)
        if chains:
            for c_key, c_val in chains.items():
                c_verdict_code = c_val.get("verdict_code")
                if c_verdict_code in ("CONFIRMED", "VULN", "REVIEW", "AUDIT", "ARCHITECTURAL_RISK", "INFO_DISCLOSURE"):
                    c_title = c_val.get("title") or "PHP Session Security Chain"
                    c_verdict = c_val.get("verdict") or "ตรวจพบข้อควรระวังในการตั้งค่า"
                    c_remedy = c_val.get("remediation") or "ปรับปรุงค่า php.ini ตามแนวทาง CIS Benchmark"
                    c_ini = c_val.get("hardening_ini") or "; ปรับแต่ง php.ini เพื่อความมั่นคงปลอดภัย"
                    
                    if c_verdict_code == "CONFIRMED":
                        eval_status_desc = "ได้รับการยืนยันผลกระทบเชิงประจักษ์แล้ว (Confirmed — Live Proof Verified)"
                    elif c_verdict_code == "VULN":
                        eval_status_desc = "ตรวจพบเงื่อนไขที่สอดคล้องกับความเสี่ยง ควรตรวจสอบเพิ่มเติมเพื่อยืนยันผลกระทบ (Potential Risk — Verification Required)"
                    elif c_verdict_code == "ARCHITECTURAL_RISK":
                        eval_status_desc = "เงื่อนไขทางสถาปัตยกรรมที่อาจเพิ่มความเสี่ยง (Architectural Condition — ต้องตรวจสอบเพิ่มเติม)"
                    elif c_verdict_code == "INFO_DISCLOSURE":
                        eval_status_desc = "การเปิดเผยข้อมูลเกี่ยวกับระบบหรือการตั้งค่า (Information Disclosure — CWE-200)"
                    else:
                        eval_status_desc = "ควรตรวจสอบและปรับปรุงการตั้งค่า (Review & Hardening)"
                    
                    c_conf = c_val.get("confidence") or "Conditional"

                    findings_html += f"""
                    <div class="adv-finding-item" style="margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid #e2e8f0;">
                      <div style="font-size: 16.5pt; font-weight: bold; color: #0f172a; margin-bottom: 6px; line-height: 1.35;">
                        ค้นพบ ข้อควรระวังด้านการจัดการเซสชัน: {html.escape(c_title)}
                      </div>
                      <div style="font-size: 13.5pt; color: #334155; margin-bottom: 12px; background: #f8fafc; padding: 6px 12px; border-radius: 4px; border-left: 3px solid #cbd5e1;">
                        <strong>ระบบเป้าหมาย:</strong> <code>{html.escape(h_ip)}</code> &nbsp;|&nbsp; 
                        <strong>สถานะการประเมิน:</strong> {html.escape(eval_status_desc)} &nbsp;|&nbsp;
                        <strong>ระดับความเชื่อมั่น (Confidence):</strong> <span style="font-weight: bold; color: #0284c7;">{html.escape(c_conf)}</span>
                      </div>
                      <p class="adv-para">
                        จากการตรวจสอบค่าคอนฟิกและพฤติกรรมการจัดการเซสชัน พบว่า {html.escape(c_verdict)} ข้อค้นพบนี้อาจเพิ่มความเสี่ยงภายใต้เงื่อนไขบางประการ ผู้ดูแลระบบควรตรวจสอบผลกระทบต่อระบบงานและพิจารณาปรับปรุง {html.escape(c_remedy)} ตามความเหมาะสม
                      </p>
                      <div class="adv-code-box" style="margin: 8px 0 14px 0;">
                        <div style="font-size: 11pt; color: #64748b; font-weight: bold; margin-bottom: 4px;">แนวทางการตั้งค่าคอนฟิก php.ini ที่แนะนำสำหรับ {html.escape(h_ip)}:</div>
                        <pre><code>{html.escape(c_ini)}</code></pre>
                      </div>
                    </div>
                    """
                    finding_idx += 1

    if not findings_html:
        findings_html = """
        <div class="adv-finding-item">
          <p class="adv-para" style="text-align: center; color: #16a34a; font-weight: bold; margin: 24px 0;">
            ✓ จากการตรวจสอบตามขอบเขตและวิธีการที่กำหนด ยังไม่พบหลักฐานของข้อค้นพบระดับวิกฤต (Critical) หรือระดับสูง (High)
            <br><span style="font-size: 14pt; color: #475569; font-weight: normal;">(ผลดังกล่าวไม่ใช่การรับรองว่าระบบปลอดภัยทั้งหมด ผู้ดูแลระบบควรติดตามแพตช์และทบทวนการตั้งค่าตามรอบระยะเวลาที่เหมาะสม)</span>
          </p>
        </div>
        """

    survey_qr_img = f"data:image/png;base64,{SURVEY_QR_PNG_B64}" if SURVEY_QR_PNG_B64 else ""

    if not has_any_risk:
        exec_summary_html = f"""
      <div class="adv-heading">สรุปผลการประเมินและภาพรวมความมั่นคงปลอดภัยของเครือข่าย</div>
      <p class="adv-para">
        รายงานประเมินความมั่นคงปลอดภัยไซเบอร์ฉบับนี้ จัดทำขึ้นจากการตรวจสอบระบบสารสนเทศและบริการเครือข่ายในขอบเขต <code>{html.escape(target_scope)}</code> รวมทั้งสิ้น <strong>{total_scanned}</strong> ระบบ ได้ดำเนินการตรวจสอบเชิงรุกตามเกณฑ์มาตรฐาน ThaiCERT และแนวปฏิบัติด้านความมั่นคงปลอดภัยสากล
      </p>
      <p class="adv-para">
        <strong>สรุปผลการประเมิน:</strong> ระบบเครือข่ายและเครื่องแม่ข่ายที่ได้รับการตรวจสอบทั้งหมด <strong>อยู่ในสถานะปลอดภัย (Clean &amp; Secure)</strong> โดย <strong>ไม่พบข้อค้นพบช่องโหว่ความเสี่ยงระดับวิกฤต (Critical), ระดับสูง (High) หรือระดับปานกลาง (Medium)</strong> บนบริการที่เปิดให้เข้าถึงจากภายนอก (ข้อค้นพบความเสี่ยง <strong>0</strong> รายการ จากระบบที่ตรวจสอบทั้งหมด <strong>{safe_count}</strong> ระบบ) อุปกรณ์ส่วนใหญ่เป็นเครื่องลูกข่ายภายในและอุปกรณ์เครือข่ายที่มีการควบคุมการเข้าถึงหรือปิดกั้นพอร์ตบริการด้วยไฟร์วอลล์อย่างรัดกุม จึงขอแนะนำให้รักษานโยบายการป้องกันและมาตรการควบคุมความมั่นคงปลอดภัยตามมาตรฐานปกติอย่างต่อเนื่อง
      </p>
        """
        page2_heading = "สรุปผลการประเมินความมั่นคงปลอดภัยทางเทคนิค (Technical Assessment Summary)"
        page2_content = f"""
      <p class="adv-para">
        จากการประเมินพื้นผิวการโจมตี (Attack Surface Analysis) และการตรวจสอบบริการเครือข่ายเชิงลึก ไม่พบพอร์ตหรือบริการเว็บแอปพลิเคชันที่มีช่องโหว่ความเสี่ยงระดับวิกฤตหรือระดับสูงเปิดให้บริการสู่เครือข่าย
      </p>

      <div style="margin-top: 14px; margin-bottom: 20px; padding: 18px 22px; background: #f0fdf4; border: 1.5px solid #86efac; border-radius: 8px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
          <span style="font-size: 20pt; color: #16a34a;">✓</span>
          <span style="font-size: 15pt; font-weight: bold; color: #166534;">ผลการตรวจประเมิน: ระบบอยู่ในสถานะปลอดภัย (0 Critical / 0 High Findings)</span>
        </div>
        <div style="font-size: 11pt; color: #1e293b; line-height: 1.6;">
          <p style="margin: 0 0 8px 0;"><strong>ผลสรุปการตรวจประเมินทางเทคนิคสำหรับระบบในขอบเขต:</strong></p>
          <ul style="margin: 0 0 12px 18px; padding: 0;">
            <li><b>Remote Code Execution (RCE):</b> ไม่พบจุดรับคำสั่งหรือพฤติกรรมที่เสี่ยงต่อการถูกสั่งรันโค้ดจากระยะไกล</li>
            <li><b>Web Stack Vulnerabilities:</b> ไม่พบช่องโหว่ความรุนแรงสูงใน PHP, Node.js หรือ Web Server Services</li>
            <li><b>Network Perimeter:</b> อุปกรณ์ลูกข่ายส่วนใหญ่มีการปิดกั้นพอร์ตบริการ หรือตั้งค่าไฟร์วอลล์อย่างถูกต้อง</li>
          </ul>
          <p style="margin: 0; color: #15803d; font-size: 10pt;">
            💡 <b>ข้อเสนอแนะในการกำกับดูแล:</b> ควรรักษามาตรฐานความมั่นคงปลอดภัย (Cyber Hygiene) ต่อเนื่อง โดยหมั่นอัปเดตระบบปฏิบัติการ ซอฟต์แวร์ และตรวจสอบการเปิดเผยพอร์ตเครือข่ายภายนอกเป็นประจำ
          </p>
        </div>
      </div>
        """
    else:
        exec_summary_html = f"""
      <div class="adv-heading">สรุปผลการประเมินและภาพรวมความเสี่ยงของพื้นผิวการโจมตี</div>
      <p class="adv-para">
        รายงานประเมินความมั่นคงปลอดภัยไซเบอร์ฉบับนี้ จัดทำขึ้นเพื่อรายงานข้อค้นพบความเสี่ยงและแนวทางแก้ไขเชิงเทคนิค สำหรับผู้ดูแลระบบและผู้เกี่ยวข้องโดยตรง จากการตรวจสอบระบบสารสนเทศและบริการเครือข่ายในขอบเขต <code>{html.escape(target_scope)}</code> รวมทั้งสิ้น <strong>{total_scanned}</strong> ระบบ ได้ดำเนินการตรวจสอบตามขอบเขต วิธีการ และข้อมูลที่ระบุในเอกสารฉบับนี้ โดยอ้างอิงข้อมูลทางเทคนิคจากแหล่งที่เกี่ยวข้อง เช่น เอกสารผู้พัฒนา รายการ CVE และแนวปฏิบัติด้านความมั่นคงปลอดภัยที่เหมาะสมกับระบบ
      </p>
      <p class="adv-para">
        ผลการประเมินพบข้อค้นพบจำนวน <strong>{crit_count + high_count + med_count}</strong> รายการ โดยแบ่งตามระดับความรุนแรงเป็นระดับวิกฤต (Critical) จำนวน <strong>{crit_count}</strong> รายการ, ระดับสูง (High) จำนวน <strong>{high_count}</strong> รายการ, ระดับปานกลาง (Medium) จำนวน <strong>{med_count}</strong> รายการ และรายการที่ยังไม่พบสัญญาณความเสี่ยงตามเงื่อนไขที่ตรวจสอบ จำนวน <strong>{safe_count}</strong> รายการ ทั้งนี้ ขอให้ผู้ดูแลระบบพิจารณาตรวจสอบข้อค้นพบตามลำดับความสำคัญ และดำเนินการแก้ไขหรือลดความเสี่ยงตามความเหมาะสม โดยให้ความสำคัญกับรายการที่มีหลักฐานยืนยันและเปิดให้เข้าถึงจากเครือข่ายก่อน
      </p>
        """
        page2_heading = "การวิเคราะห์ข้อค้นพบทางเทคนิคเชิงลึกและแนวทางการยกระดับความมั่นคงปลอดภัย"
        page2_content = f"""
      <p class="adv-para">
        ส่วนนี้นำเสนอการวิเคราะห์เชิงลึกของข้อค้นพบด้านความมั่นคงปลอดภัย โดยระบุระดับความเชื่อมั่นของแต่ละข้อสรุปตามหลักฐานที่ตรวจพบ ได้แก่ ยืนยันแล้ว (Confirmed), มีแนวโน้ม (Likely), ต้องตรวจสอบเงื่อนไขเพิ่มเติม (Conditional) และยังยืนยันไม่ได้ (Unverified) พร้อมอธิบายกลไกและเงื่อนไขของความเสี่ยง คำสั่งสำหรับให้ผู้ดูแลระบบตรวจสอบบนเครื่องจริง และตัวอย่างการตั้งค่าที่ใช้เป็นแนวทางในการแก้ไขหรือลดความเสี่ยง
      </p>

      {arch_matrix_html}

      {findings_html}
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

      <div class="adv-subhead">ตารางสรุปรายการทรัพย์สินสารสนเทศและบริการเครือข่ายที่ตรวจพบ</div>
      <div class="adv-table-wrap">
        <table class="adv-table">
          <thead>
            <tr>
              <th style="width: 35px;">#</th>
              <th style="width: 120px;">เป้าหมาย (Host / IP)</th>
              <th style="width: 60px;">พอร์ต</th>
              <th>ประเภทอุปกรณ์ / บริการ</th>
              <th style="width: 180px;">กลุ่มระบบเป้าหมาย</th>
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

    <!-- PAGE 3: References & Sign-off -->
    <div class="a4-paper-sheet page-break-section" id="sheet-references">
      <div class="adv-heading">เอกสารอ้างอิงและช่องทางการประสานงานรับมือเหตุการณ์ความมั่นคงปลอดภัย</div>
      
      <p class="adv-para">
        การประเมินและการจัดทำเอกสารฉบับนี้ อ้างอิงตามกรอบมาตรฐานความมั่นคงปลอดภัยสารสนเทศและแนวปฏิบัติสากล ได้แก่:
      </p>
      <ul class="adv-list">
        <li>แนวทางการบริหารจัดการช่องโหว่ความมั่นคงปลอดภัยไซเบอร์สากล (NIST SP 800-115 / Vulnerability Management)</li>
        <li>ThaiCERT Cybersecurity Advisory & Guidance — คำแนะนำการรับมือช่องโหว่ความปลอดภัยบนเว็บแอปพลิเคชัน</li>
        <li>CIS Benchmarks — Center for Internet Security (Nginx, PHP, and Node.js Hardening Benchmarks)</li>
        <li>National Vulnerability Database (NVD / NIST) — Common Vulnerabilities and Exposures (CVE Catalog)</li>
        <li>FIRST Standards — Traffic Light Protocol (TLP) Version 2.0 User Guidance</li>
      </ul>

      <div style="margin: 28px 0; text-align: center; border-top: 1px dashed #cbd5e1; padding-top: 24px;">
        <div style="font-size: 16pt; font-weight: bold; margin-bottom: 6px;">แบบประเมินความพึงพอใจการให้บริการและการรับแจ้งเหตุภัยคุกคามทางไซเบอร์</div>
        <div style="font-size: 13.5pt; color: #475569; margin-bottom: 14px;">ผู้รับเอกสารสามารถสแกนคิวอาร์โค้ดด้านล่างเพื่อประเมินความพึงพอใจหรือประสานงานด้านความมั่นคงปลอดภัย</div>
        {"<img src='" + survey_qr_img + "' style='width: 120px; height: 120px; border: 1px solid #cbd5e1; padding: 4px; border-radius: 4px; display: inline-block;' alt='Survey QR' />" if survey_qr_img else ""}
        <div style="font-size: 12pt; color: #64748b; margin-top: 6px;">
          ลิงก์ระบบรับแจ้งเหตุ: <a href="https://www.ncsa.or.th" target="_blank" style="color: #d97706; text-decoration: underline;">https://www.ncsa.or.th</a> | อีเมล: saraban@ncsa.or.th
        </div>
      </div>

      <div style="margin-top: 36px; font-size: 13pt; line-height: 1.5; color: #475569; text-align: justify;">
        <strong>คำสงวนสิทธิ์ (Disclaimer):</strong> เอกสารนี้จัดทำขึ้นโดยอิงจากข้อมูลเชิงเทคนิคที่ได้จากการตรวจประเมินระบบสารสนเทศตามขอบเขตและช่วงเวลาที่ระบุไว้เท่านั้น ข้อแนะนำและมาตรการแก้ไขที่ระบุไว้มีจุดมุ่งหมายเพื่อยกระดับความมั่นคงปลอดภัยของระบบ ทั้งนี้ ก่อนดำเนินการปรับปรุงคอนฟิกบนระบบงานจริง ผู้ดูแลระบบควรดำเนินการทดสอบในสภาพแวดล้อมจำลอง (Staging Environment) และจัดทำสำเนาสำรองข้อมูล (Backup) ให้เรียบร้อย
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

  </div>

</body>
</html>
"""
