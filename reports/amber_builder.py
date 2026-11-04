"""
TLP:AMBER Security Advisory Builder - Evidence-based Assessment Format
Produces standardized A4 security advisories in HTML,
complying with FIRST TLP, 18pt/16pt typography,
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

try:
    from core.database import NGINX_CVE_DESCS, CVE_DATABASE
    _CVE_DB_MAP = {x["id"]: x for x in CVE_DATABASE}
except Exception:
    NGINX_CVE_DESCS = {}
    CVE_DATABASE = []
    _CVE_DB_MAP = {}


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
    """Generate official FIRST TLP TLP:AMBER traffic light widget using vector SVG."""
    return """
    <div class="ncsa-tlp-container" style="display: flex; flex-direction: column; align-items: flex-end;">
      <div class="ncsa-tlp-pill" style="background: #f59e0b; color: #0f172a; font-weight: bold; font-size: 11pt; letter-spacing: 0.5px; padding: 2px 10px; border-radius: 3px; text-align: center; min-width: 82px; margin-bottom: 3px;">
        TLP:AMBER
      </div>
      <div style="background: #334155; border-radius: 4px; padding: 3px 6px; display: inline-flex; align-items: center; justify-content: center;">
        <svg width="44" height="12" viewBox="0 0 44 12" fill="none" xmlns="http://www.w3.org/2000/svg" style="display: block;">
          <circle cx="8" cy="6" r="4.5" fill="#64748b"/>
          <circle cx="22" cy="6" r="4.5" fill="#f59e0b"/>
          <circle cx="36" cy="6" r="4.5" fill="#64748b"/>
        </svg>
      </div>
      <div style="font-size: 12pt; color: #64748b; margin-top: 2px;">
        จำกัดการเผยแพร่ตามหลัก Need-to-know
      </div>
    </div>
    """


def get_ncsa_header_banner_html() -> str:
    """Generate official NCSA Thailand Letterhead Banner without backgrounds or borders."""
    logo_src = get_ncsa_logo_png_data_uri()
    tlp_widget = get_tlp_amber_traffic_light_html()
    return f"""
    <div class="ncsa-header-banner">
      <div class="ncsa-header-left">
        <img class="ncsa-logo-img" src="{logo_src}" alt="NCSA Thailand" />
        <div class="ncsa-header-text">
          <div class="ncsa-agency-name">รายงานประเมินความมั่นคงปลอดภัยไซเบอร์ (อ้างอิงแนวทาง TLP:AMBER)</div>
          <div class="ncsa-agency-addr">Cybersecurity Technical Assessment Report | อ้างอิงแนวทาง FIRST TLP และกรอบการประเมินเชิงเทคนิค</div>
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
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif;
      font-size: 22px;
      font-weight: bold;
      fill: #dc2626;
      opacity: 0.05;
      letter-spacing: 1.2px;
    }
    .wm-sub {
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif;
      font-size: 12px;
      font-weight: normal;
      fill: #b91c1c;
      opacity: 0.04;
      letter-spacing: 2px;
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
    """Official Thai Government & NCSA Typography CSS with Unified Font, NO BOLD on body/content, and NO BACKGROUND COLORS."""
    wm_uri = get_watermark_svg_data_uri()
    css = """
    @font-face {
      font-family: 'TH Sarabun PSK';
      src: local('TH SarabunPSK'), local('THSarabunPSK'), local('TH Sarabun PSK'), local('TH Sarabun New'), local('Sarabun'),
           url('/fonts/THSarabunNew.ttf') format('truetype');
      font-weight: normal;
      font-style: normal;
    }
    @font-face {
      font-family: 'TH Sarabun PSK';
      src: local('TH SarabunPSK Bold'), local('THSarabunPSK-Bold'), local('TH Sarabun PSK Bold'), local('TH Sarabun New Bold'), local('Sarabun Bold'),
           url('/fonts/THSarabunNew Bold.ttf') format('truetype');
      font-weight: bold;
      font-style: normal;
    }

    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif !important;
    }

    body {
      background: #0b101b;
      margin: 0;
      padding: 0;
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif !important;
      color: #000;
    }

    /* Strict Font Uniformity: Apply identical Thai Sarabun font across ALL elements */
    table, th, td, div, span, p, a, code, pre, ul, li, label, strong, b, input, button {
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif !important;
    }

    /* Strict Bold Control: If not a heading, DO NOT use bold */
    b, strong {
      font-weight: normal !important;
    }

    /* Only headings are allowed to be bold */
    .adv-doc-title,
    .adv-heading,
    .adv-subhead,
    .adv-device-title,
    .adv-port-title,
    .adv-item-title {
      font-weight: bold !important;
    }

    /* Strictly NO BACKGROUND COLOR across all document containers */
    .adv-table,
    .adv-table thead,
    .adv-table tbody,
    .adv-table tr,
    .adv-table th,
    .adv-table td,
    .adv-tlp-rule-box,
    .adv-device-block,
    .adv-finding-item,
    .adv-code-box,
    .adv-code-box pre,
    .adv-card,
    .adv-section-box,
    .adv-item-badge-crit,
    .adv-item-badge-high,
    .adv-item-badge-med,
    .adv-item-badge-sec {
      background: transparent !important;
      background-color: transparent !important;
    }

    /* Print / Preview Toolbar (no-print) */
    .adv-toolbar {
      background: #080d1a !important;
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
      font-size: 14px;
    }

    .adv-toolbar-title {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: normal;
      color: #eaf6ff;
    }

    .adv-toolbar-badge {
      background: #f59e0b !important;
      color: #0f172a;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 12px;
      letter-spacing: 0.5px;
    }

    .adv-toolbar-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    .adv-btn {
      padding: 6px 14px;
      border-radius: 7px;
      font-size: 13px;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: none;
      transition: all 0.18s ease-in-out;
    }

    .adv-btn-primary {
      background: linear-gradient(135deg, #d97706, #f59e0b) !important;
      color: #0f172a;
      box-shadow: 0 0 12px rgba(245, 158, 11, 0.25);
    }
    .adv-btn-primary:hover {
      background: linear-gradient(135deg, #b45309, #d97706) !important;
      transform: translateY(-1px);
    }

    .adv-btn-outline {
      background: rgba(245, 158, 11, 0.15) !important;
      color: #fde68a;
    }

    /* A4 Paper Sheets Screen Simulation */
    .a4-paper-sheet {
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif !important;
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

    /* NCSA Official Letterhead Banner (No Border, No Background) */
    .ncsa-header-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 8px;
      margin-bottom: 14px;
      border: none !important;
      background: transparent !important;
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
      font-size: 9pt;
      font-weight: normal;
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

    /* Document Title: 18pt Bold (Main Title) */
    .adv-doc-title {
      font-size: 18pt !important;
      font-weight: bold !important;
      color: #000000;
      text-align: center;
      margin-top: 6px;
      margin-bottom: 4px;
      line-height: 1.3;
      break-after: avoid !important;
      page-break-after: avoid !important;
    }

    .adv-doc-meta {
      font-size: 16pt !important;
      font-weight: normal;
      color: #475569;
      text-align: center;
      margin-bottom: 14px;
      break-after: avoid !important;
      page-break-after: avoid !important;
    }

    /* TLP Notice Banner: 16pt Normal, No Border, No Background */
    .adv-tlp-rule-box {
      border: none !important;
      background: transparent !important;
      padding: 4px 0 10px 0;
      margin-bottom: 14px;
      font-size: 16pt !important;
      font-weight: normal;
      line-height: 1.35;
      color: #451a03;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    /* Typography Standards: All Headings = 16pt Bold, Body/Content = 16pt Normal */
    .adv-heading {
      font-size: 16pt !important;
      font-weight: bold !important;
      margin-top: 18px;
      margin-bottom: 8px;
      color: #000000;
      line-height: 1.35;
      break-after: avoid !important;
      page-break-after: avoid !important;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-subhead {
      font-size: 16pt !important;
      font-weight: bold !important;
      color: #000000;
      margin: 14px 0 6px 0;
      break-after: avoid !important;
      page-break-after: avoid !important;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    /* Narrative Paragraphs: 16pt Thai 1.25cm indent, Normal Weight */
    .adv-para {
      font-size: 16pt !important;
      font-weight: normal !important;
      text-align: justify;
      text-justify: inter-cluster;
      text-indent: 1.25cm;
      line-height: 1.4;
      margin: 0 0 8px 0;
      color: #000000;
      word-break: break-word;
      orphans: 4 !important;
      widows: 4 !important;
      break-inside: auto;
      page-break-inside: auto;
    }

    /* Lists: Normal Weight */
    .adv-list {
      margin: 6px 0 10px 0;
      padding: 0;
      list-style: none;
    }

    .adv-list li {
      font-size: 16pt !important;
      font-weight: normal !important;
      line-height: 1.4;
      margin-bottom: 5px;
      padding-left: 1.25cm;
      text-indent: -0.45cm;
      text-align: left !important;
      orphans: 4 !important;
      widows: 4 !important;
      color: #000000;
    }

    .adv-list li::before {
      content: "• ";
      font-weight: normal !important;
      color: #000000;
    }

    /* Tables: Clear borders for ease of reading */
    .adv-table-wrap {
      overflow-x: auto;
      margin: 8px 0 14px 0;
      border: none !important;
      background: transparent !important;
    }

    .adv-table {
      width: 100%;
      border-collapse: collapse;
      margin: 8px 0 14px 0;
      border: 1px solid #94a3b8 !important;
      background: transparent !important;
      font-size: 16pt !important;
      break-inside: auto;
      page-break-inside: auto;
    }

    .adv-table thead {
      display: table-header-group !important;
      background: transparent !important;
    }

    .adv-table thead tr {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      background: transparent !important;
    }

    .adv-table th {
      border: 1px solid #94a3b8 !important;
      background: transparent !important;
      padding: 4px 6px !important;
      font-size: 15pt !important;
      line-height: 1.25 !important;
      font-weight: normal !important;
      text-align: center;
      color: #000000;
      vertical-align: middle;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    .adv-table tbody {
      display: table-row-group !important;
      background: transparent !important;
    }

    .adv-table tr {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      background: transparent !important;
    }

    .adv-table td {
      border: 1px solid #94a3b8 !important;
      background: transparent !important;
      padding: 4px 6px !important;
      font-size: 15pt !important;
      line-height: 1.25 !important;
      font-weight: normal !important;
      color: #000000;
      vertical-align: top;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
    }

    /* Device Block & Findings: Strictly NO BORDER, NO BACKGROUND */
    .adv-device-block {
      margin-bottom: 20px;
      padding: 6px 0;
      background: transparent !important;
      border: none !important;
      break-inside: auto;
      page-break-inside: auto;
    }

    .adv-port-section {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      margin-top: 14px;
      margin-bottom: 14px;
    }

    .adv-precond-box {
      break-inside: avoid !important;
      page-break-inside: avoid !important;
      margin-top: 6px;
      margin-bottom: 10px;
    }

    .adv-finding-item {
      margin-top: 8px;
      margin-bottom: 14px;
      padding: 4px 0;
      background: transparent !important;
      border: none !important;
      break-inside: avoid !important;
      page-break-inside: avoid !important;
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
      background: transparent !important;
    }

    .adv-item-title,
    .adv-port-title,
    .adv-device-title {
      font-size: 16pt !important;
      font-weight: bold !important;
      color: #000000;
      line-height: 1.35;
      break-after: avoid !important;
      page-break-after: avoid !important;
    }

    /* Severity Text Labels: Text color only, Strictly NO BACKGROUND, Normal Weight */
    .adv-item-badge-crit {
      color: #dc2626 !important;
      background: transparent !important;
      font-size: 15pt;
      font-weight: normal !important;
      padding: 0;
      display: inline-block;
      border: none !important;
    }
    .adv-item-badge-high {
      color: #ea580c !important;
      background: transparent !important;
      font-size: 15pt;
      font-weight: normal !important;
      padding: 0;
      display: inline-block;
      border: none !important;
    }
    .adv-item-badge-med {
      color: #d97706 !important;
      background: transparent !important;
      font-size: 15pt;
      font-weight: normal !important;
      padding: 0;
      display: inline-block;
      border: none !important;
    }
    .adv-item-badge-sec {
      color: #16a34a !important;
      background: transparent !important;
      font-size: 15pt;
      font-weight: normal !important;
      padding: 0;
      display: inline-block;
      border: none !important;
    }

    /* Code Box: Clean, No Background, Same Thai Sarabun Font, Normal Weight */
    .adv-code-box {
      background: transparent !important;
      color: #000000 !important;
      padding: 4px 0 6px 1.25cm !important;
      border: none !important;
      margin: 4px 0 8px 0 !important;
      overflow-x: auto !important;
      text-indent: 0 !important;
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif !important;
      font-size: 15pt !important;
      font-weight: normal !important;
      line-height: 1.35 !important;
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
      font-weight: normal !important;
      color: inherit !important;
      text-indent: 0 !important;
      white-space: pre-wrap !important;
      word-break: break-all !important;
    }

    code {
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif !important;
      font-size: inherit !important;
      font-weight: normal !important;
      background: transparent !important;
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
      background: transparent !important;
      font-family: 'TH Sarabun PSK', 'TH SarabunPSK', 'TH Sarabun New', 'Sarabun', sans-serif !important;
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
      background: transparent !important;
    }
    .sheet-footer-left {
      flex: 1;
      text-align: left;
      font-size: 10pt;
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
      font-size: 11pt;
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
        color: #000000 !important;
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

      #sheet-references .adv-list li {
        font-size: 14pt !important;
        line-height: 1.25 !important;
        margin-bottom: 2px !important;
        padding-left: 0.6cm !important;
      }

      #sheet-references .adv-para {
        font-size: 14pt !important;
        line-height: 1.3 !important;
        margin-bottom: 4px !important;
      }

      #sheet-references .adv-heading {
        font-size: 16pt !important;
        margin-bottom: 4px !important;
      }

      #sheet-references .adv-subhead {
        font-size: 15pt !important;
        margin-top: 6px !important;
        margin-bottom: 2px !important;
      }

      #sheet-page-1 .adv-para {
        font-size: 14pt !important;
        line-height: 1.25 !important;
        margin-bottom: 3px !important;
      }

      #sheet-page-1 .adv-heading {
        font-size: 16pt !important;
        margin-bottom: 2px !important;
      }

      #sheet-page-1 .adv-subhead {
        font-size: 14.5pt !important;
        margin-top: 4px !important;
        margin-bottom: 2px !important;
      }

      #sheet-page-1 .adv-table {
        font-size: 13.5pt !important;
        margin: 4px 0 6px 0 !important;
      }

      #sheet-page-1 .adv-table th, #sheet-page-1 .adv-table td {
        padding: 2px 4px !important;
      }

      #sheet-page-1 .adv-list li {
        font-size: 14pt !important;
        line-height: 1.25 !important;
        margin-bottom: 2px !important;
        padding-left: 0.6cm !important;
      }

      #sheet-page-1 .adv-tlp-rule-box {
        margin: 3px 0 4px 0 !important;
        padding: 2px 6px !important;
        font-size: 13pt !important;
        line-height: 1.25 !important;
      }

      .adv-heading, .adv-subhead, .adv-device-title, .adv-port-title, .adv-item-title {
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

      .adv-table,
      .adv-table th,
      .adv-table td {
        border: 1px solid #94a3b8 !important;
      }

      .adv-code-box,
      .adv-finding-item,
      .adv-port-section,
      .adv-precond-box {
        break-inside: avoid !important;
        page-break-inside: avoid !important;
      }
    }
    """
    return css.replace("__WATERMARK_DATA_URI__", wm_uri)


def extract_compact_thaicert_groups(p_hosts: List[Dict[str, Any]]) -> str:
    """
    Extract concise, deduplicated ThaiCERT group labels for table display.
    Keywords: Website, Software/OS, Hosting, Network, Container, Window, Backup/Staging.
    Formatted as one group per line for clean readability.
    """
    SHORT_GROUP_NAMES = {
        1: "Website",
        2: "Software/OS",
        3: "Hosting",
        4: "Network",
        5: "Container",
        6: "Window",
        7: "Backup/Staging",
        8: "Hosting",
    }
    
    found_group_ids = set()
    for h in p_hosts:
        # 1. From thaicert_groups array (e.g. [1, 2, 7])
        for g in (h.get("thaicert_groups") or []):
            if isinstance(g, int) and g in SHORT_GROUP_NAMES:
                found_group_ids.add(g)
            elif isinstance(g, str):
                m = re.search(r"([1-8])", g)
                if m:
                    found_group_ids.add(int(m.group(1)))
        
        # 2. From deep_audit thaicert_groups
        da = h.get("deep_audit") or {}
        for g in (da.get("thaicert_groups") or []):
            if isinstance(g, int) and g in SHORT_GROUP_NAMES:
                found_group_ids.add(g)
            elif isinstance(g, str):
                m = re.search(r"([1-8])", g)
                if m:
                    found_group_ids.add(int(m.group(1)))
                    
        # 3. From primary_group strings or labels
        for field in [h.get("primary_group"), da.get("primary_group")]:
            if field:
                m = re.search(r"กลุ่ม\s*([1-8])", str(field))
                if m:
                    found_group_ids.add(int(m.group(1)))

        # 4. From group_labels if present
        for gl in (h.get("group_labels") or []):
            m = re.search(r"กลุ่ม\s*([1-8])", str(gl))
            if m:
                found_group_ids.add(int(m.group(1)))

    if not found_group_ids:
        return "-"

    sorted_ids = sorted(list(found_group_ids))
    labels = []
    for gid in sorted_ids:
        lbl = SHORT_GROUP_NAMES.get(gid, f"Group {gid}")
        if lbl not in labels:
            labels.append(lbl)

    return "<br>".join(labels)


def build_amber_advisory_html(scan_report_data: Dict[str, Any]) -> str:
    """
    Builds a complete, professional TLP:AMBER A4 Security Advisory HTML.
    Groups findings by physical/logical device (IP), adheres strictly to zero borders,
    zero background colors, unified Thai font, and bold weight ONLY on actual headings.
    """
    now = datetime.now()
    date_str = f"{now.day} {['มกราคม','กุมภาพันธ์','มีนาคม','เมษายน','พฤษภาคม','มิถุนายน','กรกฎาคม','สิงหาคม','กันยายน','ตุลาคม','พฤศจิกายน','ธันวาคม'][now.month-1]} พ.ศ. {now.year + 543}"
    ref_id = f"NCSA-AMBER-{now.year}-{int(now.timestamp()) % 10000:04d}"

    target_scope = scan_report_data.get("target") or scan_report_data.get("target_id") or scan_report_data.get("subnet") or "ระบบสารสนเทศเป้าหมาย"
    hosts_list = scan_report_data.get("hosts") or scan_report_data.get("all_hosts") or scan_report_data.get("results") or []
    if not hosts_list and "deep_audit" in scan_report_data:
        hosts_list = [scan_report_data]

    # Group hosts_list by unique IP address to treat each physical/logical host as one device
    hosts_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for h in hosts_list:
        ip = h.get("ip") or h.get("target_id") or "-"
        hosts_by_ip.setdefault(ip, []).append(h)

    total_scanned = len(hosts_by_ip) if len(hosts_by_ip) > 0 else len(hosts_list)
    affected_hosts_count = 0
    safe_hosts_count = 0

    confirmed_vulns_count = 0
    conditional_findings_count = 0
    lifecycle_risks_count = 0

    all_matched_cves = []
    seen_finding_keys = set()
    eol_ports = set()
    eol_versions = set()

    # Calculate rigorous metrics per host and across all findings (scalable & dynamic)
    for ip, p_hosts in hosts_by_ip.items():
        host_is_affected = False

        for h in p_hosts:
            port_val = h.get("port")
            da = h.get("deep_audit") or {}
            rce_p = h.get("rce_proof") or da.get("rce_proof") or {}
            rce_st = rce_p.get("proof_status", "")
            v_php = h.get("vulnerability")
            v_node = h.get("vulnerabilityNode")
            cves = h.get("matched_cves") or []
            chains = (da.get("security_chains") or {}).get("chains") or (h.get("security_chains") or {}).get("chains") or {}

            # 1. RCE Proof finding (Confirmed Vulnerability)
            if rce_p.get("is_rce_proved") or rce_st == "RCE_CONFIRMED":
                f_key = (ip, port_val, "RCE")
                if f_key not in seen_finding_keys:
                    seen_finding_keys.add(f_key)
                    confirmed_vulns_count += 1
                    host_is_affected = True
            elif rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI"):
                f_key = (ip, port_val, "LFI")
                if f_key not in seen_finding_keys:
                    seen_finding_keys.add(f_key)
                    confirmed_vulns_count += 1
                    host_is_affected = True

            # 2. CVE findings (Confirmed or Conditional)
            for c in cves:
                c_id = c.get("id") or c.get("cve")
                if c_id and c_id not in [x.get("id") or x.get("cve") for x in all_matched_cves]:
                    all_matched_cves.append(c)
                f_key = (ip, port_val, c_id)
                if f_key not in seen_finding_keys:
                    seen_finding_keys.add(f_key)
                    if c.get("confirmed") or c.get("verification_type") == "Confirmed Vulnerability":
                        confirmed_vulns_count += 1
                    else:
                        conditional_findings_count += 1
                    host_is_affected = True

            # Also capture any CVEs referenced in chains (e.g. CVE-2026-109619 or CVE-2026-115560)
            for ch_tag, ch_data in chains.items():
                if ch_data.get("verdict_code") in ("CONFIRMED", "VULN", "ARCHITECTURAL_RISK"):
                    title = ch_data.get("title", "")
                    cve_matches = re.findall(r"CVE-\d{4}-\d+", title)
                    for c_id in cve_matches:
                        if c_id not in [x.get("id") or x.get("cve") for x in all_matched_cves]:
                            all_matched_cves.append({"id": c_id, "name": title, "verification_type": "Conditional Finding"})
                    
                    f_key = (ip, port_val, f"CHAIN_{ch_tag}")
                    if f_key not in seen_finding_keys:
                        seen_finding_keys.add(f_key)
                        conditional_findings_count += 1
                        host_is_affected = True

            # 3. EOL finding (Lifecycle Risk) - must match exactly what is rendered
            php_v = h.get("php_version") or h.get("phpVersion")
            has_eol_runtime = (
                v_php in ("Lifecycle Risk (EOL)", "Outdated")
                or (php_v and any(php_v.replace("PHP/", "").strip().startswith(pfx) for pfx in ("5.", "7.", "8.0", "8.1")))
                or v_node in ("Outdated", "Lifecycle Risk (EOL)")
            )
            if has_eol_runtime:
                f_key = (ip, port_val, "EOL_RUNTIME")
                if f_key not in seen_finding_keys:
                    seen_finding_keys.add(f_key)
                    lifecycle_risks_count += 1
                    eol_ports.add(port_val)
                    rt_v = php_v or h.get("node_version") or h.get("nodeVersion") or h.get("runtime_version") or ""
                    if rt_v and "ไม่มี" not in str(rt_v).lower():
                        clean_rt = str(rt_v).strip()
                        if clean_rt.startswith("PHP/"):
                            clean_rt = "PHP " + clean_rt[4:]
                        eol_versions.add(clean_rt)
                    host_is_affected = True

        if host_is_affected:
            affected_hosts_count += 1
        else:
            safe_hosts_count += 1

    total_findings_count = confirmed_vulns_count + conditional_findings_count + lifecycle_risks_count
    has_any_risk = (affected_hosts_count > 0 or total_findings_count > 0)

    header_banner = get_ncsa_header_banner_html()
    css_styles = get_css_styles()

    # Table rows for Attack Surface Ledger (No bold, no background colors)
    table_rows_html = ""
    for idx, (h_ip, p_hosts) in enumerate(hosts_by_ip.items(), 1):
        # Collect all ports for this IP
        all_ports = []
        for h in p_hosts:
            for p in (h.get("ports") or [h.get("port")]):
                if p and p not in all_ports:
                    all_ports.append(p)
        sorted_ports = sorted(all_ports)
        if len(sorted_ports) > 4:
            # Pair ports: 2 ports per line for compact readability
            h_ports = "<br>".join(", ".join(html.escape(str(p)) for p in sorted_ports[i:i+2]) for i in range(0, len(sorted_ports), 2))
        elif len(sorted_ports) > 1:
            h_ports = "<br>".join(html.escape(str(p)) for p in sorted_ports)
        elif sorted_ports:
            h_ports = html.escape(str(sorted_ports[0]))
        else:
            h_ports = "-"
        
        # Determine Device Name and Technology Stack
        dev_name = ""
        web_srvs = []
        macs = []
        primary_groups = []
        host_highest_sev = "ไม่พบความเสี่ยง"
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

            # Check severity (Strictly separate Confirmed Exploits from Conditional Findings)
            v_php = h.get("vulnerability")
            v_node = h.get("vulnerabilityNode")
            v_nginx = (da.get("nginx_audit") or {}).get("severity")
            rce_p = h.get("rce_proof") or da.get("rce_proof") or {}
            rce_st = rce_p.get("proof_status", "")

            if rce_p.get("is_rce_proved") or rce_st == "RCE_CONFIRMED":
                host_highest_sev = "วิกฤต (Critical - ยืนยันผลกระทบแล้ว)"
                host_badge_cls = "adv-item-badge-crit"
            elif rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI"):
                if "วิกฤต" not in host_highest_sev:
                    host_highest_sev = "สูง (High - LFI Confirmed)"
                    host_badge_cls = "adv-item-badge-high"
            elif (any(s in ("Critical", "High") for s in [v_php, v_node, v_nginx]) or bool(h.get("matched_cves"))):
                if host_highest_sev == "ไม่พบความเสี่ยง":
                    host_highest_sev = "สูง (High - รอการตรวจสอบ)"
                    host_badge_cls = "adv-item-badge-high"
            elif ("Medium" in [v_php, v_node, v_nginx] or "Warning" in [v_php, v_node]) and host_highest_sev == "ไม่พบความเสี่ยง":
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

        if len(p_hosts) > 1 or dev_name in ("โฮสต์เครื่องตรวจการ (Host Machine)", "โฮสต์เครื่องตรวจการ", "Host Machine") or "เครื่องตรวจการ" in dev_name or dev_name == "เครื่องนี้":
            dev_name = "Target Host / Multi-Service IP" if len(p_hosts) > 1 else "Target Host"

        display_dev_name = dev_name
        if "Private Wi-Fi" in display_dev_name:
            display_dev_name = "อุปกรณ์ไร้สาย (Private Wi-Fi)"

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

        mac_badge = f'<div style="font-size: 11pt; color: #64748b; line-height: 1.15;">MAC: {html.escape(macs[0])}</div>' if macs else ""
        service_badge = f'<div style="font-size: 13pt; color: #475569; margin-top: 1px; line-height: 1.2;">บริการ: {html.escape(tech_str)}</div>' if tech_str else ""

        dev_service_cell = f"""
        <div>
          <div style="font-size: 15pt; color: #000000; line-height: 1.2;">{html.escape(display_dev_name)}</div>
          {service_badge}
          {mac_badge}
        </div>
        """

        grp_str = extract_compact_thaicert_groups(p_hosts)

        table_rows_html += f"""
        <tr>
          <td style="text-align: center;">{idx}</td>
          <td>{html.escape(h_ip)}</td>
          <td style="text-align: center;">{h_ports}</td>
          <td>{dev_service_cell}</td>
          <td>{grp_str}</td>
          <td style="text-align: center;"><span class="{host_badge_cls}">[{host_highest_sev}]</span></td>
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
        host_max_sev = "ไม่พบความเสี่ยง"
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
                host_max_sev = "ระดับวิกฤต (Critical - ยืนยันผลกระทบแล้ว)"
                host_badge_cls = "adv-item-badge-crit"
            elif rce_st in ("CANARY_CONFIRMED", "CONFIRMED_LFI"):
                host_is_vuln = True
                if "วิกฤต" not in host_max_sev:
                    host_max_sev = "ระดับสูง (High - LFI Confirmed)"
                    host_badge_cls = "adv-item-badge-high"

            v_php = h.get("vulnerability")
            v_node = h.get("vulnerabilityNode")
            v_nginx = (da.get("nginx_audit") or {}).get("severity")

            php_v_chk = h.get("php_version") or h.get("phpVersion")
            has_eol_h = (
                v_php in ("Lifecycle Risk (EOL)", "Outdated")
                or (php_v_chk and any(str(php_v_chk).replace("PHP/", "").strip().startswith(pfx) for pfx in ("5.", "7.", "8.0", "8.1")))
                or v_node in ("Outdated", "Lifecycle Risk (EOL)")
            )
            if has_eol_h:
                host_is_vuln = True
                if host_max_sev == "ไม่พบความเสี่ยง":
                    host_max_sev = "ระดับสูง (High - Outdated Lifecycle Risk)"
                    host_badge_cls = "adv-item-badge-high"

            if any(s in ("Critical", "High") for s in [v_php, v_node, v_nginx]) or bool(cves):
                host_is_vuln = True
                if host_max_sev == "ไม่พบความเสี่ยง":
                    host_max_sev = "ระดับสูง (High - มีข้อค้นพบที่ต้องตรวจสอบเร่งด่วน)"
                    host_badge_cls = "adv-item-badge-high"
            elif "Medium" in [v_php, v_node, v_nginx] or "Warning" in [v_php, v_node]:
                host_is_vuln = True
                if host_max_sev == "ไม่พบความเสี่ยง":
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
        if len(p_hosts) > 1 or dev_name in ("โฮสต์เครื่องตรวจการ (Host Machine)", "โฮสต์เครื่องตรวจการ", "Host Machine") or "เครื่องตรวจการ" in dev_name or dev_name == "เครื่องนี้":
            dev_name = "Target Host / Multi-Service IP" if len(p_hosts) > 1 else "Target Host"

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
            if h.get("node_version") or (h.get("is_node") and h.get("runtime_version")):
                nv = h.get("node_version") or h.get("runtime_version")
                if f"Node.js {nv}" not in tech_summary_parts:
                    tech_summary_parts.append(f"Node.js {nv}")
            ws = h.get("webServer") or h.get("server") or (h.get("deep_audit") or {}).get("nginx_audit", {}).get("server")
            if ws and ws not in tech_summary_parts and "ไม่มี" not in str(ws).lower():
                tech_summary_parts.append(str(ws))
        tech_summary = ", ".join(tech_summary_parts) if tech_summary_parts else "Web & Application Server"

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

            php_v_check = h.get("php_version") or h.get("phpVersion")
            has_eol_chk = (
                v_p in ("Lifecycle Risk (EOL)", "Outdated")
                or (php_v_check and any(str(php_v_check).replace("PHP/", "").strip().startswith(pfx) for pfx in ("5.", "7.", "8.0", "8.1")))
                or v_n in ("Outdated", "Lifecycle Risk (EOL)")
            )

            port_has_findings = (
                rce_is_active
                or rce_status_val in ("RCE_CONFIRMED", "CANARY_CONFIRMED", "CONFIRMED_LFI")
                or any(s in ("Critical", "High", "Medium", "Warning", "Lifecycle Risk (EOL)", "Outdated") for s in [v_p, v_n, v_nx])
                or bool(cves)
                or has_actionable_c
                or has_eol_chk
            )

            if not port_has_findings:
                continue

            port_service_name = h.get("webServer") or h.get("server") or nx_audit.get("server") or "Web Service"

            # 1. Live Proof (RCE / LFI) - NO BORDER, NO BACKGROUND
            proof_html = ""
            if rce_proof.get("is_rce_proved") or rce_status_val in ("RCE_CONFIRMED", "CANARY_CONFIRMED", "CONFIRMED_LFI"):
                is_rce = rce_proof.get("is_rce_proved") or rce_status_val == "RCE_CONFIRMED"
                title_color = "#991b1b" if is_rce else "#854d0e"
                badge_text = "[RCE CONFIRMED]" if is_rce else ("[CANARY CONFIRMED]" if rce_status_val == "CANARY_CONFIRMED" else "[LFI CONFIRMED]")
                header_title = "หลักฐานเชิงประจักษ์ยืนยันการรันคำสั่งควบคุมระบบ (Live RCE Proof)" if is_rce else "หลักฐานเชิงประจักษ์ยืนยันช่องโหว่ LFI / Arbitrary File Read"
                
                trail = rce_proof.get("audit_trail") or {}
                trail_html = ""
                if trail:
                    trail_html = f"""
                    <div style="margin-top: 6px; font-size: 10pt; color: #64748b;">
                      <div>Tamper-Evident Evidence Digest: Operator: {html.escape(trail.get('operator', '-'))} | UTC: {html.escape(trail.get('timestamp_utc', '-'))}</div>
                      <div style="word-break: break-all;">SHA-256: {html.escape(trail.get('evidence_sha256', '-'))}</div>
                    </div>
                    """

                proof_html = f"""
                <div style="margin-top: 8px; margin-bottom: 10px;">
                  <div style="font-size: 16pt; color: {title_color}; margin-bottom: 4px;">
                    {header_title} บนพอร์ต {html.escape(str(port_val or '-'))}
                  </div>
                  <p class="adv-para" style="color: #451a03; margin-bottom: 6px;">
                    {html.escape(rce_proof.get('impact_statement', ''))} (เทคนิค: {html.escape(rce_proof.get('technique', ''))} | ระดับสิทธิ์: {html.escape(rce_proof.get('privilege_level', ''))})
                  </p>
                  <div class="adv-code-box">
                    <div style="color: #64748b; font-size: 12pt; margin-bottom: 2px;">
                      $ {html.escape(rce_proof.get('command_executed', 'canary execution'))} &nbsp;&nbsp;{badge_text} &nbsp;&nbsp;เวลา: {html.escape(rce_proof.get('verified_at', ''))}
                    </div>
                    <div>
                      {html.escape(rce_proof.get('execution_output', ''))}
                    </div>
                    {f'<div style="color: #475569; font-size: 12pt; margin-top: 4px;">คำสั่งทดสอบจริง (CLI): {html.escape(rce_proof.get("reproduce_curl", ""))}</div>' if rce_proof.get("reproduce_curl") else ''}
                    {trail_html}
                  </div>
                </div>
                """

            # 2. Architectural Preconditions (NO BORDER, NO BACKGROUND)
            br_pre = da.get("brotli_preconditions") or {}
            nx_pre = da.get("nginx_preconditions") or {}
            precond_rows = ""
            if br_pre:
                br_status = "ยอมรับและถอดรหัสบิตสตรีมเข้า (Active Decompression Confirmed)" if br_pre.get("brotli_request_accepted") else "ปฏิเสธ / ไม่พบการใช้งาน"
                precond_rows += f"""<tr><td style="padding: 2px 0; width: 40%; color: #475569;">Brotli Stream Processing (CVE-2026-111497):</td><td style="padding: 2px 0; color: #000000;">{html.escape(br_status)}</td></tr>"""
            if nx_pre:
                h3_status = "ยืนยันพอร์ต UDP 443 ผ่านแพ็กเก็ต RFC 9000 (Active QUIC Listener Confirmed)" if nx_pre.get("http3_udp_verified") else "ไม่พบการตอบสนองของ QUIC UDP บนพอร์ต 443"
                alias_status = f"ตรวจพบพฤติกรรม Traversal: {nx_pre.get('alias_evidence')}" if nx_pre.get("alias_traversal_observed") else "ปกติ (ไม่พบความผิดปกติจากคำขอ /dir../ เทียบกับ Baseline)"
                ssi_status = f"พบไฟล์: {', '.join(nx_pre.get('ssi_files', []))} (สัญญาณสภาพแวดล้อม ยังไม่ยืนยัน SSI processing หรือเงื่อนไข include virtual)" if nx_pre.get("ssi_files") else "ไม่พบไฟล์ .shtml/.shtm บนระบบ"
                precond_rows += f"""
                    <tr><td style="padding: 2px 0; color: #475569;">HTTP/3 QUIC UDP Transport:</td><td style="padding: 2px 0; color: #000000;">{html.escape(h3_status)}</td></tr>
                    <tr><td style="padding: 2px 0; color: #475569;">NGINX Alias Path Traversal:</td><td style="padding: 2px 0; color: #000000;">{html.escape(alias_status)}</td></tr>
                    <tr><td style="padding: 2px 0; color: #475569;">SSI Directive Exposure:</td><td style="padding: 2px 0; color: #000000;">{html.escape(ssi_status)}</td></tr>
                """
            precond_html = ""
            if precond_rows:
                precond_html = f"""
                <div class="adv-precond-box" style="margin-top: 6px; margin-bottom: 10px; break-inside: avoid; page-break-inside: avoid;">
                  <div style="font-size: 15pt; font-weight: bold; color: #1e293b; margin-bottom: 2px; break-after: avoid; page-break-after: avoid;">
                    การตรวจพิสูจน์เงื่อนไขสภาพแวดล้อม (Environmental Verification) พอร์ต {html.escape(str(port_val or '-'))}:
                  </div>
                  <table style="width: 100%; font-size: 15pt; border-collapse: collapse; border: none;">
                    {precond_rows}
                  </table>
                </div>
                """

            # 3. Matched CVEs for this port (NO BORDER, NO BACKGROUND, NO BOLD on labels)
            cves_html = ""
            for c in cves:
                cve_id = c.get("id") or c.get("cve") or "CVE-VULN"
                cve_name = c.get("name") or "ช่องโหว่ความมั่นคงปลอดภัย"
                cve_sev = c.get("severity") or "High"
                
                # Authoritative database lookup
                cve_ref = _CVE_DB_MAP.get(cve_id) or NGINX_CVE_DESCS.get(cve_id) or {}
                
                is_confirmed_cve = bool(c.get("confirmed") or rce_is_active or rce_status_val in ("RCE_CONFIRMED", "CANARY_CONFIRMED"))
                
                if is_confirmed_cve:
                    cvss = c.get("cvss") or cve_ref.get("cvss")
                    cvss_ver = c.get("cvss_version") or cve_ref.get("cvss_version") or "CVSS v3.1"
                    score_src = c.get("score_source") or cve_ref.get("score_source") or "Empirical Assessment"
                    vendor_sev = c.get("vendor_severity") or cve_ref.get("vendor_severity") or "Critical"
                    v_type = "ช่องโหว่ที่ยืนยันผลกระทบได้ (Confirmed Vulnerability)"
                    e_conf = "ยืนยันด้วยโค้ดทดสอบ (High - Empirical Proof)"
                else:
                    cvss = cve_ref.get("cvss") if "cvss" in cve_ref else c.get("cvss")
                    cvss_ver = cve_ref.get("cvss_version") or c.get("cvss_version") or ("CVSS v4.0" if (cvss and float(cvss) >= 9.0) else "CVSS v3.1")
                    score_src = cve_ref.get("score_source") or c.get("score_source") or "NVD / NIST"
                    vendor_sev = cve_ref.get("vendor_severity") or c.get("vendor_severity") or "Medium"
                    v_type = cve_ref.get("verification_type") or c.get("verification_type") or "ข้อค้นพบตามเงื่อนไข (Conditional Finding)"
                    e_conf = cve_ref.get("evidence_confidence") or c.get("evidence_confidence") or "ตรวจพบจากภายนอก (Medium - Externally Observable)"

                if cvss is not None:
                    cvss_str = f"{cvss} ({cvss_ver})"
                else:
                    cvss_str = f"อยู่ระหว่างการประเมินทางการ ({cvss_ver})"

                cat = c.get("category") or cve_ref.get("category") or "Web Stack"
                reason = c.get("reason") or cve_ref.get("desc") or "ตรวจพบเวอร์ชันซอฟต์แวร์ที่ตรงกับเงื่อนไขความเสี่ยง"
                host_check = cve_ref.get("host_check") or c.get("host_check") or "php -v || node -v || nginx -v"
                exp_vuln = cve_ref.get("expected_vuln") or cve_ref.get("confirm_vuln") or c.get("expected_vuln") or c.get("confirm_vuln") or "พบเวอร์ชันอยู่ในช่วงที่ได้รับผลกระทบ"
                exp_safe = cve_ref.get("expected_safe") or cve_ref.get("confirm_safe") or c.get("expected_safe") or c.get("confirm_safe") or "อัปเดตเป็นเวอร์ชันที่ได้รับแพตช์ความปลอดภัยล่าสุด"
                cmd_limits = cve_ref.get("command_limitations") or c.get("command_limitations") or "คำสั่งตรวจสอบเฉพาะคอนฟิกหลักที่ระบบตรวจพบ ไม่ครอบคลุมคอนฟิกที่กระจายตัวในพาธอื่นหรือคอนเทนเนอร์"
                confirm_safe = cve_ref.get("confirm_safe") or cve_ref.get("patched") or c.get("confirm_safe") or "อัปเดตเป็นเวอร์ชันที่ได้รับแพตช์ความปลอดภัยล่าสุด"

                # Extract observed external evidence and internal preconditions
                obs_items = []
                srv_b = h.get("webServer") or h.get("server") or nx_audit.get("server") or (h.get("headers") or {}).get("server")
                if srv_b and "ไม่มี" not in str(srv_b).lower():
                    obs_items.append(f"HTTP Server Banner: {srv_b}")
                php_v = h.get("php_version") or h.get("phpVersion")
                php_clean = str(php_v).strip() if php_v else ""
                if any(ign in php_clean.lower() for ign in ("no php", "none", "ไม่มี", "false", "n/a")):
                    php_clean = ""
                
                node_v = h.get("node_version") or h.get("nodeVersion")
                node_clean = str(node_v).strip() if node_v else ""
                if any(ign in node_clean.lower() for ign in ("no node", "none", "ไม่มี", "false", "n/a")):
                    node_clean = ""

                if php_clean:
                    php_disp = php_clean if php_clean.upper().startswith("PHP") else f"PHP {php_clean}"
                    obs_items.append(f"เวอร์ชัน {php_disp}")
                elif node_clean or (h.get("is_node") and h.get("runtime_version")):
                    nv = node_clean or str(h.get("runtime_version") or "").strip()
                    if nv and nv.lower() not in ("none", "ไม่มี"):
                        node_disp = nv if nv.upper().startswith("NODE") else f"Node.js {nv}"
                        obs_items.append(f"เวอร์ชัน {node_disp}")
                elif h.get("runtime_version") and "ไม่มี" not in str(h.get("runtime_version")):
                    rt_val = str(h.get("runtime_version")).strip()
                    if "php" in rt_val.lower():
                        obs_items.append(f"เวอร์ชัน {rt_val}")
                    elif "node" in rt_val.lower():
                        obs_items.append(f"เวอร์ชัน {rt_val}")
                    else:
                        obs_items.append(f"เวอร์ชันรันไทม์: {rt_val}")
                obs_items.append(f"พอร์ตบริการ {port_val} เปิดตอบสนองสู่เครือข่าย")
                observed_evidence_txt = " · ".join(obs_items)

                precond_directive = cve_ref.get("trigger") or cve_ref.get("expected_vuln") or c.get("trigger") or c.get("expected_vuln") or "ต้องมีการตั้งค่าเฉพาะบนเซิร์ฟเวอร์ตามเงื่อนไขของช่องโหว่"
                
                if is_confirmed_cve:
                    conclusion_txt = "ตรวจพบหลักฐานเชิงประจักษ์ยืนยันว่าช่องโหว่นี้สามารถถูกโจมตีได้จริงผ่านเครือข่ายภายนอก (Actionable Confirmed Exploit) ผู้ดูแลระบบต้องเร่งดำเนินการแก้ไขทันที"
                else:
                    conclusion_txt = "ผลประเมินจากมุมมองภายนอก (Black-box Network Assessment) ตรวจพบบริการและเวอร์ชันที่อยู่ในขอบเขตเสี่ยง โดยการโจมตีจะเกิดขึ้นได้จริงเมื่อระบบมีเงื่อนไขการตั้งค่าภายในตามที่ระบุ จึงจัดเป็นข้อค้นพบตามเงื่อนไข (Conditional Finding) เพื่อให้ผู้ดูแลระบบนำคู่มือตรวจสอบคอนฟิกบนเซิร์ฟเวอร์จริงต่อไป"

                sev_th_map = {
                    "Critical": "ระดับวิกฤต (Critical)",
                    "High": "ระดับสูง (High)",
                    "Medium": "ระดับปานกลาง (Medium)",
                    "Low": "ระดับต่ำ (Low)",
                    "Warning": "ระดับควรเฝ้าระวัง (Warning)"
                }
                cve_sev_th = sev_th_map.get(cve_sev, f"ระดับ {cve_sev}")

                cve_endpoint_ctx = ""
                if "109619" in str(cve_id):
                    cve_endpoint_ctx = f"""<div style="font-size: 13.5pt; color: #0f172a; font-weight: bold; margin-bottom: 2px;">พอร์ตบริการที่เกี่ยวข้อง: {port_val} ({html.escape(port_service_name)}) &nbsp;|&nbsp; สถาปัตยกรรมที่คาดการณ์: PHP-FPM / FastCGI (ต้องตรวจสอบยืนยันจาก Host Configuration)</div>"""

                cves_html += f"""
                <div class="adv-finding-item">
                  <div class="adv-item-title" style="font-size: 16pt; font-weight: bold; color: #000000; margin-bottom: 3px;">
                    ข้อค้นพบ: {html.escape(cve_id)} — {html.escape(cve_name)}
                  </div>
                  <div style="font-size: 14.5pt; color: #334155; margin-bottom: 6px; line-height: 1.4;">
                    {cve_endpoint_ctx}
                    ประเภทข้อค้นพบ: {html.escape(v_type)} &nbsp;|&nbsp; 
                    ระดับความเชื่อมั่นหลักฐาน: {html.escape(e_conf)} <br>
                    คะแนน CVSS: {html.escape(cvss_str)} (แหล่งอ้างอิง: {html.escape(score_src)}) &nbsp;|&nbsp; 
                    Vendor Severity: {html.escape(vendor_sev)}
                  </div>
                  <div style="font-size: 14pt; color: #1e293b; margin-bottom: 6px; line-height: 1.35;">
                    • <b>หลักฐานที่ตรวจพบจากภายนอก (Observed Evidence):</b> {html.escape(observed_evidence_txt)}<br>
                    • <b>เงื่อนไขภายในระบบที่ต้องตรวจสอบ (Internal Preconditions):</b> {html.escape(precond_directive)}<br>
                    • <b>ข้อสรุปการประเมิน (Assessment Conclusion):</b> {html.escape(conclusion_txt)}
                  </div>
                  <div class="adv-code-box">
                    <div style="font-size: 14pt; color: #1e293b; font-weight: bold; margin-bottom: 2px;">
                       Host-based Verification Guide (คำแนะนำสำหรับผู้ดูแลระบบที่มีสิทธิ์ Root/Administrator):
                    </div>
                    <div style="font-size: 12.5pt; color: #64748b; margin-bottom: 4px;">
                      *คำสั่งนี้จัดทำขึ้นเป็นแนวทางสำหรับผู้ดูแลระบบนำไปตรวจสอบคอนฟิกภายในเครื่องเป้าหมาย มิได้ถูกรันโดยเครื่องสแกน OPScaner จากภายนอกเครือข่าย*
                    </div>
                    <pre>{html.escape(host_check)}</pre>
                    <div style="font-size: 13.5pt; color: #334155; margin-top: 4px; line-height: 1.35;">
                      • ผลลัพธ์ที่เข้าข่ายความเสี่ยง: {html.escape(exp_vuln)}<br>
                      • ผลลัพธ์ที่ไม่พบความเสี่ยง: {html.escape(exp_safe)}<br>
                      • ข้อจำกัดของคำสั่ง: {html.escape(cmd_limits)}
                    </div>
                  </div>
                  <div class="adv-code-box">
                    <div style="font-size: 14pt; color: #1e293b; font-weight: bold; margin-bottom: 2px;">แนวทางแก้ไขและเกณฑ์ความปลอดภัยที่แนะนำ:</div>
                    <div style="font-size: 13.5pt; color: #334155; line-height: 1.4;">
                      • <b>มาตรการแก้ไข:</b> {html.escape(confirm_safe)}<br>
                      • <b>คำแนะนำการปฏิบัติงาน:</b> ควรสำรองข้อมูลและทดสอบในสภาพแวดล้อม Staging ก่อนปรับปรุงระบบจริง
                    </div>
                  </div>
                </div>
                """

            # Software Lifecycle Risk (EOL) Finding Card (Independent of whether CVEs matched)
            php_v = h.get("php_version") or h.get("phpVersion")
            has_eol_runtime = (
                v_p in ("Lifecycle Risk (EOL)", "Outdated")
                or (php_v and any(php_v.replace("PHP/", "").strip().startswith(pfx) for pfx in ("5.", "7.", "8.0", "8.1")))
                or v_n in ("Outdated", "Lifecycle Risk (EOL)")
            )
            if has_eol_runtime:
                rt_version = php_v or h.get("node_version") or h.get("nodeVersion") or h.get("runtime_version") or "ไม่ระบุเวอร์ชัน"
                rt_disp = str(rt_version).replace("PHP/", "PHP ")
                note_text = h.get("cveNote") or f"ตรวจพบการเปิดให้บริการซอฟต์แวร์เวอร์ชันที่สิ้นสุดการสนับสนุนอย่างเป็นทางการ ({rt_disp}) ซึ่งผู้พัฒนาต้นทางยุติการออกแพตช์ความมั่นคงปลอดภัยแล้ว"
                h_check = "php -v && (php -i | grep -E 'Server API|Configuration File')" if "php" in str(rt_version).lower() else "node -v || php -v"
                safe_crit = (h.get("deep_audit") or {}).get("safe_criteria") or "อัปเกรดเป็นเวอร์ชันล่าสุดที่ได้รับการสนับสนุนอย่างเป็นทางการ (เช่น PHP 8.2+ / 8.3+ หรือ Node.js LTS)"

                cves_html += f"""
                <div class="adv-finding-item">
                  <div class="adv-item-title" style="font-size: 16pt; font-weight: bold; color: #000000; margin-bottom: 3px;">
                    ข้อค้นพบ: ความเสี่ยงจากการใช้ซอฟต์แวร์เวอร์ชันเก่าที่สิ้นสุดระยะการดูแลรักษา ({html.escape(rt_disp)})
                  </div>
                  <div style="font-size: 14.5pt; color: #334155; margin-bottom: 6px; line-height: 1.4;">
                    ประเภทข้อค้นพบ: Software Lifecycle Risk (EOL) &nbsp;|&nbsp;
                    ระดับความเชื่อมั่นหลักฐาน: ตรวจพบเวอร์ชันจากภายนอก (Externally Observable Fingerprint) <br>
                    ระดับความเสี่ยงตามนโยบาย: ระดับสูง (High - Outdated Lifecycle Risk) &nbsp;|&nbsp; 
                    สถานะ: สิ้นสุดระยะสนับสนุน (EOL)
                  </div>
                  <div style="font-size: 14pt; color: #1e293b; margin-bottom: 6px; line-height: 1.35;">
                    • <b>หลักฐานที่ตรวจพบจากภายนอก (Observed Evidence):</b> พอร์ต {html.escape(str(port_val or '-'))} ส่งข้อมูลระบุรันไทม์ {html.escape(rt_disp)}<br>
                    • <b>สาระสำคัญของความเสี่ยง (Risk Nature):</b> ซอฟต์แวร์รุ่นนี้สิ้นสุดระยะการดูแลรักษาอย่างเป็นทางการ (EOL) ทำให้ไม่ได้รับแพตช์ความมั่นคงปลอดภัยเมื่อพบช่องโหว่ใหม่<br>
                    • <b>ข้อสรุปการประเมิน (Assessment Conclusion):</b> เป็นความเสี่ยงเชิงนโยบายการกำกับดูแล (Policy Risk) ไม่ใช่ข้อผิดพลาดจากการตั้งค่าเพียงจุดเดียว แนะนำวางแผนปรับปรุงสู่รุ่นที่ยังได้รับการสนับสนุน
                  </div>
                  <div class="adv-code-box">
                    <div style="font-size: 14pt; color: #1e293b; font-weight: bold; margin-bottom: 2px;">
                      Host-based Verification Guide (คำแนะนำสำหรับผู้ดูแลระบบที่มีสิทธิ์ Root/Administrator):
                    </div>
                    <div style="font-size: 12.5pt; color: #64748b; margin-bottom: 4px;">
                      *คำสั่งนี้จัดทำขึ้นเป็นแนวทางสำหรับผู้ดูแลระบบนำไปตรวจสอบคอนฟิกภายในเครื่องเป้าหมาย มิได้ถูกรันโดยเครื่องสแกน OPScaner จากภายนอกเครือข่าย*
                    </div>
                    <pre>{html.escape(h_check)}</pre>
                    <div style="font-size: 13.5pt; color: #334155; margin-top: 4px;">
                      • เกณฑ์ความปลอดภัยที่แนะนำ: {html.escape(safe_crit)}<br>
                      • ข้อจำกัดของคำสั่ง: ตรวจสอบเวอร์ชัน CLI เริ่มต้นของระบบ แนะนำตรวจสอบแพ็กเกจที่ติดตั้งผ่าน dpkg / rpm เพิ่มเติม
                    </div>
                  </div>
                  <div class="adv-code-box">
                    <div style="font-size: 14pt; color: #1e293b; font-weight: bold; margin-bottom: 2px;">แนวทางแก้ไขและเกณฑ์ความปลอดภัยที่แนะนำ:</div>
                    <div style="font-size: 13.5pt; color: #334155; line-height: 1.4;">
                      • <b>มาตรการแก้ไข:</b> วางแผนปรับปรุงและอัปเกรดซอฟต์แวร์เป็นเวอร์ชันที่ยังได้รับการบำรุงรักษาอย่างเป็นทางการ<br>
                      • <b>เกณฑ์ความปลอดภัยที่แนะนำ:</b> {html.escape(safe_crit)}<br>
                      • <b>ข้อแนะนำด้านสถาปัตยกรรม (Architectural Guidance):</b>
                      <div style="margin-left: 14px; margin-top: 2px;">
                        - หากพอร์ตนี้รันเป็น Container / Microservice แยกอิสระ ให้ปรับปรุง Base Image ของบริการนี้<br>
                        - หากเป็นการเปิดหลายพอร์ตที่เชื่อมโยงสู่ Shared Runtime เดียวกัน การอัปเกรดที่โฮสต์หลักจะครอบคลุมทุกพอร์ตทันที
                      </div>
                    </div>
                  </div>
                </div>
                """

            # 4. Session Chains / PHP Hardening (NO BORDER, NO BACKGROUND)
            session_html = ""
            if chains:
                for c_key, c_val in chains.items():
                    c_verdict_code = c_val.get("verdict_code")
                    if c_verdict_code in ("CONFIRMED", "VULN", "REVIEW", "AUDIT", "ARCHITECTURAL_RISK"):
                        c_title = c_val.get("title") or "Security Hardening Chain"
                        c_verdict = c_val.get("verdict") or "ตรวจพบข้อควรระวังในการตั้งค่า"
                        c_remedy = c_val.get("remediation") or "ปรับปรุงค่าคอนฟิกตามแนวทาง CIS Benchmark"
                        c_ini = c_val.get("hardening_ini") or "; ปรับแต่งคอนฟิกเพื่อความมั่นคงปลอดภัย"
                        
                        if c_key == "chain_e" or "109619" in c_title or "FastCGI" in c_title:
                            c_remedy = (
                                "1. [มาตรการลดความเสี่ยงโดยตรงสำหรับ GHSA-6wmf-4rv5-p3rp / CVE-2026-109619]: ในไฟล์ pool.d/www.conf กำหนด 'pm.max_requests = 500' เพื่อบังคับรีไซเคิล Worker Process ป้องกันสถานะ FastCGI ตกค้าง และปิด 'session.upload_progress.enabled = Off' ใน php.ini | 2. [เกณฑ์ Baseline การปฏิบัติงานทั่วไป (Operational Baseline Sizing)]: ปรับแต่งขนาดคำขอและหน่วยความจำให้เหมาะสมกับระบบ เช่น 'memory_limit = 256M' และ 'post_max_size = 32M'"
                            )
                            c_ini = (
                                "; --- 1. Direct Vulnerability Mitigation (GHSA-6wmf-4rv5-p3rp / CVE-2026-109619) ---\n"
                                "; ในไฟล์ php-fpm pool config (เช่น /etc/php/*/fpm/pool.d/www.conf):\n"
                                "pm.max_requests = 500\n\n"
                                "; ในไฟล์ php.ini:\n"
                                "session.upload_progress.enabled = Off\n\n"
                                "; --- 2. Operational Baseline Sizing (คำแนะนำทั่วไปตามขอบเขตงานระบบ) ---\n"
                                "memory_limit = 256M\n"
                                "post_max_size = 32M"
                            )

                        chain_endpoint_ctx = ""
                        if "109619" in c_title or "PHP-FPM" in c_title or port_val:
                            chain_endpoint_ctx = f"""<div style="font-size: 13.5pt; color: #0f172a; font-weight: bold; margin-bottom: 2px;">พอร์ตบริการที่เกี่ยวข้อง: {port_val} ({html.escape(port_service_name)}) &nbsp;|&nbsp; สถาปัตยกรรมที่คาดการณ์: PHP-FPM / FastCGI (ต้องตรวจสอบยืนยันจาก Host Configuration)</div>"""

                        session_html += f"""
                        <div class="adv-finding-item">
                          <div class="adv-item-title" style="font-size: 16pt; font-weight: bold; color: #000000; margin-bottom: 3px;">
                            ข้อควรระวังด้านการตั้งค่า: {html.escape(c_title)}
                          </div>
                          <div style="font-size: 14.5pt; color: #334155; margin-bottom: 6px; line-height: 1.4;">
                            {chain_endpoint_ctx}
                            ประเภทข้อค้นพบ: Architectural Precondition &nbsp;|&nbsp;
                            สถานะ: {html.escape(c_val.get('confidence', 'Conditional'))} &nbsp;|&nbsp;
                            รหัสการประเมิน: {html.escape(c_verdict_code)}
                          </div>
                          <p class="adv-para">
                            {html.escape(c_verdict)} แนะนำให้ผู้ดูแลระบบตรวจสอบ {html.escape(c_remedy)}
                          </p>
                          <div class="adv-code-box">
                            <div style="font-size: 15pt; color: #475569; margin-bottom: 2px;">แนวทางการตั้งค่า php.ini ที่แนะนำ:</div>
                            <pre>{html.escape(c_ini)}</pre>
                          </div>
                        </div>
                        """

            # Combine port section (only render if there are actionable findings on this port)
            port_content = f"{proof_html}{precond_html}{cves_html}{session_html}".strip()
            if not port_content:
                continue

            host_port_findings_html += f"""
            <div class="adv-port-section" style="margin-top: 14px; margin-bottom: 14px; break-inside: avoid; page-break-inside: avoid;">
              <div class="adv-port-title" style="font-size: 16pt; font-weight: bold; color: #000000; margin-bottom: 6px; break-after: avoid; page-break-after: avoid;">
                พอร์ตบริการ: {html.escape(str(port_val or '-'))} — {html.escape(port_service_name)}
              </div>
              {port_content}
            </div>
            """

        # Build Port-Service Fingerprint Mapping Table for this Device
        mapping_rows = ""
        seen_map_ports = set()
        unique_srv_profiles = set()
        unique_runtimes = set()
        for h in sorted(p_hosts, key=lambda x: (x.get("ports") or [x.get("port") or 0])[0] if (x.get("ports") or [x.get("port")]) else 0):
            p_val = (h.get("ports") or [h.get("port")])[0] if (h.get("ports") or [h.get("port")]) else None
            if not p_val or p_val in seen_map_ports:
                continue
            seen_map_ports.add(p_val)
            
            da = h.get("deep_audit") or {}
            nx_audit = da.get("nginx_audit", {})
            proto = h.get("protocol") or "TCP"
            
            srv_raw = h.get("webServer") or h.get("server") or nx_audit.get("server") or (h.get("headers") or {}).get("server") or "Web Service"
            if "ไม่มี" in str(srv_raw).lower():
                srv_name = "Network Service"
                ver_name = "-"
                evidence_str = "พอร์ตตอบสนองการเชื่อมต่อเครือข่าย"
            else:
                srv_str = str(srv_raw).strip()
                if " / " in srv_str:
                    srv_name = f"HTTP Service — Server Identity Ambiguous ({srv_str})"
                    ver_name = "-"
                elif "/" in srv_str:
                    parts = srv_str.split("/", 1)
                    srv_name = parts[0].strip()
                    ver_name = parts[1].strip()
                else:
                    srv_name = srv_str
                    ver_name = "-"
                
                php_v = h.get("php_version") or h.get("phpVersion")
                php_clean = str(php_v).strip() if php_v else ""
                if any(ign in php_clean.lower() for ign in ("no php", "none", "ไม่มี", "false", "n/a")):
                    php_clean = ""

                node_v = h.get("node_version") or h.get("nodeVersion")
                node_clean = str(node_v).strip() if node_v else ""
                if any(ign in node_clean.lower() for ign in ("no node", "none", "ไม่มี", "false", "n/a")):
                    node_clean = ""

                # 1. Detect Python runtime from banner
                py_match = re.search(r"Python/([\d\.]+)", f"{srv_raw} {ver_name}", re.I)
                py_clean = f"Python {py_match.group(1)}" if py_match else ""
                if py_clean:
                    unique_runtimes.add(py_clean)

                # 2. Detect PHP runtime
                php_num = ""
                if php_clean:
                    p_m = re.search(r"(\d+\.\d+\.[\d\w\.\-]+)", php_clean)
                    php_num = p_m.group(1) if p_m else php_clean.replace("PHP/", "").strip()
                    php_disp = f"PHP {php_num}"
                    ver_name = f"{ver_name} ({php_disp})" if ver_name != "-" else php_disp
                    unique_runtimes.add(php_disp)
                elif node_clean or (h.get("is_node") and h.get("runtime_version")):
                    nv = node_clean or str(h.get("runtime_version") or "").strip()
                    if nv and nv.lower() not in ("none", "ไม่มี"):
                        node_disp = nv if nv.upper().startswith("NODE") else f"Node.js {nv}"
                        ver_name = f"{ver_name} ({node_disp})" if ver_name != "-" else node_disp
                        unique_runtimes.add(node_disp)
                elif h.get("runtime_version") and "ไม่มี" not in str(h.get("runtime_version")):
                    rt_val = str(h.get("runtime_version")).strip()
                    ver_name = f"{ver_name} ({rt_val})" if ver_name != "-" else rt_val
                    unique_runtimes.add(rt_val)
                
                if srv_name and srv_name != "Network Service":
                    unique_srv_profiles.add(srv_name)
                
                evidence_str = f"Server Banner: {srv_raw}"
                hdr_powered = (h.get("headers") or {}).get("x-powered-by")
                if " / " in srv_str and php_clean:
                    evidence_str = f"Server Banner: {srv_raw} | Runtime from Header: X-Powered-By: PHP/{php_num}"
                elif hdr_powered:
                    evidence_str += f" | Runtime from Header: X-Powered-By: {hdr_powered}"
                elif php_clean and php_clean not in evidence_str:
                    evidence_str += f" | {php_disp}"
            
            mapping_rows += f"""
            <tr>
              <td style="text-align: center;">{html.escape(str(p_val))}</td>
              <td style="text-align: center;">{html.escape(str(proto))}</td>
              <td>{html.escape(str(srv_name))}</td>
              <td>{html.escape(str(ver_name))}</td>
              <td>{html.escape(str(evidence_str))}</td>
            </tr>
            """
        
        sorted_runtimes_str = ", ".join(sorted(unique_runtimes, key=lambda x: (0 if "Python" in x else 1, x)))

        # Clean service families for display
        srv_families = []
        for s in unique_srv_profiles:
            if "Ambiguous" in s:
                srv_families.append("Ambiguous Proxy")
            elif "Werkzeug" in s or "Python" in s:
                srv_families.append("Werkzeug")
            elif "Apache" in s:
                srv_families.append("Apache")
            elif "nginx" in s.lower():
                srv_families.append("NGINX")
            elif "lighttpd" in s.lower():
                srv_families.append("Lighttpd")
            elif "iis" in s.lower():
                srv_families.append("Microsoft-IIS")
            else:
                srv_families.append(s.split()[0])
        family_order = {"Werkzeug": 1, "Apache": 2, "NGINX": 3, "Lighttpd": 4, "Microsoft-IIS": 5, "Ambiguous Proxy": 6}
        sorted_families = sorted(set(srv_families), key=lambda x: (family_order.get(x, 99), x))
        families_str = f"Service Families: {', '.join(sorted_families)}" if sorted_families else "Service Families"

        port_mapping_table_html = f"""
        <div style="margin: 6px 0 14px 0; break-inside: avoid; page-break-inside: avoid;">
          <div style="font-size: 15pt; font-weight: bold; color: #000000; margin-bottom: 3px;">
            ตารางจับคู่พอร์ตและข้อมูลบริการที่ตรวจพบ (Port &amp; Service Fingerprint Mapping):
          </div>
          <table class="adv-table" style="font-size: 13.5pt; margin: 3px 0 6px 0; width: 100%;">
            <thead>
              <tr>
                <th style="width: 65px; text-align: center;">Port</th>
                <th style="width: 75px; text-align: center;">Protocol</th>
                <th style="width: 140px;">Service</th>
                <th style="width: 160px;">Version</th>
                <th>หลักฐานที่ตรวจพบ (Evidence)</th>
              </tr>
            </thead>
            <tbody>
              {mapping_rows}
            </tbody>
          </table>
          <div style="font-size: 13pt; color: #334155; margin-top: 4px; line-height: 1.35;">
            • <b>สรุปลายนิ้วมือบริการ (Observed Fingerprint Profiles):</b> ตรวจพบ {len(seen_map_ports)} Service Endpoints ({len(seen_map_ports)} Observed Banner Signatures จัดกลุ่มได้เป็น {len(sorted_families)} ตระกูลบริการหลัก ({families_str}) / {len(unique_runtimes)} รูปแบบ Runtime Profiles: {sorted_runtimes_str})<br>
            • <b>ข้อสรุปเชิงสถาปัตยกรรมจากมุมมองภายนอก (Architectural Assessment from External View):</b> 
            การตรวจพบ Application Fingerprint ที่แตกต่างกันบนหลาย Service Ports ภายใต้ IP เดียวกัน บ่งชี้ว่าแต่ละ Service Endpoint อาจทำงานอยู่บน Execution Environment ที่แตกต่างกัน หรือมีระบบ Reverse Proxy, NAT, Port Forwarding หรือ Containerization อยู่เบื้องหลัง อย่างไรก็ตาม ข้อมูลจากการตรวจภายนอกแบบ Black-box เพียงอย่างเดียวไม่เพียงพอที่จะยืนยันจำนวน Physical Servers, Virtual Machines หรือ Containers ที่แท้จริงได้ จึงจัดประเภทผลดังกล่าวเป็น Architecture Assessment และแนะนำให้ใช้ชุดคำสั่งด้านล่างเพื่อตรวจสอบยืนยันโครงสร้างจริงต่อไป
          </div>
          <div class="adv-code-box" style="margin-top: 4px; margin-bottom: 2px;">
            <div style="font-size: 13.5pt; color: #1e293b; font-weight: bold; margin-bottom: 4px;">
              คำแนะนำสำหรับผู้ดูแลระบบในการตรวจสอบสถาปัตยกรรมจริงของ IP นี้ (Host-based Architecture Verification):
            </div>
            <div style="font-size: 13pt; color: #334155; margin-bottom: 2px;"><b>1. ตรวจสอบ Listening Ports และ Process เบื้องหลัง (ต้องใช้สิทธิ์ sudo):</b></div>
            <pre>sudo ss -tulpn | grep -E ':(5050|808[0-8])\\b'</pre>

            <div style="font-size: 13pt; color: #334155; margin-top: 4px; margin-bottom: 2px;"><b>2. ตรวจสอบ Docker Containers และ Port Mapping (กรณีระบบใช้ Container):</b></div>
            <pre>docker ps --format "table {{{{.Names}}}}\\t{{{{.Ports}}}}\\t{{{{.Image}}}}" 2>/dev/null || true</pre>

            <div style="font-size: 13pt; color: #334155; margin-top: 4px; margin-bottom: 2px;"><b>3. ตรวจสอบกฎการ Forward พอร์ตของไฟร์วอลล์ภายใน (iptables / nftables):</b></div>
            <pre>sudo iptables -t nat -L -n -v 2>/dev/null || sudo nft list ruleset 2>/dev/null || true</pre>
            <div style="font-size: 12pt; color: #64748b; margin-top: 4px;">
              *ข้อจำกัด: ss ตรวจเฉพาะใน Network Namespace ปัจจุบัน, docker ps ตรวจเฉพาะ Docker Daemon ที่เข้าถึงได้ (ไม่รวม K8s อื่น) และหาก IP นี้เป็น Gateway/Reverse Proxy ต้องตรวจสอบที่อุปกรณ์ต้นทางเพิ่มเติม*
            </div>
          </div>
        </div>
        """ if mapping_rows else ""

        # Assemble Full Device Block (NO BORDER, NO BACKGROUND)
        vulnerable_devices_html += f"""
        <div class="adv-device-block">
          <div class="adv-device-title" style="font-size: 16pt; font-weight: bold; color: #000000; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <span>อุปกรณ์ที่พบความเสี่ยงลำดับที่ {vuln_device_count}: {html.escape(dev_name)} ({html.escape(ip)})</span>
            <div><span class="{host_badge_cls}">[{host_max_sev}]</span></div>
          </div>
          
          <div style="font-size: 16pt; color: #334155; margin-bottom: 8px;">
            ที่อยู่ IP: {html.escape(ip)} &nbsp;|&nbsp; พอร์ตบริการที่เปิด: {html.escape(ports_str)} &nbsp;|&nbsp; บริการ: {html.escape(tech_summary)}
          </div>

          {port_mapping_table_html}
          {host_port_findings_html}
        </div>
        """

    if not vulnerable_devices_html:
        vulnerable_devices_html = """
        <div class="adv-finding-item">
          <p class="adv-para" style="text-align: center; color: #16a34a; margin: 24px 0;">
            ✓ จากการตรวจสอบตามขอบเขตและวิธีการที่กำหนด ยังไม่พบหลักฐานของข้อค้นพบระดับวิกฤต (Critical) หรือระดับสูง (High) บนอุปกรณ์ใดในเครือข่าย
            <br><span style="font-size: 16pt; color: #475569;">(ผลดังกล่าวไม่ใช่การรับรองว่าระบบปลอดภัยทั้งหมด ผู้ดูแลระบบควรติดตามแพตช์และทบทวนการตั้งค่าตามรอบระยะเวลาที่เหมาะสม)</span>
          </p>
        </div>
        """

    survey_qr_img = f"data:image/png;base64,{SURVEY_QR_PNG_B64}" if SURVEY_QR_PNG_B64 else ""
    total_vulns = total_findings_count

    if not has_any_risk:
        exec_summary_html = f"""
      <div class="adv-heading">สรุปผลการประเมินภาพรวมความปลอดภัยเชิงรุก</div>
      <p class="adv-para">
        รายงานฉบับนี้จัดทำขึ้นเพื่อแจ้งผลการตรวจสอบความมั่นคงปลอดภัยสำหรับผู้ดูแลระบบ โดยจากการตรวจสอบระบบสารสนเทศและบริการเครือข่ายในวง IP {html.escape(target_scope)} (รวมทั้งสิ้น {total_scanned} ระบบ) อ้างอิงตามเกณฑ์มาตรฐานความปลอดภัยสากล NIST SP 800-115 และข้อมูลช่องโหว่ (CVE)
      </p>
      <p class="adv-para">
        ผลการตรวจสอบพบว่า ระบบทั้งหมดอยู่ในสถานะไม่พบสัญญาณความเสี่ยงตามขอบเขตการตรวจประเมิน โดยไม่พบช่องโหว่ความเสี่ยงระดับวิกฤต (Critical), ระดับสูง (High) หรือระดับปานกลาง (Medium) บนบริการที่เปิดให้เข้าถึงได้ อุปกรณ์ส่วนใหญ่เป็นเครื่องลูกข่ายภายในและอุปกรณ์เครือข่ายที่มีการปิดกั้นพอร์ตบริการด้วยไฟร์วอลล์อย่างถูกต้อง
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

      <div style="margin-top: 14px; margin-bottom: 20px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
          <span style="font-size: 18pt; color: #16a34a;">✓</span>
          <span style="font-size: 16pt; color: #166534;">ผลการตรวจประเมิน: ไม่พบข้อค้นพบความเสี่ยงระดับวิกฤตหรือระดับสูงตามขอบเขตการตรวจสอบ</span>
        </div>
        <div style="font-size: 16pt; color: #1e293b; line-height: 1.6;">
          <p style="margin: 0 0 8px 0;">ผลสรุปการตรวจประเมินทางเทคนิคสำหรับระบบในขอบเขต:</p>
          <ul style="margin: 0 0 12px 18px; padding: 0;">
            <li>Remote Code Execution (RCE): ไม่พบจุดรับคำสั่งหรือพฤติกรรมที่เสี่ยงต่อการถูกสั่งรันโค้ดจากระยะไกล</li>
            <li>Web Stack Vulnerabilities: ไม่พบช่องโหว่ความรุนแรงสูงใน PHP, Node.js หรือ Web Server Services</li>
            <li>Network Perimeter: อุปกรณ์ลูกข่ายส่วนใหญ่มีการปิดกั้นพอร์ตบริการ หรือตั้งค่าไฟร์วอลล์อย่างถูกต้อง</li>
          </ul>
          <p style="margin: 0; color: #15803d; font-size: 16pt;">
            💡 ข้อเสนอแนะในการกำกับดูแล: ควรรักษามาตรฐานความมั่นคงปลอดภัย (Cyber Hygiene) ต่อเนื่อง โดยหมั่นอัปเดตระบบปฏิบัติการ ซอฟต์แวร์ และตรวจสอบการเปิดเผยพอร์ตเครือข่ายภายนอกเป็นประจำ
          </p>
        </div>
      </div>
        """
    else:
        tax_items = []
        if confirmed_vulns_count > 0:
            tax_items.append(f"<li>ช่องโหว่ที่ยืนยันผลกระทบได้ (Confirmed Vulnerabilities): {confirmed_vulns_count} รายการ (มีหลักฐานเชิงประจักษ์จากการทดสอบภายนอก เช่น RCE หรือไฟล์หลุด)</li>")
        if conditional_findings_count > 0:
            tax_items.append(f"<li>ข้อค้นพบตามเงื่อนไขสถาปัตยกรรม (Conditional Findings): {conditional_findings_count} รายการ (ตรวจพบบริการหรือเวอร์ชันที่ตรงกับช่องโหว่ ซึ่งต้องตรวจสอบคอนฟิกภายในเพิ่มเติม)</li>")
        if lifecycle_risks_count > 0:
            eol_ports_count = len(eol_ports)
            unique_eol_count = len(eol_versions)
            ver_list_str = f" จาก {unique_eol_count} เวอร์ชันหลัก: {', '.join(sorted(eol_versions))}" if unique_eol_count > 0 else ""
            if eol_ports_count > 1:
                port_inst_txt = f" ({lifecycle_risks_count} instances บน {eol_ports_count} พอร์ตบริการ{ver_list_str})"
            else:
                port_inst_txt = f" (1 instance บน 1 พอร์ตบริการ{ver_list_str})"
            tax_items.append(f"<li>ความเสี่ยงตามวงจรชีวิตซอฟต์แวร์ (Software Lifecycle Risks - EOL): {lifecycle_risks_count} รายการ{port_inst_txt} (ซอฟต์แวร์สิ้นสุดระยะสนับสนุนอย่างเป็นทางการ)</li>")
        tax_list_html = f"""<ul class="adv-list" style="margin: 2px 0 4px 18px; line-height: 1.3;">{''.join(tax_items)}</ul>""" if tax_items else ""

        cve_summary = f" โดยมีรายการช่องโหว่ความมั่นคงปลอดภัยสากลที่เกี่ยวข้อง (Unique CVEs) รวม {len(all_matched_cves)} รายการ" if all_matched_cves else ""
        safe_tail = f" และมีอุปกรณ์ที่ไม่พบสัญญาณความเสี่ยงตามขอบเขตและระเบียบวิธีตรวจประเมินจำนวน {safe_hosts_count} ระบบ" if safe_hosts_count > 0 else ""

        if confirmed_vulns_count > 0:
            remediation_strategy_text = "โดยทางทีมงานขอแนะนำให้ผู้ดูแลระบบเร่งดำเนินการแก้ไขตามลำดับความสำคัญ โดยเน้นข้อค้นพบลักษณะยืนยันผลกระทบแล้ว (Confirmed Vulnerabilities) ก่อนเป็นอันดับแรก จากนั้นนำคำสั่งในคู่มือ Host-based Verification Guide ไปตรวจสอบคอนฟิกภายในสำหรับรายการตามเงื่อนไข (Conditional Findings) ต่อไป"
        elif conditional_findings_count > 0 and lifecycle_risks_count > 0:
            remediation_strategy_text = "เนื่องจากผลการประเมินรอบนี้ไม่พบข้อค้นพบลักษณะยืนยันการถูกโจมตี (No Confirmed Exploits) ทางทีมงานจึงแนะนำให้ผู้ดูแลระบบจัดลำดับความเร่งด่วนในการดำเนินงาน ดังนี้: (1) นำคู่มือ Host-based Verification Guide ในรายงานไปตรวจสอบและปิดเงื่อนไขการตั้งค่าภายในของข้อค้นพบตามเงื่อนไข (Conditional Findings) ที่มีค่า CVSS สูง และ (2) วางแผนปรับปรุงรุ่นซอฟต์แวร์ที่หมดอายุการสนับสนุน (EOL) สู่เวอร์ชันปัจจุบันที่ยังได้รับการดูแลรักษาความมั่นคงปลอดภัย"
        elif conditional_findings_count > 0:
            remediation_strategy_text = "เนื่องจากข้อค้นพบทั้งหมดจัดเป็นข้อค้นพบตามเงื่อนไข (Conditional Findings) ทางทีมงานขอแนะนำให้ผู้ดูแลระบบนำคู่มือ Host-based Verification Guide ไปตรวจสอบคอนฟิกบนเซิร์ฟเวอร์จริงเพื่อยืนยันและปิดกั้นเงื่อนไขความเสี่ยงดังกล่าว"
        elif lifecycle_risks_count > 0:
            remediation_strategy_text = "ทางทีมงานขอแนะนำให้ผู้ดูแลระบบวางแผนการปรับปรุงรุ่นซอฟต์แวร์ที่สิ้นสุดระยะสนับสนุน (EOL) สู่เวอร์ชันปัจจุบันที่ได้รับการสนับสนุนอย่างเป็นทางการเพื่อความมั่นคงปลอดภัยระยะยาว"
        else:
            remediation_strategy_text = "ขอแนะนำให้ผู้ดูแลระบบหมั่นรักษามาตรฐานความมั่นคงปลอดภัย (Cyber Hygiene) และตรวจติดตามระบบอย่างต่อเนื่อง"

        exec_summary_html = f"""
      <div class="adv-heading" style="margin-bottom: 4px;">สรุปผลการประเมินภาพรวมความเสี่ยงเชิงรุก</div>
      <p class="adv-para" style="margin-bottom: 4px;">
        รายงานฉบับนี้จัดทำขึ้นเพื่อแจ้งข้อค้นพบทางเทคนิคสำหรับผู้ดูแลระบบ จากการตรวจสอบระบบสารสนเทศและบริการเครือข่ายในวง IP {html.escape(target_scope)} (รวม {total_scanned} ระบบ) อ้างอิงตามกรอบมาตรฐาน NIST SP 800-115, ฐานข้อมูลช่องโหว่สากล (CVE / NVD) และข้อกำหนด FIRST TLP
      </p>
      <p class="adv-para" style="margin-bottom: 3px;">
        ผลการประเมินพบระบบหรืออุปกรณ์ที่พบความเสี่ยง (Affected Assets) จำนวน {affected_hosts_count} ระบบ รวมข้อค้นพบความเสี่ยงทั้งหมด {total_findings_count} รายการ{cve_summary} โดยจำแนกตามมาตรฐานการตรวจประเมิน (Assessment Taxonomy) ออกเป็นดังนี้:
      </p>
      {tax_list_html}
      <p class="adv-para" style="margin-top: 3px; margin-bottom: 4px;">
        {safe_tail.strip()} {remediation_strategy_text}
      </p>
        """
        page2_heading = "รายละเอียดข้อค้นพบทางเทคนิคและแนวทางการแก้ไขจำแนกตามอุปกรณ์"
        legend_taxonomy_html = """
      <div style="margin-top: 6px; margin-bottom: 12px; font-size: 14pt; color: #1e293b; line-height: 1.4; break-inside: avoid; page-break-inside: avoid;">
        <div style="font-size: 15pt; font-weight: bold; color: #000000; margin-bottom: 4px;">
          เกณฑ์จำแนกสถานะข้อค้นพบตามมาตรฐานสากล (Assessment Status Taxonomy):
        </div>
        <table style="width: 100%; border-collapse: collapse; border: none; font-size: 14pt; line-height: 1.35;">
          <tr>
            <td style="width: 50%; padding: 2px 10px 2px 0; vertical-align: top; border: none;">
              <span style="color: #991b1b; font-weight: bold;">● ยืนยันช่องโหว่แล้ว (Confirmed):</span> ยืนยันผลกระทบเชิงประจักษ์จากภายนอก (Live PoC / Canary Token / File Leak) ต้องแก้ไขด่วนที่สุด
            </td>
            <td style="width: 50%; padding: 2px 0 2px 10px; vertical-align: top; border: none;">
              <span style="color: #c2410c; font-weight: bold;">● ข้อค้นพบตามเงื่อนไข (Conditional):</span> ตรวจพบบริการและเวอร์ชันที่อยู่ในขอบเขตเสี่ยง แต่เวกเตอร์โจมตีต้องอาศัยการตั้งค่าเฉพาะภายใน
            </td>
          </tr>
          <tr>
            <td style="padding: 2px 10px 2px 0; vertical-align: top; border: none;">
              <span style="color: #854d0e; font-weight: bold;">● ความเสี่ยงวงจรชีวิต (Lifecycle EOL):</span> ซอฟต์แวร์สิ้นสุดระยะสนับสนุนอย่างเป็นทางการ (End-of-Life) ไม่มีแพตช์อัปเดต ต้องวางแผนย้ายรุ่น
            </td>
            <td style="padding: 2px 0 2px 10px; vertical-align: top; border: none;">
              <span style="color: #15803d; font-weight: bold;">● ไม่พบความเสี่ยง (No Findings):</span> ผ่านการตรวจสอบตามขอบเขตและระเบียบวิธี ไม่พบสัญญาณความเสี่ยงตามเกณฑ์ที่กำหนด
            </td>
          </tr>
        </table>
      </div>
        """
        page2_content = f"""
      <p class="adv-para">
        ส่วนนี้นำเสนอรายละเอียดเชิงเทคนิคของข้อค้นพบและช่องโหว่ความมั่นคงปลอดภัยโดยจำแนกตามอุปกรณ์ที่ตรวจพบ เพื่อให้ผู้ดูแลระบบเห็นภาพรวมความเสี่ยงและรายละเอียดเฉพาะของแต่ละอุปกรณ์อย่างชัดเจน พร้อมข้อมูลบริการที่เปิด คำสั่งตรวจสอบจริงบนเครื่อง (Host-Check) และแนวทางการแก้ไขที่เหมาะสมกับอุปกรณ์นั้นๆ
      </p>

      {legend_taxonomy_html}
      {vulnerable_devices_html}
        """

    attack_surface_table_html = ""
    if table_rows_html.strip():
        attack_surface_table_html = f"""
      <div class="adv-subhead">ตารางสรุปรายการอุปกรณ์และบริการเครือข่ายที่ตรวจพบ</div>
      <div class="adv-table-wrap">
        <table class="adv-table">
          <thead>
            <tr>
              <th style="width: 45px; text-align: center;">ลำดับ</th>
              <th style="width: 120px;">IP</th>
              <th style="width: 80px; text-align: center;">PORT</th>
              <th>ประเภทอุปกรณ์</th>
              <th style="width: 190px;">Observed Service / Environment Indicators (กลุ่มบ่งชี้บริการและสภาพแวดล้อมที่สังเกตได้)</th>
              <th style="width: 110px; text-align: center;">สถานะความเสี่ยง</th>
            </tr>
          </thead>
          <tbody>
            {table_rows_html}
          </tbody>
        </table>
      </div>
        """

    return f"""<!DOCTYPE html>
<html lang="th">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>เอกสารแจ้งเตือนความมั่นคงปลอดภัยไซเบอร์ (TLP:AMBER) - {ref_id}</title>
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
        รหัสอ้างอิง: {ref_id} &nbsp;|&nbsp; วันที่: {date_str} &nbsp;|&nbsp; ขอบเขต: {html.escape(target_scope)} &nbsp;|&nbsp; เครื่องมือ: OPScaner Engine (Non-intrusive Heuristic Scan)
      </div>

      <div class="adv-tlp-rule-box">
        ข้อกำหนดการเผยแพร่ตามมาตรฐาน FIRST TLP (TLP:AMBER): ข้อมูลในรายงานฉบับนี้จำกัดการเข้าถึงเฉพาะบุคคลหรือหน่วยงานที่มีความจำเป็นต้องใช้ข้อมูลในการปฏิบัติงาน (Need-to-know) ผู้รับสามารถแบ่งปันต่อได้ภายในองค์กรของตน รวมถึงคู่ค้าหรือบุคคลภายนอกที่มีความจำเป็นต้องทราบเพื่อการป้องกัน ตรวจสอบ หรือบรรเทาผลกระทบจากภัยคุกคาม ห้ามเผยแพร่สู่สาธารณะ
      </div>

      {exec_summary_html}

      {attack_surface_table_html}

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
    <div class="a4-paper-sheet page-break-section" id="sheet-references" style="font-size: 14pt; line-height: 1.35;">
      <div class="adv-heading" style="margin-bottom: 6px;">เอกสารอ้างอิงและช่องทางการประสานงานรับมือเหตุการณ์ความมั่นคงปลอดภัย</div>
      
      <p class="adv-para" style="margin-bottom: 4px;">
        การตรวจประเมินและจัดทำรายงานฉบับนี้ ดำเนินการโดยอ้างอิงตามกรอบมาตรฐานความมั่นคงปลอดภัยสารสนเทศและแนวปฏิบัติสากล ได้แก่:
      </p>
      <ul class="adv-list" style="margin: 2px 0 6px 18px; line-height: 1.3;">
        <li>NIST SP 800-115: Technical Guide to Information Security Testing and Assessment (กรอบการประเมินและทดสอบช่องโหว่)</li>
        <li>ThaiCERT Advisory &amp; Guidance: แนวปฏิบัติการบริหารจัดการและรับมือช่องโหว่ความมั่นคงปลอดภัยบนเว็บแอปพลิเคชัน</li>
        <li>CIS Benchmarks: Center for Internet Security (แนวทางการตั้งค่าความมั่นคงปลอดภัยระบบแม่ข่าย Nginx, PHP และ Node.js)</li>
        <li>National Vulnerability Database (NVD/NIST): ฐานข้อมูลรายการช่องโหว่และความเสี่ยงสากล (Common Vulnerabilities and Exposures)</li>
        <li>FIRST Standards: Traffic Light Protocol (TLP) มาตรฐานการจำแนกชั้นความลับและการแลกเปลี่ยนข้อมูลไซเบอร์</li>
      </ul>

      <div class="adv-subhead" style="margin-top: 8px; margin-bottom: 2px; font-weight: bold;">ระเบียบวิธีและขอบเขตการตรวจประเมิน (Assessment Methodology &amp; Scope)</div>
      <p class="adv-para" style="margin-bottom: 4px;">
        การประเมินนี้ใช้ระเบียบวิธีทดสอบแบบไม่รุกล้ำระบบ (Non-intrusive Heuristic Assessment) จากมุมมองภายนอกเครือข่าย ณ เวลาทดสอบ (Point-in-time External Assessment) โดยเครื่องมือ OPScaner วางกรอบการวิเคราะห์ออกเป็น 3 ระดับตามหลักวิชาการ:
      </p>
      <ul class="adv-list" style="margin: 2px 0 6px 18px; line-height: 1.35;">
        <li><b>Level 1 — Service Endpoint Detection:</b> ตรวจระบุ IP:Port, Protocol, Server Banner และ Runtime Fingerprint ที่สังเกตได้จริงจากภายนอก</li>
        <li><b>Level 2 — Infrastructure Correlation:</b> วิเคราะห์ความสัมพันธ์และความแตกต่างของ Service Endpoints ผ่าน L7 Application Fingerprint และ L4 Network Stack เพื่อประเมินความเป็นไปได้เชิงโครงสร้าง</li>
        <li><b>Level 3 — Architecture Verification:</b> จำแนกโครงสร้างสถาปัตยกรรมจริง (Physical Server, Virtual Machine, Container, NAT หรือ Reverse Proxy) ซึ่งเป็นสิ่งที่ Black-box Network Assessment ไม่กล่าวอ้างเกินหลักฐาน โดยจัดเตรียมคำสั่ง Host-based Verification Guide เพื่อให้ผู้ดูแลระบบที่มีสิทธิ์ภายในใช้ตรวจสอบยืนยันโครงสร้างจริง</li>
      </ul>

      <div class="adv-subhead" style="margin-top: 8px; margin-bottom: 2px; font-weight: bold;">ช่องทางการประสานงานรับมือเหตุการณ์ความมั่นคงปลอดภัย (Incident Response Contacts)</div>
      <p class="adv-para" style="margin-bottom: 4px;">
        หากหน่วยงานของท่านตรวจพบเหตุการณ์ภัยคุกคามทางไซเบอร์ หรือประสงค์ขอรับคำปรึกษาทางเทคนิคเพิ่มเติม สามารถประสานงานฝ่ายปฏิบัติการได้ตามช่องทางดังต่อไปนี้:
      </p>

      <div style="margin: 4px 0 6px 0; font-size: 14pt;">
        <div style="color: #000000; margin-bottom: 3px;">
          ศูนย์ประสานการรักษาความมั่นคงปลอดภัยระบบคอมพิวเตอร์แห่งชาติ (ThaiCERT / สกมช.)
        </div>
        <table style="width: 100%; font-size: 14pt; border-collapse: collapse; border: none; line-height: 1.25;">
          <tr>
            <td style="width: 28%; color: #475569; padding: 1px 0; border: none;">เว็บไซต์หลัก:</td>
            <td style="padding: 1px 0; border: none;"><a href="https://www.ncsa.or.th" target="_blank" style="color: #0284c7; text-decoration: underline;">https://www.ncsa.or.th</a></td>
          </tr>
          <tr>
            <td style="color: #475569; padding: 1px 0; border: none;">สายด่วนรับแจ้งเหตุ (24 ชม.):</td>
            <td style="padding: 1px 0; border: none;">02-114-3531 (สายด่วนรับแจ้งเหตุฉุกเฉินทางไซเบอร์ สกมช.)</td>
          </tr>
          <tr>
            <td style="color: #475569; padding: 1px 0; border: none;">โทรศัพท์สำนักงาน:</td>
            <td style="padding: 1px 0; border: none;">02-143-7777 (ในวันและเวลาราชการ)</td>
          </tr>
          <tr>
            <td style="color: #475569; padding: 1px 0; border: none;">อีเมลประสานงาน ThaiCERT:</td>
            <td style="padding: 1px 0; border: none;"><a href="mailto:thaicert@ncsa.or.th" style="color: #0284c7; text-decoration: underline;">thaicert@ncsa.or.th</a></td>
          </tr>
          <tr>
            <td style="color: #475569; padding: 1px 0; border: none;">อีเมลรับแจ้งเหตุสำรอง:</td>
            <td style="padding: 1px 0; border: none;"><a href="mailto:incident@thaicert.or.th" style="color: #0284c7; text-decoration: underline;">incident@thaicert.or.th</a></td>
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

      <div style="margin: 16px auto; max-width: 480px; text-align: center; padding: 10px 0;">
        <div style="font-size: 16pt; color: #000000; margin-bottom: 4px;">สแกนคิวอาร์โค้ดเพื่อทำแบบประเมินความพึงพอใจ</div>
        <p class="adv-para" style="text-indent: 0; text-align: center; margin-bottom: 12px; color: #475569;">
          ผู้รับเอกสารสามารถใช้สมาร์ตโฟนสแกน QR Code ด้านล่างนี้เพื่อเข้าสู่แบบประเมินและส่งข้อเสนอแนะ
        </p>
        {"<div style='margin-bottom: 10px;'><img src='" + survey_qr_img + "' style='width: 115px; height: 115px; border: none; padding: 0; display: inline-block;' alt='Survey QR' /></div>" if survey_qr_img else ""}
        <div style="font-size: 16pt; color: #000000; line-height: 1.35;">
          ลิงก์ทำแบบประเมินออนไลน์: <br>
          <a href="https://www.ncsa.or.th/survey" target="_blank" style="color: #0284c7; text-decoration: underline;">https://www.ncsa.or.th/survey</a>
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
