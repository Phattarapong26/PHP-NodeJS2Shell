"""
Headless PDF Generator & Vector Footer Stamping Engine
Uses Headless Chromium for pixel-perfect A4 CSS layout rendering
and ReportLab + pypdf for official vector running footers on 100% of pages.
"""

import io
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from typing import Tuple, Dict, Any, Optional

from .amber_builder import build_amber_advisory_html


def build_pdf_footer_overlay(total_pages: int) -> io.BytesIO:
    """
    Creates a multi-page PDF overlay with ReportLab:
    - Left: สำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สกมช.)
    - Center: TLP:AMBER pill and 3 traffic light circles
    - Right: Dynamic Page Number (e.g. 1 | P a g e)
    - Top: Divider line
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    fonts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fonts")
    candidate_fonts = [
        os.path.join(fonts_dir, "THSarabunNew.ttf"),
        "/usr/local/share/fonts/sarabun/THSarabunNew.ttf",
        "/usr/share/fonts/truetype/sarabun/THSarabunPSK.ttf",
        "/usr/share/fonts/truetype/tlwg/Laksaman.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    font_name = "THSarabunPSK"
    bold_name = "THSarabunPSK-Bold"

    chosen_regular = None
    for p in candidate_fonts:
        if os.path.exists(p):
            chosen_regular = p
            break

    candidate_bolds = [
        os.path.join(fonts_dir, "THSarabunNew Bold.ttf"),
        "/usr/local/share/fonts/sarabun/THSarabunNew Bold.ttf",
        "/usr/share/fonts/truetype/sarabun/THSarabunPSK-Bold.ttf",
        "/usr/share/fonts/truetype/tlwg/Laksaman-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ]
    chosen_bold = None
    for p in candidate_bolds:
        if os.path.exists(p):
            chosen_bold = p
            break

    try:
        if chosen_regular:
            pdfmetrics.registerFont(TTFont(font_name, chosen_regular))
        else:
            font_name = "Helvetica"
    except Exception:
        font_name = "Helvetica"

    try:
        if chosen_bold:
            pdfmetrics.registerFont(TTFont(bold_name, chosen_bold))
        else:
            bold_name = font_name
    except Exception:
        bold_name = font_name

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    page_w, page_h = A4
    margin_left = 56.7   # 20mm
    margin_right = 56.7  # 20mm

    for p in range(1, total_pages + 1):
        # 1. Divider Line omitted per design requirement (Zero borders)

        # 2. Left Agency Name
        c.setFont(font_name, 9)
        c.setFillColorRGB(0.35, 0.38, 0.42)
        agency_text = "รายงานประเมินความมั่นคงปลอดภัยไซเบอร์ (Cybersecurity Technical Assessment Report)"
        c.drawString(margin_left, 24, agency_text)

        # 3. Center TLP:AMBER Symbol + Traffic Light Box (No border / stroke=0)
        cx = page_w / 2.0
        pill_text = "TLP:AMBER"
        c.setFont(bold_name, 8)
        tw = c.stringWidth(pill_text, bold_name, 8)

        # Amber Pill background
        c.setFillColorRGB(0.96, 0.62, 0.04) # #f59e0b
        c.roundRect(cx - tw - 20, 20, tw + 8, 12, 2, fill=1, stroke=0)
        # Pill text
        c.setFillColorRGB(0.06, 0.09, 0.16) # #0f172a
        c.drawString(cx - tw - 16, 23, pill_text)

        # Traffic light box (borderless)
        box_x = cx - 8
        c.setFillColorRGB(0.2, 0.25, 0.33)
        c.roundRect(box_x, 20, 28, 12, 3, fill=1, stroke=0)

        # 3 circles inside traffic light box (White, Amber, White, borderless)
        amber_lights = ((0.4, 0.45, 0.53), (0.96, 0.62, 0.04), (0.4, 0.45, 0.53))
        for idx, (r, g, b) in enumerate(amber_lights):
            c.setFillColorRGB(r, g, b)
            c.circle(box_x + 5.5 + idx * 8.5, 26, 3.2, fill=1, stroke=0)

        # 4. Right Page Number
        c.setFont(font_name, 10)
        c.setFillColorRGB(0.44, 0.45, 0.47)
        page_str = f"{p} | P a g e"
        pw = c.stringWidth(page_str, font_name, 10)
        c.drawString(page_w - margin_right - pw, 24, page_str)

        c.showPage()

    c.save()
    buf.seek(0)
    return buf


def stamp_pdf_footers(raw_pdf_bytes: bytes) -> bytes:
    """Stamps vector running footers on every page using pypdf."""
    try:
        import pypdf
    except ImportError:
        return raw_pdf_bytes

    in_stream = io.BytesIO(raw_pdf_bytes)
    reader = pypdf.PdfReader(in_stream)
    total_pages = len(reader.pages)
    if total_pages == 0:
        return raw_pdf_bytes

    try:
        overlay_stream = build_pdf_footer_overlay(total_pages)
        overlay_reader = pypdf.PdfReader(overlay_stream)

        writer = pypdf.PdfWriter()
        for idx, page in enumerate(reader.pages):
            if idx < len(overlay_reader.pages):
                page.merge_page(overlay_reader.pages[idx])
            writer.add_page(page)

        out_stream = io.BytesIO()
        writer.write(out_stream)
        out_stream.seek(0)
        return out_stream.getvalue()
    except Exception:
        return raw_pdf_bytes


def find_chrome_binary() -> Optional[str]:
    """Find available Chromium or Chrome executable across Linux and macOS platforms."""
    candidates = [
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        shutil.which("google-chrome"),
        shutil.which("chrome"),
        shutil.which("google-chrome-stable"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def generate_amber_pdf(scan_report_data: Dict[str, Any]) -> Tuple[bytes, str]:
    """
    Renders A4 TLP:AMBER PDF using Headless Chromium and vector footer stamping.
    Returns (pdf_bytes, filename).
    """
    now = datetime.now()
    scope = scan_report_data.get("target") or scan_report_data.get("target_id") or scan_report_data.get("subnet") or "Target_Audit"
    scope_clean = re.sub(r"[^a-zA-Z0-9_\-]+", "_", str(scope)).strip("_")
    if not scope_clean:
        scope_clean = "Network_Audit"
    filename = f"NCSA_Advisory_TLPAMBER_{scope_clean}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"

    html_content = build_amber_advisory_html(scan_report_data)

    chrome_bin = find_chrome_binary()

    if not chrome_bin:
        raise RuntimeError("Chromium binary not found for server-side PDF generation. Please use browser print.")

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f_in:
        f_in.write(html_content)
        in_path = f_in.name

    out_path = in_path.replace(".html", ".pdf")
    try:
        cmd = [
            chrome_bin,
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-pdf-header-footer",
            f"--print-to-pdf={out_path}",
            in_path
        ]
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
        with open(out_path, "rb") as f_out:
            raw_pdf = f_out.read()

        final_pdf = stamp_pdf_footers(raw_pdf)
        return final_pdf, filename
    finally:
        if os.path.exists(in_path):
            try: os.remove(in_path)
            except OSError: pass
        if os.path.exists(out_path):
            try: os.remove(out_path)
            except OSError: pass
