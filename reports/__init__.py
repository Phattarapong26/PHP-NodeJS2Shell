"""
Reports Package - OPScaner
Provides TLP:AMBER ThaiCERT / NCSA Security Advisory generators and PDF engines.
"""

from .amber_builder import build_amber_advisory_html
from .pdf_engine import generate_amber_pdf, build_pdf_footer_overlay, stamp_pdf_footers

__all__ = [
    "build_amber_advisory_html",
    "generate_amber_pdf",
    "build_pdf_footer_overlay",
    "stamp_pdf_footers",
]
