"""
API Package - OPScaner
Blueprints for Scanning, Reporting, and Test Labs.
"""

from .scan_routes import scan_bp
from .report_routes import report_bp
from .test_routes import test_bp

__all__ = ["scan_bp", "report_bp", "test_bp"]
