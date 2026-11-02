"""
Audit Package - OPScaner
"""

from .php_audit import evaluate_php_security, evaluate_security_chains
from .node_audit import evaluate_node_security
from .nginx_audit import evaluate_nginx_security, collect_target_cves
from .thaicert_rules import (
    classify_thaicert_groups,
    GROUP_NAMES,
    GROUP_CHECKS,
    PRODUCT_SIGNATURES,
    EDGE_SIGNATURES,
    DEVICE_RULES,
    identify_products,
    detect_edge_product,
    generate_random_canary_path,
    verify_checklist_hit,
)
from .probe_audit import probe_lfi_prerequisite, check_tcp_port, probe_endpoint

__all__ = [
    "evaluate_php_security",
    "evaluate_security_chains",
    "evaluate_node_security",
    "evaluate_nginx_security",
    "collect_target_cves",
    "classify_thaicert_groups",
    "probe_lfi_prerequisite",
    "check_tcp_port",
    "probe_endpoint",
]
