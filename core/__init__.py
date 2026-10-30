"""
Core Module - OPScaner
"""

from .semver import parse_semver, in_range
from .database import NGINX_VULN, NGINX_CVE_DESCS, CVE_DATABASE
from .network import (
    OUI_DATABASE,
    resolve_device_details,
    get_fast_latency,
    is_valid_unicast_host,
    get_live_lan_hosts,
    is_ignored_interface,
    detect_host_network,
    get_host_network_info,
    get_docker_gateway,
    parse_target_hosts,
)

__all__ = [
    "parse_semver",
    "in_range",
    "NGINX_VULN",
    "NGINX_CVE_DESCS",
    "CVE_DATABASE",
    "OUI_DATABASE",
    "resolve_device_details",
    "get_fast_latency",
    "is_valid_unicast_host",
    "get_live_lan_hosts",
    "is_ignored_interface",
    "detect_host_network",
    "get_host_network_info",
    "get_docker_gateway",
    "parse_target_hosts",
]
