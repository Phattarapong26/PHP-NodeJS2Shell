"""
Core Network Scanner and Discovery Engine
Handles interface detection, subnet calculations, live ARP table lookups,
OUI vendor resolution, and target host parsing with zero hardcoded IPs.
"""

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import time
from typing import Dict, List, Optional, Tuple, Any

# Hardware Vendor OUI Lookup Table
OUI_DATABASE = {
    "e48d8c": "MikroTik (RouterBoard)",
    "488f5a": "MikroTik (RouterBoard)",
    "64d154": "MikroTik (RouterBoard)",
    "b869f4": "MikroTik (RouterBoard)",
    "cc2de0": "MikroTik (RouterBoard)",
    "dc2c6e": "MikroTik (RouterBoard)",
    "f44eb4": "Cloud Network / Wi-Fi AP",
    "f889d2": "Cloud Network / Wi-Fi AP",
    "849e56": "Cloud Network / Wi-Fi AP",
    "c889f3": "Apple Inc. (Mac/iPhone)",
    "acde48": "Apple Inc. (Mac/iPhone)",
    "f01898": "Apple Inc. (Mac/iPhone)",
    "a483e7": "Apple Inc. (Mac/iPhone)",
    "3c22fb": "Apple Inc. (Mac/iPhone)",
    "147dda": "Apple Inc. (Mac/iPhone)",
    "bcfe4e": "Apple Inc. (Mac/iPhone)",
    "a85b78": "Apple Inc. (Mac/iPhone)",
    "70cd0d": "Apple Inc. (Mac/iPhone)",
    "40ec99": "Apple Inc. (Mac/iPhone)",
    "9801a7": "Apple Inc. (Mac/iPhone)",
    "38ca84": "HP Inc. (PC/Printer)",
    "001e4f": "HP Inc. (Workstation)",
    "3c5282": "HP Inc. (Workstation)",
    "2c4138": "HP Inc. (LaserJet)",
    "b06088": "Intel Corporate (Workstation)",
    "001e67": "Intel Corporation",
    "00216a": "Intel Corporation",
    "002314": "Intel Corporation",
    "3413e8": "Intel Corporation",
    "4851b7": "Intel Corporation",
    "701ce7": "Intel Corporation",
    "8c8d28": "Intel Corporation",
    "001422": "Dell Inc. (OptiPlex/PowerEdge)",
    "180373": "Dell Inc. (Workstation)",
    "54bf64": "Dell Inc. (Laptop)",
    "0021b7": "Lexmark Printer",
    "0017c8": "Kyocera Document Solution",
    "000085": "Canon Inc. (Network Printer)",
    "001e8f": "Canon Inc. (imageRUNNER)",
    "0026ab": "Seiko Epson (Printer)",
    "008077": "Brother Industries (Printer)",
    "005056": "VMware Virtual Machine",
    "000c29": "VMware Virtual Machine",
    "00155d": "Microsoft Hyper-V",
    "080027": "Oracle VirtualBox",
    "b827eb": "Raspberry Pi Foundation",
    "dca632": "Raspberry Pi Foundation",
    "e45f01": "Raspberry Pi 4",
    "001132": "Synology DiskStation NAS",
    "00089b": "QNAP TurboNAS",
    "001a11": "Google LLC",
    "3c5ab4": "Google LLC",
    "f4f5d8": "Google Pixel",
    "001a2b": "Cisco Systems",
    "002414": "Cisco Catalyst",
    "002698": "Cisco Systems",
    "00180a": "Cisco Meraki AP",
    "00259c": "Cisco Meraki",
    "0418d6": "Ubiquiti UniFi AP",
    "24a43c": "Ubiquiti Networks",
    "687251": "Ubiquiti UniFi",
    "788a20": "Ubiquiti Networks",
    "802aa8": "Ubiquiti UniFi Switch",
    "dc9fdb": "Ubiquiti EdgeRouter",
    "f09fc2": "Ubiquiti Networks",
    "000e8f": "Samsung Electronics",
    "001247": "Samsung Galaxy",
    "508569": "Samsung Electronics",
    "641cb0": "Samsung Galaxy",
    "88365f": "Samsung Electronics",
    "002127": "TP-Link Technologies",
    "0023cd": "TP-Link Corporation",
    "14cc20": "TP-Link Router",
    "503eaa": "TP-Link Archer",
    "60e327": "TP-Link Technologies",
    "001f3f": "Xiaomi Communications",
    "04cf4b": "Xiaomi Phone",
    "3480b3": "Xiaomi Communications",
    "001e68": "Huawei Technologies",
    "002568": "Huawei Router",
    "101b54": "Huawei Technologies",
    "5439df": "Huawei Technologies"
}

_HOST_NET_CACHE = None
_HOST_NET_CACHE_TIME = 0


def resolve_device_details(ip_str: str, mac_str: str, is_gw: bool = False) -> Tuple[str, str, bool]:
    """Resolve real device vendor, hardware model, and randomized Wi-Fi status from MAC address."""
    clean_mac = mac_str.lower().strip()
    parts = clean_mac.split(':')

    if is_gw:
        if len(parts) >= 3:
            clean_oui = ''.join(f"{int(p, 16):02x}" for p in parts[:3])
            vendor = OUI_DATABASE.get(clean_oui)
            if vendor:
                return f"{vendor} (Gateway Router)", "Gateway Router", False
        return "Gateway Router (เกตเวย์วงเครือข่าย)", "Gateway Router", False

    if len(parts) >= 3:
        try:
            clean_oui = ''.join(f"{int(p, 16):02x}" for p in parts[:3])
            first_byte = int(parts[0], 16)
            is_randomized = bool(first_byte & 0x02)  # Locally Administered Bit
            vendor = OUI_DATABASE.get(clean_oui)
            if vendor:
                return vendor, "Workstation / Hardware", False
            if is_randomized:
                return "อุปกรณ์ไร้สาย (Private Wi-Fi / Smartphone & Laptop)", "Mobile Client", True
            return f"เครื่องลูกข่ายเครือข่าย (OUI: {clean_oui.upper()})", "LAN Client", False
        except Exception:
            pass

    return "เครื่องลูกข่ายทั่วไป (LAN Client)", "LAN Client", False


def get_fast_latency(ip_str: str, default_ms: str = "< 5 ms") -> str:
    """Measure real round-trip latency in milliseconds for LAN host."""
    try:
        t0 = time.perf_counter()
        r = subprocess.run(["ping", "-c", "1", "-W", "200", ip_str], capture_output=True, text=True, timeout=0.25)
        if r.returncode == 0:
            m = re.search(r'time=([\d\.]+)\s*ms', r.stdout)
            if m:
                return f"{float(m.group(1)):.1f} ms"
            return f"{(time.perf_counter() - t0) * 1000:.1f} ms"
    except Exception:
        pass
    return default_ms


def is_valid_unicast_host(ip_str: str) -> bool:
    """Validate IP address and exclude multicast, broadcast, loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_reserved:
            return False
        if ip_str.endswith(".255"):
            return False
        return True
    except Exception:
        return False


def get_live_lan_hosts(target_net=None) -> Dict[str, str]:
    """Query live ARP table from OS dynamically on every request without stale files."""
    hosts = {}
    # 1. Real-time OS ARP lookup
    try:
        r = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=1.5)
        for line in r.stdout.splitlines():
            if "incomplete" in line:
                continue
            m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
            if m:
                ip_str = m.group(1)
                mac_str = m.group(2)
                if is_valid_unicast_host(ip_str):
                    if target_net:
                        try:
                            if ipaddress.ip_address(ip_str) in target_net:
                                hosts[ip_str] = mac_str
                        except Exception:
                            pass
                    else:
                        hosts[ip_str] = mac_str
    except Exception:
        pass

    # 2. Real-time Linux 'ip neigh show'
    try:
        r_ip = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=1.5)
        for line in r_ip.stdout.splitlines():
            if "FAILED" in line or "INCOMPLETE" in line:
                continue
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip_str = parts[0]
                mac_str = parts[parts.index("lladdr") + 1]
                if is_valid_unicast_host(ip_str) and ip_str not in hosts:
                    if target_net:
                        try:
                            if ipaddress.ip_address(ip_str) in target_net:
                                hosts[ip_str] = mac_str
                        except Exception:
                            pass
                    else:
                        hosts[ip_str] = mac_str
    except Exception:
        pass

    # 3. Docker fallback active_hosts.txt
    is_container = os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER") == "true" or os.environ.get("IS_DOCKER") == "true"
    if is_container and os.path.exists("active_hosts.txt"):
        try:
            with open("active_hosts.txt") as f:
                content = f.read().strip()
                if content:
                    for ip_str in content.split(','):
                        ip_str = ip_str.strip()
                        if is_valid_unicast_host(ip_str):
                            if target_net:
                                try:
                                    if ipaddress.ip_address(ip_str) in target_net and ip_str not in hosts:
                                        hosts[ip_str] = "LAN Device"
                                except Exception:
                                    pass
                            else:
                                if ip_str not in hosts:
                                    hosts[ip_str] = "LAN Device"
        except Exception:
            pass

    return hosts


def is_ignored_interface(iface: str) -> bool:
    """Filter out virtual bridge, container, VPN, or loopback interfaces."""
    if not iface:
        return True
    iface_low = iface.lower()
    ignored_prefixes = ('lo', 'docker', 'br-', 'veth', 'virbr', 'tun', 'tap', 'utun', 'vmnet', 'vbox', 'cni', 'flannel', 'dummy', 'kube')
    return any(iface_low.startswith(p) for p in ignored_prefixes)


def detect_host_network() -> Optional[Dict[str, Any]]:
    """Direct host network probe (macOS & Linux) with zero hardcoded values."""
    is_container = os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER") == "true" or os.environ.get("IS_DOCKER") == "true"
    gw = ''

    # 1. macOS / BSD default route
    try:
        r = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=2)
        iface_m = re.search(r'interface:\s+(\S+)', r.stdout)
        gw_m = re.search(r'gateway:\s+(\S+)', r.stdout)
        iface = iface_m.group(1) if iface_m else ''
        gw = gw_m.group(1) if gw_m else ''

        if iface and not is_ignored_interface(iface):
            res_if = subprocess.run(['ifconfig', iface], capture_output=True, text=True, timeout=2)
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)', res_if.stdout)
            if m:
                ip_str = m.group(1)
                mask_raw = m.group(2)
                mask_ip = str(ipaddress.IPv4Address(int(mask_raw, 16))) if mask_raw.startswith('0x') else mask_raw
                net = ipaddress.IPv4Network(f'{ip_str}/{mask_ip}', strict=False)
                return {
                    'interface': iface, 'ip': ip_str, 'gateway': gw,
                    'netmask': mask_ip, 'subnet': str(net), 'cidr': net.prefixlen,
                    'first_host': str(net.network_address + 1),
                    'last_host': str(net.broadcast_address - 1),
                    'total_hosts': net.num_addresses - 2
                }
    except Exception:
        pass

    # 2. macOS / BSD - scan all interfaces if no default gateway
    try:
        r_all = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
        current_iface = None
        for line in r_all.stdout.splitlines():
            m_if = re.match(r'^([a-zA-Z0-9_\-]+):', line)
            if m_if:
                current_iface = m_if.group(1)
            if current_iface and not is_ignored_interface(current_iface) and 'inet ' in line:
                m_inet = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)', line)
                if m_inet:
                    ip_str = m_inet.group(1)
                    if is_valid_unicast_host(ip_str) and not ip_str.startswith('127.'):
                        mask_raw = m_inet.group(2)
                        mask_ip = str(ipaddress.IPv4Address(int(mask_raw, 16))) if mask_raw.startswith('0x') else mask_raw
                        net = ipaddress.IPv4Network(f'{ip_str}/{mask_ip}', strict=False)
                        return {
                            'interface': current_iface, 'ip': ip_str, 'gateway': '',
                            'netmask': mask_ip, 'subnet': str(net), 'cidr': net.prefixlen,
                            'first_host': str(net.network_address + 1),
                            'last_host': str(net.broadcast_address - 1),
                            'total_hosts': net.num_addresses - 2
                        }
    except Exception:
        pass

    # 3. Linux default route
    try:
        r = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=2)
        parts = r.stdout.split()
        gw = parts[parts.index('via') + 1] if 'via' in parts else ''
        iface = parts[parts.index('dev') + 1] if 'dev' in parts else ''
        if iface and not is_ignored_interface(iface):
            r_addr = subprocess.run(['ip', '-4', '-o', 'addr', 'show', iface], capture_output=True, text=True, timeout=2)
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', r_addr.stdout)
            if m:
                net = ipaddress.IPv4Network(m.group(1), strict=False)
                ip_str = m.group(1).split('/')[0]
                if is_container:
                    try:
                        if ipaddress.IPv4Address(ip_str) in ipaddress.IPv4Network("172.16.0.0/12"):
                            pass
                        else:
                            return {
                                'interface': iface, 'ip': ip_str, 'gateway': gw,
                                'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                                'first_host': str(net.network_address + 1),
                                'last_host': str(net.broadcast_address - 1),
                                'total_hosts': net.num_addresses - 2
                            }
                    except Exception:
                        pass
                else:
                    return {
                        'interface': iface, 'ip': ip_str, 'gateway': gw,
                        'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                        'first_host': str(net.network_address + 1),
                        'last_host': str(net.broadcast_address - 1),
                        'total_hosts': net.num_addresses - 2
                    }
    except Exception:
        pass

    # 4. Linux - scan all interfaces if no default gateway
    try:
        r_addr = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=2)
        for line in r_addr.stdout.splitlines():
            m = re.search(r'^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
            if m:
                iface = m.group(1)
                if is_ignored_interface(iface):
                    continue
                net = ipaddress.IPv4Network(m.group(2), strict=False)
                ip_str = str(net.network_address) if net.prefixlen == 32 else m.group(2).split('/')[0]
                if is_valid_unicast_host(ip_str) and not ip_str.startswith('127.'):
                    if is_container:
                        try:
                            if ipaddress.IPv4Address(ip_str) in ipaddress.IPv4Network("172.16.0.0/12"):
                                continue
                        except Exception:
                            pass
                    return {
                        'interface': iface, 'ip': ip_str, 'gateway': '',
                        'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                        'first_host': str(net.network_address + 1),
                        'last_host': str(net.broadcast_address - 1),
                        'total_hosts': net.num_addresses - 2
                    }
    except Exception:
        pass

    # 5. Dynamic POSIX socket probe
    socket_targets = [gw, '192.168.1.1', '10.0.0.1', '172.16.0.1', '1.1.1.1', '8.8.8.8']
    for target in socket_targets:
        if not target:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 80))
            ip_str = s.getsockname()[0]
            s.close()
            if is_valid_unicast_host(ip_str) and not ip_str.startswith('127.'):
                if is_container:
                    try:
                        if ipaddress.IPv4Address(ip_str) in ipaddress.IPv4Network("172.16.0.0/12"):
                            continue
                    except Exception:
                        pass
                net = ipaddress.IPv4Network(f'{ip_str}/24', strict=False)
                return {
                    'interface': 'auto', 'ip': ip_str, 'gateway': gw,
                    'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                    'first_host': str(net.network_address + 1),
                    'last_host': str(net.broadcast_address - 1),
                    'total_hosts': net.num_addresses - 2
                }
        except Exception:
            continue

    return None


def get_host_network_info(force_refresh: bool = False) -> Dict[str, Any]:
    """Detect real host network info dynamically with zero hardcoded values, cached for 60s."""
    global _HOST_NET_CACHE, _HOST_NET_CACHE_TIME
    now = time.time()
    if not force_refresh and _HOST_NET_CACHE and (now - _HOST_NET_CACHE_TIME < 60):
        return _HOST_NET_CACHE.copy()

    is_container = os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER") == "true" or os.environ.get("IS_DOCKER") == "true"

    if is_container:
        if os.path.isfile("host_network.json") and os.path.getsize("host_network.json") > 0:
            try:
                with open("host_network.json", "r") as f:
                    data = json.load(f)
                    ip = data.get("ip", "").strip()
                    subnet = data.get("subnet", "").strip()
                    if ip and subnet and is_valid_unicast_host(ip) and not ip.startswith("127."):
                        data["is_docker"] = True
                        data["source"] = "host_network_json"
                        parts = ip.split('.')
                        data["prefix"] = f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else ""
                        _HOST_NET_CACHE = data.copy()
                        _HOST_NET_CACHE_TIME = now
                        return data
            except Exception:
                pass

        env_ip = (os.environ.get("HOST_IP") or "").strip()
        env_subnet = (os.environ.get("HOST_SUBNET") or "").strip()
        if env_ip and env_subnet and is_valid_unicast_host(env_ip) and not env_ip.startswith("127."):
            try:
                net = ipaddress.IPv4Network(env_subnet, strict=False)
                parts = env_ip.split('.')
                prefix = f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else ""
                data = {
                    "ip": env_ip,
                    "subnet": str(net),
                    "cidr": net.prefixlen,
                    "netmask": os.environ.get("HOST_NETMASK", str(net.netmask)),
                    "gateway": os.environ.get("HOST_GATEWAY", ""),
                    "interface": os.environ.get("HOST_INTERFACE", ""),
                    "first_host": str(net.network_address + 1),
                    "last_host": str(net.broadcast_address - 1),
                    "total_hosts": net.num_addresses - 2,
                    "prefix": prefix,
                    "is_docker": True,
                    "source": "environment_variables"
                }
                _HOST_NET_CACHE = data.copy()
                _HOST_NET_CACHE_TIME = now
                return data
            except Exception:
                pass

    direct = detect_host_network()
    if direct and direct.get("ip"):
        direct["is_docker"] = is_container
        parts = direct["ip"].split('.')
        direct["prefix"] = f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else ""
        direct["source"] = "os_direct"
        _HOST_NET_CACHE = direct.copy()
        _HOST_NET_CACHE_TIME = now
        return direct

    res = {
        "ip": "",
        "subnet": "",
        "cidr": 0,
        "netmask": "",
        "gateway": "",
        "interface": "",
        "first_host": "",
        "last_host": "",
        "total_hosts": 0,
        "prefix": "",
        "is_docker": is_container,
        "source": "offline"
    }
    _HOST_NET_CACHE = res.copy()
    _HOST_NET_CACHE_TIME = now
    return res


def get_docker_gateway() -> Optional[str]:
    """Detect default bridge gateway inside Docker container to connect to host ports."""
    try:
        with open('/proc/net/route') as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == '00000000':
                    return socket.inet_ntoa(struct.pack('<L', int(fields[2], 16)))
    except Exception:
        pass
    return None


def parse_target_hosts(target_str: str, max_scan: int = 512, host_ip: str = ""):
    """Parse any CIDR, IP range, single IP, or Domain with optional port into target host list."""
    target_str = target_str.strip()
    clean_target = re.sub(r'^https?://', '', target_str).rstrip('/')

    target_port = None
    if ":" in clean_target:
        parts = clean_target.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            port_num = int(parts[1])
            if 1 <= port_num <= 65535:
                target_port = port_num
                clean_target = parts[0]

    if clean_target.endswith("/32") and not re.match(r'^\d+\.\d+\.\d+\.\d+/32$', clean_target):
        clean_target = clean_target[:-3]

    if "/" in clean_target:
        try:
            net = ipaddress.ip_network(clean_target, strict=False)
            total = net.num_addresses - 2 if net.prefixlen < 31 else (1 if net.prefixlen == 32 else 2)
            if total <= max_scan:
                return list(net.hosts()), net, net.prefixlen, total, None, target_port
            else:
                if host_ip:
                    try:
                        curr_ip = ipaddress.ip_address(host_ip)
                        if curr_ip in net:
                            slice_net = ipaddress.ip_network(f"{curr_ip}/24", strict=False)
                            return list(slice_net.hosts()), net, net.prefixlen, total, None, target_port
                    except Exception:
                        pass
                try:
                    c_slices = list(net.subnets(new_prefix=24))
                    if c_slices:
                        return list(c_slices[0].hosts()), net, net.prefixlen, total, None, target_port
                except Exception:
                    pass
                return list(net.hosts())[:max_scan], net, net.prefixlen, total, None, target_port
        except ValueError:
            clean_target = clean_target.split('/')[0]

    if "-" in clean_target and not any(c.isalpha() for c in clean_target):
        s, e = clean_target.split("-")
        s_ip = int(ipaddress.ip_address(s.strip()))
        e_ip = int(ipaddress.ip_address(e.strip()))
        hosts = [ipaddress.ip_address(i) for i in range(s_ip, min(e_ip + 1, s_ip + max_scan))]
        return hosts, None, 32, len(hosts), None, target_port
    else:
        clean = clean_target.split(":")[0].strip()
        try:
            ip = ipaddress.ip_address(clean)
            return [ip], None, 32, 1, None, target_port
        except ValueError:
            try:
                resolved = socket.gethostbyname(clean)
                ip = ipaddress.ip_address(resolved)
                return [ip], None, 32, 1, clean, target_port
            except Exception as e:
                raise ValueError(f"ไม่สามารถค้นหา IP หรือโดเมน '{clean}' ได้: {e}")
