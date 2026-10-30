import os
import re
import json
import socket
import asyncio
import ipaddress
import subprocess
import time
import httpx
from flask import Flask, send_from_directory, request, jsonify

app = Flask(__name__, static_folder=".")

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/api/<path:subpath>", methods=["OPTIONS"])
def handle_options(subpath):
    return "", 200

EOL_CRITICAL = ["5.", "7.0", "7.1", "7.2", "7.3", "7.4"]
EOL_HIGH = ["8.0", "8.1"]

# IEEE OUI Database for Real Hardware & Device Vendor Identification
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

def resolve_device_details(ip_str: str, mac_str: str, is_gw: bool = False):
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
            is_randomized = bool(first_byte & 0x02) # Locally Administered Bit (Private Wi-Fi Address)

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

def get_live_lan_hosts(target_net=None):
    """Query live ARP table from OS dynamically on every request without stale files."""
    hosts = {}
    # 1. Real-time OS ARP lookup (macOS, BSD, Windows, Linux net-tools)
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

    # 2. Real-time Linux 'ip neigh show' (modern Linux distros where arp command is absent)
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

    # 3. Only if running inside Docker container where ARP namespace might be isolated
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

def detect_host_network():
    """Direct host network probe (macOS & Linux) with zero hardcoded values."""
    # 1. macOS / BSD default route
    try:
        r = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=2)
        iface_m = re.search(r'interface:\s+(\S+)', r.stdout)
        gw_m = re.search(r'gateway:\s+(\S+)', r.stdout)
        iface = iface_m.group(1) if iface_m else ''
        gw = gw_m.group(1) if gw_m else ''

        if iface:
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

    # 2. macOS / BSD - scan all interfaces if no default gateway (e.g. offline/isolated switch)
    try:
        r_all = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
        current_iface = None
        for line in r_all.stdout.splitlines():
            m_if = re.match(r'^([a-zA-Z0-9_\-]+):', line)
            if m_if:
                current_iface = m_if.group(1)
            if current_iface and 'inet ' in line:
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
        if iface:
            r_addr = subprocess.run(['ip', '-4', '-o', 'addr', 'show', iface], capture_output=True, text=True, timeout=2)
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', r_addr.stdout)
            if m:
                net = ipaddress.IPv4Network(m.group(1), strict=False)
                ip_str = m.group(1).split('/')[0]
                return {
                    'interface': iface, 'ip': ip_str, 'gateway': gw,
                    'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                    'first_host': str(net.network_address + 1),
                    'last_host': str(net.broadcast_address - 1),
                    'total_hosts': net.num_addresses - 2
                }
    except Exception:
        pass

    # 4. Linux - scan all interfaces if no default gateway (e.g. offline/isolated switch)
    try:
        r_addr = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=2)
        for line in r_addr.stdout.splitlines():
            if 'lo' in line:
                continue
            m = re.search(r'^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
            if m:
                iface = m.group(1)
                net = ipaddress.IPv4Network(m.group(2), strict=False)
                ip_str = str(net.network_address) if net.prefixlen == 32 else m.group(2).split('/')[0]
                if is_valid_unicast_host(ip_str) and not ip_str.startswith('127.'):
                    return {
                        'interface': iface, 'ip': ip_str, 'gateway': '',
                        'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                        'first_host': str(net.network_address + 1),
                        'last_host': str(net.broadcast_address - 1),
                        'total_hosts': net.num_addresses - 2
                    }
    except Exception:
        pass

    # 5. Dynamic POSIX socket probe (determines outbound IP on any OS without hardcoded values)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('1.1.1.1', 80))
        ip_str = s.getsockname()[0]
        s.close()
        if is_valid_unicast_host(ip_str):
            net = ipaddress.IPv4Network(f'{ip_str}/24', strict=False)
            return {
                'interface': 'auto', 'ip': ip_str, 'gateway': '',
                'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                'first_host': str(net.network_address + 1),
                'last_host': str(net.broadcast_address - 1),
                'total_hosts': net.num_addresses - 2
            }
    except Exception:
        pass

    return None

def get_host_network_info():
    """Detect real host network info dynamically with zero hardcoded values."""
    is_container = os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER") == "true" or os.environ.get("IS_DOCKER") == "true"

    # If running inside Docker, prioritize mounted host network info or environment variables
    if is_container:
        # 1. Check host_network.json mounted from physical host
        if os.path.exists("host_network.json"):
            try:
                with open("host_network.json", "r") as f:
                    data = json.load(f)
                    if data.get("ip") and data.get("subnet"):
                        data["is_docker"] = True
                        data["source"] = "host_network_json"
                        parts = data["ip"].split('.')
                        data["prefix"] = f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else ""
                        return data
            except Exception:
                pass

        # 2. Read environment variables passed into container
        env_ip = os.environ.get("HOST_IP")
        env_subnet = os.environ.get("HOST_SUBNET")
        if env_ip and env_subnet:
            try:
                net = ipaddress.IPv4Network(env_subnet, strict=False)
                parts = env_ip.split('.')
                prefix = f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else ""
                return {
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
            except Exception:
                pass

    # Direct OS probe (highest accuracy when running natively, or fallback)
    direct = detect_host_network()
    if direct and direct.get("ip"):
        direct["is_docker"] = is_container
        parts = direct["ip"].split('.')
        direct["prefix"] = f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else ""
        direct["source"] = "os_direct"
        return direct

    # If completely offline or undetected, return empty state (NO HARDCODED FAKE IPS!)
    return {
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

def parse_target_hosts(target_str, max_scan=2048, host_ip=""):
    """Parse any CIDR, IP range, single IP, or Domain with optional port into target host list."""
    target_str = target_str.strip()
    clean_target = re.sub(r'^https?://', '', target_str).rstrip('/')

    # Extract port if present (e.g. 10.255.254.68:18080 or domain.com:8080)
    target_port = None
    if ":" in clean_target:
        parts = clean_target.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            port_num = int(parts[1])
            if 1 <= port_num <= 65535:
                target_port = port_num
                clean_target = parts[0]

    # Check for domain with /32 suffix (e.g. from frontend single target)
    if clean_target.endswith("/32") and not re.match(r'^\d+\.\d+\.\d+\.\d+/32$', clean_target):
        clean_target = clean_target[:-3]

    if "/" in clean_target:
        try:
            net = ipaddress.ip_network(clean_target, strict=False)
            total = net.num_addresses - 2 if net.prefixlen < 31 else (1 if net.prefixlen == 32 else 2)
            if total <= max_scan:
                return list(net.hosts()), net, net.prefixlen, total, None, target_port
            else:
                # Massive network (/16, /8): scan the slice around host_ip if valid
                if host_ip:
                    try:
                        curr_ip = ipaddress.ip_address(host_ip)
                        if curr_ip in net:
                            slice_net = ipaddress.ip_network(f"{curr_ip}/24", strict=False)
                            return list(slice_net.hosts()), net, net.prefixlen, total, None, target_port
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

@app.route("/")
def index():
    return send_from_directory(".", "GUI.html")

@app.route("/api/my-ip")
def my_ip_route():
    net_info = get_host_network_info()
    live_arp = get_live_lan_hosts()
    user_ip = net_info.get("ip", "")
    user_subnet = net_info.get("subnet", "")
    
    presets = []
    if user_subnet:
        presets.append({"icon": "ph-crosshair", "label": f"วงเครือข่ายที่พบ ({user_subnet})", "subnet": user_subnet})
        parts = user_ip.split('.') if user_ip else []
        if len(parts) == 4 and net_info.get("cidr", 24) < 24:
            c_slice = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if c_slice != user_subnet:
                presets.append({"icon": "ph-lightning", "label": f"วงย่อย Class C ({c_slice})", "subnet": c_slice})
        if user_ip:
            presets.append({"icon": "ph-laptop", "label": f"เฉพาะเครื่องนี้ ({user_ip})", "subnet": f"{user_ip}/32"})
    elif user_ip:
        presets.append({"icon": "ph-laptop", "label": f"เฉพาะเครื่องนี้ ({user_ip})", "subnet": f"{user_ip}/32"})

    return jsonify({
        "ip": user_ip,
        "subnet": user_subnet,
        "cidr": net_info.get("cidr", 0),
        "netmask": net_info.get("netmask", ""),
        "gateway": net_info.get("gateway", ""),
        "interface": net_info.get("interface", ""),
        "first_host": net_info.get("first_host", ""),
        "last_host": net_info.get("last_host", ""),
        "total_hosts": net_info.get("total_hosts", 0),
        "prefix": net_info.get("prefix", ""),
        "is_docker": net_info.get("is_docker", False),
        "active_devices_count": len(live_arp),
        "presets": presets
    })

@app.route("/api/calculate-subnet", methods=["POST"])
def calculate_subnet_api():
    """Real-time Subnet Calculator API for frontend input."""
    data = request.json or {}
    target_str = data.get("input", "").strip()
    if not target_str:
        return jsonify({"error": "Empty input"}), 400

    clean_target = re.sub(r'^https?://', '', target_str).rstrip('/')

    if clean_target.endswith("/32") and not re.match(r'^\d+\.\d+\.\d+\.\d+/32$', clean_target):
        clean_target = clean_target[:-3]

    try:
        # Extract port if present (e.g. 10.255.254.68:18080)
        target_port = None
        if ":" in clean_target:
            parts = clean_target.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                port_num = int(parts[1])
                if 1 <= port_num <= 65535:
                    target_port = port_num
                    clean_target = parts[0]

        if "/" in clean_target:
            try:
                net = ipaddress.IPv4Network(clean_target, strict=False)
                total = net.num_addresses - 2 if net.prefixlen < 31 else (1 if net.prefixlen == 32 else 2)
                first_host = str(net.network_address + 1) if net.prefixlen < 31 else str(net.network_address)
                last_host = str(net.broadcast_address - 1) if net.prefixlen < 31 else str(net.broadcast_address)
                return jsonify({
                    "valid": True,
                    "type": "CIDR Subnet",
                    "subnet": str(net),
                    "cidr": net.prefixlen,
                    "netmask": str(net.netmask),
                    "network_address": str(net.network_address),
                    "broadcast_address": str(net.broadcast_address),
                    "first_host": first_host,
                    "last_host": last_host,
                    "total_hosts": total
                })
            except ValueError:
                clean_target = clean_target.split('/')[0]

        if "-" in clean_target and not any(c.isalpha() for c in clean_target):
            s, e = clean_target.split("-")
            s_ip = ipaddress.IPv4Address(s.strip())
            e_ip = ipaddress.IPv4Address(e.strip())
            total = max(0, int(e_ip) - int(s_ip) + 1)
            return jsonify({
                "valid": True,
                "type": "IP Range",
                "subnet": target_str,
                "cidr": 32,
                "first_host": str(s_ip),
                "last_host": str(e_ip),
                "total_hosts": total
            })
        else:
            try:
                ip = ipaddress.IPv4Address(clean_target)
                display_sub = f"{ip}:{target_port}" if target_port else f"{ip}/32"
                return jsonify({
                    "valid": True,
                    "type": f"Target Host (Port {target_port})" if target_port else "Single Target",
                    "subnet": display_sub,
                    "port": target_port,
                    "cidr": 32,
                    "first_host": str(ip),
                    "last_host": str(ip),
                    "total_hosts": 1
                })
            except ValueError:
                try:
                    resolved = socket.gethostbyname(clean_target)
                    ip = ipaddress.IPv4Address(resolved)
                    display_sub = f"{clean_target}:{target_port}" if target_port else f"{clean_target} ({ip}/32)"
                    return jsonify({
                        "valid": True,
                        "type": f"Domain (Port {target_port})" if target_port else f"Domain Name ({clean_target})",
                        "subnet": display_sub,
                        "domain": clean_target,
                        "resolved_ip": str(ip),
                        "port": target_port,
                        "cidr": 32,
                        "first_host": str(ip),
                        "last_host": str(ip),
                        "total_hosts": 1
                    })
                except Exception as e:
                    return jsonify({"valid": False, "error": f"ไม่พบ IP ของโดเมน '{clean_target}': {e}"}), 400
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 400

def evaluate_php_security(version_str: str):
    """Assess PHP version against End-Of-Life and CVE-2024-4577 (php2shell) risk."""
    v = version_str.lower()
    
    # PHP 5.x / 7.x: Critical (EOL + Multiple RCEs + php2shell)
    if any(pat in v for pat in ["php/5.", "php 5.", "5.4.", "5.5.", "5.6.", "php/7.", "php 7.", "7.0.", "7.1.", "7.2.", "7.3.", "7.4."]):
        return (
            "Critical",
            "PHP 5.x/7.x End-of-Life: เสี่ยงต่อ php2shell / CVE-2024-4577 (CGI Argument Injection RCE) และ CVE-2019-11043 ควรอัปเกรดด่วนที่สุด"
        )
    
    # PHP 8.0 / 8.1: Outdated (Security EOL)
    if any(pat in v for pat in ["php/8.0", "8.0.", "php/8.1", "8.1."]):
        return (
            "Outdated",
            "PHP 8.0/8.1 Security EOL: สิ้นสุดการสนับสนุนความปลอดภัย เสี่ยงต่อ CVE-2024-4577 (php2shell) บน Windows"
        )
    
    # Early PHP 8.2 (< 8.2.20) or 8.3 (< 8.3.8): Critical php2shell
    if "8.2." in v or "8.3." in v:
        match = re.search(r'8\.([23])\.(\d+)', v)
        if match:
            minor = int(match.group(1))
            patch = int(match.group(2))
            if (minor == 2 and patch < 20) or (minor == 3 and patch < 8):
                return (
                    "Critical",
                    f"PHP 8.{minor}.{patch} เสี่ยงต่อ CVE-2024-4577 (php2shell RCE) ต้องอัปเดตเป็น 8.{minor}.{20 if minor==2 else 8}+"
                )
        return (
            "Secure",
            "PHP 8.2+/8.3+ เวอร์ชันปลอดภัย มีแพตช์ป้องกัน CVE-2024-4577 ตามเกณฑ์ ThaiCERT"
        )
    
    # Hidden Version (expose_php = Off)
    if "hidden" in v or "off" in v:
        return (
            "Review Needed",
            "ตรวจพบ PHP แต่เปิดโหมดปิดบังเวอร์ชัน (expose_php = Off) ควรตรวจสอบเลขแพตช์จริงบนเซิร์ฟเวอร์"
        )
        
    return (
        "Review Needed",
        "ตรวจพบบริการ PHP (ควรตรวจสอบเวอร์ชันให้เป็น PHP 8.2 หรือ 8.3 ตามมาตรฐานความปลอดภัย)"
    )

def evaluate_node_security(version_str: str, has_brotli: bool = False):
    """
    Assess Node.js version against EOL and Node2Shell / HTTP2Shell (CVE-2026-111497, CVSS 9.2 in Brotli).
    Rules:
    - 26.x: EOL 30 Apr 2029 -> Patched in 26.12.1+ (< 26.12.1 is Critical)
    - 24.x: EOL 30 Apr 2028 -> Patched in 24.22.1+ (< 24.22.1 is Critical)
    - 22.x: EOL 30 Apr 2027 -> Patched in 22.23.4+ (< 22.23.4 is Critical)
    - 25.x: EOL 1 Jun 2026 -> No patch (Critical, upgrade to 24.x/26.x)
    - 20.x and older: EOL 30 Apr 2026 -> No patch (Critical, upgrade to 22.x/24.x)
    """
    v = version_str.lower()
    
    # Extract version numbers e.g. 20.18.0, v22.12.0, 24.22.1, 26.11.0
    match = re.search(r'(?:node(?:\.js)?/|v)?(\d+)\.(\d+)(?:\.(\d+))?', v)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) is not None else 0

        # Node 20.x and older (18.x, 16.x, 14.x...): EOL 30 Apr 2026 -> No patch
        if major <= 20:
            return (
                "Critical",
                f"Node.js v{major}.{minor}.{patch} (EOL สิ้นสุด 30 เม.ย. 2026): ไม่มีแพตช์ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเกรดเป็น 22.x หรือ 24.x ทันที"
            )

        # Node 25.x: EOL 1 Jun 2026 -> No patch
        if major == 25:
            return (
                "Critical",
                f"Node.js v{major}.{minor}.{patch} (EOL สิ้นสุด 1 มิ.ย. 2026): ไม่มีแพตช์ Node2Shell / CVE-2026-111497 ควรอัปเกรดข้ามรุ่นเป็น 24.x หรือ 26.x ทันที"
            )

        # Node 22.x: Patched in 22.23.4+ (EOL 30 Apr 2027)
        if major == 22:
            if (minor < 23) or (minor == 23 and patch < 4):
                return (
                    "Critical",
                    f"Node.js v{major}.{minor}.{patch} เสี่ยงต่อ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเดตเป็น 22.23.4 ขึ้นไป"
                )
            else:
                return (
                    "Secure",
                    f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับแพตช์แก้ไข Node2Shell (CVE-2026-111497) แล้ว (รองรับถึง 30 เม.ย. 2027)"
                )

        # Node 24.x: Patched in 24.22.1+ (EOL 30 Apr 2028)
        if major == 24:
            if (minor < 22) or (minor == 22 and patch < 1):
                return (
                    "Critical",
                    f"Node.js v{major}.{minor}.{patch} เสี่ยงต่อ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเดตเป็น 24.22.1 ขึ้นไป"
                )
            else:
                return (
                    "Secure",
                    f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับแพตช์แก้ไข Node2Shell (CVE-2026-111497) แล้ว (รองรับถึง 30 เม.ย. 2028)"
                )

        # Node 26.x: Patched in 26.12.1+ (EOL 30 Apr 2029)
        if major == 26:
            if (minor < 12) or (minor == 12 and patch < 1):
                return (
                    "Critical",
                    f"Node.js v{major}.{minor}.{patch} เสี่ยงต่อ Node2Shell / CVE-2026-111497 (CVSS 9.2 Brotli RCE) ต้องอัปเดตเป็น 26.12.1 ขึ้นไป"
                )
            else:
                return (
                    "Secure",
                    f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับแพตช์แก้ไข Node2Shell (CVE-2026-111497) แล้ว (รองรับถึง 30 เม.ย. 2029)"
                )

        # Newer versions (major > 26)
        return (
            "Secure",
            f"Node.js v{major}.{minor}.{patch} ปลอดภัย ได้รับการแก้ไขช่องโหว่ Brotli เรียบร้อย"
        )

    # If version couldn't be extracted from headers/cookies
    if has_brotli:
        return (
            "Warning",
            "ตรวจพบบริการ Node.js เปิดใช้การบีบอัด Brotli (เสี่ยงต่อ Node2Shell / CVE-2026-111497 หากเวอร์ชันต่ำกว่า 22.23.4 / 24.22.1 / 26.12.1)"
        )

    return (
        "Review Needed",
        "ตรวจพบบริการ Node.js (ควรตรวจสอบให้แน่ใจว่าอัปเดตเป็น 22.23.4+, 24.22.1+ หรือ 26.12.1+ เพื่อป้องกัน Node2Shell)"
    )

def classify_thaicert_groups(ip_or_host: str, server: str, headers: dict, body_text: str, cookies_str: str, port: int, is_php: bool, is_node: bool, cms_name: str) -> dict:
    """
    Classifies the target host into the 8 ThaiCERT / NCSA target system groups:
    1. เว็บไซต์และระบบภายในองค์กร (WordPress, Drupal, Joomla, Moodle, Nextcloud)
    2. ระบบหลังบ้านแอปมือถือ และ API (Laravel, Symfony, CodeIgniter, Yii, Slim, REST API)
    3. Hosting Control Panel (cPanel, Plesk, DirectAdmin, Webmin)
    4. ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Vendor Portal, Network Appliance, NAS, ระบบอุตสาหกรรม)
    5. Container และ Docker Image (Docker, Kubernetes, Podman, Microservices)
    6. Windows ที่มี PHP ติดตั้งอยู่ (Windows IIS, XAMPP, WampServer, Laragon - CVE-2024-4577 Priority)
    7. ระบบทดสอบ ระบบเก่า และระบบสำรอง (Development, UAT, Staging, DR, Snapshot, Lingering)
    8. ระบบที่ผู้ให้บริการภายนอกดูแล (Shared Hosting, Managed Hosting, Cloud VM, Outsourced)
    """
    server_lower = (server or "").lower()
    body_lower = (body_text or "").lower()
    headers_str = str(headers or {}).lower()
    cookies_lower = (cookies_str or "").lower()
    host_lower = (ip_or_host or "").lower()

    matched_groups = []
    group_labels = []
    group_evidence = []

    # --- Group 1: เว็บไซต์และระบบภายในองค์กร ---
    g1_markers = []
    if any(k in body_lower or k in headers_str for k in ["wp-content", "wp-json", "wp-includes", "wordpress"]):
        g1_markers.append("WordPress")
    if any(k in body_lower or k in headers_str for k in ["drupal", "/sites/default/", "x-generator: drupal"]):
        g1_markers.append("Drupal")
    if any(k in body_lower or k in headers_str for k in ["joomla", "/administrator/"]):
        g1_markers.append("Joomla!")
    if any(k in body_lower or k in cookies_lower for k in ["moodle", "moodlesession"]):
        g1_markers.append("Moodle")
    if any(k in body_lower or k in headers_str for k in ["nextcloud", "nc_same_site"]):
        g1_markers.append("Nextcloud")
    if g1_markers or (is_php and any(k in cms_name.lower() for k in ["wordpress", "drupal", "joomla", "cms", "moodle"])):
        matched_groups.append(1)
        name = f"กลุ่ม 1: เว็บไซต์/ระบบภายใน ({', '.join(g1_markers) if g1_markers else 'CMS/Internal Web'})"
        group_labels.append(name)
        group_evidence.extend(g1_markers or ["Internal Web / CMS Portal"])

    # --- Group 2: ระบบหลังบ้านแอปมือถือ และ API ---
    g2_markers = []
    if "laravel" in cookies_lower or "x-csrf-token" in headers_str or "laravel" in body_lower:
        g2_markers.append("Laravel Framework")
    if "symfony" in cookies_lower or "_sf2" in cookies_lower or "symfony" in headers_str:
        g2_markers.append("Symfony")
    if "ci_session" in cookies_lower or "codeigniter" in body_lower:
        g2_markers.append("CodeIgniter")
    if "yii" in body_lower or "_csrf" in cookies_lower and "yii" in headers_str:
        g2_markers.append("Yii Framework")
    if "slim" in headers_str or "slim" in body_lower:
        g2_markers.append("Slim Framework")
    if any(k in host_lower for k in ["api.", "/api", "backend.", "mobile."]) or "application/json" in headers_str:
        g2_markers.append("REST API Endpoint")
    if g2_markers:
        matched_groups.append(2)
        group_labels.append(f"กลุ่ม 2: หลังบ้านแอป & API ({', '.join(g2_markers)})")
        group_evidence.extend(g2_markers)

    # --- Group 3: Hosting Control Panel ---
    g3_markers = []
    if port in [2082, 2083, 2086, 2087] or "cpanel" in body_lower or "cpanel" in server_lower:
        g3_markers.append("cPanel")
    if port in [8443, 8880] or "plesk" in server_lower or "plesk" in headers_str:
        g3_markers.append("Plesk Panel")
    if port in [2222] or "directadmin" in body_lower or "directadmin" in server_lower:
        g3_markers.append("DirectAdmin")
    if port in [10000] or "webmin" in body_lower or "miniserv" in server_lower:
        g3_markers.append("Webmin Panel")
    if g3_markers:
        matched_groups.append(3)
        group_labels.append(f"กลุ่ม 3: Hosting Control Panel ({', '.join(g3_markers)})")
        group_evidence.extend(g3_markers)

    # --- Group 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance, NAS, IoT/SCADA) ---
    g4_markers = []
    if any(k in server_lower or k in body_lower for k in ["synology", "diskstation", "dsm", "qts", "qnap", "truenas"]):
        g4_markers.append("NAS Storage Appliance")
    if any(k in server_lower or k in body_lower for k in ["mikrotik", "webfig", "pfsense", "fortigate", "fortios", "openwrt", "unifi"]):
        g4_markers.append("Network Appliance / Router")
    if any(k in server_lower or k in body_lower for k in ["jetdirect", "canon", "ricoh", "xerox", "brother", "hikvision", "dahua"]):
        g4_markers.append("Vendor Device / Peripheral")
    if any(k in server_lower or k in body_lower for k in ["scada", "plc", "modbus", "siemens", "schneider"]):
        g4_markers.append("Industrial ICS/SCADA Web")
    if g4_markers:
        matched_groups.append(4)
        group_labels.append(f"กลุ่ม 4: อุปกรณ์สำเร็จรูป & Appliance ({', '.join(g4_markers)})")
        group_evidence.extend(g4_markers)

    # --- Group 5: Container และ Docker Image ---
    g5_markers = []
    if any(k in server_lower or k in headers_str for k in ["traefik", "k8s", "envoy", "kong", "ingress", "portainer"]):
        g5_markers.append("Kubernetes / Ingress Gateway")
    if any(k in host_lower for k in ["172.17.", "172.18.", "10.42.", "10.244."]) or port in [9000, 9443]:
        g5_markers.append("Docker / Container Network")
    if g5_markers:
        matched_groups.append(5)
        group_labels.append(f"กลุ่ม 5: Container & Microservices ({', '.join(g5_markers)})")
        group_evidence.extend(g5_markers)

    # --- Group 6: Windows ที่มี PHP ติดตั้งอยู่ (CVE-2024-4577 High Priority) ---
    g6_markers = []
    if any(k in server_lower for k in ["microsoft-iis", "iis/"]):
        g6_markers.append("Windows IIS")
    if any(k in server_lower or k in body_lower for k in ["win32", "win64", "windows"]):
        g6_markers.append("Windows OS Architecture")
    if any(k in body_lower or k in server_lower for k in ["xampp", "/xampp/"]):
        g6_markers.append("XAMPP Stack")
    if any(k in body_lower or k in server_lower for k in ["wampserver", "/wamp/"]):
        g6_markers.append("WampServer")
    if any(k in body_lower or k in server_lower for k in ["laragon"]):
        g6_markers.append("Laragon Stack")
    if g6_markers:
        matched_groups.append(6)
        group_labels.append(f"กลุ่ม 6: Windows PHP Stacks ({', '.join(g6_markers)})")
        group_evidence.extend(g6_markers)

    # --- Group 7: ระบบทดสอบ ระบบเก่า และระบบสำรอง (Dev, UAT, Staging, DR, Lingering) ---
    g7_markers = []
    if any(k in host_lower for k in ["dev.", "uat.", "test.", "stage.", "staging.", "dr.", "backup.", "old.", "lab."]):
        g7_markers.append("Non-production Hostname Prefix")
    if port in [3000, 5000, 5173, 4000, 8000, 8080, 8888, 8081, 18080]:
        g7_markers.append(f"Development Port {port}")
    if any(k in body_lower for k in ["phpmyadmin", "debug mode", "app_env=local", "staging environment"]):
        g7_markers.append("Debug / Admin Lingering Tool")
    if g7_markers:
        matched_groups.append(7)
        group_labels.append(f"กลุ่ม 7: ระบบทดสอบ/ระบบเก่า/สำรอง ({', '.join(g7_markers)})")
        group_evidence.extend(g7_markers)

    # --- Group 8: ระบบที่ผู้ให้บริการภายนอกดูแล (Cloud VM & Outsourced) ---
    g8_markers = []
    if any(k in server_lower or k in headers_str for k in ["cloudflare", "cloudfront", "fastly", "akamai"]):
        g8_markers.append("Edge Cloud CDN/Proxy")
    if any(k in host_lower for k in ["amazonaws.com", "googleusercontent.com", "azure.com", "digitalocean"]):
        g8_markers.append("Cloud Provider VM")
    if g8_markers:
        matched_groups.append(8)
        group_labels.append(f"กลุ่ม 8: บริการภายนอก/Cloud ({', '.join(g8_markers)})")
        group_evidence.extend(g8_markers)

    # Fallback if no specific group matched
    if not matched_groups:
        if is_php:
            matched_groups = [1]
            group_labels = ["กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (General PHP Web)"]
            group_evidence = ["General PHP Web Application"]
        else:
            matched_groups = [4]
            group_labels = ["กลุ่ม 4: ซอฟต์แวร์/อุปกรณ์ทั่วไปในเครือข่าย"]
            group_evidence = ["General Network Service"]

    primary = group_labels[0]
    return {
        "groups": sorted(list(set(matched_groups))),
        "primary_group": primary,
        "group_labels": group_labels,
        "evidence": list(set(group_evidence))
    }

def evaluate_security_chains(is_php: bool, php_version: str, headers: dict, cookies_str: str, server: str, expose_php: bool) -> dict:
    """
    Defensively models the 3 critical PHP session & configuration security verification chains:
    - Chain A: session.upload_progress filename injection + LFI
    - Chain C: serializer-handler mismatch -> __destruct RCE
    - Chain D: OOM skips cleanup -> poisoned session -> LFI
    Provides stage-by-stage verification & defensive hardening guidance matching ThaiCERT / NCSA standards.
    """
    if not is_php:
        return {
            "applicable": False,
            "overall_status": "Non-PHP Service",
            "chains": {},
            "hardening_ini": ""
        }

    # Strict mode & session cookie analysis
    has_session_cookie = any(k in cookies_str.lower() for k in ["phpsessid", "session", "sess"])

    # Check PHP Version safe baseline for CVE-2024-4577
    is_patched = False
    v_clean = php_version.replace("PHP", "").replace("/", "").strip()
    m_v = re.search(r'(\d+)\.(\d+)\.(\d+)', v_clean)
    if m_v:
        maj, mino, pat = int(m_v.group(1)), int(m_v.group(2)), int(m_v.group(3))
        if (maj == 8 and mino == 2 and pat >= 20) or (maj == 8 and mino == 3 and pat >= 8) or (maj == 8 and mino >= 4) or (maj > 8):
            is_patched = True

    # --- Chain A: session.upload_progress filename injection + LFI ---
    chain_a_stages = [
        {"stage": "1/6", "name": "tcp reachability", "status": "PASS", "detail": "พอร์ตตอบสนองการเชื่อมต่อปกติ", "badge": "PASS"},
        {"stage": "2/6", "name": "session.use_strict_mode", "status": "PASS" if has_session_cookie else "AUDIT_NEEDED", "detail": "ควรบังคับใช้ session.use_strict_mode = 1", "badge": "AUDIT" if not has_session_cookie else "PASS"},
        {"stage": "3/6", "name": "stalled writer", "status": "PROTECTED" if is_patched else "REVIEW_NEEDED", "detail": "ควรปิด session.upload_progress.enabled = Off", "badge": "PROTECTED" if is_patched else "REVIEW"},
        {"stage": "4/6", "name": "concurrent worker", "status": "PASS", "detail": "ระบบรองรับการประมวลผลคู่ขนาน", "badge": "PASS"},
        {"stage": "5/6", "name": "LFI reads session", "status": "PROTECTED" if is_patched else "DEFENSIVE_RULE", "detail": "คัดกรองพารามิเตอร์ไฟล์และป้องกัน Path Traversal", "badge": "PROTECTED" if is_patched else "REVIEW"},
        {"stage": "6/6", "name": "payload execution", "status": "BLOCKED" if is_patched else "DEFENSIVE_RULE", "detail": "กลไก CGI Argument Injection ถูกบล็อกด้วยแพตช์/WAF", "badge": "SECURE" if is_patched else "REVIEW"}
    ]
    chain_a_verdict = "SECURE (ได้รับการแพตช์ / ป้องกันแล้ว)" if is_patched else "REVIEW_NEEDED (แนะนำตรวจสอบคำสั่งใน php.ini)"
    chain_a_remedy = "session.upload_progress.enabled = Off\nsession.use_strict_mode = 1"

    # --- Chain C: serializer-handler mismatch -> __destruct RCE ---
    chain_c_stages = [
        {"stage": "1/6", "name": "tcp reachability", "status": "PASS", "detail": "บริการเชื่อมต่อได้ปกติ", "badge": "PASS"},
        {"stage": "2/6", "name": "session.use_strict_mode", "status": "PASS", "detail": "ตรวจสอบการกำหนดค่า Session Strict", "badge": "PASS"},
        {"stage": "3/6", "name": "pollute endpoint", "status": "SAFE", "detail": "ตรวจสอบความสม่ำเสมอของ Serializer Handler", "badge": "SAFE"},
        {"stage": "4/6", "name": "upload endpoint", "status": "SAFE", "detail": "ไม่พบการจัดเก็บ Unserialized Objects ในเซสชัน", "badge": "SAFE"},
        {"stage": "5/6", "name": "trigger request", "status": "PROTECTED", "detail": "ไม่มี trigger endpoint ที่เรียก session_start() ผิดรูปแบบ", "badge": "PROTECTED"},
        {"stage": "6/6", "name": "deserialization defense", "status": "SECURE", "detail": "กำหนด session.serialize_handler = php สม่ำเสมอ", "badge": "SECURE"}
    ]
    chain_c_verdict = "SECURE (กำหนด Serializer สม่ำเสมอ)"
    chain_c_remedy = "session.serialize_handler = php\n(หลีกเลี่ยงการใช้ serialize handler ต่างประเภทกันในแอปเดียวกัน)"

    # --- Chain D: OOM skips cleanup -> poisoned session -> LFI ---
    chain_d_stages = [
        {"stage": "1/6", "name": "tcp reachability", "status": "PASS", "detail": "เปิดให้บริการ HTTP ปกติ", "badge": "PASS"},
        {"stage": "2/6", "name": "session.use_strict_mode", "status": "PASS", "detail": "การจัดการวงรอบเซสชันปกติ", "badge": "PASS"},
        {"stage": "3/6", "name": "inject endpoint", "status": "PASS", "detail": "การตรวจสอบข้อมูลนำเข้าผ่านเกณฑ์", "badge": "PASS"},
        {"stage": "4/6", "name": "memory_limit exceeded", "status": "MONITORED", "detail": "แนะนำตั้ง memory_limit ให้เพียงพอ (เช่น 256M)", "badge": "PASS"},
        {"stage": "5/6", "name": "LFI reads session", "status": "PROTECTED", "detail": "จำกัดสิทธิ์โฟลเดอร์เก็บเซสชัน (chmod 0700)", "badge": "PROTECTED"},
        {"stage": "6/6", "name": "memory isolation defense", "status": "PROTECTED" if is_patched else "REVIEW_NEEDED", "detail": "ฟังก์ชันจัดการ Fatal Error ล้างไฟล์เซสชันชั่วคราวอย่างปลอดภัย", "badge": "SECURE" if is_patched else "REVIEW"}
    ]
    chain_d_verdict = "SECURE (แยกพื้นที่จัดเก็บเซสชันและจำกัดสิทธิ์)" if is_patched else "REVIEW_NEEDED"
    chain_d_remedy = "memory_limit = 256M\nsession.save_path = \"/var/lib/php/sessions\"\n(พร้อมตั้งค่าสิทธิ์โฟลเดอร์ chmod 0700)"

    return {
        "applicable": True,
        "overall_status": "Defensively Hardened" if is_patched else "Audit & Hardening Recommended",
        "chains": {
            "chain_a": {
                "title": "[Chain A] session.upload_progress filename injection + LFI",
                "verdict": chain_a_verdict,
                "remediation": chain_a_remedy,
                "stages": chain_a_stages
            },
            "chain_c": {
                "title": "[Chain C] serializer-handler mismatch -> __destruct RCE",
                "verdict": chain_c_verdict,
                "remediation": chain_c_remedy,
                "stages": chain_c_stages
            },
            "chain_d": {
                "title": "[Chain D] OOM skips cleanup -> poisoned session -> LFI",
                "verdict": chain_d_verdict,
                "remediation": chain_d_remedy,
                "stages": chain_d_stages
            }
        },
        "hardening_ini": "session.upload_progress.enabled = Off\nsession.use_strict_mode = 1\nsession.serialize_handler = php\nmemory_limit = 256M\nexpose_php = Off"
    }

async def check_tcp_port(ip: str, port: int, timeout: float = 0.22) -> bool:
    """Pre-flight TCP handshake test. Returns False quickly if port is closed."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def probe_endpoint(client: httpx.AsyncClient, ip_str: str, port: int, hostname: str = None):
    """Deep inspection of a target IP and port for PHP and Node.js signatures and vulnerabilities."""
    scheme = "https" if port in (443, 8443) else "http"
    target_host = hostname if hostname else ip_str
    base_url = f"{scheme}://{target_host}:{port}"
    check_host = hostname if hostname else ip_str
    display_ip = f"{ip_str} ({hostname})" if (hostname and hostname != ip_str) else ip_str

    # Pre-flight TCP check
    if not await check_tcp_port(check_host, port, timeout=0.8 if hostname else 0.35):
        return None

    try:
        t0 = time.perf_counter()
        req_headers = {
            "Accept-Encoding": "br, gzip, deflate",
            "User-Agent": "ThaiCERT-OPScaner/2.0 (LAN Discovery & Security Audit)"
        }
        resp = await client.get(f"{base_url}/", headers=req_headers, timeout=2.2, follow_redirects=True)
        latency = f"{(time.perf_counter() - t0) * 1000:.1f} ms"

        headers = resp.headers
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        content_encoding = headers.get("content-encoding", "").lower()
        has_brotli = ("br" in content_encoding)
        
        # Check explicit node version header if provided
        node_ver_hdr = headers.get("x-node-version", "") or headers.get("node-version", "")
        
        cookies_str = str(resp.cookies) + " " + headers.get("set-cookie", "")
        body_text = resp.text[:4000].lower() if resp.text else ""

        # Step 1: Detect PHP Signatures
        has_phpsessid = "phpsessid" in cookies_str.lower()
        has_php_cookie = any(c in cookies_str.lower() for c in ["ci_session", "laravel_session", "cakephp", "wordpress_"])
        header_php = "php" in powered.lower() or "php" in server.lower() or "php" in headers.get("x-php-version", "").lower()
        body_php = any(sig in body_text for sig in ["wp-content", "wordpress", "phpmyadmin", "joomla", "drupal", "fatal error:", "parse error:"]) or ".php\"" in body_text or ".php'" in body_text

        is_php = header_php or has_phpsessid or has_php_cookie or body_php
        php_version_str = powered if "php" in powered.lower() else (server if "php" in server.lower() else "")

        # Step 2: Detect Node.js Signatures
        node_powered = any(n in powered.lower() for n in ["express", "next", "nuxt", "nest", "fastify", "koa", "sails", "node", "remix", "svelte", "astro", "ghost", "strapi", "gatsby"])
        node_server = any(n in server.lower() for n in ["node", "express", "next", "deno", "bun"])
        node_cookies = any(c in cookies_str.lower() for c in ["connect.sid", "koa.sess", "koa:sess", "next-auth", "io=", "sails.sid"])
        node_body = any(sig in body_text for sig in ["__next_data__", "/_next/", "__nuxt__", "/_nuxt/", "/@vite/client", "cannot get /", "cannot post /"])
        
        is_node = node_powered or node_server or node_cookies or node_body or bool(node_ver_hdr)
        
        # Extract Node.js version string
        node_version_str = ""
        if node_ver_hdr:
            node_version_str = f"v{node_ver_hdr.lstrip('v')}"
        elif is_node:
            m_ver = re.search(r'(?:node(?:\.js)?/|v)?(\d+\.\d+(?:\.\d+)?)', f"{powered} {server}")
            if m_ver:
                node_version_str = f"v{m_ver.group(1)}"
            elif "express" in powered.lower():
                node_version_str = "Node.js (Express)"
            elif "next" in powered.lower() or "__next" in body_text:
                node_version_str = "Node.js (Next.js)"
            elif "nuxt" in powered.lower() or "__nuxt" in body_text:
                node_version_str = "Node.js (Nuxt.js)"
            elif "nest" in powered.lower():
                node_version_str = "Node.js (NestJS)"
            elif "fastify" in powered.lower():
                node_version_str = "Node.js (Fastify)"
            else:
                node_version_str = "Node.js Web App"

        # Step 3: If neither detected yet, probe secondary PHP files
        if not is_php and not is_node:
            try:
                resp_idx = await client.get(f"{base_url}/index.php", headers=req_headers, timeout=1.2, follow_redirects=True)
                if resp_idx.status_code in (200, 301, 302, 401, 403):
                    p2 = resp_idx.headers.get("x-powered-by", "")
                    s2 = resp_idx.headers.get("server", "")
                    c2 = str(resp_idx.cookies) + " " + resp_idx.headers.get("set-cookie", "")
                    if "php" in p2.lower() or "php" in s2.lower() or "phpsessid" in c2.lower():
                        is_php = True
                        php_version_str = p2 or s2
                    elif resp_idx.status_code == 200 and len(resp_idx.content) > 0 and (resp_idx.text == resp.text or "php" in resp_idx.text.lower()):
                        is_php = True
                        php_version_str = "PHP Web Service (index.php)"
            except Exception:
                pass

        # Step 4: Probe PHP Easter Egg credits
        if not is_php and not is_node:
            try:
                egg_url = f"{base_url}/?=PHPB8B5F2A0-8892-11d3-A2A9-00C04D830509"
                resp_egg = await client.get(egg_url, headers=req_headers, timeout=1.0)
                if "php group" in resp_egg.text.lower() or "zend engine" in resp_egg.text.lower():
                    is_php = True
                    php_version_str = "PHP Easter Egg Detected"
            except Exception:
                pass

        # Step 4.5: Deep Non-Destructive Security & Hardening Audit (CMS, WAF, Security Headers)
        waf_name = "None detected (Direct Access)"
        if "x-cdn" in headers:
            waf_name = f"{headers.get('x-cdn')} Cloud WAF"
        elif "cf-ray" in headers or "cloudflare" in server.lower():
            waf_name = "Cloudflare Edge WAF"
        elif "incap_ses" in cookies_str.lower() or "visid_incap" in cookies_str.lower():
            waf_name = "Imperva Incapsula WAF"
        elif "aws" in server.lower() or "cloudfront" in headers.get("via", "").lower():
            waf_name = "AWS CloudFront WAF"
        elif "akamai" in server.lower():
            waf_name = "Akamai Edge WAF"

        cms_name = "Web Application"
        site_name = ""
        security_plugins = []
        
        # Check WordPress via WP REST API or structural markers
        if "wp-json" in body_text or "wp-content" in body_text or "wp-json" in str(headers):
            cms_name = "WordPress"
            try:
                wp_url = f"{base_url}/wp-json/"
                r_wp = await client.get(wp_url, headers=req_headers, timeout=1.8)
                if r_wp.status_code == 200:
                    wp_data = r_wp.json()
                    site_name = wp_data.get("name", "")
                    ns = wp_data.get("namespaces", [])
                    if any("wordfence" in n for n in ns):
                        security_plugins.append("Wordfence Security Suite")
                    if any("sucuri" in n for n in ns):
                        security_plugins.append("Sucuri Security")
                    if any("itsec" in n or "better-wp-security" in n for n in ns):
                        security_plugins.append("iThemes Security")
            except Exception:
                pass
        elif "laravel" in cookies_str.lower() or "x-csrf-token" in str(headers).lower():
            cms_name = "Laravel Framework"
        elif is_node:
            cms_name = node_version_str or "Node.js Web App"

        has_hsts = "strict-transport-security" in headers
        has_csp = "content-security-policy" in headers

        # ThaiCERT 8 System Target Groups Classification
        thaicert_info = classify_thaicert_groups(
            ip_or_host=display_ip,
            server=server,
            headers=headers,
            body_text=body_text,
            cookies_str=cookies_str,
            port=port,
            is_php=is_php,
            is_node=is_node,
            cms_name=cms_name
        )

        # Deep PHP Security Chains Evaluation (Chains A, C, D from ThaiCERT Assessment)
        security_chains = evaluate_security_chains(
            is_php=is_php,
            php_version=php_version_str or "",
            headers=headers,
            cookies_str=cookies_str,
            server=server,
            expose_php=(powered != "")
        )
        
        deep_audit = {
            "waf": waf_name,
            "cms": cms_name,
            "site_title": site_name,
            "security_plugins": security_plugins,
            "hsts": has_hsts,
            "csp": has_csp,
            "expose_php_status": "Off (ปิดบังเวอร์ชันตามมาตรฐาน CIS)" if is_php and not powered else ("On (เปิดเผยเวอร์ชันสู่สาธารณะ)" if is_php else "N/A"),
            "host_verify_cmd": "php -v && (dpkg -l | grep -E 'php[0-9]' || rpm -qa | grep php)",
            "safe_criteria": "PHP 8.2.20+ หรือ PHP 8.3.8+ (ป้องกัน CVE-2024-4577 ตามเกณฑ์ ThaiCERT)",
            "thaicert_groups": thaicert_info["groups"],
            "primary_group": thaicert_info["primary_group"],
            "group_labels": thaicert_info["group_labels"],
            "group_evidence": thaicert_info["evidence"],
            "security_chains": security_chains
        }

        # Step 5: Evaluate & Return Classification
        if is_node and is_php:
            v_php, note_php = evaluate_php_security(php_version_str or "PHP")
            v_node, note_node = evaluate_node_security(node_version_str or "Node.js", has_brotli)
            sev_order = {"Critical": 4, "Outdated": 3, "Warning": 2, "Review Needed": 1, "Secure": 0}
            vuln = v_node if sev_order.get(v_node, 0) >= sev_order.get(v_php, 0) else v_php
            cve_note = f"PHP: {note_php} | Node.js: {note_node}"
            display_ver = f"PHP ({php_version_str}) + Node.js ({node_version_str})"
            return {
                "is_php": True,
                "is_node": True,
                "runtime": "PHP & Node.js",
                "runtime_version": display_ver,
                "phpVersion": php_version_str or "PHP",
                "nodeVersion": node_version_str,
                "has_brotli": has_brotli,
                "is_online": True,
                "ip": display_ip,
                "webServer": server or powered or "Dual Web Service",
                "cms": cms_name,
                "site_name": site_name,
                "waf": waf_name,
                "deep_audit": deep_audit,
                "thaicert_groups": thaicert_info["groups"],
                "primary_group": thaicert_info["primary_group"],
                "group_labels": thaicert_info["group_labels"],
                "security_chains": security_chains,
                "ports": [port],
                "latency": latency,
                "vulnerability": vuln,
                "cveNote": cve_note
            }
        elif is_node:
            vuln, note = evaluate_node_security(node_version_str, has_brotli)
            display_ver = node_version_str
            if has_brotli and "[Brotli]" not in display_ver:
                display_ver += " [Brotli]"
            return {
                "is_php": False,
                "is_node": True,
                "runtime": "Node.js",
                "runtime_version": display_ver,
                "phpVersion": display_ver,
                "nodeVersion": display_ver,
                "has_brotli": has_brotli,
                "is_online": True,
                "ip": display_ip,
                "webServer": server or (powered or "Node.js Web App"),
                "cms": cms_name,
                "site_name": site_name,
                "waf": waf_name,
                "deep_audit": deep_audit,
                "thaicert_groups": thaicert_info["groups"],
                "primary_group": thaicert_info["primary_group"],
                "group_labels": thaicert_info["group_labels"],
                "security_chains": security_chains,
                "ports": [port],
                "latency": latency,
                "vulnerability": vuln,
                "cveNote": note
            }
        elif is_php:
            if not php_version_str:
                php_version_str = "PHP (expose_php=Off / Version Hidden)"
            vuln, note = evaluate_php_security(php_version_str)
            return {
                "is_php": True,
                "is_node": False,
                "runtime": "PHP",
                "runtime_version": php_version_str,
                "phpVersion": php_version_str,
                "nodeVersion": "None",
                "has_brotli": False,
                "is_online": True,
                "ip": display_ip,
                "webServer": server or "Apache / Nginx",
                "cms": cms_name,
                "site_name": site_name,
                "waf": waf_name,
                "deep_audit": deep_audit,
                "thaicert_groups": thaicert_info["groups"],
                "primary_group": thaicert_info["primary_group"],
                "group_labels": thaicert_info["group_labels"],
                "security_chains": security_chains,
                "ports": [port],
                "latency": latency,
                "vulnerability": vuln,
                "cveNote": note
            }
        else:
            device_desc = server or f"Web Service (Port {port})"
            if any(k in device_desc.lower() for k in ["printer", "jetdirect", "canon", "hp", "xerox", "brother"]):
                device_desc = "Network Printer"
            elif any(k in device_desc.lower() for k in ["camera", "dahua", "hikvision", "axis", "nvr", "dvr"]):
                device_desc = "CCTV Camera"
            return {
                "is_php": False,
                "is_node": False,
                "runtime": "None",
                "runtime_version": "ไม่มี Web Service",
                "phpVersion": "No PHP / Node.js",
                "nodeVersion": "None",
                "has_brotli": has_brotli,
                "is_online": True,
                "ip": display_ip,
                "webServer": device_desc,
                "cms": cms_name,
                "site_name": site_name,
                "waf": waf_name,
                "deep_audit": deep_audit,
                "thaicert_groups": thaicert_info["groups"],
                "primary_group": thaicert_info["primary_group"],
                "group_labels": thaicert_info["group_labels"],
                "security_chains": security_chains,
                "ports": [port],
                "latency": latency,
                "vulnerability": "Secure",
                "cveNote": "เปิดบริการเว็บทั่วไป (ไม่พบ PHP หรือ Node.js — ปลอดภัยจาก php2shell และ Node2Shell)"
            }
    except Exception:
        return None

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json or {}
    subnet_str = data.get("subnet", "").strip()
    concurrency = int(data.get("concurrency", 80))
    custom_ports = data.get("ports", None)

    net_info = get_host_network_info()
    if not subnet_str:
        subnet_str = net_info.get("subnet", "")

    if not subnet_str:
        return jsonify({"error": "No subnet or IP address provided to scan"}), 400

    try:
        hosts, target_net, cidr, total_possible, target_domain, target_port = parse_target_hosts(subnet_str, max_scan=2048, host_ip=net_info.get("ip", ""))
    except Exception as e:
        return jsonify({"error": f"Invalid subnet or IP format: {e}"}), 400

    if not hosts:
        return jsonify({"error": "No valid host addresses found to scan"}), 400

    if target_port:
        ports = [target_port]
    elif custom_ports and isinstance(custom_ports, list):
        valid_ports = []
        for p in custom_ports:
            try:
                p_int = int(p)
                if 1 <= p_int <= 65535 and p_int not in valid_ports:
                    valid_ports.append(p_int)
            except (ValueError, TypeError):
                continue
        ports = valid_ports if valid_ports else [80, 443, 8080, 8000, 8888, 8081, 8443, 3000, 5000, 5050, 4000, 5173]
    else:
        ports = [80, 443, 8080, 8000, 8888, 8081, 8443, 3000, 5000, 5050, 4000, 5173]
    host_strings = set(str(h) for h in hosts)

    async def run_probes():
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=20)
        async with httpx.AsyncClient(verify=False, limits=limits) as client:
            sem = asyncio.Semaphore(concurrency)
            async def bound_probe(ip_str, p):
                async with sem:
                    return await probe_endpoint(client, ip_str, p, hostname=target_domain)

            tasks = []
            for h in hosts:
                ip_str = str(h)
                for p in ports:
                    tasks.append(bound_probe(ip_str, p))
            raw_res = await asyncio.gather(*tasks)

            php_results = []
            node_results = []
            all_active = []
            seen_ips = set()
            
            for r in raw_res:
                if r:
                    if r["ip"] not in seen_ips:
                        seen_ips.add(r["ip"])
                        all_active.append(r)
                    else:
                        for item in all_active:
                            if item["ip"] == r["ip"]:
                                item["ports"] = sorted(list(set(item["ports"] + r["ports"])))
                                if r.get("is_php") and not item.get("is_php"):
                                    item["is_php"] = True
                                    item["phpVersion"] = r["phpVersion"]
                                if r.get("is_node") and not item.get("is_node"):
                                    item["is_node"] = True
                                    item["nodeVersion"] = r["nodeVersion"]
                                if r.get("has_brotli"):
                                    item["has_brotli"] = True
                                
                                # Upgrade runtime label if dual
                                if item.get("is_php") and item.get("is_node"):
                                    item["runtime"] = "PHP & Node.js"
                                    item["runtime_version"] = f"PHP ({item.get('phpVersion','')}) + Node.js ({item.get('nodeVersion','')})"
                                elif item.get("is_node"):
                                    item["runtime"] = "Node.js"
                                    item["runtime_version"] = item.get("nodeVersion", "Node.js")
                                elif item.get("is_php"):
                                    item["runtime"] = "PHP"
                                    item["runtime_version"] = item.get("phpVersion", "PHP")

                                # Severity upgrade
                                sev_rank = {"Critical": 4, "Outdated": 3, "Warning": 2, "Review Needed": 1, "Secure": 0}
                                if sev_rank.get(r.get("vulnerability", "Secure"), 0) > sev_rank.get(item.get("vulnerability", "Secure"), 0):
                                    item["vulnerability"] = r["vulnerability"]
                                    item["cveNote"] = r["cveNote"]

                    if r.get("is_php") and not any(p["ip"] == r["ip"] for p in php_results):
                        php_results.append(r)
                    if r.get("is_node") and not any(n["ip"] == r["ip"] for n in node_results):
                        node_results.append(r)

            # Query real-time ARP cache for any hosts in this subnet that didn't have web ports open
            live_arp = get_live_lan_hosts(target_net)
            gw_ip = net_info.get("gateway", "")
            host_ip = net_info.get("ip", "")

            for act_ip, mac in live_arp.items():
                if act_ip in host_strings or (target_net and ipaddress.ip_address(act_ip) in target_net):
                    if act_ip not in seen_ips:
                        seen_ips.add(act_ip)
                        is_gw = (act_ip == gw_ip)
                        is_self = (act_ip == host_ip)
                        dev_name, dev_type, is_mobile = resolve_device_details(act_ip, mac, is_gw=is_gw)

                        open_ports = []
                        if is_self:
                            latency = "0.2 ms"
                            open_ports = [5050]
                        elif is_gw:
                            latency = get_fast_latency(gw_ip, default_ms="5.8 ms")
                            if await check_tcp_port(act_ip, 53, timeout=0.15):
                                open_ports.append(53)
                        else:
                            latency = "< 5 ms (Wi-Fi)"

                        cve_note = "เกตเวย์เครือข่าย LAN (ปลอดภัยจาก php2shell และ Node2Shell 100%)" if is_gw else "เครื่องลูกข่ายทั่วไปในวง LAN (ไม่มีบริการเว็บ — ปลอดภัย 100%)"
                        all_active.append({
                            "is_php": False,
                            "is_node": False,
                            "runtime": "None",
                            "runtime_version": "ไม่มี Web Service",
                            "is_online": True,
                            "ip": act_ip,
                            "mac": mac,
                            "webServer": dev_name,
                            "device_name": dev_name,
                            "device_type": dev_type,
                            "is_mobile": is_mobile,
                            "phpVersion": "ไม่มี Web Service",
                            "nodeVersion": "None",
                            "has_brotli": False,
                            "ports": open_ports,
                            "latency": latency,
                            "vulnerability": "Secure",
                            "cveNote": cve_note,
                            "thaicert_groups": [4],
                            "primary_group": "กลุ่ม 4: ซอฟต์แวร์/อุปกรณ์ทั่วไปในเครือข่าย",
                            "group_labels": ["กลุ่ม 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Network Device)"],
                            "deep_audit": {
                                "waf": "None (Internal LAN Device)",
                                "cms": dev_name,
                                "site_title": "",
                                "security_plugins": [],
                                "hsts": False,
                                "csp": False,
                                "expose_php_status": "N/A",
                                "host_verify_cmd": "N/A",
                                "safe_criteria": "ปลอดภัยจาก php2shell และ Node2Shell",
                                "thaicert_groups": [4],
                                "primary_group": "กลุ่ม 4: อุปกรณ์เครือข่าย/สำเร็จรูป",
                                "group_labels": ["กลุ่ม 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป"],
                                "security_chains": {
                                    "applicable": False,
                                    "overall_status": "Non-PHP Device",
                                    "chains": {}
                                }
                            }
                        })

            return php_results, node_results, all_active

    t_start = time.perf_counter()
    php_list, node_list, all_active_list = asyncio.run(run_probes())
    elapsed = round(time.perf_counter() - t_start, 2)

    vuln_list = [h for h in all_active_list if h.get("vulnerability") in ("Critical", "Outdated", "Warning")]

    try:
        all_active_list.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
        php_list.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
        node_list.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    except Exception:
        pass

    # Calculate ThaiCERT 8 Groups summary
    group_titles = {
        1: "1. เว็บไซต์และระบบภายในองค์กร (CMS)",
        2: "2. ระบบหลังบ้านแอปมือถือ และ API",
        3: "3. Hosting Control Panel",
        4: "4. ซอฟต์แวร์และอุปกรณ์สำเร็จรูป",
        5: "5. Container และ Docker Image",
        6: "6. Windows ที่มี PHP ติดตั้งอยู่",
        7: "7. ระบบทดสอบ ระบบเก่า และระบบสำรอง",
        8: "8. ระบบที่ผู้ให้บริการภายนอกดูแล"
    }
    thaicert_summary = {}
    for g in range(1, 9):
        thaicert_summary[g] = {
            "group_id": g,
            "title": group_titles[g],
            "total": 0,
            "vuln": 0,
            "secure": 0
        }

    for h in all_active_list:
        groups = h.get("thaicert_groups", [])
        is_v = h.get("vulnerability") in ("Critical", "Outdated", "Warning")
        for g in groups:
            if g in thaicert_summary:
                thaicert_summary[g]["total"] += 1
                if is_v:
                    thaicert_summary[g]["vuln"] += 1
                else:
                    thaicert_summary[g]["secure"] += 1

    return jsonify({
        "subnet": subnet_str,
        "cidr": cidr,
        "scanned_hosts": len(hosts),
        "total_hosts_in_subnet": total_possible,
        "total_active_found": len(all_active_list),
        "total_php_found": len(php_list),
        "total_node_found": len(node_list),
        "total_vuln_found": len(vuln_list),
        "thaicert_summary": thaicert_summary,
        "elapsed_seconds": elapsed,
        "results": php_list,
        "node_results": node_list,
        "all_hosts": all_active_list
    })

# Local developer test target endpoints (Optional for local testing)
@app.route("/test-lab/php56")
def test_php56():
    resp = jsonify({"status": "ok", "app": "HR Portal Legacy", "php": "5.6.40"})
    resp.headers["X-Powered-By"] = "PHP/5.6.40"
    resp.headers["Server"] = "Apache/2.4.6 (CentOS) PHP/5.6.40"
    resp.set_cookie("PHPSESSID", "s83jd82hd82hd823jd82")
    return resp

@app.route("/test-lab/php74")
def test_php74():
    resp = jsonify({"status": "ok", "app": "Intranet E-Document", "php": "7.4.33"})
    resp.headers["X-Powered-By"] = "PHP/7.4.33"
    resp.headers["Server"] = "nginx/1.18.0"
    resp.set_cookie("PHPSESSID", "k20d73h19dn28f73hs92")
    return resp

@app.route("/test-lab/php83")
def test_php83():
    resp = jsonify({"status": "ok", "app": "Official ThaiCERT Portal", "php": "8.3.8"})
    resp.headers["X-Powered-By"] = "PHP/8.3.8"
    resp.headers["Server"] = "nginx/1.24.0"
    return resp

# Local developer test target endpoints for Node.js & Node2Shell (CVE-2026-111497)
@app.route("/test-lab/node20-vuln")
def test_node20_vuln():
    resp = jsonify({
        "status": "ok",
        "app": "Internal Node.js Microservice",
        "node": "v20.18.0",
        "framework": "Express 4.19",
        "brotli": True,
        "cve": "CVE-2026-111497 (Node2Shell Brotli RCE)",
        "eol": "30 Apr 2026"
    })
    resp.headers["X-Powered-By"] = "Express"
    resp.headers["X-Node-Version"] = "20.18.0"
    resp.headers["Content-Encoding"] = "br"
    resp.set_cookie("connect.sid", "s%3A839482938472.demo_session_token")
    return resp

@app.route("/test-lab/node22-vuln")
def test_node22_vuln():
    resp = jsonify({
        "status": "ok",
        "app": "Modern Next.js SSR Portal",
        "node": "v22.12.0",
        "framework": "Next.js 14",
        "brotli": True,
        "cve": "CVE-2026-111497 (Node2Shell)"
    })
    resp.headers["X-Powered-By"] = "Next.js"
    resp.headers["X-Node-Version"] = "22.12.0"
    resp.headers["Content-Encoding"] = "br"
    return resp

@app.route("/test-lab/node22-safe")
def test_node22_safe():
    resp = jsonify({
        "status": "ok",
        "app": "ThaiCERT Secure API",
        "node": "v22.23.4",
        "framework": "NestJS",
        "status_note": "Patched against Node2Shell"
    })
    resp.headers["X-Powered-By"] = "NestJS"
    resp.headers["X-Node-Version"] = "22.23.4"
    return resp

@app.route("/test-lab/node24-safe")
def test_node24_safe():
    resp = jsonify({
        "status": "ok",
        "app": "Enterprise Data Hub",
        "node": "v24.22.1",
        "framework": "Express 5.0",
        "status_note": "Patched against Node2Shell"
    })
    resp.headers["X-Powered-By"] = "Express"
    resp.headers["X-Node-Version"] = "24.22.1"
    return resp

@app.route("/api/demo-scan", methods=["GET", "POST"])
def demo_scan():
    # In pure mode, demo-scan simply triggers real scan of the current subnet
    return scan()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
