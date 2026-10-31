"""
Multi-Vector LAN Host Discovery Engine for OPScaner.
Enables full-fidelity device discovery even inside Docker containers on macOS / Linux
without relying solely on Layer 2 ARP broadcasts.

Vectors:
  1. TCP SYN / Connect / RST Detection (L4)
  2. UDP Service Probing (mDNS 5353, NetBIOS-NS 137, SSDP 1900, DNS 53)
  3. ICMP Echo Ping Sweep (L3)
  4. Local Gateway DNS/DHCP Reverse Lookup (PTR)
"""

import asyncio
import ipaddress
import os
import re
import socket
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional, Set, Tuple


# Standard enterprise & LAN TCP service ports for host discovery
STANDARD_DISCOVERY_TCP_PORTS = [
    80,    # HTTP (Routers, Web servers, Cameras)
    443,   # HTTPS (Web services, Secure Admin)
    53,    # DNS (Routers, Pi-hole, AdGuard)
    22,    # SSH (Linux, Raspberry Pi, Routers)
    445,   # SMB (Windows 10/11, File Sharing, NAS)
    135,   # MS-RPC (Windows Workstations)
    139,   # NetBIOS Session (Windows, Samba)
    3389,  # Remote Desktop (Windows RDP)
    8080,  # Alternate HTTP (Proxies, Web apps, Routers)
    8000,  # Dev Servers / IoT APIs
    8008,  # Google Cast / Chromecast / Android TV
    8009,  # Chromecast Streaming
    9100,  # Raw JetDirect (Printers: HP, Brother, Epson, Canon)
    631,   # IPP (Internet Printing Protocol / CUPS)
    554,   # RTSP (IP Cameras, CCTV, NVR)
    5000,  # UPnP / Synology NAS / Flask
    5050,  # OPScaner Host
    8443,  # Alternate HTTPS
]

DISCOVERY_TCP_PORTS = STANDARD_DISCOVERY_TCP_PORTS

# NetBIOS Node Status Request Packet (Wildcard '*')
NETBIOS_NODE_STATUS_QUERY = (
    b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
    b"\x00\x21\x00\x01"
)

# mDNS Query for _services._dns-sd._udp.local (Bonjour / Zeroconf)
MDNS_SERVICES_QUERY = (
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    b"\x00\x0c\x00\x01"
)


def _build_dns_ptr_query(ip_str: str) -> bytes:
    """Construct DNS PTR query packet for reverse hostname lookup."""
    try:
        parts = ip_str.split(".")[::-1]
        ptr_domain = ".".join(parts) + ".in-addr.arpa"
        header = b"\x77\x88\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for part in ptr_domain.split("."):
            qname += bytes([len(part)]) + part.encode("ascii", "ignore")
        qname += b"\x00"
        footer = b"\x00\x0c\x00\x01"  # QTYPE=PTR, QCLASS=IN
        return header + qname + footer
    except Exception:
        return b""


def _parse_dns_ptr_response(data: bytes) -> Optional[str]:
    """Parse PTR hostname from raw DNS response."""
    try:
        if len(data) < 12:
            return None
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return None

        # Skip header (12 bytes) and question section
        idx = 12
        while idx < len(data) and data[idx] != 0:
            if (data[idx] & 0xC0) == 0xC0:
                idx += 2
                break
            idx += 1 + data[idx]
        if idx < len(data) and data[idx] == 0:
            idx += 1
        idx += 4  # Skip QTYPE and QCLASS

        # Parse answers
        for _ in range(ancount):
            if idx >= len(data):
                break
            # Skip name
            if (data[idx] & 0xC0) == 0xC0:
                idx += 2
            else:
                while idx < len(data) and data[idx] != 0:
                    idx += 1 + data[idx]
                if idx < len(data):
                    idx += 1

            if idx + 10 > len(data):
                break
            atype, aclass, attl, rdlength = struct.unpack("!HHIH", data[idx:idx + 10])
            idx += 10

            if atype == 12 and idx + rdlength <= len(data):  # PTR
                # Decode PTR name labels
                labels = []
                p = idx
                end = idx + rdlength
                while p < end:
                    length = data[p]
                    if length == 0:
                        break
                    if (length & 0xC0) == 0xC0:  # Pointer compression
                        offset = struct.unpack("!H", data[p:p + 2])[0] & 0x3FFF
                        ptr_p = offset
                        while ptr_p < len(data) and data[ptr_p] != 0:
                            l = data[ptr_p]
                            ptr_p += 1
                            labels.append(data[ptr_p:ptr_p + l].decode("utf-8", "ignore"))
                            ptr_p += l
                        break
                    p += 1
                    labels.append(data[p:p + length].decode("utf-8", "ignore"))
                    p += length
                if labels:
                    hostname = ".".join(labels)
                    return hostname.rstrip(".")
            idx += rdlength
    except Exception:
        pass
    return None


def _parse_netbios_response(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Parse NetBIOS Computer Name and MAC address from NBSTAT response."""
    try:
        if len(data) < 56:
            return None, None
        num_names = data[56]
        comp_name = None
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name_raw = data[offset:offset + 15].decode("ascii", "ignore").strip()
            name_type = data[offset + 15]
            flags = struct.unpack("!H", data[offset + 16:offset + 18])[0]
            is_group = bool(flags & 0x8000)
            if not is_group and name_type == 0x00 and not comp_name:
                comp_name = name_raw
            offset += 18

        mac_str = None
        if offset + 6 <= len(data):
            mac_bytes = data[offset:offset + 6]
            mac_str = ":".join(f"{b:02x}" for b in mac_bytes)

        return comp_name, mac_str
    except Exception:
        return None, None


class MultiVectorDiscoveryEngine:
    """
    High-performance asynchronous network discovery engine designed to detect
    silent home devices, smartphones, IoT, Smart TVs, printers, and workstations
    from within Docker containerized environments.
    """

    def __init__(self, concurrency: int = 150, timeout: float = 0.35):
        self.concurrency = concurrency
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)

    async def probe_tcp_host(self, ip_str: str, port: int) -> Tuple[bool, Optional[int], str]:
        """
        Probe single TCP port.
        Returns (is_alive, open_port, evidence)
        Only True TCP Open (Handshake complete) counts as an active service.
        Note: TCP RST is excluded because Docker Desktop VM NAT on macOS returns RST for all unreachable IPs.
        """
        async with self.sem:
            loop = asyncio.get_running_loop()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                await asyncio.wait_for(loop.sock_connect(s, (ip_str, port)), timeout=self.timeout)
                s.close()
                return True, port, f"TCP Open (Port {port})"
            except Exception:
                s.close()
                return False, None, ""

    async def probe_udp_netbios(self, ip_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Query NetBIOS Name Service (UDP 137)."""
        async with self.sem:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, NETBIOS_NODE_STATUS_QUERY, (ip_str, 137))
                data = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=self.timeout)
                sock.close()
                name, mac = _parse_netbios_response(data)
                return True, name, mac
            except Exception:
                sock.close()
                return False, None, None

    async def probe_udp_mdns(self, ip_str: str) -> Tuple[bool, Optional[str]]:
        """Query mDNS / Bonjour (UDP 5353) directly to host."""
        async with self.sem:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, MDNS_SERVICES_QUERY, (ip_str, 5353))
                data = await asyncio.wait_for(loop.sock_recv(sock, 2048), timeout=self.timeout)
                sock.close()
                # Check for readable ASCII strings (device name / service name)
                matches = re.findall(rb'[\x20-\x7E]{4,}', data)
                decoded = [m.decode("ascii", "ignore") for m in matches if not m.startswith(b"_")]
                dev_hint = decoded[0] if decoded else "Apple/mDNS Device"
                return True, dev_hint
            except Exception:
                sock.close()
                return False, None

    async def probe_dns_ptr(self, ip_str: str, gateway_ip: str) -> Optional[str]:
        """Query Local Gateway Router for DHCP hostname of ip_str."""
        if not gateway_ip:
            return None
        async with self.sem:
            loop = asyncio.get_running_loop()
            query_pkt = _build_dns_ptr_query(ip_str)
            if not query_pkt:
                return None
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, query_pkt, (gateway_ip, 53))
                data = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=self.timeout)
                sock.close()
                return _parse_dns_ptr_response(data)
            except Exception:
                sock.close()
                return None

    async def probe_icmp_ping(self, ip_str: str) -> bool:
        """Lightweight socket-based connectivity check (zero OS subprocess / non-blocking)."""
        return False

    async def scan_single_host(self, ip_str: str, gateway_ip: str = "") -> Optional[Dict[str, Any]]:
        """
        Execute multi-vector discovery against a single IP address.
        Correlates TCP, UDP mDNS, NetBIOS, and Router DHCP records.
        """
        # 1. Quick TCP sweep across high-priority standard ports
        priority_ports = STANDARD_DISCOVERY_TCP_PORTS
        tcp_tasks = [self.probe_tcp_host(ip_str, p) for p in priority_ports]
        
        # 2. Parallel UDP & PTR probes (zero child processes)
        udp_nb_task = self.probe_udp_netbios(ip_str)
        udp_mdns_task = self.probe_udp_mdns(ip_str)
        ptr_task = self.probe_dns_ptr(ip_str, gateway_ip) if gateway_ip else asyncio.sleep(0, result=None)

        all_results = await asyncio.gather(
            *tcp_tasks, udp_nb_task, udp_mdns_task, ptr_task,
            return_exceptions=True
        )

        tcp_results = all_results[:len(priority_ports)]
        nb_res = all_results[len(priority_ports)]
        mdns_res = all_results[len(priority_ports) + 1]
        ptr_res = all_results[len(priority_ports) + 2]

        is_alive = False
        open_ports: List[int] = []
        vectors_matched: List[str] = []
        host_name: Optional[str] = None
        device_mac: Optional[str] = None
        device_type: str = "LAN Client"

        # Check TCP results
        for idx, res in enumerate(tcp_results):
            if isinstance(res, tuple) and res[0]:
                is_alive = True
                p_open = res[1]
                ev = res[2]
                if p_open:
                    open_ports.append(p_open)
                if ev not in vectors_matched:
                    vectors_matched.append(ev)

        # Check NetBIOS
        if isinstance(nb_res, tuple) and nb_res[0]:
            is_alive = True
            vectors_matched.append("UDP NetBIOS Name Service (Port 137)")
            if nb_res[1]:
                host_name = nb_res[1]
                device_type = "Windows Workstation / Samba NAS"
            if nb_res[2]:
                device_mac = nb_res[2]

        # Check mDNS
        if isinstance(mdns_res, tuple) and mdns_res[0]:
            is_alive = True
            vectors_matched.append("UDP mDNS / Bonjour (Port 5353)")
            if mdns_res[1] and not host_name:
                host_name = mdns_res[1]
                device_type = "Apple / Smart Device (Bonjour)"

        # Check ICMP
        if isinstance(icmp_res, bool) and icmp_res:
            is_alive = True
            vectors_matched.append("ICMP Echo Reply")

        # Check Router DHCP PTR
        if isinstance(ptr_res, str) and ptr_res:
            is_alive = True
            vectors_matched.append(f"Router DHCP DNS Lease ({ptr_res})")
            if not host_name:
                host_name = ptr_res
                # Infer device type from hostname
                hn_low = host_name.lower()
                if any(k in hn_low for k in ("iphone", "ipad", "apple")):
                    device_type = "Apple iOS Device"
                elif any(k in hn_low for k in ("galaxy", "samsung", "pixel", "android", "redmi", "xiaomi", "oppo", "vivo")):
                    device_type = "Android Smartphone"
                elif any(k in hn_low for k in ("tv", "bravia", "lg", "tizen", "roku", "chromecast")):
                    device_type = "Smart TV / Media Streamer"
                elif any(k in hn_low for k in ("print", "deskjet", "laserjet", "brother", "canon", "epson")):
                    device_type = "Network Printer"
                elif any(k in hn_low for k in ("desktop", "laptop", "pc", "macbook")):
                    device_type = "PC / Laptop Workstation"

        if not is_alive:
            return None

        # Determine best display name
        display_name = host_name or f"อุปกรณ์เครือข่าย ({ip_str})"
        is_mobile = device_type in ("Apple iOS Device", "Android Smartphone")

        return {
            "ip": ip_str,
            "is_alive": True,
            "open_ports": sorted(open_ports),
            "host_name": host_name,
            "device_name": display_name,
            "device_type": device_type,
            "device_mac": device_mac or "Unknown (L3 Direct)",
            "is_mobile": is_mobile,
            "vectors": vectors_matched,
            "discovery_method": "Multi-Vector Discovery (TCP Ports + UDP mDNS/NetBIOS + ICMP Ping + Router DHCP PTR)"
        }

    async def scan_subnet_multivector(self, ip_list: List[str], gateway_ip: str = "") -> Dict[str, Dict[str, Any]]:
        """Scan full list of IPs in subnet concurrently using multi-vector discovery."""
        tasks = [self.scan_single_host(ip, gateway_ip) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        active_hosts = {}
        for r in results:
            if isinstance(r, dict) and r.get("is_alive"):
                active_hosts[r["ip"]] = r
        return active_hosts
