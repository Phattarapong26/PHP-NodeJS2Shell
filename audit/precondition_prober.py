"""
Defensive Behavioral Precondition Probing Module for OPScaner
Analyzes system architecture and environmental preconditions (Brotli decompression,
HTTP/3 QUIC UDP listener, NGINX alias path normalization, and SSI candidate files)
to verify whether vulnerability prerequisites are truly met before drawing conclusions.
"""

import asyncio
import os
import re
import socket
import uuid
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import httpx


def probe_quic_udp_listener(host: str, port: int = 443, timeout: float = 1.5) -> bool:
    """
    Sends an RFC 9000 QUIC Initial Version Negotiation packet to verify
    whether an active UDP QUIC listener is responding, confirming HTTP/3 transport support.
    """
    if not host:
        return False
    try:
        dcid = os.urandom(8)
        scid = os.urandom(8)
        # RFC 9000 Long Header (0xc0) + Reserved Version (0xdeadbeef to trigger Version Negotiation)
        pkt = b"\xc0\xde\xad\xbe\xef" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        pkt += b"\x00" * max(0, 1200 - len(pkt))
        
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as usock:
            usock.settimeout(min(timeout, 2.0))
            usock.sendto(pkt, (host, int(port or 443)))
            resp, _ = usock.recvfrom(2048)
            # QUIC Long Header response starts with bit 1 (0x80) and length >= 7
            if resp and len(resp) >= 7 and (resp[0] & 0x80):
                return True
    except Exception:
        pass
    return False


async def probe_brotli_preconditions(
    client: httpx.AsyncClient,
    base_url: str,
    headers: Optional[dict] = None
) -> Dict[str, Any]:
    """
    Evaluates whether the application environment supports and decompresses Brotli streams:
    1. Tests response decompression via Accept-Encoding: br.
    2. Tests request decompression via Content-Encoding: br with a minimal valid Brotli stream vs malformed stream.
    """
    res = {
        "brotli_supported": False,
        "brotli_request_accepted": False,
        "brotli_evidence": "",
        "precondition_verdict": "PRECONDITION_ABSENT"
    }
    
    t_hdrs = dict(headers or {})
    t_hdrs["Accept-Encoding"] = "br, gzip, deflate"
    
    # 1. Probe server outbound compression
    try:
        r_resp = await client.get(f"{base_url}/", headers=t_hdrs, timeout=2.5)
        ce = r_resp.headers.get("content-encoding", "").lower()
        vary = r_resp.headers.get("vary", "").lower()
        if "br" in ce:
            res["brotli_supported"] = True
            res["brotli_evidence"] = "Server returns Content-Encoding: br"
        elif "accept-encoding" in vary:
            res["brotli_supported"] = True
            res["brotli_evidence"] = "Server acknowledges Vary: Accept-Encoding"
    except Exception:
        pass

    # 2. Probe server inbound Brotli request body acceptance
    # Valid minimal Brotli stream of "{}" (6-8 bytes)
    valid_br_stream = b"\x0b\x00\x80{}\x03"
    invalid_br_stream = b"\xff\xff\xff\xff"
    
    post_hdrs = dict(t_hdrs)
    post_hdrs["Content-Encoding"] = "br"
    post_hdrs["Content-Type"] = "application/json"
    
    try:
        r_valid = await client.post(f"{base_url}/", content=valid_br_stream, headers=post_hdrs, timeout=2.5)
        # Server accepts or processes decompression if not 415 / 501
        if r_valid.status_code in (200, 204, 301, 302, 400):
            try:
                r_invalid = await client.post(f"{base_url}/", content=invalid_br_stream, headers=post_hdrs, timeout=2.0)
                # If invalid stream produces an error or differs, decompression occurs on server
                if r_invalid.status_code != r_valid.status_code or r_invalid.status_code in (400, 500):
                    res["brotli_request_accepted"] = True
                    res["brotli_evidence"] += " | Inbound Brotli decompression accepted and evaluated"
            except Exception:
                res["brotli_request_accepted"] = True
        elif r_valid.status_code in (415, 501):
            res["brotli_request_accepted"] = False
            res["brotli_evidence"] += f" | Inbound Content-Encoding: br rejected (HTTP {r_valid.status_code})"
    except Exception:
        pass

    if res["brotli_request_accepted"] or res["brotli_supported"]:
        res["precondition_verdict"] = "PRECONDITION_IDENTIFIED"
    
    return res


async def probe_nginx_preconditions(
    client: httpx.AsyncClient,
    base_url: str,
    ssi_candidates: Optional[List[str]] = None,
    baseline_404_code: int = 404,
    headers: Optional[dict] = None
) -> Dict[str, Any]:
    """
    Evaluates behavioral preconditions for NGINX architecture:
    - SSI candidate files (.shtml, .shtm) for CVE-2026-97205.
    - Off-by-slash alias path normalization (e.g. /static../) for CVE-2026-15176.
    - UDP QUIC port 443 handshake for CVE-2026-95101.
    """
    hints = {
        "ssi_files": [],
        "alias_traversal_observed": False,
        "alias_evidence": "",
        "http3_udp_verified": False,
        "preconditions_summary": []
    }
    
    t_hdrs = dict(headers or {})
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    # 1. SSI files probe
    cands = list(ssi_candidates or [])
    for std_ssi in ["/index.shtml", "/index.shtm"]:
        if std_ssi not in cands:
            cands.append(std_ssi)
            
    for s_path in cands[:4]:
        try:
            r_ssi = await client.get(f"{base_url}{s_path}", headers=t_hdrs, timeout=2.0)
            if r_ssi.status_code == 200:
                body_low = (r_ssi.text or "").lower()
                ct = r_ssi.headers.get("content-type", "").lower()
                if "text/html" in ct and ("<!--#" in body_low or "include virtual" in body_low or s_path.endswith(".shtml")):
                    hints["ssi_files"].append(s_path)
                    hints["preconditions_summary"].append(f"SSI candidate accessible: {s_path}")
        except Exception:
            pass

    # 2. HTTP/3 QUIC UDP probe if HTTPS
    if parsed.scheme == "https" and host:
        loop = asyncio.get_event_loop()
        hints["http3_udp_verified"] = await loop.run_in_executor(None, probe_quic_udp_listener, host, port)
        if hints["http3_udp_verified"]:
            hints["preconditions_summary"].append("HTTP/3 (QUIC) active UDP listener confirmed")

    # 3. Off-by-slash alias path normalization probe (CVE-2026-15176)
    alias_dirs = ["/static", "/assets", "/uploads", "/public", "/media", "/files"]
    for adir in alias_dirs:
        try:
            # Check if normal directory exists
            r_norm = await client.get(f"{base_url}{adir}/", headers=t_hdrs, timeout=2.0, follow_redirects=False)
            if r_norm.status_code in (200, 301, 302, 403):
                # Check traversal request /dir../
                r_trav = await client.get(f"{base_url}{adir}../", headers=t_hdrs, timeout=2.0, follow_redirects=False)
                loc = r_trav.headers.get("location", "")
                
                # If /adir../ differs from baseline 404
                if r_trav.status_code in (200, 403) and r_trav.status_code != baseline_404_code:
                    hints["alias_traversal_observed"] = True
                    hints["alias_evidence"] = f"{adir}../ responded with HTTP {r_trav.status_code} (differs from baseline {baseline_404_code})"
                    hints["preconditions_summary"].append(f"Alias path normalization behavior: {hints['alias_evidence']}")
                    break
                elif r_trav.status_code in (301, 302, 307, 308) and loc and adir.lstrip("/") in loc:
                    hints["alias_traversal_observed"] = True
                    hints["alias_evidence"] = f"{adir}../ redirect rewrite to {loc[:40]}"
                    hints["preconditions_summary"].append(f"Alias rewrite anomaly: {hints['alias_evidence']}")
                    break
        except Exception:
            continue

    return hints
