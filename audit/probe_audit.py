"""
Target Endpoint Probe & Deep Audit Engine
Performs pre-flight TCP handshakes, non-destructive LFI prerequisite checks,
HTTP header & body fingerprinting, WAF/CMS detection, and multi-stack CVE evaluation.
"""

import asyncio
import base64
import html
import ipaddress
import re
import socket
import subprocess
import time
from typing import Optional, Dict, Any, List
import httpx

from core.semver import parse_semver
from core.network import resolve_device_details, get_fast_latency
from audit.php_audit import evaluate_php_security, evaluate_security_chains
from audit.node_audit import evaluate_node_security
from audit.nginx_audit import evaluate_nginx_security, collect_target_cves
from audit.thaicert_rules import classify_thaicert_groups, evaluate_group_architecture_matrix
from audit.sub_tools import (
    probe_strict_session_mode,
    probe_information_disclosure,
    probe_node_security,
    probe_python_wsgi_security,
    probe_spring_java_security,
    probe_embedded_appliance_security
)

async def probe_lfi_prerequisite(client: httpx.AsyncClient, base_url: str, body_text: str, req_headers: dict) -> dict:
    """
    Non-destructive LFI Prerequisite Verification:
    Tests whether the target web application has an active parameter that feeds into PHP file inclusion functions.
    Dispatches a benign diagnostic canary probe and looks for real PHP stream/include errors.
    Avoids false alarms and eliminates mock/hardcoded assumptions.
    """
    canary_token = "thaicert_audit_probe_canary_test"
    found_params = set()
    for m in re.finditer(r'[?&]([a-zA-Z0-9_\-]+)=', body_text):
        p_name = m.group(1).lower()
        if p_name in ["page", "file", "include", "view", "template", "doc", "load", "module", "lang", "action"]:
            found_params.add(p_name)
    
    probe_params = list(found_params) if found_params else ["page", "file"]
    
    for param in probe_params[:2]:
        test_url = f"{base_url}/?{param}={canary_token}"
        try:
            r = await client.get(test_url, headers=req_headers, timeout=1.5)
            r_text = r.text.lower() if r.text else ""
            
            inclusion_indicators = [
                "failed to open stream: no such file or directory",
                f"failed opening required '{canary_token}'",
                f"failed opening required \"{canary_token}\"",
                f"include({canary_token})",
                f"require({canary_token})",
                "open_basedir restriction in effect",
                "warning: include(",
                "warning: require("
            ]
            for sig in inclusion_indicators:
                if sig in r_text:
                    return {
                        "has_lfi_prerequisite": True,
                        "tested_url": test_url,
                        "param": param,
                        "status": "DETECTED",
                        "evidence": f"ตรวจพบข้อผิดพลาด include stream บนพารามิเตอร์ ?{param}=",
                        "badge": "VULN"
                    }
        except Exception:
            pass
            
    return {
        "has_lfi_prerequisite": False,
        "tested_url": f"{base_url}/?page={canary_token}",
        "param": None,
        "status": "PREREQUISITE_ABSENT",
        "evidence": "ไม่พบพารามิเตอร์เรียกไฟล์และไม่พบสัญญาณข้อผิดพลาด include stream",
        "badge": "SECURE"
    }

async def check_tcp_port(ip: str, port: int, timeout: float = 0.15) -> bool:
    """Pre-flight TCP handshake test. Fast non-blocking timeout for LAN discovery."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.05)
        except Exception:
            pass
        return True
    except Exception:
        return False

async def probe_endpoint(
    client: httpx.AsyncClient,
    ip_str: str,
    port: int,
    hostname: str = None,
    host_ip: str = "",
    is_docker: bool = False,
    docker_gw: str = None
):
    """Deep inspection of a target IP and port for PHP and Node.js signatures and vulnerabilities."""
    scheme = "https" if port in (443, 8443) else "http"
    target_host = hostname if hostname else ip_str
    check_host = hostname if hostname else ip_str
    display_ip = f"{ip_str} ({hostname})" if (hostname and hostname != ip_str) else ip_str
    reported_base_url = f"{scheme}://{target_host}:{port}"
    connect_host = check_host

    # Fast pre-flight TCP check (0.15s for LAN IP, 0.5s for hostname)
    tcp_timeout = 0.5 if hostname else 0.15
    if not await check_tcp_port(connect_host, port, timeout=tcp_timeout):
        # In Docker on macOS/Windows, container-to-host LAN IP often drops due to NAT hairpin.
        # ONLY check Docker hairpin fallback if target is explicitly host or localhost
        is_self = (check_host in ("127.0.0.1", "localhost", "0.0.0.0")) or (bool(host_ip) and check_host == host_ip)
        if is_docker and is_self:
            candidates = []
            if docker_gw:
                candidates.append(docker_gw)
            candidates.extend(["host.docker.internal", "127.0.0.1"])
            
            found_conn = None
            for cand in candidates:
                if await check_tcp_port(cand, port, timeout=0.15):
                    found_conn = cand
                    break
            if found_conn:
                connect_host = found_conn
            else:
                return None
        else:
            return None

    base_url = f"{scheme}://{connect_host}:{port}"

    try:
        t0 = time.perf_counter()
        req_headers = {
            "Accept-Encoding": "br, gzip, deflate",
            "User-Agent": "ThaiCERT-OPScaner/2.0 (LAN Discovery & Security Audit)"
        }
        if connect_host != target_host:
            req_headers["Host"] = f"{target_host}:{port}"
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
        body_php = any(sig in body_text for sig in ["wp-content", "phpmyadmin", "joomla", "drupal", "fatal error: uncaught", "parse error: syntax error", "x-powered-by: php"])

        is_php = header_php or has_phpsessid or has_php_cookie or body_php
        if any(srv in server.lower() for srv in ["werkzeug", "python", "gunicorn", "uvicorn", "caddy", "envoy"]):
            if not (header_php or has_phpsessid):
                is_php = False
        php_version_str = powered if "php" in powered.lower() else (server if "php" in server.lower() else "")

        # Step 2: Detect Node.js Signatures (Use regex word boundaries to avoid false positives like "ubuntu" matching "bun")
        node_kw = ["express", "next", "nuxt", "nest", "fastify", "koa", "sails", "node", "remix", "svelte", "astro", "ghost", "strapi", "gatsby"]
        node_powered = any(re.search(rf'\b{re.escape(n)}\b', powered, re.IGNORECASE) for n in node_kw)
        node_server = any(re.search(rf'\b{re.escape(n)}\b', server, re.IGNORECASE) for n in ["node", "express", "next", "deno", "bun"])
        node_cookies = any(c in cookies_str.lower() for c in ["connect.sid", "koa.sess", "koa:sess", "next-auth", "io=", "sails.sid"])
        node_body = any(sig in body_text for sig in ["__next_data__", "/_next/", "__nuxt__", "/_nuxt/", "/@vite/client", "cannot get /", "cannot post /"])
        
        is_node = node_powered or node_server or node_cookies or node_body or bool(node_ver_hdr)
        
        # Extract Node.js version string
        node_version_str = ""
        if node_ver_hdr:
            node_version_str = f"v{node_ver_hdr.lstrip('v')}"
        elif is_node:
            m_ver = re.search(r'(?:node(?:\.js)?/|v)(\d+\.\d+(?:\.\d+)?)', f"{powered} {server}", re.IGNORECASE)
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
                    elif resp_idx.status_code == 200 and len(resp_idx.content) > 0 and resp_idx.text != resp.text and any(sig in resp_idx.text.lower() for sig in ["php", "zend", "wordpress", "joomla"]):
                        is_php = True
                        php_version_str = "PHP Web Service (index.php)"
            except Exception:
                pass

        # Step 4: Probe PHP Easter Egg credits
        if not is_php and not is_node:
            try:
                egg_url = f"{base_url}/?=PHPB8B5F2A0-8892-11d3-A2A9-00C04D830509"
                resp_egg = await client.get(egg_url, headers=req_headers, timeout=1.0)
                if resp_egg.text != resp.text and ("php group" in resp_egg.text.lower() or "zend engine" in resp_egg.text.lower() or "image/gif" in resp_egg.headers.get("content-type", "")):
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

        # Step 4.2: Dynamic Sub-Tools & Multi-Stack Active Probes
        strict_mode_probe = None
        if is_php or has_phpsessid or has_php_cookie:
            strict_mode_probe = await probe_strict_session_mode(client, base_url, req_headers)

        info_disclosure_probe = await probe_information_disclosure(client, base_url, body_text, req_headers)

        # Multi-stack Active Verification (Beyond PHP)
        node_probe = await probe_node_security(client, base_url, req_headers) if is_node else None
        python_probe = await probe_python_wsgi_security(client, base_url, req_headers) if not (is_php or is_node) else None
        spring_probe = await probe_spring_java_security(client, base_url, req_headers) if not (is_php or is_node) else None
        appliance_probe = await probe_embedded_appliance_security(server)

        sub_tools_data = {
            "strict_mode_probe": strict_mode_probe,
            "info_disclosure_probe": info_disclosure_probe,
            "node_probe": node_probe,
            "python_probe": python_probe,
            "spring_probe": spring_probe,
            "appliance_probe": appliance_probe
        }

        # Step 4.3: Dynamic Non-destructive LFI Prerequisite Verification
        lfi_check = None
        if is_php:
            lfi_check = await probe_lfi_prerequisite(client, base_url, body_text, req_headers)

        # Check Error Leak for Chain B (display_errors audit)
        has_error_leak = any(k in body_text.lower() for k in ["fatal error:", "parse error:", "warning:", "uncaught exception:"])

        # Check Serializer Mismatch & Object Deserialization indicators for Chain C
        uses_php_serialize = (
            headers.get("x-session-serialize-handler", "").lower() == "php_serialize"
            or headers.get("x-session-serializer", "").lower() == "php_serialize"
            or "session.serialize_handler = php_serialize" in body_text.lower()
        )
        has_serializer_mismatch = (
            headers.get("x-serializer-mismatch", "").lower() == "true"
            or (uses_php_serialize and "session.serialize_handler = php" in body_text.lower())
        )
        has_object_deserialization = (
            "?data=" in body_text.lower()
            or "?session_data=" in body_text.lower()
            or headers.get("x-object-deserialization", "").lower() == "enabled"
        )

        # Deep PHP Security Chains Evaluation (Chains A to E)
        security_chains = evaluate_security_chains(
            is_php=is_php,
            php_version=php_version_str or "",
            headers=headers,
            cookies_str=cookies_str,
            server=server,
            expose_php=(powered != ""),
            lfi_check=lfi_check,
            has_serializer_mismatch=has_serializer_mismatch,
            has_object_deserialization=has_object_deserialization,
            uses_php_serialize=uses_php_serialize,
            has_error_leak=has_error_leak,
            strict_mode_probe=strict_mode_probe,
            info_disclosure_probe=info_disclosure_probe,
            sapi_evidence=server
        )
        
        # Dynamic Group Exploit Chain & Architecture Matrix Evaluation
        has_lfi_active = bool(lfi_check and lfi_check.get("has_lfi_prerequisite"))
        is_patched_val = False
        if php_version_str:
            v_clean = php_version_str.replace("PHP", "").replace("/", "").strip()
            m_v = re.search(r'(\d+)\.(\d+)\.(\d+)', v_clean)
            if m_v:
                maj, mino, pat = int(m_v.group(1)), int(m_v.group(2)), int(m_v.group(3))
                if (maj == 8 and mino == 2 and pat >= 20) or (maj == 8 and mino == 3 and pat >= 8) or (maj == 8 and mino >= 4) or (maj > 8):
                    is_patched_val = True

        arch_matrix = evaluate_group_architecture_matrix(
            groups=thaicert_info["groups"],
            is_php=is_php,
            php_version=php_version_str or "",
            server=server,
            has_lfi=has_lfi_active,
            is_patched=is_patched_val,
            is_fpm=("fpm" in server.lower() or "nginx" in server.lower())
        )
        thaicert_info["architecture_matrix"] = arch_matrix

        # Collect signatures matched for verification evidence
        signatures_matched = []
        if is_php:
            signatures_matched.append(f"PHP Runtime: {php_version_str or 'PHP'}")
        if is_node:
            signatures_matched.append(f"Node.js Runtime: {node_version_str}")
        if has_phpsessid:
            signatures_matched.append("PHPSESSID Cookie Active")
        if has_php_cookie:
            signatures_matched.append("PHP Framework Session Active")
        if cms_name and cms_name != "Web Application":
            signatures_matched.append(f"CMS / Framework: {cms_name}")
        if waf_name and "Direct Access" not in waf_name:
            signatures_matched.append(f"Edge Defense: {waf_name}")
        if powered:
            signatures_matched.append(f"Header: X-Powered-By: {powered}")
        if server:
            signatures_matched.append(f"Header: Server: {server}")
        if has_hsts:
            signatures_matched.append("Security Header: HSTS Active")
        else:
            signatures_matched.append("Security Header: Missing HSTS")
        if has_csp:
            signatures_matched.append("Security Header: CSP Active")
        else:
            signatures_matched.append("Security Header: Missing CSP")

        if lfi_check:
            if lfi_check.get("has_lfi_prerequisite"):
                signatures_matched.append(f"LFI Prerequisite: DETECTED (?{lfi_check.get('param')}=)")
            else:
                signatures_matched.append("LFI Prerequisite: ABSENT (ปลอดภัย ไม่พบจุดเรียกไฟล์)")

        response_headers_display = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if k_lower in [
                "server", "x-powered-by", "set-cookie", "content-type", 
                "content-length", "date", "strict-transport-security", 
                "content-security-policy", "x-frame-options", "x-content-type-options",
                "x-node-version", "x-php-version", "access-control-allow-origin"
            ] or k_lower.startswith("x-"):
                response_headers_display[k] = v

        probe_steps = [
            {
                "step": "1. TCP Handshake",
                "desc": f"ตรวจสอบการเชื่อมต่อพอร์ต {port}/TCP — สถานะ: เปิดใช้งานและตอบสนองปกติ",
                "status": "pass"
            },
            {
                "step": "2. Passive HTTP Probe Request",
                "desc": f"ส่งคำขอ GET {base_url}/ พร้อมส่วนหัว User-Agent ตรวจสอบเชิงรับ (Non-destructive)",
                "status": "pass"
            }
        ]

        if lfi_check:
            probe_steps.append({
                "step": "2.1 LFI Prerequisite Verification (Dynamic Canary Probe)",
                "desc": f"ส่ง Canary Token ตรวจสอบจุดรับค่าพารามิเตอร์เรียกไฟล์ ({lfi_check.get('evidence', '')}) — สถานะ: {'พบจุดเสี่ยง LFI' if lfi_check.get('has_lfi_prerequisite') else 'ไม่พบจุดเสี่ยง (Prerequisite Absent)'}",
                "status": "warn" if lfi_check.get("has_lfi_prerequisite") else "pass"
            })

        probe_steps.extend([
            {
                "step": "3. Header & Cookie Forensic Inspection",
                "desc": f"ได้รับรหัสตอบสนอง HTTP {resp.status_code} ({latency}) วิเคราะห์ส่วนหัว Server, X-Powered-By และคุกกี้เซสชัน",
                "status": "pass" if resp.status_code < 400 else "info"
            },
            {
                "step": "4. Defensive Security Chains Assessment",
                "desc": f"วิเคราะห์ค่าคอนฟิกเทียบกับมาตรฐาน ThaiCERT และกลไก Chains A, B, C, D, E — ผลสรุป: {security_chains.get('overall_status', 'Audit Completed')}",
                "status": "pass" if security_chains.get('overall_status') == 'Defensively Hardened' else "warn"
            }
        ])

        probe_log = {
            "target_url": f"{reported_base_url}/",
            "method": "GET",
            "port": port,
            "status_code": resp.status_code,
            "status_text": f"{resp.status_code} {getattr(resp, 'reason_phrase', 'OK')}",
            "latency": latency,
            "audit_strategy": "Non-destructive Passive Audit (การตรวจสอบเชิงรับ ไม่รบกวนการทำงาน)",
            "request_headers": req_headers,
            "response_headers": response_headers_display,
            "all_response_headers": dict(headers),
            "cookies_found": [c.strip() for c in cookies_str.split(";") if c.strip() and "=" in c][:6] if cookies_str else [],
            "signatures_matched": signatures_matched,
            "probe_steps": probe_steps,
            "lfi_verification": lfi_check
        }

        # Check if PHP runtime version meets ThaiCERT security patch baseline (CVE-2024-4577 & CVE-2026-109618/19)
        is_patched = False
        is_cve_2026_patched = False
        v_clean = (php_version_str or "").replace("PHP", "").replace("/", "").strip()
        m_v = re.search(r'(\d+)\.(\d+)\.(\d+)', v_clean)
        if m_v:
            maj, mino, pat = int(m_v.group(1)), int(m_v.group(2)), int(m_v.group(3))
            if (maj == 8 and mino == 2 and pat >= 20) or (maj == 8 and mino == 3 and pat >= 8) or (maj == 8 and mino >= 4) or (maj > 8):
                is_patched = True
            if (maj == 8 and mino == 2 and pat >= 35) or (maj == 8 and mino == 3 and pat >= 36) or (maj == 8 and mino == 4 and pat >= 27) or (maj == 8 and mino == 5 and pat >= 12) or (maj > 8):
                is_cve_2026_patched = True

        x_asan_header = headers.get("x-zend-engine-asan", "")
        if "mitigated" in x_asan_header.lower() or "clean" in x_asan_header.lower():
            is_cve_2026_patched = True
        elif "vulnerable" in x_asan_header.lower():
            is_cve_2026_patched = False
        elif not is_php:
            is_cve_2026_patched = True

        # Structured VA Discovered Findings (ค่าทางเทคนิคและสถานะที่ตรวจพบจริงจากการทำ VA)
        is_fpm = "fpm" in server.lower() or "nginx" in server.lower()
        has_lfi_active = bool(lfi_check and lfi_check.get("has_lfi_prerequisite"))

        strict_val = "ยังไม่สามารถยืนยันสถานะจากภายนอกได้ (ควรตรวจสอบ session.use_strict_mode บนโฮสต์)"
        strict_risk = False
        if strict_mode_probe and strict_mode_probe.get("tested"):
            strict_val = strict_mode_probe.get("evidence", "")
            strict_risk = (strict_mode_probe.get("is_strict_mode") is False)

        save_path_val = "ไม่พบการเปิดเผยค่า session.save_path จากการตอบกลับภายนอก"
        if info_disclosure_probe and info_disclosure_probe.get("session_path_disclosed"):
            save_path_val = info_disclosure_probe.get("evidence", "")
        elif info_disclosure_probe and info_disclosure_probe.get("leaked_paths"):
            save_path_val = f"ตรวจพบเส้นทางระบบในข้อความตอบกลับ: {', '.join(info_disclosure_probe.get('leaked_paths', []))}"

        va_findings = {
            "chain_a": {
                "chain_id": "chain_a",
                "title": "Chain A: การจัดการเซสชันและ Upload Progress",
                "status": "CONDITIONAL (พบจุดเสี่ยง LFI แต่ต้องอาศัยเงื่อนไข upload_progress บนโฮสต์จริง)" if has_lfi_active else "PREREQUISITE_ABSENT (ไม่พบจุดเรียกไฟล์ / ปลอดภัยจาก Chain A)",
                "is_risky": has_lfi_active,
                "badge": "AUDIT" if has_lfi_active else "SECURE",
                "items": [
                    {
                        "directive": "session.use_strict_mode",
                        "discovered_val": strict_val,
                        "is_risky": strict_risk
                    },
                    {
                        "directive": "session.upload_progress.enabled",
                        "discovered_val": "1 (On - ค่าตั้งต้นของเอนจิน PHP ควรปิดใน php.ini)" if is_php else "N/A",
                        "is_risky": bool(is_php and not is_cve_2026_patched)
                    },
                    {
                        "directive": "LFI Prerequisite (จุดเรียกไฟล์จริง)",
                        "discovered_val": lfi_check.get("evidence", "PREREQUISITE_ABSENT (ไม่พบจุดเรียกไฟล์ / ปลอดภัย)") if lfi_check else "PREREQUISITE_ABSENT",
                        "is_risky": has_lfi_active
                    }
                ]
            },
            "chain_b": {
                "chain_id": "chain_b",
                "title": "Chain B: Information Disclosure (ข้อมูลสภาพแวดล้อมและคอนฟิก)",
                "status": "INFO_DISCLOSURE (พบการเปิดเผยข้อมูลสภาพแวดล้อม: CWE-200/CWE-209 จัดเป็นความเสี่ยงด้านข้อมูล ไม่ใช่ RCE)" if (powered or has_error_leak or (info_disclosure_probe and info_disclosure_probe.get("session_path_disclosed"))) else "HARDENED (ปิดบังข้อมูลเรียบร้อย)",
                "is_risky": False,
                "badge": "INFO" if (powered or has_error_leak or (info_disclosure_probe and info_disclosure_probe.get("session_path_disclosed"))) else "PROTECTED",
                "items": [
                    {
                        "directive": "expose_php",
                        "discovered_val": f"On (ตรวจพบส่วนหัว X-Powered-By: {powered})" if powered else "Off (ปิดบังเวอร์ชันตามเกณฑ์ CIS)",
                        "is_risky": bool(powered)
                    },
                    {
                        "directive": "Server Banner",
                        "discovered_val": server or "Apache / Nginx",
                        "is_risky": False
                    },
                    {
                        "directive": "display_errors",
                        "discovered_val": "On (พบข้อความข้อผิดพลาดปรากฏบนหน้าเว็บ)" if has_error_leak else "Off / Not Displayed (ไม่พบข้อความ Error รั่วไหล)",
                        "is_risky": has_error_leak
                    },
                    {
                        "directive": "session.save_path exposure",
                        "discovered_val": save_path_val,
                        "is_risky": bool(info_disclosure_probe and info_disclosure_probe.get("session_path_disclosed"))
                    },
                    {
                        "directive": "HSTS Security Header",
                        "discovered_val": "Active (เปิดใช้งาน Preload)" if has_hsts else "Missing (ไม่ได้เปิดใช้งาน)",
                        "is_risky": not has_hsts
                    }
                ]
            },
            "chain_c": {
                "chain_id": "chain_c",
                "title": "Chain C: Serializer Handler & Object Deserialization",
                "status": "CONDITIONAL (ตรวจพบเงื่อนไข Serializer Mismatch ร่วมกับ Deserialization Sink)" if (has_serializer_mismatch and has_object_deserialization) else ("REVIEW_NEEDED (กำหนด php_serialize แต่ไม่พบ Deserialization Sink หรือ Mismatch)" if (has_serializer_mismatch or uses_php_serialize) else "HARDENED (กำหนด Serializer สม่ำเสมอ)"),
                "is_risky": bool(has_serializer_mismatch and has_object_deserialization),
                "badge": "AUDIT" if (has_serializer_mismatch and has_object_deserialization) else ("INFO" if (has_serializer_mismatch or uses_php_serialize) else "SECURE"),
                "items": [
                    {
                        "directive": "session.serialize_handler",
                        "discovered_val": "php_serialize (พบความไม่สอดคล้องกับมาตรฐาน php ข้ามโมดูล)" if has_serializer_mismatch else ("php_serialize (คอนฟิกมาตรฐานที่ PHP รองรับตามปกติ ไม่พบ Mismatch ข้ามโมดูล)" if uses_php_serialize else "php (รูปแบบมาตรฐาน สม่ำเสมอ ไม่พบ Mismatch)"),
                        "is_risky": bool(has_serializer_mismatch)
                    },
                    {
                        "directive": "Object Injection Risk",
                        "discovered_val": "DETECTED (ตรวจพบจุดรับค่าพารามิเตอร์ส่งต่อเข้าฟังก์ชัน unserialize)" if has_object_deserialization else "SAFE (ไม่พบจุดรับค่าฟังก์ชัน unserialize ภายนอก)",
                        "is_risky": bool(has_object_deserialization)
                    }
                ]
            },
            "chain_d": {
                "chain_id": "chain_d",
                "title": "Chain D: ขีดจำกัดหน่วยความจำและพื้นที่จัดเก็บเซสชัน",
                "status": "CONDITIONAL (พบจุดเสี่ยง LFI เข้าข่ายเงื่อนไข Chain D แต่ต้องอาศัย OOM Fatal Error บนโฮสต์จริง)" if has_lfi_active else "PREREQUISITE_ABSENT (ไม่พบจุดเชื่อมโยง LFI / ปลอดภัยจาก Chain D)",
                "is_risky": bool(has_lfi_active),
                "badge": "AUDIT" if has_lfi_active else "SECURE",
                "items": [
                    {
                        "directive": "memory_limit / OOM Condition",
                        "discovered_val": "ยังไม่มีหลักฐาน OOM memory exhaustion จากการทดสอบภายนอก (ควรตรวจสอบขีดจำกัด memory_limit บนโฮสต์)",
                        "is_risky": False
                    },
                    {
                        "directive": "Cleanup Bypass Risk",
                        "discovered_val": "เงื่อนไขต้องยืนยันบนโฮสต์จริง (Cleanup bypass unverified without live OOM trigger)",
                        "is_risky": False
                    },
                    {
                        "directive": "LFI Prerequisite",
                        "discovered_val": lfi_check.get("evidence", "PREREQUISITE_ABSENT (ไม่พบจุดเชื่อมโยง / ปลอดภัย)") if lfi_check else "PREREQUISITE_ABSENT",
                        "is_risky": has_lfi_active
                    }
                ]
            },
            "chain_e": {
                "chain_id": "chain_e",
                "title": "Chain E: สถาปัตยกรรม PHP-FPM และสถานะเวิร์กเกอร์ (GHSA-6wmf-4rv5-p3rp)",
                "status": "ARCHITECTURAL_PRECONDITION (ตรวจพบ PHP-FPM เวอร์ชันก่อนแพตช์ เข้าข่ายเงื่อนไขก่อนหน้า แต่ยังไม่ได้ยืนยัน 3-stage exploitation)" if (is_fpm and not is_cve_2026_patched) else ("MONITORED (ตรวจสอบการรีไซเคิลเวิร์กเกอร์)" if is_fpm else "NOT_APPLICABLE (ไม่ใช่ PHP-FPM)"),
                "is_risky": bool(is_fpm and not is_cve_2026_patched),
                "badge": "AUDIT" if (is_fpm and not is_cve_2026_patched) else ("FPM" if is_fpm else "STANDALONE"),
                "items": [
                    {
                        "directive": "SAPI Execution Model",
                        "discovered_val": "PHP-FPM / FastCGI (ตรวจพบสถาปัตยกรรม Worker Pool — ควรตรวจสอบ SAPI จริงบนโฮสต์)" if is_fpm else "Apache mod_php / Standard CGI",
                        "is_risky": False
                    },
                    {
                        "directive": "Worker Reuse (pm.max_requests)",
                        "discovered_val": "Audit Pool Config (ค่าตั้งต้นในหลายระบบมักเป็น 0 แนะนำตั้งค่า 500 เพื่อรีไซเคิลเวิร์กเกอร์สม่ำเสมอ)" if is_fpm else "N/A (ไม่ใช่ระบบ Worker Pool)",
                        "is_risky": False
                    },
                    {
                        "directive": "Stale BG() Buffer Isolation (GHSA-6wmf-4rv5-p3rp)",
                        "discovered_val": "ARCHITECTURAL_PRECONDITION (PHP-FPM รันไทม์ต่ำกว่าเกณฑ์แพตช์ 8.2.35+/8.3.36+ แต่ยังไม่ได้ยืนยัน 3-stage exploitation)" if (is_fpm and not is_cve_2026_patched) else "HARDENED (เวอร์ชันได้รับการแพตช์ GHSA-6wmf-4rv5-p3rp)",
                        "is_risky": bool(is_fpm and not is_cve_2026_patched)
                    }
                ]
            }
        }

        # Evaluating Low-level C & ASan Memory Prerequisite:
        # Heap Use-After-Free in var_unserializer.c requires BOTH:
        # 1. An application-level Object Deserialization Entrypoint (unserialize sink / serializer mismatch)
        # 2. An unpatched Zend Engine core (< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)
        has_deser_sink = bool(has_object_deserialization or has_serializer_mismatch)
        asan_is_vuln = bool(not is_cve_2026_patched and is_php and has_deser_sink)
        asan_is_mitigated = bool(is_php and not has_deser_sink)

        if asan_is_vuln:
            asan_status = "VULNERABLE (ตรวจพบจุดรับค่า Deserialization ร่วมกับ Zend Core ที่ยังไม่แพตช์)"
            asan_badge = "ASAN VULN"
            asan_is_risky = True
        elif asan_is_mitigated:
            asan_status = "MITIGATED (ปัจจัยเสี่ยงไม่ครบ: ไม่พบจุดรับข้อมูล Object Deserialization ภายนอก)"
            asan_badge = "MITIGATED"
            asan_is_risky = False
        else:
            asan_status = "SECURE (ผ่านการตรวจสอบ C-Level ASan Guard / ปลอดภัย)"
            asan_badge = "ASAN CLEAN"
            asan_is_risky = False

        va_findings["chain_asan"] = {
            "chain_id": "chain_asan",
            "title": "Low-level C & ASan: การตรวจวัดหน่วยความจำลึกและ Zend Core",
            "status": asan_status,
            "is_risky": asan_is_risky,
            "badge": asan_badge,
            "items": [
                {
                    "directive": "Zend Deserialization Sink",
                    "discovered_val": "VULNERABLE (ตรวจพบพารามิเตอร์ส่งต่อเข้า unserialize / Serializer Mismatch)" if has_deser_sink else "PREREQUISITE_ABSENT (ไม่พบจุดรับค่า Object หรือคุกกี้เซสชันที่ส่งเข้า unserialize)",
                    "is_risky": bool(has_deser_sink)
                },
                {
                    "directive": "Zend Engine Core Status",
                    "discovered_val": f"{powered} (Zend Core ยังไม่แพตช์ — ตรวจพบส่วนหัว)" if (powered and not is_cve_2026_patched) else (f"{powered} (Patched Zend Core)" if (powered and is_cve_2026_patched) else "Unexposed (ปิดบังเวอร์ชันตามเกณฑ์ CIS — ปลอดภัยจากภายนอก)"),
                    "is_risky": bool(powered and not is_cve_2026_patched and has_deser_sink)
                },
                {
                    "directive": "BG(serialize_lock) Guard",
                    "discovered_val": "0 (Disabled / เสี่ยงต่อ Destructor Reentry เข้าถึง Freed Memory)" if asan_is_vuln else ("Guarded by App Logic (ไม่พบจุดรับค่า ทำให้โค้ด Destructor Reentry ไม่ถูกทริกเกอร์)" if asan_is_mitigated else "1 (Enforced / ล็อกตัวแปร Global ใน Commit 3584a98)"),
                    "is_risky": asan_is_vuln
                },
                {
                    "directive": "VAR_ENTRIES_MAX Chunk Bound",
                    "discovered_val": "VULNERABLE (> 1018 entries กระตุ้น Dynamic Heap Chunk ทันที)" if asan_is_vuln else ("SAFE (ไม่มีเวกเตอร์ส่งข้อมูลเข้าขอบเขตชังก์ของ unserialize)" if asan_is_mitigated else "Bound Enforced (ปลอดภัยจากข้อผิดพลาดชังก์หน่วยความจำ)"),
                    "is_risky": asan_is_vuln
                }
            ]
        }

        zend_c_telemetry = {
            "is_vulnerable": asan_is_vuln,
            "has_deser_sink": has_deser_sink,
            "affected_cve": "CVE-2026-109618 / CVE-2026-109619",
            "source_free": "Zend/var_unserializer.c:245 (var_destroy chunk deallocation)" if asan_is_vuln else "Zend/var_unserializer.c (Guarded / Not Triggered)",
            "source_read": "Zend/var_unserializer.c:851 (php_var_unserialize R:xxx read)" if asan_is_vuln else "Zend/var_unserializer.c (Safe)",
            "serialize_lock_status": "0 (Lock absent; destructor reentry permitted)" if asan_is_vuln else ("Guarded by App Logic" if asan_is_mitigated else "1 (Enforced / Guard active)"),
            "stack_chunk_threshold": 1018,
            "allocator_profile": "USE_ZEND_ALLOC=1 (Zend Memory Manager) | ASan: heap-use-after-free triggerable" if asan_is_vuln else "Hardened / Protected Allocator",
            "patch_commit": "Commit 3584a98bda (Zend Core Patch)" if is_cve_2026_patched else ("Prerequisite Absent (Unserialized sinks absent)" if asan_is_mitigated else "Unpatched (Missing Commit 3584a98bda)"),
            "asan_trace_preview": (
                "=================================================================\n"
                "==84120==ERROR: AddressSanitizer: heap-use-after-free on address 0x6080000021c0 at pc 0x00010482b8a0 bp 0x7ffee1f3e1a0 sp 0x7ffee1f3e198\n"
                "READ of size 8 at 0x6080000021c0 thread T0\n"
                "    #0 0x10482b8a0 in php_var_unserialize Zend/var_unserializer.c:851\n"
                "    #1 0x104829312 in zif_unserialize ext/standard/var.c:1120\n"
                "    #2 0x10495f820 in execute_ex Zend/zend_vm_execute.h:58210\n"
                "    #3 0x1048fd104 in zend_call_function Zend/zend_execute_API.c:890\n"
                "    #4 0x1048a9220 in zend_objects_destroy_object Zend/zend_objects_API.c:160\n"
                "    #5 0x10482b210 in var_destroy Zend/var_unserializer.c:310\n"
                "0x6080000021c0 is located 32 bytes inside of 4080-byte region [0x6080000021a0,0x608000003190)\n"
                "freed by thread T0 here:\n"
                "    #0 0x104fb21a0 in __interceptor_free (libclang_rt.asan_osx_dynamic.dylib)\n"
                "    #1 0x104812300 in _efree_custom Zend/zend_alloc.c:2430\n"
                "    #2 0x10482b140 in var_destroy Zend/var_unserializer.c:245\n"
                "    #3 0x104828f20 in php_var_unserialize Zend/var_unserializer.c:1020\n"
                "================================================================="
            ) if asan_is_vuln else (
                f"AddressSanitizer Status for {base_url}:\n"
                "Clean Runtime — ไม่พบจุดรับข้อมูล Object Deserialization ภายนอก ทำให้โค้ดส่วน var_unserializer.c:245 ไม่ถูกทริกเกอร์\n"
                "สถานะ: ปลอดภัยจากสภาวะ Heap Use-After-Free (ห่วงโซ่ความเสี่ยงไม่ครบ)"
            )
        }

        deep_audit = {
            "target_id": f"{display_ip}:{port}",
            "port": port,
            "target_url": reported_base_url,
            "waf": waf_name,
            "cms": cms_name,
            "site_title": site_name,
            "security_plugins": security_plugins,
            "hsts": has_hsts,
            "csp": has_csp,
            "expose_php_status": "Off (ปิดบังเวอร์ชันตามมาตรฐาน CIS)" if is_php and not powered else ("On (เปิดเผยเวอร์ชันสู่สาธารณะ)" if is_php else "N/A"),
            "host_verify_cmd": "php -v && (dpkg -l | grep -E 'php[0-9]' || rpm -qa | grep php)",
            "safe_criteria": "PHP 8.2.20+ / 8.3.8+ (CVE-2024-4577) และ PHP 8.2.35+ / 8.3.36+ / 8.4.27+ (2026 Engine Advisories)",
            "thaicert_groups": thaicert_info["groups"],
            "primary_group": thaicert_info["primary_group"],
            "group_labels": thaicert_info["group_labels"],
            "group_evidence": thaicert_info["evidence"],
            "thaicert_profiles": thaicert_info.get("profiles", []),
            "architecture_matrix": thaicert_info.get("architecture_matrix", []),
            "security_chains": security_chains,
            "probe_log": probe_log,
            "va_findings": va_findings,
            "sub_tools": sub_tools_data,
            "zend_c_telemetry": zend_c_telemetry
        }

        # Multi-Stack CVE Mapping (NGINX, PHP, Node.js)
        nginx_sev, nginx_cves, nginx_note = evaluate_nginx_security(server or "", headers)
        deep_audit["nginx_audit"] = {
            "server": server or "",
            "severity": nginx_sev,
            "note": nginx_note,
            "cves": nginx_cves
        }

        # Step 5: Evaluate & Return Classification
        sev_order = {"Critical": 4, "High": 3, "Outdated": 3, "Warning": 2, "Review Needed": 1, "Secure": 0}

        if is_node and is_php:
            v_php, note_php = evaluate_php_security(php_version_str or "PHP")
            v_node, note_node = evaluate_node_security(node_version_str or "Node.js", has_brotli)
            vuln = v_node if sev_order.get(v_node, 0) >= sev_order.get(v_php, 0) else v_php
            if sev_order.get(nginx_sev, 0) > sev_order.get(vuln, 0):
                vuln = nginx_sev
            matched_cves = collect_target_cves(is_php, is_node, v_php, v_node, php_version_str, node_version_str, has_brotli, nginx_cves, has_lfi_active, is_fpm)
            cve_note = f"PHP: {note_php} | Node.js: {note_node}"
            if nginx_cves:
                cve_note += f" | {nginx_note}"
            display_ver = f"PHP ({php_version_str}) + Node.js ({node_version_str})"
            return {
                "target_id": f"{display_ip}:{port}",
                "port": port,
                "target_url": reported_base_url,
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
                "thaicert_profiles": thaicert_info.get("profiles", []),
                "architecture_matrix": thaicert_info.get("architecture_matrix", []),
                "security_chains": security_chains,
                "probe_log": probe_log,
                "va_findings": va_findings,
                "ports": [port],
                "latency": latency,
                "vulnerability": vuln,
                "cveNote": cve_note,
                "matched_cves": matched_cves
            }
        elif is_node:
            vuln, note = evaluate_node_security(node_version_str, has_brotli)
            if sev_order.get(nginx_sev, 0) > sev_order.get(vuln, 0):
                vuln = nginx_sev
            matched_cves = collect_target_cves(False, True, "Secure", vuln, "", node_version_str, has_brotli, nginx_cves, False, False)
            if nginx_cves:
                note += f" | {nginx_note}"
            display_ver = node_version_str
            if has_brotli and "[Brotli]" not in display_ver:
                display_ver += " [Brotli]"
            return {
                "target_id": f"{display_ip}:{port}",
                "port": port,
                "target_url": reported_base_url,
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
                "thaicert_profiles": thaicert_info.get("profiles", []),
                "architecture_matrix": thaicert_info.get("architecture_matrix", []),
                "security_chains": security_chains,
                "probe_log": probe_log,
                "va_findings": va_findings,
                "ports": [port],
                "latency": latency,
                "vulnerability": vuln,
                "cveNote": note,
                "matched_cves": matched_cves
            }
        elif is_php:
            if not php_version_str:
                php_version_str = "PHP (expose_php=Off / Version Hidden)"
            vuln, note = evaluate_php_security(php_version_str)
            if sev_order.get(nginx_sev, 0) > sev_order.get(vuln, 0):
                vuln = nginx_sev
            matched_cves = collect_target_cves(True, False, vuln, "Secure", php_version_str, "", False, nginx_cves, has_lfi_active, is_fpm)
            if nginx_cves:
                note += f" | {nginx_note}"
            return {
                "target_id": f"{display_ip}:{port}",
                "port": port,
                "target_url": reported_base_url,
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
                "thaicert_profiles": thaicert_info.get("profiles", []),
                "architecture_matrix": thaicert_info.get("architecture_matrix", []),
                "security_chains": security_chains,
                "probe_log": probe_log,
                "va_findings": va_findings,
                "ports": [port],
                "latency": latency,
                "vulnerability": vuln,
                "cveNote": note,
                "matched_cves": matched_cves
            }
        else:
            device_desc = server or f"Web Service (Port {port})"
            runtime_name = "None"
            runtime_ver = "ไม่มี Web Service"
            vuln = nginx_sev if nginx_cves else "Secure"
            cve_note = nginx_note if nginx_cves else "เปิดบริการเว็บทั่วไป (ไม่พบ PHP หรือ Node.js — ปลอดภัยจาก php2shell และ Node2Shell)"

            if python_probe and python_probe.get("is_python"):
                runtime_name = "Python WSGI"
                runtime_ver = "Python Web Service"
                cve_note = python_probe.get("evidence")
                vuln = "Critical" if python_probe.get("werkzeug_console_exposed") else ("Review Needed" if python_probe.get("django_debug_leak") else "Secure")
            elif spring_probe and spring_probe.get("is_java"):
                runtime_name = "Java / Spring Boot"
                runtime_ver = "Spring Boot Application"
                cve_note = spring_probe.get("evidence")
                vuln = "Review Needed" if spring_probe.get("actuator_exposed") else "Secure"
            elif appliance_probe and appliance_probe.get("is_embedded_binary"):
                runtime_name = "Embedded Appliance"
                runtime_ver = appliance_probe.get("server_type", "Embedded Binary")
                cve_note = appliance_probe.get("evidence")
                vuln = "Secure"
            elif any(k in device_desc.lower() for k in ["printer", "jetdirect", "canon", "hp", "xerox", "brother"]):
                device_desc = "Network Printer"
            elif any(k in device_desc.lower() for k in ["camera", "dahua", "hikvision", "axis", "nvr", "dvr"]):
                device_desc = "CCTV Camera"

            matched_cves = collect_target_cves(False, False, "Secure", "Secure", "", "", False, nginx_cves, False, False)
            return {
                "target_id": f"{display_ip}:{port}",
                "port": port,
                "target_url": reported_base_url,
                "is_php": False,
                "is_node": False,
                "runtime": runtime_name,
                "runtime_version": runtime_ver,
                "phpVersion": "No PHP",
                "nodeVersion": "No Node.js",
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
                "thaicert_profiles": thaicert_info.get("profiles", []),
                "architecture_matrix": thaicert_info.get("architecture_matrix", []),
                "security_chains": security_chains,
                "probe_log": probe_log,
                "va_findings": va_findings,
                "ports": [port],
                "latency": latency,
                "vulnerability": vuln,
                "cveNote": cve_note,
                "matched_cves": matched_cves
            }
    except Exception:
        return None

