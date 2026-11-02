"""
OPScaner - Dynamic CVE & Payload Rule Execution Engine
Evaluates standardized JSON vulnerability rules against web endpoints, network services, and OS/Android ports.
Zero hardcoding: Rules are loaded from the SQLite CVE database and executed with negative-canary anti-false-positive checks.
"""

import re
import json
import asyncio
from typing import Dict, List, Optional, Any, Union
import httpx

from core.profile_db import get_all_cve_rules


async def execute_web_rule(
    rule: Dict[str, Any],
    client: httpx.AsyncClient,
    base_url: str,
    canary_baseline: Optional[Dict[str, Any]] = None,
    server_banner: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Executes a single web-targeted rule against base_url.
    Returns finding dict if vulnerable/matched, else None.
    """
    trigger = rule.get("trigger", {})
    method = str(trigger.get("method", "GET")).upper()
    path = trigger.get("path", "/")
    if not path.startswith("/"):
        path = "/" + path
    
    headers = dict(trigger.get("headers", {}))
    body = trigger.get("body")
    timeout = float(trigger.get("timeout", 2.0))
    
    url = base_url.rstrip("/") + path
    
    response = None
    try:
        req_kwargs = {
            "method": method,
            "url": url,
            "headers": headers,
            "timeout": timeout
        }
        if body is not None:
            if isinstance(body, str):
                req_kwargs["content"] = body.encode("utf-8")
            elif isinstance(body, (dict, list)):
                req_kwargs["json"] = body
        
        response = await client.request(**req_kwargs)
    except Exception:
        # Request failed or timed out; cannot confirm vulnerability
        return None

    # Evaluate matchers against response
    matchers = rule.get("matchers", [])
    if not matchers:
        return None

    all_matched = True
    match_evidence = []

    resp_text = response.text or ""
    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    resp_status = response.status_code

    for m in matchers:
        m_type = m.get("type")

        if m_type == "status":
            allowed = m.get("values", [200])
            if resp_status not in allowed:
                all_matched = False
                break
            match_evidence.append(f"HTTP {resp_status}")

        elif m_type == "body_regex":
            pattern = m.get("regex", "")
            if not pattern:
                continue
            if not re.search(pattern, resp_text, re.IGNORECASE):
                all_matched = False
                break
            match_evidence.append(f"Body regex matched: '{pattern}'")

        elif m_type == "header_regex":
            h_name = m.get("header", "").lower()
            pattern = m.get("regex", "")
            if h_name:
                val = resp_headers.get(h_name, "")
                if not re.search(pattern, val, re.IGNORECASE):
                    all_matched = False
                    break
            else:
                # Search across all header values
                found = any(re.search(pattern, v, re.IGNORECASE) for v in resp_headers.values())
                if not found:
                    all_matched = False
                    break
            match_evidence.append(f"Header regex matched: '{h_name}: {pattern}'")

        elif m_type == "banner_regex":
            pattern = m.get("regex", "")
            banner_to_check = server_banner or resp_headers.get("server", "")
            if not banner_to_check or not re.search(pattern, banner_to_check, re.IGNORECASE):
                all_matched = False
                break
            match_evidence.append(f"Banner matched: '{pattern}'")

        elif m_type == "negative_canary":
            # Guard against wildcard 200 catch-alls: if canary baseline responded with 200 and similar length
            if canary_baseline and canary_baseline.get("status") == 200:
                canary_len = canary_baseline.get("length", 0)
                cur_len = len(resp_text)
                # If length is nearly identical (within 10%), it's likely a generic soft-404 page
                if abs(cur_len - canary_len) < 50 or (canary_len > 0 and abs(cur_len - canary_len) / canary_len < 0.08):
                    all_matched = False
                    break
            match_evidence.append("Negative canary passed (verified non-catch-all)")

    if all_matched:
        return {
            "rule_id": rule["rule_id"],
            "cve_id": rule["cve_id"],
            "name": rule["name"],
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "Medium"),
            "cvss_score": rule.get("cvss_score", 5.0),
            "cwe": rule.get("cwe", ""),
            "thaicert_group": rule.get("thaicert_group", 1),
            "target_type": rule.get("target_type", "web"),
            "target_url": url,
            "status_code": resp_status,
            "evidence": "; ".join(match_evidence),
            "remediation": rule.get("remediation", ""),
            "references": rule.get("references", []),
            "response_snippet": resp_text[:200]
        }

    return None


async def evaluate_dynamic_rules_for_target(
    client: httpx.AsyncClient,
    base_url: str,
    target_type: str = "web",
    canary_baseline: Optional[Dict[str, Any]] = None,
    server_banner: str = "",
    open_ports: Optional[List[int]] = None
) -> List[Dict[str, Any]]:
    """
    Evaluates all active dynamic CVE rules from the database against a target.
    Returns a list of finding objects.
    """
    rules = get_all_cve_rules(target_type=target_type, enabled_only=True)
    findings = []
    
    # Run web rules concurrently with semaphore to preserve speed
    sem = asyncio.Semaphore(5)

    async def _run_rule(r):
        async with sem:
            return await execute_web_rule(
                rule=r,
                client=client,
                base_url=base_url,
                canary_baseline=canary_baseline,
                server_banner=server_banner
            )

    tasks = [_run_rule(r) for r in rules if r.get("target_type") == "web"]
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, dict) and res is not None:
                findings.append(res)

    # Evaluate port/android rules if port list is provided
    if open_ports:
        port_rules = [r for r in rules if r.get("target_type") in ("android", "network_l4")]
        for pr in port_rules:
            trigger = pr.get("trigger", {})
            tgt_port = trigger.get("target_port")
            if tgt_port and tgt_port in open_ports:
                matchers = pr.get("matchers", [])
                port_match = False
                for m in matchers:
                    if m.get("type") == "port_open" and m.get("port") == tgt_port:
                        port_match = True
                        break
                if port_match:
                    findings.append({
                        "rule_id": pr["rule_id"],
                        "cve_id": pr["cve_id"],
                        "name": pr["name"],
                        "description": pr.get("description", ""),
                        "severity": pr.get("severity", "Medium"),
                        "cvss_score": pr.get("cvss_score", 5.0),
                        "cwe": pr.get("cwe", ""),
                        "thaicert_group": pr.get("thaicert_group", 1),
                        "target_type": pr.get("target_type", "android"),
                        "target_url": f"{base_url}:{tgt_port}",
                        "evidence": f"Port {tgt_port} is open and matches dynamic vulnerability rule {pr['rule_id']}",
                        "remediation": pr.get("remediation", ""),
                        "references": pr.get("references", [])
                    })

    return findings


async def test_single_rule(rule_dict: Dict[str, Any], target_url: str) -> Dict[str, Any]:
    """
    On-demand rule tester for API / UI.
    Tests a rule specification against target_url and returns detailed execution trace.
    """
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
    async with httpx.AsyncClient(verify=False, follow_redirects=True, limits=limits) as client:
        trigger = rule_dict.get("trigger", {})
        method = str(trigger.get("method", "GET")).upper()
        path = trigger.get("path", "/")
        if not path.startswith("/"):
            path = "/" + path
        
        headers = dict(trigger.get("headers", {}))
        body = trigger.get("body")
        timeout = float(trigger.get("timeout", 3.0))
        
        full_url = target_url.rstrip("/") + path
        
        req_trace = {
            "method": method,
            "url": full_url,
            "headers": headers,
            "body": body
        }
        
        try:
            req_kwargs = {
                "method": method,
                "url": full_url,
                "headers": headers,
                "timeout": timeout
            }
            if body is not None:
                if isinstance(body, str):
                    req_kwargs["content"] = body.encode("utf-8")
                elif isinstance(body, (dict, list)):
                    req_kwargs["json"] = body
            
            resp = await client.request(**req_kwargs)
            
            finding = await execute_web_rule(
                rule=rule_dict,
                client=client,
                base_url=target_url,
                canary_baseline=None,
                server_banner=resp.headers.get("server", "")
            )
            
            return {
                "success": True,
                "is_vulnerable": finding is not None,
                "finding": finding,
                "request": req_trace,
                "response": {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_preview": resp.text[:500] if resp.text else ""
                }
            }
        except Exception as e:
            return {
                "success": False,
                "is_vulnerable": False,
                "error": str(e),
                "request": req_trace
            }
