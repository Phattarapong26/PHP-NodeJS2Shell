"""
Automated Web Crawler & Parameter Discovery Module for OPScaner
Performs shallow recursive crawling to discover real endpoints, form inputs,
query parameters, and baseline 404 response signatures for differential analysis.
"""

import asyncio
import hashlib
import re
import time
import uuid
from html.parser import HTMLParser
from typing import Dict, Set, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
import httpx


STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".pdf",
    ".zip", ".tar", ".gz", ".map"
}

NOISY_PARAMS = {"ver", "v", "_", "cb", "t", "cache", "ts", "stamp", "random"}


class _HtmlLinkParser(HTMLParser):
    """Safe streaming HTML parser to extract links, form actions, and input names."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        
        # Collect links
        if tag == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href:
                self.links.append(href)
                
        # Collect forms
        elif tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", "").strip(),
                "method": attr_dict.get("method", "get").strip().lower(),
                "inputs": set()
            }
            
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name", "").strip()
            if name:
                self._current_form["inputs"].add(name)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def hash_body(text: str) -> str:
    """Computes SHA-256 digest of response body for baseline comparison."""
    if not text:
        return ""
    # Normalize excessive dynamic whitespace
    norm = re.sub(r'\s+', ' ', text).strip()
    return hashlib.sha256(norm.encode('utf-8', errors='ignore')).hexdigest()


def is_static_path(path: str) -> bool:
    """Returns True if the path points to a static media or style asset."""
    p_lower = path.lower()
    return any(p_lower.endswith(ext) for ext in STATIC_EXTENSIONS)


class CrawlResult:
    def __init__(self):
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.all_urls: List[str] = []
        self.visited: Set[str] = set()
        self.baseline_hash: str = ""
        self.baseline_status: int = 404
        self.baseline_len: int = 0
        self.ssi_candidates: List[str] = []
        self.forms: List[Dict[str, Any]] = []


async def crawl_target(
    client: httpx.AsyncClient,
    base_url: str,
    max_depth: int = 2,
    max_pages: int = 20,
    time_budget: float = 8.0,
    rate_limit: float = 15.0
) -> CrawlResult:
    """
    Performs recursive shallow crawling on target base_url within safe rate and page limits.
    Establishes differential baseline and harvests forms, query parameters, and endpoints.
    """
    res = CrawlResult()
    t0 = time.time()
    min_interval = 1.0 / max(1.0, rate_limit)
    last_req_time = 0.0

    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # 1. Capture 404 differential baseline using random token
    try:
        rand_tok = f"thaicert_baseline_{uuid.uuid4().hex[:8]}"
        r_base = await client.get(f"{base_url}/{rand_tok}", timeout=2.0)
        res.baseline_status = r_base.status_code
        res.baseline_len = len(r_base.text or "")
        if r_base.status_code == 404:
            res.baseline_hash = hash_body(r_base.text or "")
        else:
            res.baseline_hash = ""
    except Exception:
        res.baseline_hash = ""
        res.baseline_status = 404

    # 2. Initialize crawl queue
    start_url = base_url.rstrip("/") + "/"
    queue: List[Tuple[str, int]] = [(start_url, 0)]

    while queue and len(res.visited) < max_pages and (time.time() - t0) < time_budget:
        url, depth = queue.pop(0)
        if url in res.visited or depth > max_depth:
            continue

        p = urlparse(url)
        if f"{p.scheme}://{p.netloc}" != origin:
            continue

        res.visited.add(url)
        res.all_urls.append(url)

        # Rate limiter pacing
        elapsed = time.time() - last_req_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        last_req_time = time.time()

        try:
            r = await client.get(url, timeout=2.5, follow_redirects=True)
            if r.status_code >= 400:
                continue

            resp_text = r.text or ""

            # Check for SSI candidate files
            if p.path.lower().endswith((".shtml", ".shtm", ".stm")) and p.path not in res.ssi_candidates:
                res.ssi_candidates.append(p.path)

            # Extract query parameters from URL
            if p.query and not is_static_path(p.path):
                clean_path = p.path or "/"
                if clean_path not in res.endpoints:
                    res.endpoints[clean_path] = {"params": set(), "methods": {"get"}}
                qs = parse_qs(p.query)
                for qk in qs.keys():
                    if qk.lower() not in NOISY_PARAMS:
                        res.endpoints[clean_path]["params"].add(qk.lower())

            # Parse HTML for links and forms
            parser = _HtmlLinkParser()
            try:
                parser.feed(resp_text)
            except Exception:
                pass

            # Process forms
            for f in parser.forms:
                act = urljoin(url, f["action"])
                act_parsed = urlparse(act)
                if f"{act_parsed.scheme}://{act_parsed.netloc}" != origin:
                    continue
                f_path = act_parsed.path or "/"
                if is_static_path(f_path):
                    continue
                if f_path not in res.endpoints:
                    res.endpoints[f_path] = {"params": set(), "methods": set()}
                res.endpoints[f_path]["methods"].add(f["method"])
                for inp_name in f["inputs"]:
                    if inp_name.lower() not in NOISY_PARAMS:
                        res.endpoints[f_path]["params"].add(inp_name.lower())

            # Process outgoing links for BFS crawl
            for href in parser.links:
                if href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                    continue
                full_link = urljoin(url, href).split("#")[0]
                link_parsed = urlparse(full_link)
                if f"{link_parsed.scheme}://{link_parsed.netloc}" == origin:
                    if full_link not in res.visited and not is_static_path(link_parsed.path):
                        queue.append((full_link, depth + 1))

            # Also harvest text regex for non-standard endpoint strings (e.g. in JS or tables)
            for m_ep in re.finditer(r'(/[a-zA-Z0-9_/\-]+\.(?:php|aspx|cgi|jsp|ashx|pl|shtml)[^\s<>"\'()]*)', resp_text, re.I):
                raw_ep = m_ep.group(1).strip()
                if "?" in raw_ep:
                    ep_base, ep_q = raw_ep.split("?", 1)
                    if ep_base not in res.endpoints:
                        res.endpoints[ep_base] = {"params": set(), "methods": {"get"}}
                    for qseg in ep_q.split("&"):
                        if "=" in qseg:
                            qk = qseg.split("=")[0].lower()
                            if qk not in NOISY_PARAMS:
                                res.endpoints[ep_base]["params"].add(qk)
                else:
                    if raw_ep not in res.endpoints:
                        res.endpoints[raw_ep] = {"params": set(), "methods": {"get"}}

        except Exception:
            continue

    return res
