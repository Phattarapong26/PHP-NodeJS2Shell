"""
Unit Test Suite for OPScaner Web Crawler, Differential Baseline,
and Behavioral Precondition Probing Modules.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from audit.crawler import crawl_target, hash_body, is_static_path
from audit.precondition_prober import probe_brotli_preconditions, probe_nginx_preconditions
from audit.nginx_audit import evaluate_nginx_security
from audit.node_audit import evaluate_node_security


class TestCrawlerAndPreconditions(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_static_path_filtering(self):
        self.assertTrue(is_static_path("/static/app.css"))
        self.assertTrue(is_static_path("/images/logo.png"))
        self.assertTrue(is_static_path("/bundle.js"))
        self.assertFalse(is_static_path("/index.php"))
        self.assertFalse(is_static_path("/api/users"))
        self.assertFalse(is_static_path("/portal/systeminfo.aspx"))

    def test_hash_body_consistency(self):
        h1 = hash_body("Hello   World\n\nTest")
        h2 = hash_body("Hello World Test")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_crawl_target_link_and_form_discovery(self):
        mock_client = MagicMock(spec=httpx.AsyncClient)
        
        sample_html = """
        <html>
        <body>
            <a href="/about.php?view=team&ver=1.0">About Us</a>
            <a href="/logo.png">Logo</a>
            <form action="/search.php" method="GET">
                <input name="q" type="text" />
                <input name="category" type="text" />
            </form>
            <a href="/index.shtml">SSI Index</a>
        </body>
        </html>
        """

        async def mock_get(url, **kwargs):
            if "thaicert_baseline" in url:
                return httpx.Response(404, text="404 Not Found Custom Template")
            return httpx.Response(200, text=sample_html, headers={"Content-Type": "text/html"})

        mock_client.get = AsyncMock(side_effect=mock_get)

        res = self.loop.run_until_complete(
            crawl_target(
                mock_client,
                "http://target.local",
                max_depth=2,
                max_pages=5,
                time_budget=3.0
            )
        )

        self.assertEqual(res.baseline_status, 404)
        self.assertTrue(len(res.baseline_hash) == 64)
        self.assertIn("/about.php", res.endpoints)
        self.assertIn("view", res.endpoints["/about.php"]["params"])
        # 'ver' is in NOISY_PARAMS and must be filtered out
        self.assertNotIn("ver", res.endpoints["/about.php"]["params"])
        self.assertIn("/search.php", res.endpoints)
        self.assertIn("q", res.endpoints["/search.php"]["params"])
        self.assertIn("category", res.endpoints["/search.php"]["params"])
        self.assertIn("/index.shtml", res.ssi_candidates)

    def test_brotli_precondition_acceptance(self):
        mock_client = MagicMock(spec=httpx.AsyncClient)
        
        async def mock_get(url, **kwargs):
            return httpx.Response(200, headers={"Content-Encoding": "br"})

        async def mock_post(url, **kwargs):
            content = kwargs.get("content", b"")
            if content == b"\x0b\x00\x80{}\x03":
                return httpx.Response(200, text="Decoded OK")
            return httpx.Response(400, text="Brotli Decompression Error")

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(side_effect=mock_post)

        res = self.loop.run_until_complete(
            probe_brotli_preconditions(mock_client, "http://target.local")
        )

        self.assertTrue(res["brotli_supported"])
        self.assertTrue(res["brotli_request_accepted"])
        self.assertEqual(res["precondition_verdict"], "PRECONDITION_IDENTIFIED")

    def test_nginx_preconditions_and_evaluation(self):
        mock_client = MagicMock(spec=httpx.AsyncClient)

        async def mock_get(url, **kwargs):
            if "/index.shtml" in url:
                return httpx.Response(200, text="<!--#include virtual='head.html' -->", headers={"Content-Type": "text/html"})
            if "/static../" in url:
                return httpx.Response(403, text="Forbidden Traversal")
            if "/static/" in url:
                return httpx.Response(200, text="Directory Index")
            return httpx.Response(404, text="Not Found")

        mock_client.get = AsyncMock(side_effect=mock_get)

        hints = self.loop.run_until_complete(
            probe_nginx_preconditions(
                mock_client,
                "http://target.local",
                ssi_candidates=["/index.shtml"],
                baseline_404_code=404
            )
        )

        self.assertIn("/index.shtml", hints["ssi_files"])
        self.assertTrue(hints["alias_traversal_observed"])

        # Correlate with evaluate_nginx_security
        sev, matched, note = evaluate_nginx_security("nginx/1.26.0", hints=hints)
        ssi_entry = next((c for c in matched if c["cve"] == "CVE-2026-97205"), None)
        alias_entry = next((c for c in matched if c["cve"] == "CVE-2026-15176"), None)
        
        self.assertIsNotNone(ssi_entry)
        self.assertEqual(ssi_entry["verification_status"], "PRECONDITION_IDENTIFIED")
        self.assertIsNotNone(alias_entry)
        self.assertEqual(alias_entry["verification_status"], "PRECONDITION_IDENTIFIED")

    def test_node_security_exposure_separation(self):
        # When Brotli is accepted by the server
        v_res1 = evaluate_node_security("20.18.0", has_brotli=True, accepts_untrusted_brotli=True)
        self.assertEqual(v_res1[0], "High")
        self.assertIn("Untrusted Brotli Input", v_res1.details.get("exposure_status", ""))

        # When Brotli is NOT accepted / rejected by server
        v_res2 = evaluate_node_security("20.18.0", has_brotli=False, accepts_untrusted_brotli=False)
        self.assertIn("Absent", v_res2.details.get("exposure_status", ""))


if __name__ == "__main__":
    unittest.main()
