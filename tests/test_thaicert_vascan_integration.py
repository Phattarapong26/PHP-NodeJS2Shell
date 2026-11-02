"""
Unit Tests for VASCAN8GROUP Classification & Evidence Engine Integration
Tests:
1. Product Signatures & Multi-group tagging
2. Soft-404 Anti-False-Positive Baseline Algorithm
3. Targeted Exposure Checklists (GROUP_CHECKS)
4. Edge WAF / CDN Detection
5. Device Rules (OUI to Group mapping)
"""

import unittest
import hashlib
from audit.thaicert_rules import (
    classify_thaicert_groups,
    identify_products,
    detect_edge_product,
    generate_random_canary_path,
    verify_checklist_hit,
    GROUP_NAMES,
    GROUP_CHECKS,
    DEVICE_RULES
)


class TestThaiCertVaScanIntegration(unittest.TestCase):

    def test_group_names_complete(self):
        """Verify all 8 ThaiCERT groups are defined with enterprise descriptions."""
        self.assertEqual(len(GROUP_NAMES), 8)
        for g_id in range(1, 9):
            self.assertIn(g_id, GROUP_NAMES)

    def test_product_signatures_detection(self):
        """Test passive product detection across appliances, APIs, panels, and containers."""
        # 1. Fortinet FortiGate (Group 4)
        prods = identify_products(headers={"Server": "FortiGate"}, body="Welcome to /remote/fgt_lang portal")
        self.assertTrue(any(p["vendor"] == "Fortinet" and 4 in p["groups"] for p in prods))

        # 2. MikroTik RouterOS (Group 4)
        prods = identify_products(headers={"Server": "RouterOS"}, body="RouterOS WebFig v7.1")
        self.assertTrue(any(p["vendor"] == "MikroTik" and 4 in p["groups"] for p in prods))

        # 3. Laravel Framework (Groups 1 and 2)
        prods = identify_products(headers={"Set-Cookie": "laravel_session=abc123xyz"}, body="Whoops! There was an error")
        self.assertTrue(any(p["vendor"] == "Laravel" and 2 in p["groups"] for p in prods))

        # 4. Docker Engine / Registry (Group 5)
        prods = identify_products(headers={"Docker-Distribution-Api-Version": "registry/2.0"}, body='{"repositories": []}')
        self.assertTrue(any(p["vendor"] == "Docker" and 5 in p["groups"] for p in prods))

        # 5. cPanel / WHM (Groups 3 and 8)
        prods = identify_products(headers={"Server": "cpsrvd"}, body="cPanel & WHM login portal")
        self.assertTrue(any(p["vendor"] == "cPanel" and 3 in p["groups"] and 8 in p["groups"] for p in prods))

    def test_edge_waf_detection(self):
        """Test WAF / Edge CDN detection from response headers."""
        edge = detect_edge_product(headers={"Server": "cloudflare", "cf-ray": "890123abc-BKK"})
        self.assertIsNotNone(edge)
        self.assertEqual(edge["vendor"], "Cloudflare")

        edge_f5 = detect_edge_product(headers={"Set-Cookie": "BIGipServer_pool_http=123456789.20480.0000"})
        self.assertIsNotNone(edge_f5)
        self.assertEqual(edge_f5["vendor"], "F5")

    def test_soft404_baseline_filtering(self):
        """Verify that catch-all SPA servers returning 200 do not produce false positives."""
        spa_content = b"<html><head><title>My React App</title></head><body><div id='root'></div></body></html>"
        spa_hash = hashlib.md5(spa_content[:4096]).hexdigest()
        baseline = {"status": 200, "len": len(spa_content), "hash": spa_hash}

        # A false hit: Server returns the same React HTML page for /.env
        is_hit = verify_checklist_hit(
            status_code=200,
            content_bytes=spa_content,
            text_body=spa_content.decode("utf-8"),
            signature_regex=r"APP_KEY|DB_PASSWORD|=",
            baseline_info=baseline
        )
        self.assertFalse(is_hit, "Soft-404 SPA page must be discarded as false positive")

        # A real hit: Distinct real .env file with APP_KEY
        real_env = b"APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:s0meSecretKey=\nDB_PASSWORD=secret"
        is_real_hit = verify_checklist_hit(
            status_code=200,
            content_bytes=real_env,
            text_body=real_env.decode("utf-8"),
            signature_regex=r"APP_KEY|DB_PASSWORD|=",
            baseline_info=baseline
        )
        self.assertTrue(is_real_hit, "Real .env file with matching signature must be verified as hit")

    def test_classify_thaicert_groups_evidence_hierarchy(self):
        """Test complete classification pipeline with multi-group evidence hierarchy."""
        # Target with confirmed checklist hit on .env and Git
        result = classify_thaicert_groups(
            ip_or_host="192.168.1.50",
            server="Apache/2.4.52",
            headers={"Server": "Apache/2.4.52"},
            body_text="<html><body>Corporate System</body></html>",
            cookies_str="",
            port=80,
            is_php=True,
            checklist_hits=[
                {"group_id": 1, "path": "/.env", "label": ".env Credentials Exposed", "severity": "High"},
                {"group_id": 2, "path": "/swagger.json", "label": "Swagger API Specification", "severity": "Medium"}
            ]
        )

        self.assertIn(1, result["groups"])
        self.assertIn(2, result["groups"])
        self.assertTrue(any("Checklist Hit: /.env" in e for e in result["evidence"]))
        self.assertGreaterEqual(len(result["architecture_matrix"]), 2)

    def test_hostname_dev_indicator(self):
        """Verify dev/staging hostnames are tagged as Group 7."""
        result = classify_thaicert_groups(
            ip_or_host="uat-portal.internal.corp",
            server="nginx",
            headers={},
            body_text="",
            cookies_str="",
            port=443,
            is_php=False
        )
        self.assertIn(7, result["groups"])
        self.assertTrue(any("Hostname Indicator" in e for e in result["evidence"]))


if __name__ == "__main__":
    unittest.main()
