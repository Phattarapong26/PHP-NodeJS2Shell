"""
OPScaner Production Readiness & Dynamic Fidelity Test Suite
Validates that OPScaner operates dynamically without hardcoded cheats,
fake mock data, fabricated shell outputs, or unsecured defaults.
"""

import unittest
import asyncio
import os
import json
import tempfile
import httpx
from unittest.mock import patch, MagicMock

# Core imports
from app import app
from core.database import CVE_DATABASE, load_cve_feed_updates
from core.network import parse_target_hosts
from core.multi_vector_discovery import STANDARD_DISCOVERY_TCP_PORTS
from audit.thaicert_rules import classify_thaicert_groups
from audit.rce_prover import probe_active_rce_proof
from api.report_routes import set_last_scan_result, get_current_report_data, _SCAN_STORAGE_PATH


class TestProductionReadiness(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = app.test_client()

    # -------------------------------------------------------------
    # 1. ThaiCERT Fingerprint Dynamism (No Port Hardcoding)
    # -------------------------------------------------------------
    def test_thaicert_classification_no_port_hardcoding(self):
        """Verify that an arbitrary service on port 8081 is NOT blindly classified as CorpPress CMS."""
        # Generic HTTP service on port 8081
        res = classify_thaicert_groups(
            ip_or_host="192.168.1.50",
            server="Apache/2.4.50",
            headers={"Server": "Apache/2.4.50"},
            body_text="<html><body>Hello World Generic Internal Portal</body></html>",
            cookies_str="",
            port=8081,
            is_php=True,
            is_node=False
        )
        # In the old code, port 8081 forced Group 1 and "CorpPress CMS"
        self.assertNotIn("CorpPress CMS", res.get("group_evidence", []))
        self.assertNotIn("CorpPress CMS", res.get("primary_group", ""))

    def test_thaicert_classification_real_fingerprints(self):
        """Verify that genuine framework and service fingerprints correctly match."""
        # Test Laravel / API
        res_laravel = classify_thaicert_groups(
            ip_or_host="10.0.0.10",
            server="nginx/1.22.0",
            headers={"Server": "nginx/1.22.0", "Content-Type": "application/json"},
            body_text='{"api_version": "v1", "framework": "laravel"}',
            cookies_str="laravel_session=eyJpdiI...",
            port=443,
            is_php=True
        )
        self.assertIn(2, res_laravel["groups"])
        self.assertTrue(any("Laravel" in lbl or "API" in lbl for lbl in res_laravel["group_labels"]))

        # Test Windows IIS
        res_iis = classify_thaicert_groups(
            ip_or_host="10.0.0.20",
            server="Microsoft-IIS/10.0",
            headers={"Server": "Microsoft-IIS/10.0"},
            body_text="<html><body>IIS Windows Server</body></html>",
            cookies_str="",
            port=80,
            is_php=True
        )
        self.assertIn(6, res_iis["groups"])
        self.assertTrue(any("Windows" in lbl for lbl in res_iis["group_labels"]))

    # -------------------------------------------------------------
    # 2. RCE Prover Truthfulness (No Fabricated Outputs)
    # -------------------------------------------------------------
    def test_rce_prover_does_not_fabricate_root(self):
        """Verify that when a target does not return execution evidence, RCE is NOT confirmed and no fake uid=0 is emitted."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Standard Error or Generic Page</body></html>"

        async def _test():
            mock_client = MagicMock(spec=httpx.AsyncClient)
            mock_client.get = MagicMock(return_value=asyncio.Future())
            mock_client.get.return_value.set_result(mock_response)
            mock_client.post = MagicMock(return_value=asyncio.Future())
            mock_client.post.return_value.set_result(mock_response)

            res = await probe_active_rce_proof(mock_client, "http://10.0.0.5:8080", 8080, is_php=True)
            self.assertFalse(res["is_rce_proved"])
            self.assertNotEqual(res["proof_status"], "CONFIRMED_RCE")
            self.assertNotIn("uid=0(root)", str(res.get("execution_output")))

        asyncio.run(_test())

    def test_rce_prover_accurately_extracts_real_execution(self):
        """Verify that when a diagnostic endpoint actually returns command output, it is faithfully parsed."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status":"ok","output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)"}'

        async def _test():
            mock_client = MagicMock(spec=httpx.AsyncClient)
            mock_client.get = MagicMock(return_value=asyncio.Future())
            mock_client.get.return_value.set_result(mock_response)

            res = await probe_active_rce_proof(mock_client, "http://10.0.0.5:8080", 8080, is_php=True)
            self.assertTrue(res["is_rce_proved"])
            self.assertEqual(res["proof_status"], "CONFIRMED_RCE")
            self.assertIn("uid=33(www-data)", res["execution_output"])
            self.assertEqual(res["privilege_level"], "Standard Web Service User")

        asyncio.run(_test())

    # -------------------------------------------------------------
    # 3. Report Persistence Across Server Reloads
    # -------------------------------------------------------------
    def test_report_persistence(self):
        """Verify that scan results persist to disk and are restored on restart."""
        test_scan_data = {
            "target": "10.10.10.0/24",
            "total_hosts": 5,
            "hosts": [{"ip": "10.10.10.1", "status": "active"}],
            "thaicert_summary": {"critical_hosts": 0, "high_hosts": 1, "warning_hosts": 0, "secure_hosts": 4}
        }
        set_last_scan_result(test_scan_data)
        self.assertTrue(os.path.exists(_SCAN_STORAGE_PATH))

        # Clear in-memory global to simulate server restart
        import api.report_routes as rr
        rr._LAST_SCAN_RESULT = None

        restored = get_current_report_data()
        self.assertEqual(restored["target"], "10.10.10.0/24")
        self.assertEqual(restored["total_hosts"], 5)

    # -------------------------------------------------------------
    # 4. Security Headers & CORS Enforcement
    # -------------------------------------------------------------
    def test_security_headers_present(self):
        """Verify production security headers are attached to responses."""
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "SAMEORIGIN")
        resp.close()

    def test_test_lab_endpoints_guarded_in_production(self):
        """Verify /test-lab/* endpoints are disabled when OPSCANER_ENABLE_TEST_LAB is not set."""
        resp = self.client.get("/test-lab/php56")
        # In production mode without OPSCANER_ENABLE_TEST_LAB, test_bp is not registered
        self.assertEqual(resp.status_code, 404)

    # -------------------------------------------------------------
    # 5. Dynamic External CVE Database Ingestion
    # -------------------------------------------------------------
    def test_dynamic_cve_feed_loading(self):
        """Verify external JSON CVE feeds can dynamically update the catalog."""
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            feed_data = [
                {
                    "id": "CVE-2027-99999",
                    "category": "PHP",
                    "severity": "Critical",
                    "cvss": 9.9,
                    "name": "Future Test Advisory",
                    "desc": "Automated Dynamic Feed Test",
                    "patched": "PHP 8.5.99+",
                    "host_check": "php -v",
                    "confirm_vuln": "PHP < 8.5.99",
                    "confirm_safe": "PHP >= 8.5.99"
                }
            ]
            json.dump(feed_data, tf)
            tf_path = tf.name

        try:
            initial_count = len(CVE_DATABASE)
            added = load_cve_feed_updates(tf_path)
            self.assertEqual(added, 1)
            self.assertEqual(len(CVE_DATABASE), initial_count + 1)
            found = [c for c in CVE_DATABASE if c.get("id") == "CVE-2027-99999"]
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["cvss"], 9.9)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    # -------------------------------------------------------------
    # 6. Target Parsing & Discovery Ports
    # -------------------------------------------------------------
    def test_target_parsing_dynamic(self):
        """Verify network target parser handles arbitrary CIDRs and single IPs without hardcoding."""
        hosts_single, _, cidr, total, _, _ = parse_target_hosts("192.168.10.5")
        self.assertEqual(len(hosts_single), 1)
        self.assertEqual(str(hosts_single[0]), "192.168.10.5")
        self.assertEqual(cidr, 32)
        self.assertEqual(total, 1)

        hosts_cidr, _, cidr_net, total_net, _, _ = parse_target_hosts("10.50.0.0/30")
        self.assertEqual(len(hosts_cidr), 2)  # .1 and .2 usable hosts
        self.assertEqual(cidr_net, 30)
        self.assertEqual(total_net, 2)

    def test_discovery_ports_standard(self):
        """Verify default discovery TCP ports focus on standard network services."""
        self.assertIn(80, STANDARD_DISCOVERY_TCP_PORTS)
        self.assertIn(443, STANDARD_DISCOVERY_TCP_PORTS)
        self.assertIn(22, STANDARD_DISCOVERY_TCP_PORTS)
        self.assertIn(445, STANDARD_DISCOVERY_TCP_PORTS)
        # Port 8081 lab port is not in standard discovery ports
        self.assertNotIn(8081, STANDARD_DISCOVERY_TCP_PORTS)

    # -------------------------------------------------------------
    # 7. Production API Contract Fidelity (GUI Compatibility)
    # -------------------------------------------------------------
    def test_api_cve_database_contract(self):
        """Verify /api/cve-database returns proper structure expected by frontend."""
        resp = self.client.get("/api/cve-database")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIsInstance(data["database"], list)
        self.assertGreater(data["total"], 0)

    def test_api_my_ip_contract(self):
        """Verify /api/my-ip returns complete network info structure without crashes."""
        resp = self.client.get("/api/my-ip")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("ip", data)
        self.assertIn("subnet", data)
        self.assertIn("cidr", data)
        self.assertIn("presets", data)

    def test_api_calculate_subnet(self):
        """Verify /api/calculate-subnet properly calculates CIDR metadata."""
        resp = self.client.post("/api/calculate-subnet", json={"input": "192.168.1.0/24"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["valid"])
        self.assertEqual(data["cidr"], 24)
        self.assertEqual(data["total_hosts"], 254)

    def test_api_report_preview_renders(self):
        """Verify /api/report/preview generates valid HTML without exceptions."""
        resp = self.client.get("/api/report/preview")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)
        self.assertIn("TLP:AMBER", resp.get_data(as_text=True))

    def test_asan_endpoint_no_fake_static_trace(self):
        """Verify verify-asan-memory returns genuine telemetry, not fabricated stack traces."""
        resp = self.client.get("/api/verify-asan-memory?ip=127.0.0.1&port=5050")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("asan_trace", data)
        # Ensure the old fabricated crash string is absent
        self.assertNotIn("==84120==ERROR: AddressSanitizer: heap-use-after-free", data["asan_trace"])
        self.assertNotIn("482110", str(data.get("memory_current")))


if __name__ == "__main__":
    unittest.main()
