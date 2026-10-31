"""
Automated Test Suite for OPScaner RCE Prover, Safety Gate, and Evidence Integrity
Ensures that the refactored LFI-to-RCE flow, tri-state classification, and safety controls
work reliably without regressions across edge cases.
"""

import asyncio
import hashlib
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from audit.rce_prover import probe_active_rce_proof, generate_audit_trail
from core.network import is_public_target


class TestRceVerifierAndSafetyGate(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_safety_gate_default_disabled(self):
        """Verify that without allow_active_rce=True, no active probes are dispatched."""
        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock()
        mock_client.post = AsyncMock()

        res = self.loop.run_until_complete(
            probe_active_rce_proof(
                mock_client,
                "http://127.0.0.1:8080",
                8080,
                is_php=True,
                allow_active_rce=False
            )
        )

        self.assertFalse(res["is_rce_proved"])
        self.assertEqual(res["proof_status"], "PROBING_DISABLED_BY_SAFETY_GATE")
        self.assertIn("Safety Gate", res["proof_badge"])
        mock_client.get.assert_not_called()
        mock_client.post.assert_not_called()

    def test_is_public_target_logic(self):
        """Verify IP/domain classification for public vs private networks."""
        self.assertFalse(is_public_target("127.0.0.1"))
        self.assertFalse(is_public_target("192.168.1.50"))
        self.assertFalse(is_public_target("10.0.0.1"))
        self.assertFalse(is_public_target("172.16.5.10"))
        self.assertFalse(is_public_target("localhost"))
        self.assertTrue(is_public_target("8.8.8.8"))
        self.assertTrue(is_public_target("1.1.1.1"))

    def test_lfi_session_poisoning_rce_confirmed(self):
        """Verify RCE_CONFIRMED when PHP engine executes the arithmetic canary."""
        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=httpx.Response(200, text="Uploaded"))
        
        # When triggered via LFI, return executed canary token
        def mock_get(url, **kwargs):
            if "/?page=/tmp/sess_" in url or "/?file=/tmp/sess_" in url:
                # Extract math seeds or simulate successful eval
                return httpx.Response(200, text="Some prefix THAICERT_CANARY_EVAL_ suffix")
            return httpx.Response(404, text="Not Found")

        with patch("random.randint", return_value=1000):
            # seeds: seed_a = 1000, seed_b = 1000 => 2000 => "THAICERT_CANARY_EVAL_2000"
            mock_client.get = AsyncMock(return_value=httpx.Response(200, text="Executed THAICERT_CANARY_EVAL_2000 output"))

            res = self.loop.run_until_complete(
                probe_active_rce_proof(
                    mock_client,
                    "http://127.0.0.1:8080",
                    8080,
                    is_php=True,
                    allow_active_rce=True,
                    operator="unit-tester"
                )
            )

            self.assertTrue(res["is_rce_proved"])
            self.assertEqual(res["proof_status"], "RCE_CONFIRMED")
            self.assertIn("RCE สำเร็จ", res["proof_badge"])
            self.assertIsNotNone(res["audit_trail"])
            self.assertEqual(res["audit_trail"]["operator"], "unit-tester")
            self.assertTrue(len(res["audit_trail"]["evidence_sha256"]) == 64)

    def test_lfi_session_poisoning_canary_confirmed_not_rce(self):
        """Verify CANARY_CONFIRMED when canary string is read verbatim but NOT executed as PHP."""
        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=httpx.Response(200, text="Uploaded"))
        
        # Return raw canary text without arithmetic calculation
        mock_client.get = AsyncMock(return_value=httpx.Response(200, text="Raw unparsed <?php echo 'THAICERT_CANARY_EVAL_'.(1234); ?>"))

        with patch("random.randint", return_value=5000):
            res = self.loop.run_until_complete(
                probe_active_rce_proof(
                    mock_client,
                    "http://127.0.0.1:8080",
                    8080,
                    is_php=True,
                    allow_active_rce=True,
                    operator="unit-tester"
                )
            )

            self.assertFalse(res["is_rce_proved"])
            self.assertEqual(res["proof_status"], "CANARY_CONFIRMED")
            self.assertIn("ไม่เกิด Code Execution", res["proof_badge"])
            self.assertIsNotNone(res["audit_trail"])

    def test_lfi_arbitrary_file_read_classified_as_lfi_not_rce(self):
        """Verify reading /etc/passwd is strictly classified as CONFIRMED_LFI and is_rce_proved=False."""
        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=httpx.Response(404, text="No upload progress"))
        
        def mock_get(url, **kwargs):
            if "/etc/passwd" in url:
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
            return httpx.Response(404, text="Not Found")

        mock_client.get = AsyncMock(side_effect=mock_get)

        res = self.loop.run_until_complete(
            probe_active_rce_proof(
                mock_client,
                "http://127.0.0.1:8080",
                8080,
                is_php=True,
                allow_active_rce=True,
                operator="unit-tester"
            )
        )

        self.assertFalse(res["is_rce_proved"])
        self.assertEqual(res["proof_status"], "CONFIRMED_LFI")
        self.assertIn("root:x:0:0", res["execution_output"])
        self.assertIn("Arbitrary File Read", res["impact_statement"])
        self.assertIsNotNone(res["audit_trail"])

    def test_cve_2024_4577_active_rce_confirmed(self):
        """Verify CVE-2024-4577 yields RCE_CONFIRMED when PHP-CGI executes canary."""
        mock_client = MagicMock(spec=httpx.AsyncClient)
        
        def mock_post(url, **kwargs):
            if "%ADd+allow_url_include%3d1" in url:
                return httpx.Response(200, text="THAICERT_CGI_RCE_2000 output")
            return httpx.Response(200, text="Default")

        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.get = AsyncMock(return_value=httpx.Response(404, text="Not Found"))

        with patch("random.randint", return_value=1000):
            res = self.loop.run_until_complete(
                probe_active_rce_proof(
                    mock_client,
                    "http://127.0.0.1:8080",
                    8080,
                    is_php=True,
                    allow_active_rce=True,
                    operator="unit-tester"
                )
            )

            self.assertTrue(res["is_rce_proved"])
            self.assertEqual(res["proof_status"], "RCE_CONFIRMED")
            self.assertIn("CVE-2024-4577", res["technique"])

    def test_tamper_evident_sha256_audit_trail(self):
        """Verify that SHA-256 evidence digest is computed correctly and changes upon modification."""
        trail1 = generate_audit_trail(
            operator="auditor-1",
            method="GET",
            url="http://test.local/?page=/etc/passwd",
            req_headers={"Host": "test.local"},
            payload_str="test_payload",
            status_code=200,
            resp_headers={"Content-Type": "text/plain"},
            resp_text="root:x:0:0:root"
        )

        # Expected SHA-256 of payload_str
        expected_payload_sha = hashlib.sha256(b"test_payload").hexdigest()
        self.assertEqual(trail1["payload_sha256"], expected_payload_sha)
        self.assertEqual(len(trail1["evidence_sha256"]), 64)

        # Different response content must yield different evidence_sha256
        trail2 = generate_audit_trail(
            operator="auditor-1",
            method="GET",
            url="http://test.local/?page=/etc/passwd",
            req_headers={"Host": "test.local"},
            payload_str="test_payload",
            status_code=200,
            resp_headers={"Content-Type": "text/plain"},
            resp_text="root:x:0:0:tampered"
        )
        self.assertNotEqual(trail1["evidence_sha256"], trail2["evidence_sha256"])

    def test_edge_cases_connection_error_and_timeout(self):
        """Verify that connection drops and timeouts fail gracefully to NOT_CONFIRMED without throwing exceptions."""
        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectTimeout("Connection timed out"))
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        res = self.loop.run_until_complete(
            probe_active_rce_proof(
                mock_client,
                "http://192.168.1.99:9999",
                9999,
                is_php=True,
                allow_active_rce=True,
                operator="unit-tester"
            )
        )

        self.assertFalse(res["is_rce_proved"])
        self.assertEqual(res["proof_status"], "NOT_CONFIRMED")
        self.assertIsNone(res["audit_trail"])


if __name__ == "__main__":
    unittest.main()
