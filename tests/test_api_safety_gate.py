"""
Test Web API Safety Gate Enforcement
Ensures that the /api/scan endpoint requires explicit target ownership and consent
phrase before allowing active RCE probing on external targets.
"""

import unittest
from unittest.mock import patch, AsyncMock
from app import app


class TestApiSafetyGate(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    @patch("api.scan_routes.probe_endpoint", new_callable=AsyncMock)
    @patch("core.multi_vector_discovery.MultiVectorDiscoveryEngine.scan_subnet_multivector", new_callable=AsyncMock)
    def test_api_public_target_active_rce_downgraded_without_consent(self, mock_mv, mock_probe):
        """Verify that sending allow_active_rce=true on a public IP without consent_phrase is downgraded."""
        mock_mv.return_value = {}
        mock_probe.return_value = None
        resp = self.client.post("/api/scan", json={
            "subnet": "8.8.8.8",
            "ports": [80],
            "concurrency": 20,
            "allow_active_rce": True
            # Missing i_own_this_target and consent_phrase
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("safety_gate_notice", data)
        self.assertIn("Safety Gate: Active RCE disabled", data["safety_gate_notice"])

    def test_verify_rce_endpoint_blocks_public_target_without_ownership(self):
        """Ensure /api/verify-rce rejects public target without consent phrase."""
        resp = self.client.post("/api/verify-rce", json={
            "target": "8.8.8.8",
            "port": 80,
            "allow_active_rce": True
        })
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "SAFETY_GATE_BLOCKED")
        self.assertIn("Safety Gate", data.get("impact_statement", ""))

    @patch("api.scan_routes.probe_active_rce_proof", new_callable=AsyncMock)
    def test_verify_rce_endpoint_allows_private_target(self, mock_probe):
        """Ensure /api/verify-rce executes on private IP targets."""
        mock_probe.return_value = {
            "is_rce_proved": False,
            "proof_status": "CANARY_NOT_TRIGGERED",
            "verified_at": "2026-10-31 21:00:00"
        }
        resp = self.client.post("/api/verify-rce", json={
            "target": "192.168.1.50",
            "port": 80,
            "allow_active_rce": True,
            "is_php": True
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("rce_proof", data)
        mock_probe.assert_called_once()


if __name__ == "__main__":
    unittest.main()
