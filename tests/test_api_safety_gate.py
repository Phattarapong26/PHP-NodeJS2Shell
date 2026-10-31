"""
Test Web API Safety Gate Enforcement
Ensures that the /api/scan endpoint requires explicit target ownership and consent
phrase before allowing active RCE probing on external targets.
"""

import unittest
from app import app


class TestApiSafetyGate(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    def test_api_public_target_active_rce_downgraded_without_consent(self):
        """Verify that sending allow_active_rce=true on a public IP without consent_phrase is downgraded."""
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


if __name__ == "__main__":
    unittest.main()
