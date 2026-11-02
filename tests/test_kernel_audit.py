import unittest
from audit.kernel_audit import evaluate_cve_2026_98432, probe_mptcp_listeners

class TestKernelAudit(unittest.TestCase):
    def test_windows_rejection(self):
        finding, note = evaluate_cve_2026_98432(
            is_windows=True,
            server="Microsoft-IIS/10.0",
            open_ports=[80, 443],
            mptcp_results={80: "MPTCP-ACTIVE"}
        )
        self.assertIsNone(finding)
        self.assertIn("ไม่ใช่ระบบปฏิบัติการ Linux", note)

    def test_linux_mptcp_active(self):
        finding, note = evaluate_cve_2026_98432(
            is_windows=False,
            server="Apache/2.4.41 (Ubuntu)",
            open_ports=[80, 443],
            mptcp_results={80: "MPTCP-ACTIVE", 443: "PLAIN-TCP"}
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding["id"], "CVE-2026-98432")
        self.assertEqual(finding["confidence"], "Likely")
        self.assertIn("LIKELY_VULNERABLE", finding["verification_status"])
        self.assertIn("cat /etc/os-release && uname -r", finding["host_check"])

    def test_container_shared_kernel_evaluation(self):
        finding, note = evaluate_cve_2026_98432(
            is_windows=False,
            server="nginx/1.24.0",
            open_ports=[80],
            mptcp_results={80: "PLAIN-TCP"},
            is_container=True
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding["confidence"], "Conditional")
        self.assertIn("Container แชร์เคอร์เนลเดียวกันกับเครื่องแม่ข่ายจริง", note)
        self.assertIn("Container แชร์เคอร์เนลเดียวกันกับเครื่องแม่ข่ายจริง", finding["name"])

if __name__ == "__main__":
    unittest.main()
