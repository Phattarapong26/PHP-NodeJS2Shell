import unittest
import asyncio
from audit.php_audit import evaluate_php_security, evaluate_security_chains
from audit.sub_tools import probe_embedded_appliance_security


class TestAuditChains(unittest.TestCase):

    def test_evaluate_php_security_baselines(self):
        # PHP 5 / 7 EOL
        sev5, desc5 = evaluate_php_security("PHP/5.6.40")
        self.assertEqual(sev5, "Critical")
        self.assertIn("End-of-Life", desc5)

        # PHP 8.1 EOL
        sev81, desc81 = evaluate_php_security("PHP/8.1.12")
        self.assertEqual(sev81, "Outdated")
        self.assertIn("Security EOL", desc81)

        # PHP 8.2.19 (Unpatched for both CVE-2024-4577 and 2026 Engine)
        sev82_19, desc82_19 = evaluate_php_security("PHP/8.2.19")
        self.assertEqual(sev82_19, "Critical")
        self.assertIn("CVE-2024-4577", desc82_19)

        # PHP 8.2.20 (Patched for CVE-2024-4577, but unpatched for 2026 Engine Advisories)
        sev82_20, desc82_20 = evaluate_php_security("PHP/8.2.20")
        self.assertEqual(sev82_20, "Review Needed")
        self.assertIn("8.2.35+", desc82_20)

        # PHP 8.2.35 (Patched for both)
        sev82_35, desc82_35 = evaluate_php_security("PHP/8.2.35")
        self.assertEqual(sev82_35, "Secure")
        self.assertIn("ตรงตามเกณฑ์แพตช์", desc82_35)

        # PHP 8.3.36 (Patched for both)
        sev83_36, desc83_36 = evaluate_php_security("PHP/8.3.36")
        self.assertEqual(sev83_36, "Secure")

    def test_no_synthetic_cli_output(self):
        # Evaluate with LFI active and unpatched PHP
        res = evaluate_security_chains(
            is_php=True,
            php_version="8.2.19",
            headers={"Server": "nginx/1.24.0"},
            cookies_str="PHPSESSID=abc12345",
            server="nginx/1.24.0",
            expose_php=True,
            lfi_check={"has_lfi_prerequisite": True, "evidence": "found page parameter", "param": "page", "tested_url": "/?page=test"},
            has_error_leak=True
        )
        chains = res["chains"]
        
        # Assert no fake "uid=33(www-data)"
        for c_key, c_val in chains.items():
            for stage in c_val.get("cli_stages", []):
                self.assertNotIn("uid=33(www-data)", stage["evidence"])
                self.assertNotIn("fatal error in Unknown on line 0 at 12 MB", stage["evidence"])

    def test_strict_mode_probe_integration(self):
        strict_probe_enforced = {
            "tested": True,
            "status": "PROTECTED",
            "badge": "PASS",
            "is_strict_mode": True,
            "evidence": "เซิร์ฟเวอร์ปฏิเสธ ID ภายนอกและออกรหัสใหม่ (use_strict_mode = 1)"
        }
        res = evaluate_security_chains(
            is_php=True,
            php_version="8.2.35",
            headers={"Server": "Apache/2.4.52"},
            cookies_str="PHPSESSID=test",
            server="Apache/2.4.52",
            expose_php=False,
            strict_mode_probe=strict_probe_enforced
        )
        stage2 = res["chains"]["chain_a"]["stages"][1]
        self.assertEqual(stage2["status"], "PASS")
        self.assertEqual(stage2["badge"], "PASS")
        self.assertIn("use_strict_mode = 1", stage2["detail"])

    def test_info_disclosure_no_tmp_assumption(self):
        # Without path leak
        res = evaluate_security_chains(
            is_php=True,
            php_version="8.2.35",
            headers={},
            cookies_str="",
            server="Apache/2.4.52",
            expose_php=False,
            info_disclosure_probe={"session_path_disclosed": False, "leaked_paths": []}
        )
        cli_stages = res["chains"]["chain_b"]["cli_stages"]
        stage5 = [s for s in cli_stages if s["num"] == "5/6"][0]
        self.assertNotIn("/tmp", stage5["evidence"])
        self.assertEqual(res["chains"]["chain_b"]["confidence"], "Unverified")

        # With real path leak
        res_leaked = evaluate_security_chains(
            is_php=True,
            php_version="8.2.35",
            headers={},
            cookies_str="",
            server="Apache/2.4.52",
            expose_php=False,
            info_disclosure_probe={"session_path_disclosed": True, "leaked_paths": ["/var/sessions/user"]}
        )
        cli_stages_leaked = res_leaked["chains"]["chain_b"]["cli_stages"]
        stage5_leaked = [s for s in cli_stages_leaked if s["num"] == "5/6"][0]
        self.assertIn("/var/sessions/user", stage5_leaked["evidence"])
        self.assertEqual(res_leaked["chains"]["chain_b"]["confidence"], "Confirmed")

    def test_appliance_probe(self):
        res = asyncio.run(probe_embedded_appliance_security("Boa/0.94.14rc21"))
        self.assertTrue(res["is_embedded_binary"])
        self.assertFalse(res["php_present"])


if __name__ == "__main__":
    unittest.main()
