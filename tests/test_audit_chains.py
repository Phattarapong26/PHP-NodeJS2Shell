import unittest
import asyncio
from audit.php_audit import evaluate_php_security, evaluate_security_chains
from audit.node_audit import evaluate_node_security
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

    def test_node_security_eol_dates_and_CVE_separation(self):
        # Node 20: EOL 24 March 2026
        res20 = evaluate_node_security("v20.18.0", has_brotli=True)
        sev20, note20 = res20
        self.assertEqual(sev20, "Outdated")
        self.assertIn("24 มี.ค. 2026", note20)
        self.assertIn("ผู้จัดจำหน่าย", note20)  # Recommends checking OS vendor backports
        self.assertNotIn("HTTP2Shell", note20)

        # Node 25: EOL 31 March 2026
        res25 = evaluate_node_security("Node.js/25.0.0")
        sev25, note25 = res25
        self.assertEqual(sev25, "Outdated")
        self.assertIn("31 มี.ค. 2026", note25)
        self.assertNotIn("HTTP2Shell", note25)

    def test_node_security_patch_baselines_and_exposure_distinction(self):
        # Node 22 below patch (22.20.0) without active decompression
        res22_unpatched = evaluate_node_security("v22.20.0", has_brotli=True)
        sev22, note22 = res22_unpatched
        self.assertEqual(sev22, "High")
        self.assertEqual(res22_unpatched.details["confidence"], "Conditional")
        self.assertIn("22.23.4", note22)
        self.assertIn("หากแอปพลิเคชันรับข้อมูล Brotli", note22)

        # Node 22 with confirmed exposed decompression
        res22_exposed = evaluate_node_security("v22.20.0", has_brotli=True, accepts_untrusted_brotli=True, uses_node_zlib_decompress=True)
        self.assertEqual(res22_exposed.details["confidence"], "Likely")

        # Node 22 at or above patch (22.23.4)
        res22_patched = evaluate_node_security("v22.23.4", has_brotli=True)
        sev22_p, note22_p = res22_patched
        self.assertEqual(sev22_p, "Patched for this CVE")
        self.assertIn("อยู่ที่หรือสูงกว่าเวอร์ชันที่มีแพตช์", note22_p)
        self.assertIn("ยังต้องตรวจสอบการใช้งาน Brotli", note22_p)
        self.assertNotEqual(sev22_p, "Secure")  # Not unconditionally claiming system is safe

        # Node 24 patched (24.22.1)
        res24_patched = evaluate_node_security("v24.22.1")
        self.assertEqual(res24_patched[0], "Patched for this CVE")

        # Node 26 patched (26.12.1)
        res26_patched = evaluate_node_security("v26.12.1")
        self.assertEqual(res26_patched[0], "Patched for this CVE")

    def test_node_security_newer_major_not_assumed_safe(self):
        # Major > 26 (e.g. 28.0.0)
        res28 = evaluate_node_security("v28.0.0")
        sev28, note28 = res28
        self.assertEqual(sev28, "Review Needed")
        self.assertNotEqual(sev28, "Secure")
        self.assertIn("รุ่นใหม่กว่าช่วงที่กฎนี้ครอบคลุม", note28)

    def test_node_security_no_http2shell_alias(self):
        # Ensure 'HTTP2Shell' is never emitted
        for v_str in ["v18.0.0", "v20.10.0", "v22.10.0", "v24.10.0", "v25.0.0", "v26.0.0", "v28.0.0", "Node.js (Unknown)"]:
            res = evaluate_node_security(v_str, has_brotli=True)
            self.assertNotIn("HTTP2Shell", res.note)
            self.assertNotIn("HTTP2Shell", str(res.details))


if __name__ == "__main__":
    unittest.main()
