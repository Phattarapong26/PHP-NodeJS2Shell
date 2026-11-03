import unittest
from core.database import NGINX_CVE_DESCS, CVE_DATABASE
from audit.php_audit import evaluate_php_security
from reports.amber_builder import build_amber_advisory_html


class TestAuditTaxonomyAndCVSS(unittest.TestCase):
    """
    Regression and compliance tests ensuring CVSS scores, versions,
    taxonomies, and lifecycle risk evaluations comply with international standards.
    """

    def test_cve_cvss_accuracy(self):
        # CVE-2021-23017: NVD Base Score 7.7 (CVSS v3.1), Vendor: Medium
        self.assertEqual(NGINX_CVE_DESCS["CVE-2021-23017"]["cvss"], 7.7)
        self.assertEqual(NGINX_CVE_DESCS["CVE-2021-23017"]["cvss_version"], "CVSS v3.1")
        self.assertEqual(NGINX_CVE_DESCS["CVE-2021-23017"]["vendor_severity"], "Medium (NGINX)")

        # CVE-2026-15176: F5 CNA / CSA CVSS v4.0 = 9.2, Vendor: Medium
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-15176"]["cvss"], 9.2)
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-15176"]["cvss_version"], "CVSS v4.0")
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-15176"]["vendor_severity"], "Medium (NGINX)")

        # CVE-2026-97205: CVSS v4.0 = 9.2
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-97205"]["cvss"], 9.2)
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-97205"]["cvss_version"], "CVSS v4.0")

    def test_cve_database_catalog(self):
        cve_map = {c["id"]: c for c in CVE_DATABASE}

        # CVE-2024-4577: PHP Group CVSS v3.1 = 9.8
        self.assertIn("CVE-2024-4577", cve_map)
        self.assertEqual(cve_map["CVE-2024-4577"]["cvss"], 9.8)
        self.assertEqual(cve_map["CVE-2024-4577"]["cvss_version"], "CVSS v3.1")

        # CVE-2026-115560: Pending Official NVD Scoring
        self.assertIn("CVE-2026-115560", cve_map)
        self.assertIsNone(cve_map["CVE-2026-115560"]["cvss"])
        self.assertEqual(cve_map["CVE-2026-115560"]["cvss_version"], "Pending Official NVD Scoring")
        self.assertEqual(cve_map["CVE-2026-115560"]["severity"], "High")

    def test_php_eol_lifecycle_classification(self):
        # PHP 7.4.33 & 5.6.40 must classify as Lifecycle Risk (EOL), not Critical
        sev_74, note_74 = evaluate_php_security("PHP/7.4.33")
        self.assertEqual(sev_74, "Lifecycle Risk (EOL)")
        self.assertIn("End-of-Life", note_74)

        sev_56, note_56 = evaluate_php_security("PHP/5.6.40")
        self.assertEqual(sev_56, "Lifecycle Risk (EOL)")

    def test_amber_advisory_taxonomy_summary(self):
        mock_scan_data = {
            "target": "10.255.250.0/24",
            "hosts": [
                {
                    "ip": "10.255.250.102",
                    "port": 5000,
                    "webServer": "Werkzeug",
                    "rce_proof": {
                        "is_rce_proved": True,
                        "technique": "Diagnostic Command Injection",
                        "command_executed": "id",
                        "execution_output": "uid=0(root) gid=0(root)"
                    }
                },
                {
                    "ip": "10.255.250.102",
                    "port": 8082,
                    "webServer": "nginx/1.18.0",
                    "matched_cves": [
                        {
                            "id": "CVE-2026-15176",
                            "name": "NGINX Heap Buffer Overflow",
                            "severity": "Critical",
                            "cvss": 9.2,
                            "cvss_version": "CVSS v4.0",
                            "score_source": "F5 CNA / CSA",
                            "vendor_severity": "Medium (NGINX)",
                            "verification_type": "Conditional Finding"
                        }
                    ]
                },
                {
                    "ip": "10.255.250.102",
                    "port": 8081,
                    "webServer": "Apache",
                    "php_version": "7.4.33",
                    "vulnerability": "Lifecycle Risk (EOL)"
                },
                {
                    "ip": "10.255.250.1",
                    "port": 80,
                    "webServer": "RouterOS"
                }
            ]
        }
        html = build_amber_advisory_html(mock_scan_data)
        self.assertIn("Confirmed Vulnerabilities", html)
        self.assertIn("Conditional Findings", html)
        self.assertIn("Software Lifecycle Risks - EOL", html)
        self.assertIn("Host-based Verification Guide", html)
        self.assertIn("OPScaner Engine v2.0", html)


if __name__ == "__main__":
    unittest.main()
