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

        # CVE-2026-15176: F5 CNA CVSS v3.1 = 8.1 (CVSS v4.0: 9.2), Vendor: Medium
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-15176"]["cvss"], 8.1)
        self.assertIn("CVSS v3.1", NGINX_CVE_DESCS["CVE-2026-15176"]["cvss_version"])
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-15176"]["vendor_severity"], "Medium (NGINX)")

        # CVE-2026-97205: CVSS v3.1 = 8.1 (Singapore CSA v4.0 = 9.2)
        self.assertEqual(NGINX_CVE_DESCS["CVE-2026-97205"]["cvss"], 8.1)
        self.assertIn("CVSS v3.1", NGINX_CVE_DESCS["CVE-2026-97205"]["cvss_version"])

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
        self.assertIn("OPScaner Engine", html)
        self.assertNotIn("v2.0", html)
        self.assertNotIn("V2.0", html)
        self.assertIn("Assessment Status Taxonomy", html)
        self.assertIn("Observed Evidence", html)
        self.assertIn("Internal Preconditions", html)
        self.assertIn("Assessment Conclusion", html)
        self.assertIn("Port &amp; Service Fingerprint Mapping", html)
        self.assertIn("8.1", html)
        self.assertIn("F5 CNA", html)

    def test_multi_port_eol_instance_counting(self):
        # When multiple ports run EOL software, instances and ports must match
        multi_port_data = {
            "target": "10.255.250.0/24",
            "hosts": [
                {"ip": "10.255.250.102", "port": 8081, "phpVersion": "PHP/7.4.33"},
                {"ip": "10.255.250.102", "port": 8082, "phpVersion": "PHP/7.4.33"},
                {"ip": "10.255.250.102", "port": 8084, "phpVersion": "PHP/5.6.40"}
            ]
        }
        html = build_amber_advisory_html(multi_port_data)
        self.assertIn("3 instances บน 3 พอร์ตบริการ", html)

    def test_cve_2024_4577_and_97205_accuracy(self):
        cve_map = {c["id"]: c for c in CVE_DATABASE}
        # CVE-2024-4577 must verify FastCGI invoking php-cgi.exe on Windows via PowerShell
        cve_4577 = cve_map["CVE-2024-4577"]
        self.assertIn("php-cgi.exe", cve_4577["expected_safe"])
        self.assertIn("PowerShell", cve_4577["host_check"])
        self.assertIn("php-cgi.exe", cve_4577["confirm_vuln"])

        # CVE-2026-97205 must split host check into 2 steps
        cve_97205 = NGINX_CVE_DESCS["CVE-2026-97205"]
        self.assertIn("ขั้นตอนที่ 1", cve_97205["host_check"])
        self.assertIn("ขั้นตอนที่ 2", cve_97205["host_check"])
        self.assertIn("<!--#include", cve_97205["host_check"])

    def test_architecture_verification_commands_formatting(self):
        mock_data = {
            "target": "10.255.250.0/24",
            "hosts": [
                {"ip": "10.255.250.102", "port": 5050, "webServer": "Werkzeug/3.1.9 Python/3.11.18"},
                {"ip": "10.255.250.102", "port": 8080, "webServer": "Apache / Nginx", "phpVersion": "PHP/8.2.35"},
                {"ip": "10.255.250.102", "port": 8081, "webServer": "Apache", "phpVersion": "PHP/7.4.33"}
            ]
        }
        html = build_amber_advisory_html(mock_data)
        # Must escape Docker format template correctly
        self.assertIn(r'table {{.Names}}\t{{.Ports}}\t{{.Image}}', html)
        # ss must cover port 5050
        self.assertIn(r':(5050|808[0-8])\b', html)
        # Port 8080 ambiguous service & evidence
        self.assertIn("HTTP Service — Server Identity Ambiguous (Apache / Nginx)", html)
        self.assertIn("Server Banner: Apache / Nginx | Runtime from Header: X-Powered-By: PHP/8.2.35", html)
        # Device name
        self.assertIn("Target Host / Multi-Service IP", html)
        self.assertNotIn("เครื่องนี้", html)


if __name__ == "__main__":
    unittest.main()
