"""
Unit & Integration Tests for Standard Dynamic CVE & Payload Rules Engine (ภาษากลาง JSON)
Tests schema validation, SQLite persistence, rule import/export, dynamic evaluation, and API routes.
"""

import os
import json
import unittest
import tempfile
import httpx

from app import app
from core.cve_schema import validate_cve_rule, normalize_cve_rule, DEFAULT_CVE_RULES
import core.profile_db as profile_db
from audit.dynamic_rule_engine import execute_web_rule, test_single_rule


class TestDynamicCveRules(unittest.TestCase):
    def setUp(self):
        # Use an isolated temporary database for test runs
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.orig_db_path = profile_db.DB_PATH
        profile_db.DB_PATH = self.temp_db_path
        profile_db.init_profile_db()

        self.app = app.test_client()
        self.app.testing = True

    def tearDown(self):
        profile_db.DB_PATH = self.orig_db_path
        try:
            os.close(self.temp_db_fd)
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
        except Exception:
            pass

    def test_schema_validation(self):
        """Tests that rule validator accepts valid standard rules and rejects invalid ones."""
        valid_rule = {
            "rule_id": "TEST-CVE-001",
            "cve_id": "CVE-2026-9999",
            "name": "Test Vulnerability Rule",
            "target_type": "web",
            "severity": "High",
            "cvss_score": 8.0,
            "thaicert_group": 1,
            "trigger": {
                "method": "GET",
                "path": "/vuln"
            },
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "body_regex", "regex": "root:.*:0:0:"}
            ]
        }
        ok, err = validate_cve_rule(valid_rule)
        self.assertTrue(ok)
        self.assertIsNone(err)

        norm = normalize_cve_rule(valid_rule)
        self.assertEqual(norm["rule_id"], "TEST-CVE-001")
        self.assertEqual(norm["cvss_score"], 8.0)
        self.assertEqual(norm["thaicert_group"], 1)

        # Invalid rule missing matchers
        invalid_rule = {
            "rule_id": "TEST-002",
            "name": "Missing matchers",
            "trigger": {"path": "/"}
        }
        ok2, err2 = validate_cve_rule(invalid_rule)
        self.assertFalse(ok2)
        self.assertIn("cve_id", err2 or "")

    def test_database_default_seeding(self):
        """Tests that SQLite automatically seeds default standard rules when initialized."""
        rules = profile_db.get_all_cve_rules()
        self.assertGreaterEqual(len(rules), len(DEFAULT_CVE_RULES))
        ids = [r["rule_id"] for r in rules]
        self.assertIn("CVE-2024-4577", ids)
        self.assertIn("EXPOSURE-ENV-SECRETS", ids)
        self.assertIn("EXPOSURE-GIT-CONFIG", ids)
        self.assertIn("ANDROID-ADB-PORT-5555", ids)

    def test_crud_and_toggle(self):
        """Tests adding, updating, toggling, and deleting rules in SQLite."""
        new_rule = {
            "rule_id": "CUSTOM-SPRING4SHELL",
            "cve_id": "CVE-2022-22965",
            "name": "Spring Framework RCE Spring4Shell",
            "target_type": "web",
            "severity": "Critical",
            "cvss_score": 9.8,
            "cwe": "CWE-94",
            "thaicert_group": 6,
            "trigger": {
                "method": "POST",
                "path": "/helloworld",
                "body": "class.module.classLoader=1"
            },
            "matchers": [
                {"type": "status", "values": [200, 400]}
            ],
            "remediation": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+"
        }
        saved = profile_db.save_cve_rule(new_rule)
        self.assertEqual(saved["rule_id"], "CUSTOM-SPRING4SHELL")

        retrieved = profile_db.get_cve_rule_by_id("CUSTOM-SPRING4SHELL")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["cve_id"], "CVE-2022-22965")
        self.assertTrue(retrieved["is_enabled"])

        # Toggle disable
        profile_db.toggle_cve_rule("CUSTOM-SPRING4SHELL", False)
        retrieved2 = profile_db.get_cve_rule_by_id("CUSTOM-SPRING4SHELL")
        self.assertFalse(retrieved2["is_enabled"])

        # Delete
        deleted = profile_db.delete_cve_rule("CUSTOM-SPRING4SHELL")
        self.assertTrue(deleted)
        self.assertIsNone(profile_db.get_cve_rule_by_id("CUSTOM-SPRING4SHELL"))

    def test_export_and_import(self):
        """Tests exporting rules to standard JSON format and importing them."""
        export_bundle = profile_db.export_cve_rules_json()
        self.assertEqual(export_bundle["format"], "OPScaner-CVE-Rule-Schema")
        self.assertIn("rules", export_bundle)
        self.assertGreaterEqual(export_bundle["total_rules"], 5)

        # Import a custom rule bundle
        custom_import = {
            "format": "OPScaner-CVE-Rule-Schema",
            "rules": [
                {
                    "rule_id": "IMPORTED-RULE-001",
                    "cve_id": "CVE-2025-1111",
                    "name": "Imported Test Vulnerability",
                    "target_type": "web",
                    "severity": "High",
                    "cvss_score": 8.5,
                    "thaicert_group": 1,
                    "trigger": {
                        "method": "GET",
                        "path": "/secret.json"
                    },
                    "matchers": [
                        {"type": "status", "values": [200]},
                        {"type": "body_regex", "regex": "secret_token"}
                    ]
                }
            ]
        }
        summary = profile_db.import_cve_rules_json(custom_import)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["imported"], 1)

        rule = profile_db.get_cve_rule_by_id("IMPORTED-RULE-001")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["name"], "Imported Test Vulnerability")

    def test_api_endpoints(self):
        """Tests REST API endpoints for CVE rules."""
        # 1. GET /api/cve/rules
        res = self.app.get("/api/cve/rules")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertGreater(data["total"], 0)

        # 2. POST /api/cve/rules
        rule_payload = {
            "rule_id": "API-TEST-RULE",
            "cve_id": "CVE-2026-0001",
            "name": "API Test Rule",
            "target_type": "web",
            "severity": "Medium",
            "trigger": {"method": "GET", "path": "/test"},
            "matchers": [{"type": "status", "values": [200]}]
        }
        res_post = self.app.post("/api/cve/rules", json=rule_payload)
        self.assertEqual(res_post.status_code, 200)
        self.assertEqual(res_post.get_json()["rule"]["rule_id"], "API-TEST-RULE")

        # 3. POST /api/cve/rules/<id>/toggle
        res_toggle = self.app.post("/api/cve/rules/API-TEST-RULE/toggle", json={"is_enabled": False})
        self.assertEqual(res_toggle.status_code, 200)

        # 4. GET /api/cve/export
        res_export = self.app.get("/api/cve/export")
        self.assertEqual(res_export.status_code, 200)
        exp_data = res_export.get_json()
        self.assertEqual(exp_data["format"], "OPScaner-CVE-Rule-Schema")

        # 5. DELETE /api/cve/rules/<id>
        res_del = self.app.delete("/api/cve/rules/API-TEST-RULE")
        self.assertEqual(res_del.status_code, 200)


if __name__ == "__main__":
    unittest.main()
