import os
import unittest
import tempfile
import sqlite3
from app import app
import core.profile_db as profile_db
from core.update_checker import check_for_updates, get_cached_update_status


class TestProfileDBAndAPI(unittest.TestCase):
    def setUp(self):
        # Create temporary database file for test isolation
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        # Override DB path in module
        self.orig_db_path = profile_db.DB_PATH
        profile_db.DB_PATH = self.temp_db_path
        profile_db.init_profile_db()

        # Set up Flask app test client
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        profile_db.PROFILES_DB_PATH = self.orig_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def test_database_crud(self):
        # 1. Initially empty
        profs = profile_db.get_all_profiles()
        self.assertEqual(len(profs), 0)
        self.assertIsNone(profile_db.get_active_profile())

        # 2. Create first profile
        p1 = profile_db.create_profile(
            title="HQ Office Network",
            description="Main corporate network in Bangkok",
            network_target="192.168.1.0/24",
            set_active=True,
            concurrency=80,
            timeout=3.0,
            user_agent="Mozilla/5.0 Googlebot",
            custom_headers="X-Forwarded-For: 127.0.0.1",
            port_mode="standard",
            scope_preset="all"
        )
        self.assertIsNotNone(p1.get("id"))
        self.assertEqual(p1["title"], "HQ Office Network")
        self.assertEqual(p1["network_target"], "192.168.1.0/24")
        self.assertEqual(p1["concurrency"], 80)
        self.assertEqual(p1["timeout"], 3.0)
        self.assertEqual(p1["user_agent"], "Mozilla/5.0 Googlebot")
        self.assertEqual(p1["custom_headers"], "X-Forwarded-For: 127.0.0.1")
        self.assertTrue(p1["is_active"])

        # Test scan history
        hist = profile_db.add_scan_history(
            profile_id=p1["id"],
            target_subnet="192.168.1.0/24",
            total_hosts=10,
            php_hosts=2,
            node_hosts=1,
            vuln_hosts=0,
            elapsed_seconds=1.5,
            scan_summary="10 เครื่องตรวจสอบแล้ว",
            scan_result_json='{"hosts": [{"ip": "192.168.1.5", "port": 80}]}'
        )
        self.assertIsNotNone(hist.get("id"))
        history_list = profile_db.get_scan_history(profile_id=p1["id"])
        self.assertEqual(len(history_list), 1)
        self.assertEqual(history_list[0]["php_hosts"], 2)

        # 3. Create second profile without making active
        p2 = profile_db.create_profile(
            title="Branch Lab",
            description="Testing lab without explicit subnet (Auto IP)",
            network_target="",
            set_active=False
        )
        self.assertFalse(p2["is_active"])

        all_p = profile_db.get_all_profiles()
        self.assertEqual(len(all_p), 2)

        # 4. Switch active profile
        activated = profile_db.set_active_profile(p2["id"])
        self.assertTrue(activated["is_active"])
        curr_active = profile_db.get_active_profile()
        self.assertEqual(curr_active["id"], p2["id"])

        # 5. Update profile
        updated = profile_db.update_profile(
            profile_id=p2["id"],
            title="Branch Lab Production",
            description="Updated description",
            network_target="10.10.20.0/24"
        )
        self.assertEqual(updated["title"], "Branch Lab Production")
        self.assertEqual(updated["network_target"], "10.10.20.0/24")

        # 6. Delete profile
        deleted = profile_db.delete_profile(p2["id"])
        self.assertTrue(deleted)
        remaining = profile_db.get_all_profiles()
        self.assertEqual(len(remaining), 1)

    def test_profile_api_endpoints(self):
        # GET /api/profiles (empty)
        res = self.client.get("/api/profiles")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["total"], 0)

        # POST /api/profiles (create)
        res_post = self.client.post("/api/profiles", json={
            "title": "DataCenter Subnet",
            "description": "DC Tier 3",
            "network_target": "172.16.50.0/24",
            "set_active": True,
            "concurrency": 100,
            "timeout": 2.5,
            "user_agent": "CustomTestUA/1.0",
            "custom_headers": "Referer: https://internal.test\nX-Forwarded-For: 10.0.0.1",
            "port_mode": "wide",
            "scope_preset": "windows"
        })
        self.assertEqual(res_post.status_code, 201)
        created = res_post.get_json()["profile"]
        pid = created["id"]
        self.assertEqual(created["concurrency"], 100)
        self.assertEqual(created["user_agent"], "CustomTestUA/1.0")

        # GET /api/profiles/<id>/history (empty initially)
        res_hist_empty = self.client.get(f"/api/profiles/{pid}/history")
        self.assertEqual(res_hist_empty.status_code, 200)
        self.assertEqual(len(res_hist_empty.get_json()["history"]), 0)

        # Add history record and test retrieval and restore
        hist_rec = profile_db.add_scan_history(
            profile_id=pid,
            target_subnet="172.16.50.0/24",
            total_hosts=25,
            php_hosts=4,
            node_hosts=2,
            vuln_hosts=1,
            elapsed_seconds=2.1,
            scan_summary="25 hosts scanned",
            scan_result_json='{"hosts": [{"ip": "172.16.50.10", "port": 80}]}'
        )
        res_hist = self.client.get(f"/api/profiles/{pid}/history")
        self.assertEqual(res_hist.status_code, 200)
        self.assertEqual(len(res_hist.get_json()["history"]), 1)

        # POST /api/scan-history/<id>/restore
        res_restore = self.client.post(f"/api/scan-history/{hist_rec['id']}/restore")
        self.assertEqual(res_restore.status_code, 200)
        self.assertEqual(res_restore.get_json()["history_record"]["total_hosts"], 25)

        # GET /api/profiles/<id>
        res_get = self.client.get(f"/api/profiles/{pid}")
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.get_json()["profile"]["title"], "DataCenter Subnet")

        # PUT /api/profiles/<id>
        res_put = self.client.put(f"/api/profiles/{pid}", json={
            "title": "DataCenter Subnet (Primary)",
            "description": "Updated",
            "network_target": "172.16.50.0/24"
        })
        self.assertEqual(res_put.status_code, 200)
        self.assertEqual(res_put.get_json()["profile"]["title"], "DataCenter Subnet (Primary)")

        # DELETE /api/profiles/<id>
        res_del = self.client.delete(f"/api/profiles/{pid}")
        self.assertEqual(res_del.status_code, 200)

    def test_system_update_endpoints(self):
        # GET /api/system/check-update
        res = self.client.get("/api/system/check-update")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        info = data["update_info"]
        self.assertIn("current_commit", info)
        self.assertIn("has_update", info)
        self.assertIn("is_docker", info)


if __name__ == "__main__":
    unittest.main()
