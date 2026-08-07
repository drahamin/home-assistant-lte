import importlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = cls.temp.name
        os.environ["CONFIG_DIR"] = cls.temp.name
        cls.server = importlib.import_module("server")
        cls.client = cls.server.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_health(self):
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_rejects_bad_subscriber(self):
        response = self.client.post("/api/subscribers", json={"imsi": "bad"})
        self.assertEqual(response.status_code, 400)

    def test_log_analyzer_finds_attach_problems(self):
        payload = {"file": (io.BytesIO(b"MME: authentication failure for UE\nattach reject EMM cause 9\n"), "mme.log")}
        response = self.client.post("/api/logs/analyze", data=payload, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["findings"]), 2)

    def test_diagnostics_are_allowlisted(self):
        with patch.object(self.server, "ping_check", return_value=True), \
             patch.object(self.server, "tcp_check", return_value={"online": True, "latency_ms": 1}), \
             patch.object(self.server, "sctp_check", return_value={"online": True, "latency_ms": 1}):
            response = self.client.post("/api/diagnostics/run")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["failures"], 0)

    def test_local_subscriber_round_trip(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {"epc_type": "local", "apn": "internet", "mcc": "001", "mnc": "01", "tac": 1, "sim_programming_enabled": False}
            profile = {"imsi": "001010000000001", "name": "Test UE", "zone": "Cellar", "k": "A" * 32, "opc": "B" * 32, "amf": "8000", "apn": "internet", "msisdn": ""}
            self.assertEqual(self.client.post("/api/subscribers", json=profile).status_code, 201)
            rows = self.client.get("/api/subscribers").get_json()
            self.assertEqual(rows[0]["zone"], "Cellar")
            changed = self.client.patch("/api/subscribers/001010000000001/zone", json={"zone": "North Vineyard"})
            self.assertEqual(changed.status_code, 200)
            self.assertEqual(self.client.get("/api/subscribers").get_json()[0]["zone"], "North Vineyard")
        finally:
            self.server.settings = original

    def test_history_returns_uptime(self):
        with self.server.db() as conn:
            conn.execute("DELETE FROM status_history")
            now = int(self.server.time.time())
            conn.execute("INSERT INTO status_history VALUES(?,?,?,?,?)", (now - 2, 1, 0, 1, 1))
            conn.execute("INSERT INTO status_history VALUES(?,?,?,?,?)", (now - 1, 1, 1, 1, 1))
        data = self.client.get("/api/history?hours=6").get_json()
        self.assertEqual(data["uptime"]["epc"], 100.0)
        self.assertEqual(data["uptime"]["radio"], 50.0)

    def test_alert_settings_are_configurable(self):
        response = self.client.put("/api/alerts/settings", json={
            "epc_enabled": True, "radio_enabled": False,
            "failure_threshold": 5, "cooldown_minutes": 240,
        })
        self.assertEqual(response.status_code, 200)
        settings = self.client.get("/api/alerts/settings").get_json()["settings"]
        self.assertEqual(settings["failure_threshold"], 5)
        self.assertFalse(settings["radio_enabled"])

    def test_internet_plan_is_safe_and_specific(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {"ue_subnet": "45.45.0.0/16", "epc_uplink_interface": "eth0", "apn": "internet"}
            data = self.client.get("/api/internet-plan").get_json()
            self.assertEqual(data["subnet"], "45.45.0.0/16")
            self.assertIn("test", data["steps"][-1].lower())
        finally:
            self.server.settings = original

    def test_opc_matches_3gpp_milenage_vector(self):
        response = self.client.post("/api/sim/opc", json={
            "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
            "op": "CDC202D5123E20F62B6D676AC72CB318",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["opc"], "CD63CB71954A9F4E48A5994E37A02BAF")
        self.assertFalse(response.get_json()["stored"])

    def test_secure_sim_values_have_valid_lengths(self):
        data = self.client.post("/api/sim/test-values").get_json()
        self.assertEqual(len(data["k"]), 32)
        self.assertEqual(len(data["op"]), 32)
        self.assertEqual(len(data["opc"]), 32)
        self.assertFalse(data["stored"])

    def test_routing_apply_requires_exact_confirmation(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {
                "epc_routing_management_enabled": True, "epc_host": "192.168.1.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "45.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            response = self.client.post("/api/epc-routing/apply", json={"confirm": "yes"})
            self.assertEqual(response.status_code, 400)
            self.assertIn("APPLY 192.168.1.151", response.get_json()["error"])
        finally:
            self.server.settings = original

    def test_routing_script_is_scoped_and_reversible(self):
        cfg = {"subnet": "45.45.0.0/16", "interface": "eth0"}
        apply_script = self.server.routing_apply_script(cfg)
        rollback_script = self.server.routing_rollback_script(cfg)
        self.assertIn("Managed by Baiamonte LTE", apply_script)
        self.assertIn("baiamonte-lte-routing.service", apply_script)
        self.assertIn("previous_forwarding", rollback_script)
        self.assertIn("45.45.0.0/16", rollback_script)

    def test_routing_key_generator_returns_only_public_key(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {
                "epc_routing_management_enabled": True, "epc_host": "192.168.1.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "45.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            response = self.client.post("/api/epc-routing/key/generate", json={})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.get_json()["public_key"].startswith("ssh-ed25519 "))
            self.assertNotIn("PRIVATE", response.get_data(as_text=True))
        finally:
            self.server.settings = original


if __name__ == "__main__":
    unittest.main()
