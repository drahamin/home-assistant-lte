import importlib
import io
import os
from pathlib import Path
import socket
import subprocess
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
             patch.object(self.server, "sctp_check", return_value={"online": True, "latency_ms": 1}), \
             patch.object(self.server, "dns_check", return_value={"online": True, "latency_ms": 1, "addresses": ["1.2.3.4"]}):
            response = self.client.post("/api/diagnostics/run")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["failures"], 0)

    def test_local_subscriber_round_trip(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {"epc_type": "local", "apn": "internet", "mcc": "001", "mnc": "01", "tac": 1, "sim_programming_enabled": False}
            profile = {"imsi": "001010000000001", "name": "North Cellar Camera", "zone": "Cellar", "device_type": "Camera", "critical": True, "notes": "Recorder bay 2", "k": "A" * 32, "opc": "B" * 32, "amf": "8000", "apn": "internet", "msisdn": ""}
            self.assertEqual(self.client.post("/api/subscribers", json=profile).status_code, 201)
            rows = self.client.get("/api/subscribers").get_json()
            self.assertEqual(rows[0]["zone"], "Cellar")
            self.assertEqual(rows[0]["device_type"], "Camera")
            self.assertTrue(rows[0]["critical"])
            self.assertEqual(rows[0]["notes"], "Recorder bay 2")
            changed = self.client.patch("/api/subscribers/001010000000001/zone", json={"zone": "North Vineyard"})
            self.assertEqual(changed.status_code, 200)
            self.assertEqual(self.client.get("/api/subscribers").get_json()[0]["zone"], "North Vineyard")
            changed = self.client.patch("/api/subscribers/001010000000001/profile", json={"device_type": "Environmental sensor", "critical": False})
            self.assertEqual(changed.status_code, 200)
            changed_row = self.client.get("/api/subscribers").get_json()[0]
            self.assertEqual(changed_row["device_type"], "Environmental sensor")
            self.assertFalse(changed_row["critical"])
            export = self.client.get("/api/subscribers/export.csv")
            self.assertEqual(export.status_code, 200)
            self.assertIn("North Cellar Camera", export.get_data(as_text=True))
            self.assertNotIn("A" * 32, export.get_data(as_text=True))
            self.assertNotIn("B" * 32, export.get_data(as_text=True))
        finally:
            self.server.settings = original

    def test_subscriber_rejects_unknown_device_role(self):
        profile = {"imsi": "001010000000009", "name": "Unknown", "device_type": "Telephone", "k": "A" * 32, "opc": "B" * 32, "amf": "8000", "apn": "internet"}
        response = self.client.post("/api/subscribers", json=profile)
        self.assertEqual(response.status_code, 400)
        self.assertIn("device role", response.get_json()["error"])

    def test_interface_loads_shared_suite_styles(self):
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("static/suite.css", page)
        self.assertIn("Estate device inventory", page)
        self.assertIn("SAFE NETWORK TOOLKIT", page)
        self.assertIn("PBX voice &amp; text gateway", page)
        self.assertIn("Traffic &amp; connection gauges", page)

    def test_network_visibility_has_actionable_status_lights(self):
        with patch.object(self.server, "ping_check", return_value=True), \
             patch.object(self.server, "tcp_check", return_value={"online": True, "latency_ms": 2}), \
             patch.object(self.server, "sctp_check", return_value={"online": True, "latency_ms": 3}), \
             patch.object(self.server, "dns_check", return_value={"online": True, "latency_ms": 4, "addresses": ["1.2.3.4"]}):
            data = self.client.get("/api/network/visibility").get_json()
        ids = {item["id"] for item in data["lights"]}
        self.assertTrue({"epc", "s1", "database", "radio", "bts_admin", "ssh", "dns", "uplink", "routing", "ue_data", "communications"}.issubset(ids))
        self.assertIsInstance(data["actions"], list)
        self.assertIn("health_score", data)

    def test_subscriber_gauges_use_measured_network_and_routing_data(self):
        status = {
            "epc": {"online": True, "s1": {"online": True}, "database": {"online": True}},
            "bts": {"online": False},
        }
        routing = {
            "checks": {"forwarding": True, "interface": True, "route": True, "nat": True,
                       "outbound": True, "return": True, "service": False},
            "counters": {"nat": 22, "outbound": 18, "return": 15},
            "checked_at": 1234,
        }
        rows = [{"zone": "North Vineyard", "device_type": "Camera"},
                {"zone": "Unassigned", "device_type": "Other IoT"}]
        data = self.server.subscriber_gauges(status, routing, rows)
        gauges = {item["id"]: item for item in data["items"]}
        self.assertEqual(gauges["connections"]["value"], 75)
        self.assertEqual(gauges["routing"]["value"], 86)
        self.assertEqual(gauges["traffic"]["display"], "2-way")
        self.assertEqual(gauges["profiles"]["value"], 50)

    def test_subscriber_gauges_show_unmeasured_epc_data(self):
        status = {"epc": {"online": False, "s1": {"online": False}, "database": {"online": False}},
                  "bts": {"online": False}}
        gauges = {item["id"]: item for item in self.server.subscriber_gauges(status, None, [])["items"]}
        self.assertIsNone(gauges["routing"]["value"])
        self.assertIsNone(gauges["traffic"]["value"])
        self.assertIsNone(gauges["profiles"]["value"])

    def test_network_tools_are_allowlisted(self):
        rejected = self.client.post("/api/tools/run", json={"action": "shell"})
        self.assertEqual(rejected.status_code, 400)
        with patch.object(self.server, "tcp_check", return_value={"online": True, "latency_ms": 1}), \
             patch.object(self.server, "sctp_check", return_value={"online": True, "latency_ms": 1}):
            accepted = self.client.post("/api/tools/run", json={"action": "ports"})
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.get_json()["kind"], "ports")
        self.assertEqual(len(accepted.get_json()["rows"]), 5)

    def test_incident_history_detects_outage_and_restore(self):
        with self.server.db() as conn:
            conn.execute("DELETE FROM status_history")
            now = int(self.server.time.time())
            conn.execute("INSERT INTO status_history VALUES(?,?,?,?,?)", (now - 120, 1, 1, 1, 1))
            conn.execute("INSERT INTO status_history VALUES(?,?,?,?,?)", (now - 60, 0, 1, 1, 1))
            conn.execute("INSERT INTO status_history VALUES(?,?,?,?,?)", (now, 1, 1, 1, 1))
        incidents = self.client.get("/api/incidents?hours=6").get_json()["incidents"]
        self.assertEqual(incidents[0]["state"], "restored")
        self.assertEqual(incidents[0]["duration_seconds"], 60)

    def test_logs_support_filtering_and_safe_download(self):
        self.server.event("tool", "Known ports checked")
        self.server.event("subscriber", "Device updated")
        rows = self.client.get("/api/logs?kind=tool&search=ports").get_json()
        self.assertTrue(rows)
        self.assertTrue(all(row["kind"] == "tool" for row in rows))
        exported = self.client.get("/api/logs/export")
        self.assertEqual(exported.status_code, 200)
        self.assertIn("Known ports checked", exported.get_data(as_text=True))

    def test_communications_require_opt_in_and_confirmation(self):
        rejected = self.client.post("/api/communications/send", json={"kind": "text", "to": "+15551234567", "message": "Test"})
        self.assertEqual(rejected.status_code, 400)
        original = self.server.settings
        try:
            self.server.settings = lambda: {
                "communications_enabled": True, "communications_gateway_url": "https://pbx.example/dispatch",
                "communications_gateway_token": "secret", "sip_gateway_host": "", "sip_gateway_port": 5060,
                "sip_transport": "tcp",
            }
            with patch.object(self.server.urllib.request, "urlopen") as urlopen:
                response = urlopen.return_value.__enter__.return_value
                response.status = 202
                response.read.return_value = b"queued"
                accepted = self.client.post("/api/communications/send", json={"confirm": "SEND", "kind": "voice", "to": "+15551234567", "message": "Irrigation alert"})
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(accepted.get_json()["gateway_response"], "queued")
            request = urlopen.call_args.args[0]
            self.assertEqual(request.headers["Authorization"], "Bearer secret")
        finally:
            self.server.settings = original

    def test_communications_secrets_are_never_public(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {"mongodb_uri": "mongodb://secret", "communications_gateway_url": "https://pbx.example/private", "communications_gateway_token": "top-secret", "epc_host": "192.0.2.151"}
            public = self.server.public_settings()
            self.assertNotIn("mongodb_uri", public)
            self.assertNotIn("communications_gateway_url", public)
            self.assertNotIn("communications_gateway_token", public)
            self.assertEqual(public["epc_host"], "192.0.2.151")
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
            self.server.settings = lambda: {"ue_subnet": "10.45.0.0/16", "epc_uplink_interface": "eth0", "apn": "internet"}
            data = self.client.get("/api/internet-plan").get_json()
            self.assertEqual(data["subnet"], "10.45.0.0/16")
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
                "epc_routing_management_enabled": True, "epc_host": "192.0.2.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "10.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            response = self.client.post("/api/epc-routing/apply", json={"confirm": "yes"})
            self.assertEqual(response.status_code, 400)
            self.assertIn("APPLY 192.0.2.151", response.get_json()["error"])
        finally:
            self.server.settings = original

    def test_routing_script_is_scoped_and_reversible(self):
        cfg = {"subnet": "10.45.0.0/16", "interface": "eth0"}
        apply_script = self.server.routing_apply_script(cfg)
        rollback_script = self.server.routing_rollback_script(cfg)
        self.assertIn("Managed by Baiamonte LTE", apply_script)
        self.assertIn("baiamonte-lte-routing.service", apply_script)
        self.assertIn("previous_forwarding", rollback_script)
        self.assertIn("10.45.0.0/16", rollback_script)

    def test_routing_key_generator_returns_only_public_key(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {
                "epc_routing_management_enabled": True, "epc_host": "192.0.2.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "10.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            response = self.client.post("/api/epc-routing/key/generate", json={"confirm": "REPLACE KEY"})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.get_json()["public_key"].startswith("ssh-ed25519 "))
            self.assertNotIn("PRIVATE", response.get_data(as_text=True))
        finally:
            self.server.settings = original

    def test_extensionless_private_key_upload_is_accepted(self):
        original = self.server.settings
        generated_key = Path(self.temp.name) / "id_ed25519_upload_test"
        try:
            self.server.settings = lambda: {
                "epc_routing_management_enabled": True, "epc_host": "192.0.2.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "10.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(generated_key)],
                check=True,
            )
            payload = {"file": (io.BytesIO(generated_key.read_bytes()), "id_ed25519")}
            response = self.client.post(
                "/api/epc-routing/key", data=payload, content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(self.server.EPC_SSH_KEY.exists())
            self.assertEqual(self.server.EPC_SSH_KEY.stat().st_mode & 0o777, 0o600)
        finally:
            self.server.settings = original

    def test_public_key_upload_explains_private_file_is_required(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {
                "epc_routing_management_enabled": True, "epc_host": "192.0.2.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "10.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            payload = {"file": (io.BytesIO(b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test\n"), "id_ed25519.pub")}
            response = self.client.post(
                "/api/epc-routing/key", data=payload, content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn("public key", response.get_json()["error"])
            self.assertIn("without .pub", response.get_json()["error"])
        finally:
            self.server.settings = original

    def test_epc_connectivity_reports_timeout(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {
                "epc_routing_management_enabled": True, "epc_host": "192.0.2.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "10.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            with patch.object(self.server.socket, "create_connection", side_effect=socket.timeout):
                response = self.client.post("/api/epc-routing/connectivity")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["state"], "timeout")
            self.assertIn("VLAN", response.get_json()["detail"])
        finally:
            self.server.settings = original

    def test_epc_console_only_runs_allowlisted_tools(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {
                "epc_routing_management_enabled": True, "epc_host": "192.0.2.151",
                "epc_ssh_user": "root", "epc_ssh_port": 22, "ue_subnet": "10.45.0.0/16",
                "epc_uplink_interface": "eth0", "apn": "internet",
            }
            rejected = self.client.post("/api/epc-console/run", json={"action": "rm-everything"})
            self.assertEqual(rejected.status_code, 400)
            with patch.object(self.server, "run_epc_script", return_value=({"host": "192.0.2.151"}, "healthy")) as run:
                accepted = self.client.post("/api/epc-console/run", json={"action": "system"})
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(accepted.get_json()["output"], "healthy")
            self.assertIn("hostname", run.call_args.args[0])
        finally:
            self.server.settings = original

    def test_epc_console_scripts_are_read_only(self):
        scripts = "\n".join(action["script"] for action in self.server.EPC_CONSOLE_ACTIONS.values())
        for destructive in ("rm ", "iptables -A", "iptables -D", "systemctl restart", "systemctl stop", "reboot"):
            self.assertNotIn(destructive, scripts)


if __name__ == "__main__":
    unittest.main()
