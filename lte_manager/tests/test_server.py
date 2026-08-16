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

    def test_missing_subscriber_log_creates_reviewable_pending_registration(self):
        imsi = "001010000000077"
        log = f"[hss] ERROR: Cannot find IMSI[{imsi}] in subscriber DB APN[internet]\n"
        payload = {"file": (io.BytesIO(log.encode()), "mme.log")}
        response = self.client.post("/api/logs/analyze", data=payload, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["pending_registrations_found"], 1)
        rows = self.client.get("/api/registrations/pending").get_json()
        row = next(item for item in rows if item["imsi"] == imsi)
        self.assertEqual(row["apn"], "internet")
        self.assertNotIn("k", row)
        self.assertNotIn("opc", row)
        with self.server.db() as conn:
            conn.execute("DELETE FROM pending_registrations WHERE imsi=?", (imsi,))

    def test_authentication_failure_is_not_offered_as_new_subscriber(self):
        imsi = "001010000000078"
        log = f"[mme] Authentication failure IMSI[{imsi}] MAC failure\n"
        self.assertEqual(self.server.failed_registration_candidates(log), [])
        normal_identity_lookup = f"[mme] Unknown UE by IMSI[{imsi}]\n[emm] Identity response\n"
        self.assertEqual(self.server.failed_registration_candidates(normal_identity_lookup), [])

    def test_admin_can_approve_pending_registration_with_sim_credentials(self):
        imsi = "001010000000079"
        original = self.server.settings
        try:
            self.server.settings = lambda: {"epc_type": "local", "apn": "internet", "mcc": "001", "mnc": "01", "tac": 1, "sim_programming_enabled": False}
            self.server.record_failed_registrations(
                f"Subscriber not found for IMSI[{imsi}] APN[internet]", "test EPC log")
            body = {"confirm": imsi, "name": "Approved field camera", "k": "A" * 32,
                    "opc": "B" * 32, "amf": "8000", "apn": "internet", "msisdn": "",
                    "zone": "North Vineyard", "device_type": "Camera", "notes": "Approved by test"}
            response = self.client.post(f"/api/registrations/pending/{imsi}/approve", json=body)
            self.assertEqual(response.status_code, 201)
            self.assertFalse(any(row["imsi"] == imsi for row in self.client.get("/api/registrations/pending").get_json()))
            self.assertTrue(any(row["imsi"] == imsi for row in self.client.get("/api/subscribers").get_json()))
        finally:
            with self.server.db() as conn:
                conn.execute("DELETE FROM pending_registrations WHERE imsi=?", (imsi,))
                conn.execute("DELETE FROM subscribers WHERE imsi=?", (imsi,))
            self.server.settings = original

    def test_production_sim_plan_uses_complete_lte_plmn_path(self):
        data = self.client.get("/api/sim/production-plan").get_json()
        files = {item["file"] for item in data["lte_files"]}
        self.assertIn("EF.PLMNwAcT / EF.OPLMNwAcT", files)
        self.assertIn("Subscriber selection is complete", data["selection_note"])
        self.assertEqual(len(data["steps"]), 6)
        self.assertEqual(self.client.post("/api/simulations/roaming", json={}).status_code, 404)

    def test_production_sim_confirmation_separates_registry_attach_and_data(self):
        imsi = "001010000000080"
        original = self.server.settings
        profile = {"imsi": imsi, "name": "Production camera", "device_type": "Camera", "zone": "Estate Gate",
                   "k": "A" * 32, "opc": "B" * 32, "amf": "8000", "apn": "internet"}
        network = {"epc": {"online": True, "s1": {"online": True}, "database": {"online": True}},
                   "bts": {"online": True}}
        try:
            self.server.settings = lambda: {"epc_type": "local", "apn": "internet", "mcc": "001", "mnc": "01",
                                             "tac": 1, "sim_programming_enabled": False}
            self.assertEqual(self.client.post("/api/subscribers", json=profile).status_code, 201)
            with patch.object(self.server, "sample_network", return_value=network), \
                 patch.object(self.server, "routing_config", return_value={"enabled": False}):
                data = self.client.post("/api/sim/confirm", json={"imsi": imsi}).get_json()
            self.assertTrue(data["registered"])
            self.assertFalse(data["attach_confirmed"])
            self.assertFalse(data["complete"])
            states = {item["id"]: item["state"] for item in data["checks"]}
            self.assertEqual(states["registry"], "online")
            self.assertEqual(states["data"], "unknown")
            inventory = self.client.get("/api/sim/inventory").get_json()
            row = next(item for item in inventory if item["imsi"] == imsi)
            self.assertEqual(row["stage"], "hss_provisioned")
            self.assertNotIn("k", row)
            self.assertNotIn("opc", row)
        finally:
            with self.server.db() as conn:
                conn.execute("DELETE FROM subscribers WHERE imsi=?", (imsi,))
                conn.execute("DELETE FROM sim_inventory WHERE imsi=?", (imsi,))
            self.server.settings = original

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
        self.assertIn('id="theme-toggle"', page)
        self.assertIn('prefers-color-scheme:dark', page)
        physical = page.split('id="nokia-physical-connections"', 1)[1].split('</article>', 1)[0]
        self.assertNotIn('type="checkbox"', physical)
        self.assertIn("MAIN antenna", physical)
        self.assertIn("Diversity", physical)
        self.assertIn('id="poll-bts"', page)
        self.assertIn('id="open-bts-management"', page)
        self.assertIn('id="check-bts-path"', page)
        self.assertIn('id="download-bts-status"', page)
        self.assertIn('id="nokia-status-grid"', page)
        self.assertIn('id="nokia-control-actions"', page)
        self.assertIn('id="radio-channel-grid"', page)
        self.assertIn('id="pending-registrations"', page)
        self.assertIn('id="troubleshooting-pending"', page)
        self.assertNotIn('id="run-roaming-simulation"', page)
        self.assertNotIn("Synthetic roaming infrastructure", page)
        self.assertIn('id="provision-sim-subscriber"', page)
        self.assertIn('id="confirm-sim-subscriber"', page)
        self.assertIn('id="sim-inventory"', page)
        self.assertIn('id="generate-sim-profile"', page)
        self.assertIn('id="read-sim-card"', page)
        self.assertIn('id="import-sim-profile"', page)
        self.assertIn('id="copy-sim-profile"', page)
        self.assertIn('id="sim-read-light"', page)
        self.assertIn('id="sim-write-light"', page)
        self.assertIn('id="sim-card-process"', page)
        self.assertIn("Complete PLMN and USIM policy", page)

    def test_commissioning_context_identifies_supported_nokia_access(self):
        path = Path(self.temp.name) / "commissioning-access-test.xml"
        path.write_text("""<raml><managedObject>
            <p name="oamTls">forced</p><p name="omsTls">forced</p>
            <p name="serviceAccountSshStatus">disabled</p>
            <p name="primBackhaulPort">EIF2 (port B)</p>
            <p name="lmtPort">EIF1 (port A)</p>
            <p name="oamIpAddr">192.168.99.99</p>
        </managedObject></raml>""", encoding="utf-8")
        try:
            data = self.server.commissioning_context()
            self.assertTrue(data["valid"])
            self.assertEqual(data["access"]["method"], "HTTPS OAM / Nokia BTS Site Manager")
            self.assertTrue(data["access"]["tls_required"])
            self.assertFalse(data["access"]["ssh_enabled"])
            self.assertNotIn("oamIpAddr", data["fields"])
            self.assertNotIn("192.168.99.99", str(data))
        finally:
            path.unlink(missing_ok=True)

    def test_nokia_status_is_read_only_and_reports_management_signals(self):
        original = self.server.settings
        try:
            self.server.settings = lambda: {"bts_host": "192.0.2.100", "epc_host": "192.0.2.151", "s1ap_port": 36412}
            with patch.object(self.server, "ping_check", return_value=True), \
                 patch.object(self.server, "tls_status", return_value={"online": True, "latency_ms": 4,
                     "protocol": "TLSv1.2", "cipher": "TEST", "certificate_sha256": "AA" * 32}), \
                 patch.object(self.server, "tcp_check", return_value={"online": False, "latency_ms": None}), \
                 patch.object(self.server, "sctp_check", return_value={"online": True, "latency_ms": 3}), \
                 patch.object(self.server, "commissioning_context", return_value={"available": False, "fields": {}}), \
                 patch.object(self.server, "nokia_api_connectivity", return_value={"enabled": False}):
                data = self.client.get("/api/bts/status").get_json()
            self.assertTrue(data["reachable"])
            self.assertTrue(data["management"]["https"]["online"])
            self.assertTrue(data["s1_target"]["online"])
            self.assertFalse(data["licensed_status"]["available"])
        finally:
            self.server.settings = original

    def test_band_2_channel_profile_labels_enb_tx_and_rx(self):
        channel = self.server.radio_channel_profile({"lte_band": 2, "dl_earfcn": 900, "ul_earfcn": 18900,
                                                     "channel_bandwidth_mhz": 10, "tx_power_dbm": 20,
                                                     "pci": 21, "enb_id": 7, "cell_id": 1})
        self.assertEqual(channel["enb_tx_mhz"], 1960.0)
        self.assertEqual(channel["enb_rx_mhz"], 1880.0)
        self.assertEqual(channel["duplex_spacing_mhz"], 80.0)

    def test_nokia_operations_filters_status_and_messages(self):
        original = self.server.settings
        cfg = {"nokia_api_enabled": True, "nokia_api_status_path": "/status", "nokia_api_cells_path": "/cells",
               "nokia_api_alarms_path": "/alarms", "nokia_api_events_path": "/events"}
        responses = {
            "/status": b'{"operationalState":"enabled","secretField":"hidden","gpsLock":"locked"}',
            "/cells": b'{"activeUes":4,"pci":21}',
            "/alarms": b'{"severity":"major","source":"cell-1","message":"GPS holdover"}',
            "/events": b'{"level":"info","description":"S1 restored"}',
        }
        try:
            self.server.settings = lambda: cfg
            def request(path, method="GET", json_body=None):
                return ({"enabled": True, "configured": True, "reachable": True, "authenticated": True,
                         "content_type": "application/json", "status": 200}, responses[path])
            with patch.object(self.server, "_nokia_api_request", side_effect=request):
                data = self.client.get("/api/nokia/operations").get_json()
            statuses = {item["label"]: item["value"] for item in data["statuses"]}
            self.assertEqual(statuses["Operational state"], "enabled")
            self.assertEqual(statuses["Active UEs"], "4")
            self.assertNotIn("secretField", str(data))
            self.assertEqual(len(data["messages"]), 2)
        finally:
            self.server.settings = original

    def test_nokia_control_is_allowlisted_and_confirmed(self):
        self.assertEqual(self.client.post("/api/nokia/control", json={"action": "shell", "confirm": "SHELL"}).status_code, 400)
        response = self.client.post("/api/nokia/control", json={"action": "cell_lock", "confirm": "yes"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("CELL_LOCK", response.get_json()["error"])

    def test_nokia_control_posts_scoped_gateway_contract(self):
        original = self.server.settings
        cfg = {"nokia_control_enabled": True, "nokia_api_enabled": True, "nokia_api_control_path": "/control",
               "enb_id": 7, "cell_id": 3}
        try:
            self.server.settings = lambda: cfg
            with patch.object(self.server, "_nokia_api_request", return_value=({"authenticated": True, "status": 202}, b'{"accepted":true}')) as gateway:
                response = self.client.post("/api/nokia/control", json={"action": "resynchronize", "confirm": "RESYNCHRONIZE"})
            self.assertEqual(response.status_code, 200)
            gateway.assert_called_once_with("/control", method="POST", json_body={"action": "resynchronize", "enb_id": 7, "cell_id": 3})
        finally:
            self.server.settings = original

    def test_nokia_configuration_validates_band_pair_and_ranges(self):
        values = {"mcc": "001", "mnc": "01", "tac": 1, "enb_id": 7, "cell_id": 3,
                  "pci": 21, "lte_band": 2, "dl_earfcn": 900, "ul_earfcn": 18901,
                  "channel_bandwidth_mhz": 10, "tx_power_dbm": 20}
        _, errors = self.server.validate_nokia_configuration(values)
        self.assertIn("ul_earfcn", errors)
        values["ul_earfcn"] = 18900
        clean, errors = self.server.validate_nokia_configuration(values)
        self.assertFalse(errors)
        self.assertEqual(clean["mnc"], "01")

    def test_nokia_configuration_snapshot_compares_live_values(self):
        original = self.server.settings
        cfg = {"mcc": "001", "mnc": "01", "tac": 1, "enb_id": 7, "cell_id": 3,
               "pci": 21, "lte_band": 2, "dl_earfcn": 900, "ul_earfcn": 18900,
               "channel_bandwidth_mhz": 10, "tx_power_dbm": 20}
        feed = {"sampled_at": 123, "statuses": [
            {"label": "MCC", "value": "001"}, {"label": "MNC", "value": "01"},
            {"label": "Tracking area", "value": "1"}, {"label": "eNodeB ID", "value": "7"},
            {"label": "Cell ID", "value": "3"}, {"label": "PCI", "value": "22"},
            {"label": "LTE band", "value": "Band 2"}, {"label": "DL EARFCN", "value": "900"},
            {"label": "UL EARFCN", "value": "18900"}, {"label": "Bandwidth", "value": "10 MHz"},
            {"label": "Transmit power", "value": "20 dBm"}]}
        try:
            self.server.settings = lambda: cfg
            with patch.object(self.server, "nokia_control_status", return_value={"ready": True}):
                data = self.server.nokia_configuration_snapshot(feed)
            comparison = {item["key"]: item for item in data["comparisons"]}
            self.assertEqual(comparison["pci"]["state"], "mismatch")
            self.assertEqual(comparison["channel_bandwidth_mhz"]["state"], "match")
            self.assertEqual(data["reported_fields"], 11)
        finally:
            self.server.settings = original

    def test_nokia_configuration_can_save_app_and_apply_gateway(self):
        values = {"mcc": "001", "mnc": "01", "tac": 2, "enb_id": 7, "cell_id": 3,
                  "pci": 21, "lte_band": 2, "dl_earfcn": 900, "ul_earfcn": 18900,
                  "channel_bandwidth_mhz": 10, "tx_power_dbm": 20}
        original = self.server.settings
        try:
            rejected = self.client.post("/api/nokia/configuration", json={"action": "save_app", "values": values})
            self.assertEqual(rejected.status_code, 400)
            saved = self.client.post("/api/nokia/configuration", json={"action": "save_app", "values": values,
                                                                        "confirm": "SAVE APP"})
            self.assertEqual(saved.status_code, 200)
            self.assertEqual(self.server.settings()["tac"], 2)
            cfg = {**values, "nokia_control_enabled": True, "nokia_api_enabled": True,
                   "nokia_api_control_path": "/control"}
            self.server.settings = lambda: cfg
            with patch.object(self.server, "_nokia_api_request",
                              return_value=({"authenticated": True, "status": 202}, b'{"accepted":true}')) as gateway:
                applied = self.client.post("/api/nokia/configuration", json={"action": "apply_nokia", "values": values,
                                                                              "confirm": "APPLY NOKIA"})
            self.assertEqual(applied.status_code, 200)
            payload = gateway.call_args.kwargs["json_body"]
            self.assertEqual(payload["action"], "apply_configuration")
            self.assertEqual(payload["values"]["pci"], 21)
            reset = self.client.post("/api/nokia/configuration", json={"action": "reset_app",
                                                                         "confirm": "RESET APP"})
            self.assertEqual(reset.status_code, 200)
            self.assertFalse(self.server.NOKIA_PROFILE_OVERRIDES.exists())
        finally:
            self.server.settings = original
            self.server.NOKIA_PROFILE_OVERRIDES.unlink(missing_ok=True)

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

    def test_complete_sim_profile_generator_uses_configured_plmn(self):
        response = self.client.post("/api/sim/profile/generate", json={"confirm": "GENERATE"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["imsi"].startswith("00101"))
        self.assertEqual(len(data["imsi"]), 15)
        self.assertEqual(len(data["iccid"]), 19)
        self.assertEqual(len(data["k"]), 32)
        self.assertEqual(len(data["op"]), 32)
        self.assertEqual(len(data["opc"]), 32)
        self.assertEqual(data["amf"], "8000")
        self.assertFalse(data["stored"])

    def test_complete_sim_profile_generation_requires_confirmation(self):
        response = self.client.post("/api/sim/profile/generate", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("GENERATE", response.get_json()["error"])

    def test_gialer_atr_profile_is_exact_and_returns_a_copy(self):
        profile = self.server.sim_card_profile(self.server.GIALER_ATR.lower())
        self.assertEqual(profile["type"], "gialersim")
        self.assertEqual(profile["adm_setting"], "sim_adm_key")
        profile["type"] = "changed"
        self.assertEqual(self.server.sim_card_profile(self.server.GIALER_ATR)["type"], "gialersim")
        self.assertIsNone(self.server.sim_card_profile("3B00"))

    def test_sim_friendly_name_validation_and_spn_decode(self):
        self.assertEqual(self.server.sim_service_provider_name({"sim_service_provider_name": "rNET"}), "rNET")
        self.assertEqual(self.server._decode_service_provider_name("00724E4554FFFFFFFF"), "rNET")
        with self.assertRaises(ValueError):
            self.server.sim_service_provider_name({"sim_service_provider_name": "name-is-longer-than-sixteen"})

    def test_sim_card_read_requires_opt_in_and_confirmation(self):
        self.assertEqual(self.client.post("/api/sim/card/read", json={}).status_code, 400)
        response = self.client.post("/api/sim/card/read", json={"confirm": "READ"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("sim_programming_enabled", response.get_json()["error"])

    def test_program_sim_writes_complete_identity_then_provisions_hss(self):
        body = {"confirm": "PROGRAM 001010000000123", "name": "Gate camera",
                "device_type": "Camera", "zone": "Estate Gate", "critical": True, "notes": "Production",
                "imsi": "001010000000123", "iccid": "8900101000000000123", "k": "A" * 32,
                "opc": "B" * 32, "amf": "8000", "apn": "internet", "msisdn": "", "adm": ""}
        cfg = {"sim_programming_enabled": True, "sim_reader_index": 0, "sim_card_type": "",
               "sim_adm_key": "12345678", "sim_adm_format": "decimal", "mcc": "001", "mnc": "01",
               "access_class": 0, "apn": "internet", "epc_type": "local"}
        original = self.server.settings
        try:
            self.server.settings = lambda: cfg
            completed = subprocess.CompletedProcess(["pySim-prog.py"], 0, "done", "")
            with patch.object(self.server.shutil, "which", side_effect=lambda name: "/usr/bin/pySim-prog.py" if "prog" in name else None), \
                 patch.object(self.server, "sim_reader_status", return_value={"selected_reader": "USB", "selected_index": 0,
                                                                                "card_profile": self.server.sim_card_profile(self.server.GIALER_ATR)}), \
                 patch.object(self.server.subprocess, "run", return_value=completed) as run, \
                 patch.object(self.server, "read_sim_card", return_value={"imsi": body["imsi"], "iccid": body["iccid"]}), \
                 patch.object(self.server, "provision_mongo", return_value="Provisioned to EPC"):
                response = self.client.post("/api/sim/card/program", json=body)
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertTrue(data["readback_verified"])
            args = run.call_args.args[0]
            self.assertIn("--ki", args)
            self.assertIn("--opc", args)
            self.assertIn("--mnclen", args)
            self.assertIn("--acc", args)
            self.assertEqual(args[args.index("--name") + 1], "rNET")
            self.assertEqual(args[args.index("--pin-adm") + 1], "12345678")
            self.assertEqual(args[args.index("--type") + 1], "gialersim")
            self.assertNotIn(body["k"], str(data))
        finally:
            with self.server.db() as conn:
                conn.execute("DELETE FROM subscribers WHERE imsi=?", (body["imsi"],))
                conn.execute("DELETE FROM sim_inventory WHERE imsi=?", (body["imsi"],))
            self.server.settings = original

    def test_replacement_sim_uses_saved_authentication_without_returning_it(self):
        imsi, iccid, key, opc = "001010000000124", "8900101000000000124", "C" * 32, "D" * 32
        cfg = {"sim_programming_enabled": True, "sim_reader_index": 0, "sim_card_type": "",
               "sim_adm_key": "", "sim_adm_format": "decimal", "mcc": "001", "mnc": "01",
               "access_class": 0, "apn": "internet", "epc_type": "local"}
        original = self.server.settings
        try:
            with self.server.db() as conn:
                conn.execute("INSERT INTO subscribers(imsi,name,k,opc,amf,apn,msisdn,zone,device_type,critical,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                             (imsi, "Orchard camera", key, opc, "8000", "internet", "", "North Vineyard", "Camera", 1, "", 1))
            self.server.settings = lambda: cfg
            completed = subprocess.CompletedProcess(["pySim-prog.py"], 0, "done", "")
            body = {"subscriber_imsi": imsi, "imsi": imsi, "iccid": iccid, "adm": "12345678",
                    "confirm": f"PROGRAM {imsi}"}
            with patch.object(self.server.shutil, "which", return_value="/usr/bin/pySim-prog.py"), \
                 patch.object(self.server, "sim_reader_status", return_value={"selected_reader": "USB", "selected_index": 0}), \
                 patch.object(self.server.subprocess, "run", return_value=completed) as run, \
                 patch.object(self.server, "read_sim_card", return_value={"imsi": imsi, "iccid": iccid}), \
                 patch.object(self.server, "provision_mongo", return_value="Provisioned to EPC"):
                response = self.client.post("/api/sim/card/program", json=body)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.get_json()["replacement"])
            self.assertIn(key, run.call_args.args[0])
            self.assertNotIn(key, str(response.get_json()))
        finally:
            with self.server.db() as conn:
                conn.execute("DELETE FROM subscribers WHERE imsi=?", (imsi,))
                conn.execute("DELETE FROM sim_inventory WHERE imsi=?", (imsi,))
                conn.execute("DELETE FROM sim_write_profiles WHERE imsi=?", (imsi,))
            self.server.settings = original

    def test_verified_card_can_recover_after_epc_provisioning_failure(self):
        imsi, iccid = "001010000000125", "8900101000000000125"
        body = {"confirm": f"PROGRAM {imsi}", "name": "Irrigation sensor", "device_type": "Environmental sensor",
                "zone": "South Vineyard", "critical": False, "notes": "Production", "imsi": imsi, "iccid": iccid,
                "k": "E" * 32, "opc": "F" * 32, "amf": "8000", "apn": "internet", "msisdn": "", "adm": "12345678"}
        cfg = {"sim_programming_enabled": True, "sim_reader_index": 0, "sim_card_type": "",
               "sim_adm_key": "", "sim_adm_format": "decimal", "mcc": "001", "mnc": "01",
               "access_class": 0, "apn": "internet", "epc_type": "nextepc"}
        original = self.server.settings
        try:
            self.server.settings = lambda: cfg
            completed = subprocess.CompletedProcess(["pySim-prog.py"], 0, "done", "")
            with patch.object(self.server.shutil, "which", return_value="/usr/bin/pySim-prog.py"), \
                 patch.object(self.server, "sim_reader_status", return_value={"selected_reader": "USB", "selected_index": 0}), \
                 patch.object(self.server.subprocess, "run", return_value=completed), \
                 patch.object(self.server, "read_sim_card", return_value={"imsi": imsi, "iccid": iccid}), \
                 patch.object(self.server, "provision_mongo", side_effect=self.server.PyMongoError("offline")):
                failed = self.client.post("/api/sim/card/program", json=body)
            self.assertEqual(failed.status_code, 502)
            self.assertTrue(failed.get_json()["recovery_available"])
            with self.server.db() as conn:
                pending = conn.execute("SELECT stage FROM sim_write_profiles WHERE imsi=?", (imsi,)).fetchone()
            self.assertEqual(pending["stage"], "card_verified")
            with patch.object(self.server, "read_sim_card", return_value={"imsi": imsi, "iccid": iccid}), \
                 patch.object(self.server, "provision_mongo", return_value="Provisioned to EPC"):
                recovered = self.client.post("/api/sim/card/recover", json={"imsi": imsi, "confirm": f"RECOVER {imsi}"})
            self.assertEqual(recovered.status_code, 200)
            with self.server.db() as conn:
                self.assertIsNotNone(conn.execute("SELECT imsi FROM subscribers WHERE imsi=?", (imsi,)).fetchone())
                self.assertIsNone(conn.execute("SELECT imsi FROM sim_write_profiles WHERE imsi=?", (imsi,)).fetchone())
        finally:
            with self.server.db() as conn:
                conn.execute("DELETE FROM subscribers WHERE imsi=?", (imsi,))
                conn.execute("DELETE FROM sim_inventory WHERE imsi=?", (imsi,))
                conn.execute("DELETE FROM sim_write_profiles WHERE imsi=?", (imsi,))
            self.server.settings = original

    def test_traffic_history_calculates_measured_rates(self):
        now = int(self.server.time.time())
        with self.server.db() as conn:
            conn.execute("DELETE FROM traffic_history")
            conn.execute("INSERT INTO traffic_history VALUES(?,?,?,?,?,?,?)", (now - 60, 10, 1000, 8, 800, 5, 500))
            conn.execute("INSERT INTO traffic_history VALUES(?,?,?,?,?,?,?)", (now, 20, 3000, 18, 1800, 15, 2500))
        data = self.client.get("/api/traffic/history?hours=1").get_json()
        self.assertTrue(data["measured"])
        self.assertEqual(data["uploaded_bytes"], 1000)
        self.assertEqual(data["downloaded_bytes"], 2000)
        self.assertEqual(data["points"][-1]["uplink_bps"], 133)
        self.assertEqual(data["points"][-1]["downlink_bps"], 267)

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

    def test_resource_status_is_bounded_and_non_secret(self):
        response = self.client.get("/api/system/resources")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["web_workers"], 1)
        self.assertGreaterEqual(data["monitor_interval_seconds"], 30)
        self.assertIn("memory_mb", data)
        self.assertIn(data["memory_scope"], {"container", "web process"})
        self.assertNotIn("mongodb_uri", data)

    def test_operational_retention_prunes_old_rows(self):
        old = 1
        with self.server.db() as conn:
            conn.execute("INSERT OR REPLACE INTO status_history VALUES(?,?,?,?,?)", (old, 0, 0, 0, 0))
            conn.execute("INSERT INTO events(kind,message,created_at) VALUES(?,?,?)", ("test", "expired", old))
        self.server._LAST_MAINTENANCE = 0
        self.server.prune_operational_data(force=True)
        with self.server.db() as conn:
            self.assertIsNone(conn.execute("SELECT sampled_at FROM status_history WHERE sampled_at=?", (old,)).fetchone())
            self.assertIsNone(conn.execute("SELECT id FROM events WHERE created_at=?", (old,)).fetchone())


if __name__ == "__main__":
    unittest.main()
