import csv
import hashlib
import io
import json
import ipaddress
import os
import re
import secrets
import shutil
import socket
import ssl
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from pymongo import MongoClient
from pymongo.errors import PyMongoError

app = Flask(__name__)
DATA_DIR = Path(os.getenv("DATA_DIR", "/data" if Path("/data").exists() else "./data"))
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "/config" if Path("/config").exists() else "./config"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "lte-manager.db"
APP_LOG = DATA_DIR / "lte-manager.log"
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
IMSI_RE = re.compile(r"^[0-9]{5,15}$")
SECRET_SETTING_KEYS = {"mongodb_uri", "communications_gateway_url", "communications_gateway_token"}


def settings():
    defaults = {
        "epc_host": "192.0.2.151", "bts_host": "192.0.2.100",
        "epc_type": "nextepc", "mongodb_uri": "mongodb://192.0.2.151:27017/nextepc",
        "apn": "internet", "mcc": "001", "mnc": "01", "tac": 1,
        "ue_subnet": "10.45.0.0/16", "epc_uplink_interface": "eth0",
        "epc_routing_management_enabled": False, "epc_ssh_user": "root", "epc_ssh_port": 22,
        "sim_programming_enabled": False, "communications_enabled": False,
        "communications_gateway_url": "", "communications_gateway_token": "",
        "sip_gateway_host": "", "sip_gateway_port": 5060, "sip_transport": "tcp",
    }
    path = Path(os.getenv("OPTIONS_PATH", "/data/options.json"))
    if path.exists():
        try:
            defaults.update(json.loads(path.read_text()))
        except (OSError, json.JSONDecodeError):
            pass
    return defaults


def public_settings():
    return {key: value for key, value in settings().items() if key not in SECRET_SETTING_KEYS}


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS subscribers (
        imsi TEXT PRIMARY KEY, name TEXT NOT NULL, k TEXT NOT NULL, opc TEXT NOT NULL,
        amf TEXT NOT NULL, apn TEXT NOT NULL, msisdn TEXT DEFAULT '', created_at INTEGER NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, message TEXT, created_at INTEGER
    )""")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(subscribers)")}
    if "zone" not in columns:
        conn.execute("ALTER TABLE subscribers ADD COLUMN zone TEXT NOT NULL DEFAULT 'Unassigned'")
    if "device_type" not in columns:
        conn.execute("ALTER TABLE subscribers ADD COLUMN device_type TEXT NOT NULL DEFAULT 'Other IoT'")
    if "critical" not in columns:
        conn.execute("ALTER TABLE subscribers ADD COLUMN critical INTEGER NOT NULL DEFAULT 0")
    if "notes" not in columns:
        conn.execute("ALTER TABLE subscribers ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
    conn.execute("""CREATE TABLE IF NOT EXISTS status_history (
        sampled_at INTEGER PRIMARY KEY, epc_online INTEGER NOT NULL, bts_online INTEGER NOT NULL,
        s1_online INTEGER NOT NULL, db_online INTEGER NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY, value TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS alert_state (
        target TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 0, last_notified INTEGER NOT NULL DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS pending_registrations (
        imsi TEXT PRIMARY KEY, apn TEXT NOT NULL DEFAULT '', cause TEXT NOT NULL,
        source TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 1
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sim_inventory (
        imsi TEXT PRIMARY KEY, iccid TEXT NOT NULL DEFAULT '', device_name TEXT NOT NULL,
        device_type TEXT NOT NULL, zone TEXT NOT NULL, stage TEXT NOT NULL,
        attach_confirmed INTEGER NOT NULL DEFAULT 0, data_verified INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL
    )""")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def event(kind, message):
    with db() as conn:
        conn.execute("INSERT INTO events(kind,message,created_at) VALUES(?,?,?)", (kind, message, int(time.time())))
    with APP_LOG.open("a", encoding="utf-8") as handle:
        handle.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} [{kind.upper()}] {message}\n")


def update_sim_inventory(sub, stage, iccid="", attach_confirmed=False, data_verified=False):
    safe_iccid = str(iccid).strip()
    if safe_iccid and (not safe_iccid.isdigit() or not 18 <= len(safe_iccid) <= 22):
        raise ValueError("ICCID must contain 18–22 digits when provided")
    now = int(time.time())
    with db() as conn:
        current = conn.execute("SELECT stage FROM sim_inventory WHERE imsi=?", (sub["imsi"],)).fetchone()
        order = {"profile_ready": 1, "hss_provisioned": 2, "attach_observed": 3, "production_ready": 4}
        if current and order.get(current["stage"], 0) > order.get(stage, 0):
            stage = current["stage"]
        conn.execute("""INSERT INTO sim_inventory
            (imsi,iccid,device_name,device_type,zone,stage,attach_confirmed,data_verified,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(imsi) DO UPDATE SET
                iccid=CASE WHEN excluded.iccid!='' THEN excluded.iccid ELSE sim_inventory.iccid END,
                device_name=excluded.device_name,device_type=excluded.device_type,zone=excluded.zone,
                stage=excluded.stage,
                attach_confirmed=MAX(sim_inventory.attach_confirmed,excluded.attach_confirmed),
                data_verified=MAX(sim_inventory.data_verified,excluded.data_verified),updated_at=excluded.updated_at""",
                     (sub["imsi"], safe_iccid, sub["name"], sub["device_type"], sub["zone"], stage,
                      int(attach_confirmed), int(data_verified), now))


def tcp_check(host, port, timeout=0.8):
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"online": True, "latency_ms": round((time.monotonic() - started) * 1000)}
    except OSError:
        return {"online": False, "latency_ms": None}


def sctp_check(host, port=36412, timeout=0.8):
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, getattr(socket, "IPPROTO_SCTP", 132)) as probe:
            probe.settimeout(timeout)
            probe.connect((host, port))
        return {"online": True, "latency_ms": round((time.monotonic() - started) * 1000)}
    except OSError:
        return {"online": False, "latency_ms": None}


def ping_check(host):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", host], capture_output=True, timeout=2, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def dns_check():
    started = time.monotonic()
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)})
        return {"online": bool(addresses), "latency_ms": round((time.monotonic() - started) * 1000),
                "addresses": addresses[:3]}
    except OSError:
        return {"online": False, "latency_ms": None, "addresses": []}


def app_setting_json(key):
    with db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["value"])
    except (json.JSONDecodeError, TypeError):
        return None


def known_port_checks():
    cfg = settings()
    targets = [
        {"id": "epc_ssh", "name": "EPC SSH", "host": cfg["epc_host"], "port": int(cfg.get("epc_ssh_port", 22))},
        {"id": "mongo", "name": "Subscriber database", "host": cfg["epc_host"], "port": 27017},
        {"id": "bts_https", "name": "Nokia HTTPS", "host": cfg["bts_host"], "port": 443},
        {"id": "bts_http", "name": "Nokia HTTP", "host": cfg["bts_host"], "port": 80},
    ]
    for target in targets:
        target.update(tcp_check(target["host"], target["port"]))
    s1 = sctp_check(cfg["epc_host"])
    targets.insert(1, {"id": "s1", "name": "S1AP / SCTP", "host": cfg["epc_host"], "port": 36412, **s1})
    return targets


def tls_status(host, port=443):
    started = time.monotonic()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=2.0) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                certificate = connection.getpeercert(binary_form=True) or b""
                cipher = connection.cipher()
                return {"online": True, "latency_ms": round((time.monotonic() - started) * 1000),
                        "protocol": connection.version(), "cipher": cipher[0] if cipher else None,
                        "certificate_sha256": hashlib.sha256(certificate).hexdigest().upper() if certificate else None}
    except (OSError, ssl.SSLError):
        return {"online": False, "latency_ms": None, "protocol": None, "cipher": None,
                "certificate_sha256": None}


def commissioning_context():
    files = sorted(CONFIG_DIR.glob("commissioning-*"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not files:
        return {"available": False, "fields": {}}
    path = files[0]
    wanted = {"activeSWReleaseVersion": "Software release", "gnssControlMode": "GNSS mode",
              "oamTls": "OAM TLS", "omsTls": "OMS TLS",
              "primBackhaulPort": "Primary backhaul", "lmtPort": "Local management port",
              "reportingIntervalPm": "PM reporting", "serviceAccountSshStatus": "Service SSH",
              "s1LinkStatus": "S1 link in backup", "idleSessionTimeWebUI": "Web UI idle timeout",
              "icmpResponseEnabled": "ICMP response", "actRemoteSyslogTransmission": "Remote syslog",
              "actTemperatureReport": "Temperature reporting"}
    fields = {}
    try:
        for element in ET.parse(path).iter():
            name = element.attrib.get("name")
            if name in wanted and name not in fields and element.text:
                fields[name] = {"label": wanted[name], "value": element.text.strip()[:120]}
    except (OSError, ET.ParseError):
        return {"available": True, "file": path.name.removeprefix("commissioning-"),
                "valid": False, "fields": {}}
    values = {name: field["value"].lower() for name, field in fields.items()}
    tls_required = values.get("oamTls") == "forced"
    ssh_enabled = values.get("serviceAccountSshStatus") not in {None, "disabled", "false"}
    return {"available": True, "file": path.name.removeprefix("commissioning-"),
            "valid": True, "fields": fields,
            "access": {"method": "HTTPS OAM / Nokia BTS Site Manager" if tls_required else "Nokia BTS Site Manager",
                       "tls_required": tls_required, "ssh_enabled": ssh_enabled,
                       "snmp_configured": False,
                       "detail": "The commissioning backup requires OAM TLS and disables service-account SSH. No SNMP management configuration was found."}}


def nokia_status():
    cfg = settings()
    host = str(cfg["bts_host"])
    ping = ping_check(host)
    https = tls_status(host)
    http = tcp_check(host, 80, timeout=1.2)
    ssh = tcp_check(host, 22, timeout=1.2)
    s1 = sctp_check(str(cfg["epc_host"]))
    reachable = bool(ping or https["online"] or http["online"])
    return {"sampled_at": int(time.time()), "host": host, "reachable": reachable,
            "software_expected": "FLF21", "ping": {"online": bool(ping)},
            "management": {"https": https, "http": http, "ssh": ssh},
            "s1_target": {"host": str(cfg["epc_host"]), "port": 36412, **s1},
            "commissioning": commissioning_context(),
            "licensed_status": {"available": False,
                "detail": "GPS lock, RF transmission, temperature, and active alarms require Nokia BTS Site Manager, a licensed status export, or documented Nokia management OIDs/API."}}


def route_to_host(host):
    try:
        result = subprocess.run(["ip", "route", "get", host], capture_output=True, text=True,
                                timeout=4, check=False)
        detail = (result.stdout or result.stderr).strip()[:1000]
        return {"ok": result.returncode == 0, "detail": detail or "No route information returned"}
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "detail": "The container route utility is unavailable"}


def communications_status():
    cfg = settings()
    enabled = bool(cfg.get("communications_enabled"))
    gateway_url = str(cfg.get("communications_gateway_url", "")).strip()
    sip_host = str(cfg.get("sip_gateway_host", "")).strip()
    sip_port = int(cfg.get("sip_gateway_port", 5060))
    transport = str(cfg.get("sip_transport", "tcp")).lower()
    valid_url = bool(re.fullmatch(r"https?://[^\s]{3,500}", gateway_url))
    sip = tcp_check(sip_host, sip_port, timeout=1.2) if sip_host and transport in ("tcp", "tls") else {
        "online": False, "latency_ms": None}
    ready = enabled and valid_url
    return {"enabled": enabled, "ready": ready, "gateway_configured": valid_url,
            "token_configured": bool(str(cfg.get("communications_gateway_token", "")).strip()),
            "sip": {"host": sip_host, "port": sip_port, "transport": transport,
                    "online": sip["online"], "latency_ms": sip.get("latency_ms")},
            "native_volte": False,
            "native_volte_note": "Native handset calls and SMS require a separate IMS/VoLTE core. This gateway is for PBX-backed outbound voice announcements and text dispatch."}


def dispatch_communication(kind, destination, message):
    cfg = settings()
    status = communications_status()
    if not status["ready"]:
        raise ValueError("Enable communications and configure the PBX gateway URL in Home Assistant first")
    if kind not in ("text", "voice"):
        raise ValueError("Choose text or voice announcement")
    if not re.fullmatch(r"[+0-9A-Za-z@._:-]{3,80}", destination):
        raise ValueError("Use a phone number or SIP address containing only safe dialing characters")
    message = message.strip()
    if not 1 <= len(message) <= 500:
        raise ValueError("Message must contain 1–500 characters")
    payload = json.dumps({"kind": kind, "to": destination, "message": message,
                          "source": "baiamonte-lte"}).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Baiamonte-LTE/1"}
    token = str(cfg.get("communications_gateway_token", "")).strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(str(cfg["communications_gateway_url"]), data=payload,
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            response_text = response.read(4096).decode("utf-8", errors="replace").strip()
            if not 200 <= response.status < 300:
                raise ValueError(f"Communications gateway returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise ValueError(f"Communications gateway returned HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise ValueError("Communications gateway could not be reached") from exc
    event("communications", f"Outbound {kind} dispatch accepted by the configured PBX gateway")
    return {"ok": True, "kind": kind, "accepted": True, "gateway_response": response_text[:500]}


ALERT_DEFAULTS = {"epc_enabled": True, "radio_enabled": True, "failure_threshold": 3, "cooldown_minutes": 60}


def alert_settings():
    result = dict(ALERT_DEFAULTS)
    with db() as conn:
        rows = conn.execute("SELECT key,value FROM app_settings WHERE key LIKE 'alert_%'").fetchall()
    for row in rows:
        key = row["key"][6:]
        if key in ("epc_enabled", "radio_enabled"):
            result[key] = row["value"] == "true"
        elif key in ("failure_threshold", "cooldown_minutes"):
            result[key] = int(row["value"])
    return result


def save_alert_settings(values):
    clean = {
        "epc_enabled": bool(values.get("epc_enabled")),
        "radio_enabled": bool(values.get("radio_enabled")),
        "failure_threshold": min(max(int(values.get("failure_threshold", 3)), 1), 10),
        "cooldown_minutes": min(max(int(values.get("cooldown_minutes", 60)), 5), 1440),
    }
    with db() as conn:
        for key, value in clean.items():
            stored = str(value).lower() if isinstance(value, bool) else str(value)
            conn.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES(?,?)", (f"alert_{key}", stored))
    return clean


def home_assistant_notification(target, online):
    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        return False
    label = "EPC" if target == "epc" else "estate radio"
    title = f"Baiamonte LTE — {label} {'restored' if online else 'offline'}"
    message = (f"The {label} is reachable again and vineyard LTE service has recovered."
               if online else f"The {label} has failed repeated health checks. Open LTE → Network care for guided checks.")
    payload = json.dumps({"title": title, "message": message,
                          "notification_id": f"baiamonte_lte_{target}"}).encode()
    req = urllib.request.Request("http://supervisor/core/api/services/persistent_notification/create",
        data=payload, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return 200 <= response.status < 300
    except (OSError, urllib.error.URLError):
        return False


def process_alert_state(status):
    prefs, now = alert_settings(), int(time.time())
    for target, online in (("epc", status["epc"]["online"]), ("radio", status["bts"]["online"])):
        enabled = prefs[f"{'radio' if target == 'radio' else 'epc'}_enabled"]
        with db() as conn:
            row = conn.execute("SELECT failures,active,last_notified FROM alert_state WHERE target=?", (target,)).fetchone()
        failures, active, last_notified = (row["failures"], bool(row["active"]), row["last_notified"]) if row else (0, False, 0)
        message = None
        if online:
            if active:
                delivered = home_assistant_notification(target, True)
                message = f"{target.upper()} connectivity restored" + ("" if delivered else " (Home Assistant notification unavailable)")
            failures, active = 0, False
        elif enabled:
            failures += 1
            due = failures >= prefs["failure_threshold"] and (not active or now - last_notified >= prefs["cooldown_minutes"] * 60)
            if due:
                delivered = home_assistant_notification(target, False)
                message = f"{target.upper()} offline alert triggered" + ("" if delivered else " (Home Assistant notification unavailable)")
                active, last_notified = True, now
        else:
            failures, active = 0, False
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO alert_state(target,failures,active,last_notified) VALUES(?,?,?,?)",
                         (target, failures, int(active), last_notified))
        if message:
            event("alert", message)


def sample_network(process_alerts=False):
    cfg = settings()
    status = {"epc": {"host": cfg["epc_host"], "online": ping_check(cfg["epc_host"]),
                      "s1": sctp_check(cfg["epc_host"]), "database": tcp_check(cfg["epc_host"], 27017)},
              "bts": {"host": cfg["bts_host"], "online": ping_check(cfg["bts_host"]), "software": "FLF21"}}
    sampled_at = int(time.time())
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO status_history(sampled_at,epc_online,bts_online,s1_online,db_online) VALUES(?,?,?,?,?)",
            (sampled_at, int(status["epc"]["online"]), int(status["bts"]["online"]),
             int(status["epc"]["s1"]["online"]), int(status["epc"]["database"]["online"])))
        conn.execute("DELETE FROM status_history WHERE sampled_at < ?", (sampled_at - 30 * 86400,))
    if process_alerts:
        process_alert_state(status)
    return status


def connection_incidents(hours=168, limit=40):
    since = int(time.time()) - min(max(int(hours), 1), 720) * 3600
    with db() as conn:
        rows = [dict(row) for row in conn.execute(
            "SELECT sampled_at,epc_online,bts_online,s1_online,db_online FROM status_history "
            "WHERE sampled_at>=? ORDER BY sampled_at", (since,))]
    labels = {"epc_online": "EPC core", "bts_online": "Nokia radio",
              "s1_online": "S1 control link", "db_online": "Subscriber database"}
    incidents, open_events = [], {}
    previous = rows[0] if rows else None
    if previous:
        for key, label in labels.items():
            if not previous[key]:
                open_events[key] = previous["sampled_at"]
                incidents.append({"target": key.removesuffix("_online"), "label": label,
                                  "state": "offline", "started_at": previous["sampled_at"], "ended_at": None})
    for row in rows[1:]:
        for key, label in labels.items():
            if previous[key] and not row[key]:
                open_events[key] = row["sampled_at"]
                incidents.append({"target": key.removesuffix("_online"), "label": label,
                                  "state": "offline", "started_at": row["sampled_at"], "ended_at": None})
            elif not previous[key] and row[key]:
                started = open_events.pop(key, previous["sampled_at"])
                outage = next((item for item in reversed(incidents)
                               if item["target"] == key.removesuffix("_online") and
                               item["state"] == "offline" and item["ended_at"] is None), None)
                if outage:
                    outage["ended_at"] = row["sampled_at"]
                    outage["duration_seconds"] = max(0, row["sampled_at"] - started)
                incidents.append({"target": key.removesuffix("_online"), "label": label,
                                  "state": "restored", "started_at": started, "ended_at": row["sampled_at"],
                                  "duration_seconds": max(0, row["sampled_at"] - started)})
        previous = row
    if rows:
        for key, started in open_events.items():
            target = key.removesuffix("_online")
            current = next((item for item in reversed(incidents)
                            if item["target"] == target and item["state"] == "offline" and item["ended_at"] is None), None)
            if current:
                current["duration_seconds"] = max(0, int(time.time()) - started)
    return list(reversed(incidents[-limit:]))


def network_visibility(status=None):
    cfg = settings()
    status = status or sample_network()
    dns = dns_check()
    internet = tcp_check("1.1.1.1", 443, timeout=1.5)
    bts_https = tcp_check(cfg["bts_host"], 443)
    bts_http = tcp_check(cfg["bts_host"], 80)
    ssh = tcp_check(cfg["epc_host"], int(cfg.get("epc_ssh_port", 22)))
    route_status = app_setting_json("routing_last_status")
    route_verified = app_setting_json("routing_last_verified")
    communications = communications_status()
    with db() as conn:
        latest = conn.execute("SELECT MAX(sampled_at) AS sampled_at FROM status_history").fetchone()["sampled_at"]
        alert_rows = conn.execute("SELECT target,failures,active,last_notified FROM alert_state").fetchall()
        counts = conn.execute("SELECT COUNT(*) total, SUM(critical) critical, "
                              "SUM(CASE WHEN zone='Unassigned' THEN 1 ELSE 0 END) unassigned FROM subscribers").fetchone()
    def light(light_id, label, state, detail, latency=None):
        return {"id": light_id, "label": label, "state": state, "detail": detail, "latency_ms": latency}
    routing_state = "online" if route_status and route_status.get("ready") else "offline" if route_status else "unknown"
    routing_detail = ("Forwarding, NAT, and persistence ready" if routing_state == "online" else
                      "Last routing check found missing rules" if routing_state == "offline" else "Run Check current routing")
    ue_state = ("online" if route_verified and route_verified.get("verified") else
                "offline" if route_verified and route_verified.get("verified") is False else "unknown")
    ue_detail = ("Subscriber traffic and return packets verified" if ue_state == "online" else
                 "Last subscriber traffic test failed" if ue_state == "offline" else "Run a live UE traffic test")
    lights = [
        light("epc", "EPC core", "online" if status["epc"]["online"] else "offline",
              f"{cfg['epc_host']} responds" if status["epc"]["online"] else f"No reply from {cfg['epc_host']}"),
        light("s1", "S1 control", "online" if status["epc"]["s1"]["online"] else "offline",
              "SCTP 36412 accepting connections" if status["epc"]["s1"]["online"] else "SCTP 36412 closed or filtered",
              status["epc"]["s1"].get("latency_ms")),
        light("database", "Subscriber DB", "online" if status["epc"]["database"]["online"] else "offline",
              "MongoDB reachable" if status["epc"]["database"]["online"] else "MongoDB port 27017 unavailable",
              status["epc"]["database"].get("latency_ms")),
        light("radio", "Nokia radio", "online" if status["bts"]["online"] else "offline",
              f"{cfg['bts_host']} responds" if status["bts"]["online"] else f"No reply from {cfg['bts_host']}"),
        light("bts_admin", "Radio admin", "online" if bts_https["online"] or bts_http["online"] else "offline",
              "Nokia web management port reachable" if bts_https["online"] or bts_http["online"] else "HTTP/HTTPS management ports unavailable"),
        light("ssh", "EPC SSH", "online" if ssh["online"] else "offline",
              f"Port {cfg.get('epc_ssh_port', 22)} reachable" if ssh["online"] else f"Port {cfg.get('epc_ssh_port', 22)} unavailable",
              ssh.get("latency_ms")),
        light("dns", "Estate DNS", "online" if dns["online"] else "offline",
              "Public names resolve" if dns["online"] else "DNS lookup failed", dns.get("latency_ms")),
        light("uplink", "Site Internet", "online" if internet["online"] else "offline",
              "Public HTTPS reachable from app" if internet["online"] else "No public HTTPS route from app", internet.get("latency_ms")),
        light("routing", "EPC routing", routing_state, routing_detail),
        light("ue_data", "UE data path", ue_state, ue_detail),
        light("communications", "Voice & text", "unknown" if not communications["enabled"] else
              "online" if communications["ready"] and (not communications["sip"]["host"] or communications["sip"]["online"])
              else "offline",
              "Optional gateway disabled" if not communications["enabled"] else
              "PBX dispatch gateway ready" if communications["ready"] and (not communications["sip"]["host"] or communications["sip"]["online"])
              else "PBX gateway configuration or SIP reachability needs attention"),
    ]
    scored = [item for item in lights if item["state"] in ("online", "offline")]
    score = round(100 * sum(item["state"] == "online" for item in scored) / len(scored)) if scored else None
    actions = []
    for item in lights:
        if item["state"] == "offline":
            actions.append({"target": item["id"], "title": item["label"], "detail": item["detail"]})
    if counts["unassigned"]:
        actions.append({"target": "inventory", "title": "Unassigned devices",
                        "detail": f"{counts['unassigned']} device(s) need a vineyard zone"})
    alerts = {row["target"]: {"failures": row["failures"], "active": bool(row["active"]),
                              "last_notified": row["last_notified"]} for row in alert_rows}
    return {"sampled_at": int(time.time()), "monitor_sampled_at": latest, "health_score": score,
            "lights": lights, "actions": actions[:8], "routing": route_status, "ue_verification": route_verified,
            "alerts": alerts, "incidents": connection_incidents(168, 12),
            "communications": communications,
            "inventory": {"total": counts["total"] or 0, "critical": counts["critical"] or 0,
                          "unassigned": counts["unassigned"] or 0},
            "home_assistant_ready": bool(os.getenv("SUPERVISOR_TOKEN"))}


def subscriber_gauges(status, route_status, subscriber_rows):
    connection_signals = [status["epc"]["online"], status["bts"]["online"],
                          status["epc"]["s1"]["online"], status["epc"]["database"]["online"]]
    connection_value = round(100 * sum(bool(value) for value in connection_signals) / len(connection_signals))
    connection_ready = sum(bool(value) for value in connection_signals)

    routing_checks = route_status.get("checks", {}) if isinstance(route_status, dict) else {}
    routing_value = (round(100 * sum(bool(value) for value in routing_checks.values()) / len(routing_checks))
                     if routing_checks else None)
    counters = route_status.get("counters", {}) if isinstance(route_status, dict) else {}
    outbound = max(0, int(counters.get("outbound", 0) or 0))
    returned = max(0, int(counters.get("return", 0) or 0))
    nat = max(0, int(counters.get("nat", 0) or 0))
    traffic_value = None if not route_status else 100 if outbound and returned else 50 if outbound else 0
    traffic_display = "2-way" if traffic_value == 100 else "Out only" if traffic_value == 50 else "None" if traffic_value == 0 else "—"

    subscriber_count = len(subscriber_rows)
    profiled = sum(row["zone"] != "Unassigned" and row["device_type"] != "Other IoT"
                   for row in subscriber_rows)
    profile_value = round(100 * profiled / subscriber_count) if subscriber_count else None

    def gauge(gauge_id, label, value, display, detail, source, updated_at=None):
        return {"id": gauge_id, "label": label, "value": value, "display": display,
                "detail": detail, "source": source, "updated_at": updated_at}

    route_checked_at = route_status.get("checked_at") if isinstance(route_status, dict) else None
    return {
        "sampled_at": int(time.time()),
        "items": [
            gauge("connections", "Connection fabric", connection_value, f"{connection_value}%",
                  f"{connection_ready} of {len(connection_signals)} EPC, radio, S1, and registry signals ready",
                  "Live network probes", int(time.time())),
            gauge("routing", "Routing readiness", routing_value,
                  f"{routing_value}%" if routing_value is not None else "—",
                  f"{sum(bool(value) for value in routing_checks.values())} of {len(routing_checks)} forwarding checks ready"
                  if routing_checks else "Run Check current routing to measure the EPC",
                  "Last EPC routing check", route_checked_at),
            gauge("traffic", "Traffic evidence", traffic_value, traffic_display,
                  f"{outbound:,} outbound · {returned:,} return · {nat:,} NAT packets"
                  if route_status else "No EPC packet-counter snapshot yet",
                  "Cumulative EPC firewall counters", route_checked_at),
            gauge("profiles", "Subscriber setup", profile_value,
                  f"{profile_value}%" if profile_value is not None else "—",
                  f"{profiled} of {subscriber_count} devices have a role and vineyard zone"
                  if subscriber_count else "Add the first subscriber profile",
                  "Baiamonte device registry", int(time.time())),
        ],
    }


def diagnostic_checks():
    cfg = settings()
    checks = []
    def add(name, ok, detail, suggestion=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "suggestion": suggestion})
    epc_ping, bts_ping = ping_check(cfg["epc_host"]), ping_check(cfg["bts_host"])
    add("EPC reachability", epc_ping, f"{cfg['epc_host']} responds to ICMP" if epc_ping else f"No ping reply from {cfg['epc_host']}", "Check the Home Assistant route to the LTE LAN and the EPC firewall.")
    add("eNodeB management", bts_ping, f"{cfg['bts_host']} responds to ICMP" if bts_ping else f"No ping reply from {cfg['bts_host']}", "Confirm power, Ethernet, management VLAN, and the eNodeB address.")
    s1 = sctp_check(cfg["epc_host"])
    add("MME S1AP port", s1["online"], "SCTP 36412 accepted a connection" if s1["online"] else "SCTP 36412 did not accept a connection", "Verify the MME is running, SCTP is available, and port 36412 is allowed.")
    mongo = tcp_check(cfg["epc_host"], 27017)
    add("Subscriber database", mongo["online"], "MongoDB port 27017 is reachable" if mongo["online"] else "MongoDB port 27017 is unavailable", "Check MongoDB bindIp/firewall, or select Local mode for UI testing.")
    plmn_ok = bool(re.fullmatch(r"\d{3}", str(cfg["mcc"]))) and bool(re.fullmatch(r"\d{2,3}", str(cfg["mnc"])))
    add("PLMN format", plmn_ok, f"MCC {cfg['mcc']} / MNC {cfg['mnc']}", "Use a 3-digit MCC and 2- or 3-digit MNC matching the SIM and eNodeB.")
    add("Tracking area", 0 < int(cfg["tac"]) <= 65535, f"TAC {cfg['tac']}", "Use the same TAC in the EPC and Nokia commissioning profile.")
    try:
        ipaddress.ip_network(cfg["ue_subnet"], strict=False)
        subnet_ok = True
    except ValueError:
        subnet_ok = False
    add("UE Internet subnet", subnet_ok, f"Data network {cfg['ue_subnet']} via {cfg['epc_uplink_interface']}",
        "Set the UE subnet to the address pool configured on the NextEPC PGW.")
    internet = tcp_check("1.1.1.1", 443, timeout=1.5)
    add("Management Internet uplink", internet["online"], "A public HTTPS endpoint is reachable from the app" if internet["online"] else "No public route is visible from Home Assistant",
        "Restore the site Internet uplink before testing subscriber data. This check does not replace a test from an attached UE.")
    return checks


@app.get("/api/internet-plan")
def internet_plan():
    cfg = settings()
    subnet = str(cfg.get("ue_subnet", "10.45.0.0/16"))
    interface = str(cfg.get("epc_uplink_interface", "eth0"))
    try:
        subnet = str(ipaddress.ip_network(subnet, strict=False))
    except ValueError:
        return jsonify({"error": "Invalid UE subnet in app configuration"}), 400
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,20}", interface):
        return jsonify({"error": "Invalid EPC uplink interface in app configuration"}), 400
    return jsonify({"subnet": subnet, "interface": interface, "apn": cfg["apn"], "steps": [
        "Confirm the APN address pool matches the UE subnet.",
        "Enable IPv4 forwarding on the EPC host.",
        f"Masquerade traffic from {subnet} out {interface} and allow established return traffic.",
        "Persist the forwarding and firewall rules using the EPC operating system's supported method.",
        "Attach a subscriber and open a public HTTPS site from that UE for the final end-to-end test."
    ], "note": "Routing changes are applied only when EPC routing management is enabled and you explicitly confirm the guarded SSH operation."})


EPC_SSH_KEY = CONFIG_DIR / "epc-routing-key"
EPC_KNOWN_HOSTS = CONFIG_DIR / "epc-known-hosts"


def routing_config():
    cfg = settings()
    try:
        subnet = str(ipaddress.ip_network(str(cfg.get("ue_subnet", "")), strict=False))
    except ValueError as exc:
        raise ValueError("The configured UE subnet is invalid") from exc
    interface = str(cfg.get("epc_uplink_interface", "")).strip()
    user = str(cfg.get("epc_ssh_user", "")).strip()
    host = str(cfg.get("epc_host", "")).strip()
    port = int(cfg.get("epc_ssh_port", 22))
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", host):
        raise ValueError("The EPC host is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", user):
        raise ValueError("The EPC SSH user is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,20}", interface):
        raise ValueError("The EPC uplink interface is invalid")
    if not 1 <= port <= 65535:
        raise ValueError("The EPC SSH port is invalid")
    return {"enabled": bool(cfg.get("epc_routing_management_enabled")), "host": host, "port": port,
            "user": user, "subnet": subnet, "interface": interface, "apn": str(cfg.get("apn", "internet"))}


def require_routing_enabled():
    cfg = routing_config()
    if not cfg["enabled"]:
        raise ValueError("Enable EPC routing management in the Home Assistant app configuration first")
    return cfg


def probe_epc_ssh():
    cfg = require_routing_enabled()
    started = time.monotonic()
    try:
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=4) as connection:
            connection.settimeout(2)
            try:
                banner = connection.recv(255).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = ""
        latency = round((time.monotonic() - started) * 1000)
        if banner.startswith("SSH-"):
            return {"reachable": True, "ssh": True, "state": "ssh_ready", "latency_ms": latency,
                    "detail": f"SSH answered on {cfg['host']}:{cfg['port']} in {latency} ms",
                    "banner": banner[:120]}
        return {"reachable": True, "ssh": False, "state": "non_ssh", "latency_ms": latency,
                "detail": f"Port {cfg['port']} is open, but it did not return an SSH banner",
                "banner": banner[:120]}
    except ConnectionRefusedError:
        return {"reachable": False, "ssh": False, "state": "refused", "latency_ms": None,
                "detail": f"Connection refused at {cfg['host']}:{cfg['port']}; no SSH service is listening there"}
    except socket.timeout:
        return {"reachable": False, "ssh": False, "state": "timeout", "latency_ms": None,
                "detail": f"Connection to {cfg['host']}:{cfg['port']} timed out; check VLAN and firewall access"}
    except OSError as exc:
        detail = str(exc).strip() or "network error"
        return {"reachable": False, "ssh": False, "state": "network_error", "latency_ms": None,
                "detail": f"Cannot reach {cfg['host']}:{cfg['port']}: {detail[:200]}"}


def scan_epc_host():
    cfg = require_routing_enabled()
    probe = probe_epc_ssh()
    if not probe["reachable"]:
        raise ValueError(probe["detail"])
    result = subprocess.run(["ssh-keyscan", "-T", "5", "-p", str(cfg["port"]), cfg["host"]],
                            capture_output=True, text=True, timeout=8, check=False)
    key_lines = [line.strip() for line in result.stdout.splitlines() if line and not line.startswith("#")]
    fingerprints = []
    for line in key_lines:
        fingerprint = subprocess.run(["ssh-keygen", "-lf", "-", "-E", "sha256"], input=line + "\n",
                                     capture_output=True, text=True, timeout=3, check=False)
        if fingerprint.returncode == 0:
            parts = fingerprint.stdout.strip().split()
            if len(parts) >= 4:
                fingerprints.append({"fingerprint": parts[1], "type": parts[-1].strip("()"), "key_line": line})
    if not fingerprints:
        if not probe["ssh"]:
            raise ValueError(f"{probe['detail']}. Confirm that this is the EPC SSH port")
        raise ValueError("SSH answered, but no compatible host key was returned; check the EPC SSH host-key configuration")
    return cfg, fingerprints


def ssh_command(cfg):
    if not EPC_SSH_KEY.exists():
        raise ValueError("Upload an EPC SSH private key first")
    if not EPC_KNOWN_HOSTS.exists():
        raise ValueError("Verify and trust the EPC host fingerprint first")
    return ["ssh", "-i", str(EPC_SSH_KEY), "-p", str(cfg["port"]), "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o",
            f"UserKnownHostsFile={EPC_KNOWN_HOSTS}", "-o", "ConnectTimeout=6",
            f"{cfg['user']}@{cfg['host']}",
            "if [ \"$(id -u)\" -eq 0 ]; then exec sh -s; else exec sudo -n sh -s; fi"]


def run_epc_script(script, timeout=25):
    cfg = require_routing_enabled()
    result = subprocess.run(ssh_command(cfg), input=script, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "Remote command failed").strip().splitlines()[-1][:600]
        raise ValueError(f"EPC SSH operation failed: {message}")
    return cfg, result.stdout.strip()


EPC_CONSOLE_ACTIONS = {
    "system": {
        "label": "System overview",
        "script": """set -eu
echo 'HOST'; hostname
echo; echo 'SYSTEM'; uname -srmo
echo; echo 'UPTIME'; uptime
echo; echo 'MEMORY'; free -h
echo; echo 'ROOT DISK'; df -h /
echo; echo 'FAILED SERVICES'; systemctl --failed --no-pager 2>/dev/null || true
""",
    },
    "core": {
        "label": "LTE core services",
        "script": """set -eu
echo 'LTE CORE PROCESSES'
ps -eo pid,etimes,comm,args --sort=comm | grep -E '[n]extepc|[o]pen5gs|[m]ongod' || echo 'No NextEPC/Open5GS/MongoDB processes found'
echo; echo 'KNOWN SERVICE STATES'
for service in nextepc-mmed nextepc-sgwd nextepc-pgwd nextepc-hssd open5gs-mmed open5gs-sgwcd open5gs-smfd open5gs-upfd mongod mongodb; do
  state=$(systemctl is-active "$service" 2>/dev/null || true)
  if [ "$state" != inactive ] && [ "$state" != unknown ]; then printf '%-24s %s\n' "$service" "$state"; fi
done
""",
    },
    "network": {
        "label": "Interfaces & routes",
        "script": """set -eu
echo 'INTERFACES'; ip -brief address
echo; echo 'ROUTES'; ip route
echo; echo 'LISTENING TCP/UDP PORTS'; ss -lntup 2>/dev/null | head -n 120
""",
    },
    "routing": {
        "label": "Forwarding & firewall",
        "script": """set -eu
echo 'IPV4 FORWARDING'; sysctl net.ipv4.ip_forward
echo; echo 'FORWARD CHAIN'; iptables -w 5 -nvL FORWARD 2>/dev/null || echo 'iptables FORWARD chain unavailable'
echo; echo 'NAT POSTROUTING'; iptables -w 5 -t nat -nvL POSTROUTING 2>/dev/null || echo 'iptables NAT table unavailable'
""",
    },
    "logs": {
        "label": "Recent EPC logs",
        "script": """set -eu
journalctl --no-pager -n 160 -u nextepc-mmed -u nextepc-sgwd -u nextepc-pgwd -u nextepc-hssd -u open5gs-mmed -u open5gs-sgwcd -u open5gs-smfd -u open5gs-upfd 2>/dev/null || echo 'No matching systemd journal entries found'
""",
    },
    "traffic": {
        "label": "LTE traffic counters",
        "script": """set -eu
echo 'INTERFACE COUNTERS'; ip -s -brief link 2>/dev/null || ip -s link
echo; echo 'GTP AND SIP SOCKETS'; ss -H -l -n -u -t 2>/dev/null | grep -E ':(2123|2152|36412|5060|5061)\\b' || echo 'No known LTE/IMS listener found'
echo; echo 'CONNECTION TRACKING';
if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then printf 'used='; cat /proc/sys/net/netfilter/nf_conntrack_count; printf 'max='; cat /proc/sys/net/netfilter/nf_conntrack_max; else echo 'Connection tracking counters unavailable'; fi
""",
    },
    "sessions": {
        "label": "S1 and user-plane sessions",
        "script": """set -eu
echo 'SCTP ASSOCIATIONS'; ss -H -n -A sctp 2>/dev/null || echo 'SCTP socket view unavailable'
echo; echo 'GTP KERNEL STATE';
if command -v ip >/dev/null 2>&1; then ip -details link show type gtp 2>/dev/null || echo 'No kernel GTP interface found'; fi
echo; echo 'CORE PROCESS AGE'; ps -eo etimes,pid,comm,args --sort=-etimes | grep -E '[n]extepc|[o]pen5gs' || echo 'No core processes found'
""",
    },
    "time": {
        "label": "Clock and time sync",
        "script": """set -eu
echo 'SYSTEM CLOCK'; date -u
echo; echo 'TIME SYNCHRONIZATION'; timedatectl status 2>/dev/null || true
if command -v chronyc >/dev/null 2>&1; then echo; chronyc tracking 2>/dev/null || true; fi
""",
    },
}


def routing_check():
    cfg = require_routing_enabled()
    script = f"""set -eu
SUBNET='{cfg['subnet']}'
UPLINK='{cfg['interface']}'
forwarding=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
if ip link show dev "$UPLINK" >/dev/null 2>&1; then interface_ok=1; else interface_ok=0; fi
if ip route get 1.1.1.1 >/dev/null 2>&1; then route_ok=1; else route_ok=0; fi
if iptables -w 5 -t nat -C POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE >/dev/null 2>&1; then nat_ok=1; else nat_ok=0; fi
if iptables -w 5 -C FORWARD -s "$SUBNET" -o "$UPLINK" -j ACCEPT >/dev/null 2>&1; then outbound_ok=1; else outbound_ok=0; fi
if iptables -w 5 -C FORWARD -d "$SUBNET" -i "$UPLINK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; then return_ok=1; else return_ok=0; fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet baiamonte-lte-routing.service; then service_ok=1; else service_ok=0; fi
nat_packets=$(iptables -w 5 -t nat -nvxL POSTROUTING 2>/dev/null | awk -v s="$SUBNET" -v o="$UPLINK" '$3=="MASQUERADE" && $7==o && $8==s {{n+=$1}} END {{print n+0}}')
outbound_packets=$(iptables -w 5 -nvxL FORWARD 2>/dev/null | awk -v s="$SUBNET" -v o="$UPLINK" '$3=="ACCEPT" && $7==o && $8==s {{n+=$1}} END {{print n+0}}')
return_packets=$(iptables -w 5 -nvxL FORWARD 2>/dev/null | awk -v s="$SUBNET" -v i="$UPLINK" '$3=="ACCEPT" && $6==i && $9==s {{n+=$1}} END {{print n+0}}')
printf 'forwarding=%s\ninterface=%s\nroute=%s\nnat=%s\noutbound=%s\nreturn=%s\nservice=%s\nnat_packets=%s\noutbound_packets=%s\nreturn_packets=%s\nos=%s\n' "$forwarding" "$interface_ok" "$route_ok" "$nat_ok" "$outbound_ok" "$return_ok" "$service_ok" "$nat_packets" "$outbound_packets" "$return_packets" "$(uname -sr)"
"""
    _, output = run_epc_script(script)
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    checks = {key: values.get(key) == "1" for key in ("forwarding", "interface", "route", "nat", "outbound", "return", "service")}
    counters = {key: int(values.get(f"{key}_packets", 0)) for key in ("nat", "outbound", "return")}
    result = {"checks": checks, "counters": counters, "ready": all(checks.values()), "os": values.get("os", "Unknown"),
              "host": cfg["host"], "subnet": cfg["subnet"], "interface": cfg["interface"], "checked_at": int(time.time())}
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES('routing_last_status',?)", (json.dumps(result),))
    return result


def routing_apply_script(cfg):
    return f"""set -eu
SUBNET='{cfg['subnet']}'
UPLINK='{cfg['interface']}'
command -v iptables >/dev/null 2>&1 || {{ echo 'iptables is required on the EPC' >&2; exit 12; }}
command -v systemctl >/dev/null 2>&1 || {{ echo 'systemd is required on the EPC' >&2; exit 13; }}
ip link show dev "$UPLINK" >/dev/null 2>&1 || {{ echo 'configured uplink interface does not exist' >&2; exit 14; }}
for path in /usr/local/sbin/baiamonte-lte-routing /etc/systemd/system/baiamonte-lte-routing.service /etc/sysctl.d/99-baiamonte-lte.conf; do
  if [ -e "$path" ] && ! grep -q 'Managed by Baiamonte LTE' "$path"; then echo "Refusing to replace unmanaged file: $path" >&2; exit 15; fi
done
install -d -m 0700 /var/lib/baiamonte-lte-routing
if [ ! -f /var/lib/baiamonte-lte-routing/previous_forwarding ]; then sysctl -n net.ipv4.ip_forward > /var/lib/baiamonte-lte-routing/previous_forwarding; fi
cat > /usr/local/sbin/baiamonte-lte-routing <<'ROUTING'
#!/bin/sh
# Managed by Baiamonte LTE
set -eu
SUBNET='{cfg['subnet']}'
UPLINK='{cfg['interface']}'
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -w 5 -t nat -C POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE 2>/dev/null || iptables -w 5 -t nat -A POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE
iptables -w 5 -C FORWARD -s "$SUBNET" -o "$UPLINK" -j ACCEPT 2>/dev/null || iptables -w 5 -I FORWARD 1 -s "$SUBNET" -o "$UPLINK" -j ACCEPT
iptables -w 5 -C FORWARD -d "$SUBNET" -i "$UPLINK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -w 5 -I FORWARD 1 -d "$SUBNET" -i "$UPLINK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ROUTING
chmod 0755 /usr/local/sbin/baiamonte-lte-routing
cat > /etc/sysctl.d/99-baiamonte-lte.conf <<'SYSCTL'
# Managed by Baiamonte LTE
net.ipv4.ip_forward=1
SYSCTL
cat > /etc/systemd/system/baiamonte-lte-routing.service <<'UNIT'
# Managed by Baiamonte LTE
[Unit]
Description=Baiamonte LTE subscriber Internet routing
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/baiamonte-lte-routing
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now baiamonte-lte-routing.service >/dev/null
echo applied
"""


def routing_rollback_script(cfg):
    return f"""set -eu
SUBNET='{cfg['subnet']}'
UPLINK='{cfg['interface']}'
while iptables -w 5 -t nat -C POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE 2>/dev/null; do iptables -w 5 -t nat -D POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE; done
while iptables -w 5 -C FORWARD -s "$SUBNET" -o "$UPLINK" -j ACCEPT 2>/dev/null; do iptables -w 5 -D FORWARD -s "$SUBNET" -o "$UPLINK" -j ACCEPT; done
while iptables -w 5 -C FORWARD -d "$SUBNET" -i "$UPLINK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do iptables -w 5 -D FORWARD -d "$SUBNET" -i "$UPLINK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; done
if command -v systemctl >/dev/null 2>&1; then systemctl disable --now baiamonte-lte-routing.service >/dev/null 2>&1 || true; fi
rm -f /usr/local/sbin/baiamonte-lte-routing /etc/systemd/system/baiamonte-lte-routing.service /etc/sysctl.d/99-baiamonte-lte.conf
if [ -f /var/lib/baiamonte-lte-routing/previous_forwarding ]; then previous=$(cat /var/lib/baiamonte-lte-routing/previous_forwarding); sysctl -w net.ipv4.ip_forward="$previous" >/dev/null; fi
rm -rf /var/lib/baiamonte-lte-routing
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload; fi
echo rolled_back
"""


@app.get("/api/epc-routing/status")
def epc_routing_status():
    try:
        cfg = routing_config()
        return jsonify({"config": cfg, "key_present": EPC_SSH_KEY.exists(), "host_trusted": EPC_KNOWN_HOSTS.exists()})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/connectivity")
def epc_routing_connectivity():
    try:
        cfg = require_routing_enabled()
        return jsonify({"host": cfg["host"], "port": cfg["port"], **probe_epc_ssh()})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/epc-console/actions")
def epc_console_actions():
    try:
        require_routing_enabled()
        return jsonify({"actions": [{"id": action_id, "label": action["label"]}
                                    for action_id, action in EPC_CONSOLE_ACTIONS.items()]})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-console/run")
def epc_console_run():
    try:
        action_id = str((request.get_json(silent=True) or {}).get("action", ""))
        action = EPC_CONSOLE_ACTIONS.get(action_id)
        if not action:
            raise ValueError("Choose one of the available read-only EPC console tools")
        cfg, output = run_epc_script(action["script"], timeout=20)
        output = output[-48_000:] if output else "Command completed with no output."
        captured = record_failed_registrations(output, "EPC recent logs") if action_id == "logs" else []
        event("console", f"Ran read-only EPC console tool: {action['label']}")
        return jsonify({"ok": True, "action": action_id, "label": action["label"],
                        "host": cfg["host"], "output": output, "checked_at": int(time.time()),
                        "pending_registrations_found": len(captured)})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/key")
def epc_routing_key():
    try:
        require_routing_enabled()
        upload = request.files.get("file")
        if not upload or not upload.filename:
            raise ValueError("Choose an SSH private key file. Standard names such as id_ed25519 are supported.")
        raw = upload.stream.read(65_537)
        if not raw.strip():
            raise ValueError("The selected SSH private key file is empty")
        if len(raw) > 65_536:
            raise ValueError("SSH key must be 64 KB or smaller")
        normalized = raw.lstrip()
        if normalized.startswith((b"ssh-", b"ecdsa-")) or b"BEGIN PUBLIC KEY" in normalized[:256]:
            raise ValueError(
                "That is a public key. Choose the private key file (usually id_ed25519 without .pub), "
                "or use Generate dedicated SSH key."
            )
        fd, temp_path = tempfile.mkstemp(prefix="epc-key-", dir=CONFIG_DIR)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
            os.chmod(temp_path, 0o600)
            result = subprocess.run(
                ["ssh-keygen", "-y", "-P", "", "-f", temp_path],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False,
            )
            if result.returncode != 0:
                key_error = result.stderr.decode("utf-8", errors="replace").lower()
                if "passphrase" in key_error or b"ENCRYPTED" in normalized[:512]:
                    raise ValueError(
                        "Encrypted private keys cannot be used by this unattended app. "
                        "Use Generate dedicated SSH key or a dedicated unencrypted key."
                    )
                raise ValueError(
                    "This is not a readable OpenSSH or PEM private key. Extensionless files are supported; "
                    "do not select the matching .pub file."
                )
            os.replace(temp_path, EPC_SSH_KEY)
            os.chmod(EPC_SSH_KEY, 0o600)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        event("routing", "Stored EPC SSH key privately")
        return jsonify({"ok": True})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


def epc_public_key():
    if not EPC_SSH_KEY.exists():
        raise ValueError("Generate or upload an EPC SSH private key first")
    result = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(EPC_SSH_KEY)], capture_output=True,
                            text=True, timeout=5, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError("The stored EPC key could not be read")
    return result.stdout.strip() + " baiamonte-lte"


@app.route("/api/epc-routing/key/generate", methods=["POST", "GET"])
def epc_routing_generate_key():
    try:
        require_routing_enabled()
        if request.method == "GET":
            return jsonify({"public_key": epc_public_key()})
        body = request.get_json(silent=True) or {}
        if EPC_SSH_KEY.exists() and body.get("confirm") != "REPLACE KEY":
            raise ValueError("A key already exists; confirmation must be REPLACE KEY")
        temp_base = CONFIG_DIR / f"epc-generated-{secrets.token_hex(6)}"
        result = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "baiamonte-lte",
                                 "-f", str(temp_base)], capture_output=True, text=True, timeout=8, check=False)
        if result.returncode != 0:
            raise ValueError("Could not generate the dedicated EPC key")
        os.replace(temp_base, EPC_SSH_KEY)
        os.chmod(EPC_SSH_KEY, 0o600)
        public_path = Path(str(temp_base) + ".pub")
        if public_path.exists():
            public_path.unlink()
        event("routing", "Generated a dedicated EPC SSH key")
        return jsonify({"ok": True, "public_key": epc_public_key()})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/scan")
def epc_routing_scan():
    try:
        cfg, fingerprints = scan_epc_host()
        return jsonify({"host": cfg["host"], "port": cfg["port"],
                        "fingerprints": [{"fingerprint": item["fingerprint"], "type": item["type"]} for item in fingerprints]})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/trust")
def epc_routing_trust():
    try:
        wanted = str((request.get_json(silent=True) or {}).get("fingerprint", ""))
        cfg, fingerprints = scan_epc_host()
        match = next((item for item in fingerprints if item["fingerprint"] == wanted), None)
        if not match:
            raise ValueError("The EPC fingerprint changed; scan it again before trusting")
        EPC_KNOWN_HOSTS.write_text(match["key_line"] + "\n", encoding="utf-8")
        os.chmod(EPC_KNOWN_HOSTS, 0o600)
        event("routing", f"Trusted EPC SSH host key {wanted}")
        return jsonify({"ok": True, "fingerprint": wanted})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/epc-routing/preview")
def epc_routing_preview():
    try:
        cfg = require_routing_enabled()
        return jsonify({"host": cfg["host"], "user": cfg["user"], "port": cfg["port"],
            "changes": ["Enable IPv4 forwarding using /etc/sysctl.d/99-baiamonte-lte.conf",
                        f"Masquerade {cfg['subnet']} out {cfg['interface']}",
                        "Allow subscriber outbound traffic and established return traffic",
                        "Create and enable baiamonte-lte-routing.service for persistence"],
            "rollback": "Removes only the Baiamonte service, sysctl file, and exact firewall rules; restores the previous forwarding value."})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/check")
def epc_routing_check_api():
    try:
        return jsonify(routing_check())
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/apply")
def epc_routing_apply():
    try:
        cfg = require_routing_enabled()
        if str((request.get_json(silent=True) or {}).get("confirm", "")) != f"APPLY {cfg['host']}":
            raise ValueError(f"Confirmation must be APPLY {cfg['host']}")
        run_epc_script(routing_apply_script(cfg), timeout=35)
        result = routing_check()
        event("routing", f"Applied subscriber Internet routing on EPC {cfg['host']}")
        return jsonify({"ok": True, "status": result})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/rollback")
def epc_routing_rollback():
    try:
        cfg = require_routing_enabled()
        if str((request.get_json(silent=True) or {}).get("confirm", "")) != f"ROLLBACK {cfg['host']}":
            raise ValueError(f"Confirmation must be ROLLBACK {cfg['host']}")
        run_epc_script(routing_rollback_script(cfg), timeout=30)
        event("routing", f"Rolled back Baiamonte routing on EPC {cfg['host']}")
        return jsonify({"ok": True})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/verify/start")
def epc_routing_verify_start():
    try:
        status = routing_check()
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES('routing_verify_baseline',?)",
                         (json.dumps({"created_at": int(time.time()), "counters": status["counters"]}),))
        return jsonify({"ok": True, "baseline": status["counters"],
                        "instruction": "On an attached LTE device, turn off Wi-Fi and open a new public HTTPS website, then return here."})
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/epc-routing/verify/finish")
def epc_routing_verify_finish():
    try:
        with db() as conn:
            row = conn.execute("SELECT value FROM app_settings WHERE key='routing_verify_baseline'").fetchone()
        if not row:
            raise ValueError("Start the UE traffic test first")
        baseline = json.loads(row["value"])
        if int(time.time()) - baseline["created_at"] > 600:
            raise ValueError("The UE traffic test expired; start a new one")
        status = routing_check()
        delta = {key: max(0, status["counters"][key] - int(baseline["counters"].get(key, 0)))
                 for key in ("nat", "outbound", "return")}
        verified = delta["nat"] > 0 and delta["outbound"] > 0 and delta["return"] > 0
        partial = not verified and delta["nat"] > 0 and delta["outbound"] > 0
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES('routing_last_verified',?)",
                         (json.dumps({"verified": verified, "checked_at": int(time.time())}),))
        event("routing", "UE Internet traffic test " + ("passed" if verified else "needs attention"))
        return jsonify({"verified": verified, "partial": partial, "delta": delta, "status": status,
                        "message": "Subscriber traffic crossed the EPC and return packets were observed." if verified else
                                   "Outbound subscriber traffic was seen, but no return traffic was observed." if partial else
                                   "No new subscriber traffic crossed the configured routing rules."})
    except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return jsonify({"error": str(exc)}), 400


def analyze_core_log(text):
    patterns = [
        (r"unknown UE|cannot find IMSI|subscriber.*not found", "Subscriber missing", "Add the IMSI and matching K/OPc to the HSS."),
        (r"MAC failure|authentication failure|synch failure", "SIM authentication failed", "Verify K, OPc/OP, AMF, and that the SIM has the same values."),
        (r"S1.*setup.*fail|SCTP.*fail|connection refused", "S1 connection failed", "Verify MME address, SCTP 36412, routing, and firewall rules."),
        (r"PLMN.*not.*match|unknown PLMN|TAI.*not.*served", "PLMN or TAC mismatch", "Match MCC, MNC, and TAC across EPC, eNodeB, and SIM."),
        (r"Mongo.*(fail|error)|database.*(fail|error)", "Subscriber database problem", "Check MongoDB service, URI, bind address, and schema version."),
        (r"GTP.*(fail|error)|create session.*fail", "User-plane session failed", "Check SGW/PGW addresses, GTP-U routing, forwarding, and NAT."),
        (r"attach reject|emm cause", "UE attach rejected", "Inspect the adjacent EMM cause and verify subscriber, PLMN, TAC, and roaming."),
    ]
    findings = []
    for pattern, title, action in patterns:
        count = len(re.findall(pattern, text, re.IGNORECASE))
        if count:
            findings.append({"title": title, "count": count, "action": action})
    return findings


def failed_registration_candidates(text):
    """Extract only explicit missing-subscriber failures; never infer SIM secrets."""
    lines = str(text).splitlines()
    candidates = {}
    missing_pattern = re.compile(
        r"cannot\s+find.{0,80}imsi|imsi.{0,80}(?:not\s+found|unknown\s+subscriber)|"
        r"subscriber.{0,80}(?:not\s+found|missing|unknown)|no\s+subscriber.{0,80}imsi|"
        r"diameter.{0,80}(?:user[_ -]?unknown|5001)", re.IGNORECASE)
    imsi_pattern = re.compile(r"\bIMSI(?:[-_ ]?[0-9]*)?\s*[:=\[]\s*([0-9]{5,15})\b", re.IGNORECASE)
    apn_pattern = re.compile(r"\b(?:APN|DNN)\s*[:=\[]\s*([A-Za-z0-9][A-Za-z0-9._-]{0,99})", re.IGNORECASE)
    for index, line in enumerate(lines):
        window = " ".join(lines[max(0, index - 2):min(len(lines), index + 3)])
        if not missing_pattern.search(window):
            continue
        for match in imsi_pattern.finditer(window):
            imsi = match.group(1)
            if not IMSI_RE.fullmatch(imsi):
                continue
            apn_match = apn_pattern.search(window)
            candidates[imsi] = {"imsi": imsi, "apn": apn_match.group(1) if apn_match else "",
                                "cause": "Subscriber missing from EPC"}
    return list(candidates.values())


def record_failed_registrations(text, source):
    candidates = failed_registration_candidates(text)
    if not candidates:
        return []
    now = int(time.time())
    safe_source = re.sub(r"[^A-Za-z0-9 ._()-]", "_", str(source))[:120] or "EPC log"
    with db() as conn:
        registered = {row[0] for row in conn.execute("SELECT imsi FROM subscribers")}
        for item in candidates:
            if item["imsi"] in registered:
                continue
            conn.execute("""INSERT INTO pending_registrations
                (imsi,apn,cause,source,first_seen,last_seen,attempts) VALUES(?,?,?,?,?,?,1)
                ON CONFLICT(imsi) DO UPDATE SET
                    apn=CASE WHEN excluded.apn!='' THEN excluded.apn ELSE pending_registrations.apn END,
                    cause=excluded.cause,source=excluded.source,last_seen=excluded.last_seen,
                    attempts=pending_registrations.attempts+1""",
                         (item["imsi"], item["apn"], item["cause"], safe_source, now, now))
    return [item for item in candidates if item["imsi"] not in registered]


def calculate_opc(k, op):
    k, op = str(k).strip().upper(), str(op).strip().upper()
    for name, value in (("K", k), ("OP", op)):
        if len(value) != 32 or not HEX_RE.fullmatch(value):
            raise ValueError(f"{name} must be 32 hexadecimal characters")
    try:
        result = subprocess.run(["openssl", "enc", "-aes-128-ecb", "-K", k, "-nopad", "-nosalt"],
                                input=bytes.fromhex(op), capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("The AES utility is unavailable") from exc
    if result.returncode != 0 or len(result.stdout) != 16:
        raise ValueError("OPc calculation failed")
    return bytes(a ^ b for a, b in zip(result.stdout, bytes.fromhex(op))).hex().upper()


def validate_subscriber(body):
    values = {k: str(body.get(k, "")).strip() for k in ("imsi", "name", "k", "opc", "amf", "apn", "msisdn", "zone")}
    values["zone"] = values["zone"][:40] or "Unassigned"
    allowed_types = {"Camera", "Environmental sensor", "Irrigation controller", "Gateway / router",
                     "Security device", "Vehicle / equipment", "Other IoT"}
    values["device_type"] = str(body.get("device_type", "Other IoT")).strip()
    if values["device_type"] not in allowed_types:
        raise ValueError("Choose a supported vineyard device role")
    values["critical"] = bool(body.get("critical", False))
    values["notes"] = str(body.get("notes", "")).strip()[:160]
    values["k"], values["opc"], values["amf"] = values["k"].upper(), values["opc"].upper(), values["amf"].upper()
    if not IMSI_RE.fullmatch(values["imsi"]):
        raise ValueError("IMSI must contain 5–15 digits")
    for key, length in (("k", 32), ("opc", 32), ("amf", 4)):
        if len(values[key]) != length or not HEX_RE.fullmatch(values[key]):
            raise ValueError(f"{key.upper()} must be {length} hexadecimal characters")
    if not values["name"] or not values["apn"]:
        raise ValueError("Name and APN are required")
    return values


def mongo_collection():
    cfg = settings()
    client = MongoClient(cfg["mongodb_uri"], serverSelectionTimeoutMS=1800, connectTimeoutMS=1800)
    client.admin.command("ping")
    database = client.get_default_database()
    if database is None:
        database = client["nextepc" if cfg["epc_type"] == "nextepc" else "open5gs"]
    return client, database.subscribers


def provision_mongo(sub):
    cfg = settings()
    if cfg["epc_type"] == "local":
        return "Saved locally"
    client, collection = mongo_collection()
    try:
        if cfg["epc_type"] == "nextepc":
            doc = {"imsi": sub["imsi"], "security": {"k": sub["k"], "opc": sub["opc"], "amf": sub["amf"], "op": None},
                   "ambr": {"downlink": 100000000, "uplink": 100000000}, "pdn": [{"apn": sub["apn"], "type": 0,
                   "qos": {"qci": 9, "arp": {"priority_level": 8, "pre_emption_capability": 0, "pre_emption_vulnerability": 1}}}],
                   "subscriber_status": 0, "network_access_mode": 2, "access_restriction_data": 32}
        else:
            doc = {"imsi": sub["imsi"], "msisdn": [sub["msisdn"]] if sub["msisdn"] else [], "security": {"k": sub["k"], "opc": sub["opc"], "amf": sub["amf"]},
                   "ambr": {"downlink": {"value": 1, "unit": 3}, "uplink": {"value": 1, "unit": 3}}, "subscriber_status": 0,
                   "network_access_mode": 0, "access_restriction_data": 32, "slice": [{"sst": 1, "default_indicator": True,
                   "session": [{"name": sub["apn"], "type": 3, "pcc_rule": [], "ambr": {"downlink": {"value": 1, "unit": 3}, "uplink": {"value": 1, "unit": 3}},
                   "qos": {"index": 9, "arp": {"priority_level": 8, "pre_emption_capability": 1, "pre_emption_vulnerability": 1}}}]}]}
        collection.replace_one({"imsi": sub["imsi"]}, doc, upsert=True)
        return "Provisioned to EPC"
    finally:
        client.close()


@app.get("/")
def index():
    return render_template("index.html", config=public_settings())


@app.get("/api/overview")
def overview():
    cfg = settings()
    status = sample_network()
    visibility = network_visibility(status)
    with db() as conn:
        ue_count = conn.execute("SELECT COUNT(*) FROM subscribers").fetchone()[0]
        events = [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 8")]
        route_row = conn.execute("SELECT value FROM app_settings WHERE key='routing_last_status'").fetchone()
        verified_row = conn.execute("SELECT value FROM app_settings WHERE key='routing_last_verified'").fetchone()
        inventory_rows = conn.execute("SELECT device_type,critical,zone FROM subscribers").fetchall()
    routing = {"configured": None, "verified": None}
    try:
        if route_row:
            routing["configured"] = bool(json.loads(route_row["value"]).get("ready"))
        if verified_row:
            routing["verified"] = bool(json.loads(verified_row["value"]).get("verified"))
    except (json.JSONDecodeError, TypeError):
        pass
    inventory = {"cameras": sum(row["device_type"] == "Camera" for row in inventory_rows),
                 "iot": sum(row["device_type"] != "Camera" for row in inventory_rows),
                 "critical": sum(bool(row["critical"]) for row in inventory_rows)}
    route_status = None
    if route_row:
        try:
            route_status = json.loads(route_row["value"])
        except (json.JSONDecodeError, TypeError):
            route_status = None
    return jsonify({"epc": status["epc"], "bts": status["bts"],
                    "routing": routing, "subscriber_count": ue_count, "events": events,
                    "inventory": inventory,
                    "subscriber_gauges": subscriber_gauges(status, route_status, inventory_rows),
                    "visibility": visibility,
                    "config": {k: v for k, v in cfg.items() if k not in SECRET_SETTING_KEYS}})


@app.get("/api/subscribers")
def list_subscribers():
    with db() as conn:
        rows = conn.execute("SELECT imsi,name,zone,device_type,critical,notes,apn,msisdn,created_at FROM subscribers ORDER BY zone,name").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/registrations/pending")
def list_pending_registrations():
    with db() as conn:
        rows = conn.execute("""SELECT imsi,apn,cause,source,first_seen,last_seen,attempts
                             FROM pending_registrations ORDER BY last_seen DESC""").fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/registrations/pending/<imsi>/approve")
def approve_pending_registration(imsi):
    body = request.get_json(silent=True) or {}
    try:
        if not IMSI_RE.fullmatch(imsi) or str(body.get("confirm", "")) != imsi:
            raise ValueError("Confirm the exact pending IMSI before approval")
        with db() as conn:
            pending = conn.execute("SELECT imsi,apn FROM pending_registrations WHERE imsi=?", (imsi,)).fetchone()
        if not pending:
            raise ValueError("This registration is no longer pending")
        body["imsi"] = imsi
        if not str(body.get("apn", "")).strip():
            body["apn"] = pending["apn"] or settings()["apn"]
        sub = validate_subscriber(body)
        result = provision_mongo(sub)
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO subscribers(imsi,name,k,opc,amf,apn,msisdn,zone,device_type,critical,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                         (sub["imsi"], sub["name"], sub["k"], sub["opc"], sub["amf"], sub["apn"], sub["msisdn"],
                          sub["zone"], sub["device_type"], int(sub["critical"]), sub["notes"], int(time.time())))
            conn.execute("DELETE FROM pending_registrations WHERE imsi=?", (imsi,))
        event("subscriber", f"Approved pending UE {imsi} as {sub['name']} — {result}")
        return jsonify({"ok": True, "message": result}), 201
    except (ValueError, PyMongoError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.delete("/api/registrations/pending/<imsi>")
def dismiss_pending_registration(imsi):
    body = request.get_json(silent=True) or {}
    if not IMSI_RE.fullmatch(imsi) or str(body.get("confirm", "")) != imsi:
        return jsonify({"error": "Confirm the exact pending IMSI before dismissal"}), 400
    with db() as conn:
        removed = conn.execute("DELETE FROM pending_registrations WHERE imsi=?", (imsi,)).rowcount
    if not removed:
        return jsonify({"error": "This registration is no longer pending"}), 404
    event("subscriber", f"Dismissed pending registration {imsi}")
    return jsonify({"ok": True})


@app.get("/api/bts/status")
def bts_status_api():
    return jsonify(nokia_status())


@app.post("/api/subscribers")
def create_subscriber():
    try:
        body = request.get_json(silent=True) or {}
        sub = validate_subscriber(body)
        result = provision_mongo(sub)
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO subscribers(imsi,name,k,opc,amf,apn,msisdn,zone,device_type,critical,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                         (sub["imsi"], sub["name"], sub["k"], sub["opc"], sub["amf"], sub["apn"], sub["msisdn"],
                          sub["zone"], sub["device_type"], int(sub["critical"]), sub["notes"], int(time.time())))
        if body.get("commissioning_source") == "sim_workbench":
            update_sim_inventory(sub, "hss_provisioned", body.get("iccid", ""))
        event("subscriber", f"{sub['name']} ({sub['imsi']}) — {result}")
        return jsonify({"ok": True, "message": result}), 201
    except (ValueError, PyMongoError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.delete("/api/subscribers/<imsi>")
def delete_subscriber(imsi):
    if not IMSI_RE.fullmatch(imsi):
        return jsonify({"error": "Invalid IMSI"}), 400
    cfg = settings()
    if cfg["epc_type"] != "local":
        try:
            client, collection = mongo_collection()
            try: collection.delete_one({"imsi": imsi})
            finally: client.close()
        except PyMongoError as exc:
            return jsonify({"error": str(exc)}), 400
    with db() as conn:
        conn.execute("DELETE FROM subscribers WHERE imsi=?", (imsi,))
    event("subscriber", f"Removed UE {imsi}")
    return jsonify({"ok": True})


@app.patch("/api/subscribers/<imsi>/zone")
def change_subscriber_zone(imsi):
    if not IMSI_RE.fullmatch(imsi):
        return jsonify({"error": "Invalid IMSI"}), 400
    zone = str((request.get_json(silent=True) or {}).get("zone", "")).strip()[:40] or "Unassigned"
    with db() as conn:
        if not conn.execute("SELECT 1 FROM subscribers WHERE imsi=?", (imsi,)).fetchone():
            return jsonify({"error": "Device not found"}), 404
        conn.execute("UPDATE subscribers SET zone=? WHERE imsi=?", (zone, imsi))
    event("subscriber", f"Moved UE {imsi} to {zone}")
    return jsonify({"ok": True, "zone": zone})


@app.patch("/api/subscribers/<imsi>/profile")
def change_subscriber_profile(imsi):
    if not IMSI_RE.fullmatch(imsi):
        return jsonify({"error": "Invalid IMSI"}), 400
    body = request.get_json(silent=True) or {}
    allowed_types = {"Camera", "Environmental sensor", "Irrigation controller", "Gateway / router",
                     "Security device", "Vehicle / equipment", "Other IoT"}
    updates, values = [], []
    if "device_type" in body:
        device_type = str(body["device_type"]).strip()
        if device_type not in allowed_types:
            return jsonify({"error": "Choose a supported vineyard device role"}), 400
        updates.append("device_type=?")
        values.append(device_type)
    if "critical" in body:
        updates.append("critical=?")
        values.append(int(bool(body["critical"])))
    if "zone" in body:
        updates.append("zone=?")
        values.append(str(body["zone"]).strip()[:40] or "Unassigned")
    if "notes" in body:
        updates.append("notes=?")
        values.append(str(body["notes"]).strip()[:160])
    if not updates:
        return jsonify({"error": "No supported inventory fields were supplied"}), 400
    with db() as conn:
        if not conn.execute("SELECT 1 FROM subscribers WHERE imsi=?", (imsi,)).fetchone():
            return jsonify({"error": "Device not found"}), 404
        conn.execute(f"UPDATE subscribers SET {','.join(updates)} WHERE imsi=?", (*values, imsi))
    event("subscriber", f"Updated inventory profile for UE {imsi}")
    return jsonify({"ok": True})


@app.get("/api/subscribers/export.csv")
def export_subscriber_inventory():
    with db() as conn:
        rows = conn.execute("SELECT name,device_type,zone,critical,imsi,apn,msisdn,notes,created_at FROM subscribers ORDER BY zone,name").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Device", "Role", "Vineyard zone", "Critical", "IMSI", "APN", "MSISDN", "Notes", "Added"])
    def safe_cell(value):
        value = str(value or "")
        return f"'{value}" if value.startswith(("=", "+", "-", "@")) else value
    for row in rows:
        writer.writerow([safe_cell(row["name"]), safe_cell(row["device_type"]), safe_cell(row["zone"]),
                         "Yes" if row["critical"] else "No", row["imsi"], safe_cell(row["apn"]),
                         safe_cell(row["msisdn"]), safe_cell(row["notes"]),
                         time.strftime("%Y-%m-%d", time.localtime(row["created_at"]))])
    return app.response_class(output.getvalue(), mimetype="text/csv",
                              headers={"Content-Disposition": "attachment; filename=baiamonte-lte-inventory.csv",
                                       "X-Content-Type-Options": "nosniff"})


@app.get("/api/history")
def connection_history():
    hours = min(max(request.args.get("hours", 24, type=int), 1), 720)
    since = int(time.time()) - hours * 3600
    with db() as conn:
        rows = [dict(row) for row in conn.execute(
            "SELECT sampled_at,epc_online,bts_online,s1_online,db_online FROM status_history WHERE sampled_at>=? ORDER BY sampled_at", (since,))]
    total = len(rows)
    uptime = {key: round(100 * sum(row[key] for row in rows) / total, 1) if total else None
              for key in ("epc_online", "bts_online")}
    return jsonify({"hours": hours, "points": rows, "uptime": {"epc": uptime["epc_online"], "radio": uptime["bts_online"]}})


@app.get("/api/network/visibility")
def network_visibility_api():
    return jsonify(network_visibility())


@app.get("/api/incidents")
def incidents_api():
    hours = min(max(request.args.get("hours", 168, type=int), 1), 720)
    return jsonify({"hours": hours, "incidents": connection_incidents(hours)})


@app.post("/api/tools/run")
def run_network_tool():
    action = str((request.get_json(silent=True) or {}).get("action", ""))
    cfg = settings()
    if action == "ports":
        result = {"title": "Known service ports", "kind": "ports", "rows": known_port_checks()}
    elif action == "route":
        routes = [{"name": "EPC core", "host": cfg["epc_host"], **route_to_host(cfg["epc_host"])},
                  {"name": "Nokia radio", "host": cfg["bts_host"], **route_to_host(cfg["bts_host"])},
                  {"name": "Public Internet", "host": "1.1.1.1", **route_to_host("1.1.1.1")}]
        result = {"title": "Container routing", "kind": "routes", "rows": routes}
    elif action == "dns":
        dns, internet = dns_check(), tcp_check("1.1.1.1", 443, timeout=1.5)
        result = {"title": "DNS and site uplink", "kind": "uplink", "dns": dns, "internet": internet}
    elif action == "inventory":
        with db() as conn:
            rows = [dict(row) for row in conn.execute(
                "SELECT device_type,COUNT(*) count,SUM(critical) critical,"
                "SUM(CASE WHEN zone='Unassigned' THEN 1 ELSE 0 END) unassigned "
                "FROM subscribers GROUP BY device_type ORDER BY count DESC")]
        result = {"title": "Inventory readiness", "kind": "inventory", "rows": rows}
    elif action == "incidents":
        result = {"title": "Recent connectivity incidents", "kind": "incidents",
                  "rows": connection_incidents(168, 30)}
    else:
        return jsonify({"error": "Choose a supported read-only network tool"}), 400
    event("tool", f"Ran read-only network tool: {result['title']}")
    return jsonify({"ok": True, "created_at": int(time.time()), **result})


@app.get("/api/communications/status")
def communications_status_api():
    return jsonify(communications_status())


@app.post("/api/communications/send")
def communications_send_api():
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != "SEND":
        return jsonify({"error": "Confirm each outbound dispatch with SEND"}), 400
    try:
        return jsonify(dispatch_communication(str(body.get("kind", "")), str(body.get("to", "")).strip(),
                                              str(body.get("message", ""))))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/alerts/settings", methods=["GET", "PUT"])
def alerts_settings_api():
    if request.method == "GET":
        prefs = alert_settings()
        with db() as conn:
            states = {row["target"]: {"failures": row["failures"], "active": bool(row["active"]), "last_notified": row["last_notified"]}
                      for row in conn.execute("SELECT * FROM alert_state")}
        return jsonify({"settings": prefs, "states": states, "home_assistant_ready": bool(os.getenv("SUPERVISOR_TOKEN"))})
    try:
        clean = save_alert_settings(request.get_json(silent=True) or {})
    except (TypeError, ValueError):
        return jsonify({"error": "Use a 1–10 failure threshold and a 5–1440 minute cooldown"}), 400
    event("alert", "Updated EPC and radio notification rules")
    return jsonify({"ok": True, "settings": clean})


@app.post("/api/commissioning")
def upload_commissioning():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"error": "Choose a commissioning file"}), 400
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(upload.filename).name)
    target = CONFIG_DIR / f"commissioning-{safe_name}"
    upload.save(target)
    os.chmod(target, 0o600)
    event("bts", f"Stored Nokia commissioning file {safe_name}; apply it with licensed BTS Site Manager")
    return jsonify({"ok": True, "name": safe_name, "size": target.stat().st_size})


def sim_reader_status():
    tool = shutil.which("pySim-shell.py") or shutil.which("pySim-shell") or shutil.which("pySim-prog.py")
    detected = []
    try:
        from smartcard.System import readers
        detected = [str(reader) for reader in readers()]
    except Exception:
        # The PC/SC service may still be starting or no USB reader may be attached.
        pass
    enabled = bool(settings()["sim_programming_enabled"])
    return {"enabled": enabled, "pysim": bool(tool), "usb_visible": Path("/dev/bus/usb").exists(),
            "readers": detected, "ready": bool(tool and detected and enabled)}


@app.get("/api/sim/readers")
def sim_readers():
    return jsonify(sim_reader_status())


@app.get("/api/sim/production-plan")
def sim_production_plan():
    cfg = settings()
    reader = sim_reader_status()
    return jsonify({
        "network": {"mcc": str(cfg["mcc"]), "mnc": str(cfg["mnc"]), "apn": str(cfg["apn"]),
                    "tac": int(cfg["tac"]), "plmn": f"{cfg['mcc']}-{cfg['mnc']}"},
        "reader": reader,
        "steps": [
            {"id": "identity", "label": "Create device identity", "detail": "Assign the camera or IoT device, zone, IMSI, ICCID record, and APN."},
            {"id": "security", "label": "Generate authentication", "detail": "Create K and OP, derive OPc, and retain the protected production record."},
            {"id": "card", "label": "Program and read back USIM", "detail": "Write the owned programmable USIM with vendor-authorized pySim commands, then verify IMSI and LTE files."},
            {"id": "hss", "label": "Provision EPC / HSS", "detail": "Store the same IMSI, K, OPc, AMF, APN, and policy in NextEPC/Open5GS."},
            {"id": "device", "label": "Configure camera or IoT modem", "detail": "Set the estate APN, automatic LTE network selection, and device reconnect policy."},
            {"id": "attach", "label": "Confirm live service", "detail": "Observe attach/session evidence, then prove DNS, outbound, and return traffic."},
        ],
        "lte_files": [
            {"file": "EF.IMSI", "purpose": "Subscriber identity", "required": True},
            {"file": "USIM authentication storage", "purpose": "K and OPc/OP; card-vendor-specific protected write", "required": True},
            {"file": "EF.AD", "purpose": "MNC length and administrative data", "required": True},
            {"file": "EF.ACC", "purpose": "Access class control", "required": True},
            {"file": "EF.PLMNwAcT / EF.OPLMNwAcT", "purpose": "Preferred LTE PLMN selection", "required": False},
            {"file": "EF.HPLMNwAcT", "purpose": "Home-network search behavior", "required": False},
            {"file": "EF.FPLMN", "purpose": "Forbidden PLMNs; clear stale entries during commissioning", "required": False},
            {"file": "EF.EPSLOCI / EF.LOCI", "purpose": "Cached location; clear before first production attach", "required": False},
        ],
        "prl_note": "PRL is a CDMA/3GPP2 file and is not used for LTE attachment. LTE network preference uses PLMN selector files such as EF.PLMNwAcT, EF.OPLMNwAcT, and EF.HPLMNwAcT.",
        "write_note": "Direct card writes remain card-vendor-specific and require the correct ADM credentials. Baiamonte LTE will not guess an ADM key or issue an unverified write command.",
    })


@app.get("/api/sim/inventory")
def sim_inventory():
    with db() as conn:
        rows = conn.execute("""SELECT imsi,iccid,device_name,device_type,zone,stage,
                            attach_confirmed,data_verified,updated_at
                            FROM sim_inventory ORDER BY updated_at DESC LIMIT 100""").fetchall()
    return jsonify([{**dict(row), "attach_confirmed": bool(row["attach_confirmed"]),
                     "data_verified": bool(row["data_verified"])} for row in rows])


@app.post("/api/sim/confirm")
def sim_confirm_subscriber():
    imsi = str((request.get_json(silent=True) or {}).get("imsi", "")).strip()
    if not IMSI_RE.fullmatch(imsi):
        return jsonify({"error": "Enter the exact programmed IMSI to confirm"}), 400
    with db() as conn:
        subscriber = conn.execute("SELECT imsi,name,device_type,zone FROM subscribers WHERE imsi=?", (imsi,)).fetchone()
        registered = bool(subscriber)
        routing_row = conn.execute("SELECT value FROM app_settings WHERE key='routing_last_verified'").fetchone()
    routing_verified = False
    if routing_row:
        try:
            routing_verified = bool(json.loads(routing_row["value"]).get("verified"))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    network = sample_network()
    evidence, epc_log_state, epc_log_detail = [], "unknown", "Remote EPC log access is not configured"
    try:
        cfg = routing_config()
        if cfg["enabled"] and EPC_SSH_KEY.exists() and EPC_KNOWN_HOSTS.exists():
            script = f"""set -eu
IMSI='{imsi}'
journalctl --no-pager -n 1200 -u nextepc-mmed -u nextepc-hssd -u open5gs-mmed -u open5gs-hssd 2>/dev/null | grep -F -- "$IMSI" | tail -n 12 || true
"""
            _, output = run_epc_script(script, timeout=20)
            evidence = [line[:500] for line in output.splitlines() if line.strip()][-12:]
            epc_log_state = "online" if evidence else "offline"
            epc_log_detail = "Matching IMSI activity found in recent EPC logs" if evidence else "No recent EPC log line contains this IMSI"
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        epc_log_detail = str(exc)[:300]
    positive = bool(re.search(r"attach accept|registration accept|initial context|create session|connected", "\n".join(evidence), re.IGNORECASE))
    checks = [
        {"id": "registry", "label": "HSS subscriber", "state": "online" if registered else "offline",
         "detail": "IMSI is provisioned in Baiamonte LTE" if registered else "Provision this IMSI to the EPC/HSS first"},
        {"id": "epc", "label": "EPC core", "state": "online" if network["epc"]["online"] else "offline",
         "detail": "Core is reachable" if network["epc"]["online"] else "Core is unreachable"},
        {"id": "s1", "label": "S1 control", "state": "online" if network["epc"]["s1"]["online"] else "offline",
         "detail": "S1 listener is reachable" if network["epc"]["s1"]["online"] else "S1 is unavailable"},
        {"id": "radio", "label": "Nokia radio", "state": "online" if network["bts"]["online"] else "offline",
         "detail": "Radio management path is reachable" if network["bts"]["online"] else "Radio management path is unreachable"},
        {"id": "attach", "label": "Attach evidence", "state": "online" if positive else epc_log_state,
         "detail": "Recent EPC logs show positive attach/session evidence" if positive else epc_log_detail},
        {"id": "data", "label": "Subscriber data", "state": "online" if routing_verified else "unknown",
         "detail": "A live UE traffic test previously passed" if routing_verified else "Run the UE traffic test with this device to prove data"},
    ]
    if subscriber:
        update_sim_inventory({"imsi": subscriber["imsi"], "name": subscriber["name"],
                              "device_type": subscriber["device_type"], "zone": subscriber["zone"]},
                             "production_ready" if positive and routing_verified else "attach_observed" if positive else "hss_provisioned",
                             attach_confirmed=positive, data_verified=routing_verified)
    event("subscriber", f"Checked production onboarding status for UE {imsi}")
    return jsonify({"imsi": imsi, "registered": registered, "attach_confirmed": positive,
                    "data_verified": routing_verified, "checks": checks, "evidence": evidence,
                    "complete": registered and positive and routing_verified})


@app.post("/api/sim/opc")
def sim_opc():
    try:
        body = request.get_json(silent=True) or {}
        return jsonify({"opc": calculate_opc(body.get("k", ""), body.get("op", "")),
                        "stored": False, "algorithm": "3GPP Milenage"})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/sim/test-values")
def sim_test_values():
    k, op = secrets.token_hex(16).upper(), secrets.token_hex(16).upper()
    return jsonify({"k": k, "op": op, "opc": calculate_opc(k, op), "stored": False,
                    "warning": "Use only with a programmable test SIM you own."})


@app.get("/api/logs")
def logs():
    limit = min(max(request.args.get("limit", 200, type=int), 10), 1000)
    kind = str(request.args.get("kind", "")).strip().lower()[:24]
    search = str(request.args.get("search", "")).strip()[:80]
    where, values = [], []
    if kind and re.fullmatch(r"[a-z0-9_-]+", kind):
        where.append("kind=?")
        values.append(kind)
    if search:
        where.append("message LIKE ?")
        values.append(f"%{search}%")
    clause = " WHERE " + " AND ".join(where) if where else ""
    with db() as conn:
        rows = conn.execute(f"SELECT id,kind,message,created_at FROM events{clause} ORDER BY id DESC LIMIT ?",
                            (*values, limit)).fetchall()
    return jsonify(list(reversed([dict(row) for row in rows])))


@app.get("/api/logs/export")
def export_logs():
    with db() as conn:
        rows = conn.execute("SELECT kind,message,created_at FROM events ORDER BY id DESC LIMIT 2000").fetchall()
    output = io.StringIO()
    for row in reversed(rows):
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row["created_at"]))
        output.write(f"{timestamp} [{row['kind'].upper()}] {row['message']}\n")
    return app.response_class(output.getvalue(), mimetype="text/plain",
                              headers={"Content-Disposition": "attachment; filename=baiamonte-lte-activity.log",
                                       "X-Content-Type-Options": "nosniff"})


@app.post("/api/diagnostics/run")
def run_diagnostics():
    results = diagnostic_checks()
    failures = sum(1 for check in results if not check["ok"])
    event("diagnostic", f"Completed {len(results)} checks — {failures} need attention")
    return jsonify({"checks": results, "failures": failures, "created_at": int(time.time()),
                    "visibility": network_visibility()})


@app.post("/api/logs/analyze")
def analyze_log_upload():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"error": "Choose an EPC log file"}), 400
    raw = upload.stream.read(2_000_001)
    if len(raw) > 2_000_000:
        return jsonify({"error": "Log file must be 2 MB or smaller"}), 400
    text = raw.decode("utf-8", errors="replace")
    findings = analyze_core_log(text)
    pending = record_failed_registrations(text, f"Uploaded {Path(upload.filename).name}")
    event("log", f"Analyzed {Path(upload.filename).name}: {len(findings)} issue patterns found")
    return jsonify({"findings": findings, "lines": len(text.splitlines()), "name": Path(upload.filename).name,
                    "pending_registrations_found": len(pending)})


@app.get("/api/support-bundle")
def support_bundle():
    cfg = settings()
    safe_cfg = {key: value for key, value in cfg.items() if key not in SECRET_SETTING_KEYS}
    created = int(time.time())
    path = DATA_DIR / f"lte-support-{created}.zip"
    with db() as conn:
        recent = [dict(row) for row in conn.execute("SELECT kind,message,created_at FROM events ORDER BY id DESC LIMIT 250")]
    report = {"created_at": created, "configuration": safe_cfg, "diagnostics": diagnostic_checks(), "events": recent,
              "privacy": "MongoDB URI, communications token, subscriber keys, OPc values, and commissioning XML are excluded."}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.json", json.dumps(report, indent=2))
        archive.writestr("README.txt", "Redacted Baiamonte LTE support bundle. Subscriber secrets and Nokia commissioning data are not included.\n")
    os.chmod(path, 0o600)
    event("diagnostic", "Generated redacted support bundle")
    return send_file(path, as_attachment=True, download_name=path.name)


@app.post("/api/sim/script")
def sim_script():
    body = request.get_json(silent=True) or {}
    try:
        sub = validate_subscriber(body)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    cfg = settings()
    iccid = str(body.get("iccid", "")).strip()
    if iccid and (not iccid.isdigit() or not 18 <= len(iccid) <= 22):
        return jsonify({"error": "ICCID must contain 18–22 digits when provided"}), 400
    script = "\n".join([
        "# BAIAMONTE LTE — PRIVATE PRODUCTION SIM RECORD",
        "# Store securely. This file contains subscriber authentication material.",
        f"Device: {sub['name']}", f"Role: {sub['device_type']}", f"Zone: {sub['zone']}",
        f"ICCID: {iccid or 'Record the printed/card-read ICCID'}", f"IMSI: {sub['imsi']}",
        f"K: {sub['k']}", f"OPc: {sub['opc']}", f"AMF: {sub['amf']}",
        f"Home PLMN: {cfg['mcc']}-{cfg['mnc']}", f"APN: {sub['apn']}", f"TAC: {cfg['tac']}",
        "",
        "USIM PROGRAMMING REVIEW",
        "[ ] Identify the exact card model and obtain its authorized ADM credentials",
        "[ ] Write and read back EF.IMSI",
        "[ ] Write K and OPc/OP using the card vendor's protected command",
        "[ ] Verify EF.AD MNC length and EF.ACC access class",
        f"[ ] Set EF.PLMNwAcT / EF.OPLMNwAcT preference to {cfg['mcc']}-{cfg['mnc']} with E-UTRAN access when supported",
        "[ ] Review EF.HPLMNwAcT and clear stale EF.FPLMN entries",
        "[ ] Clear EF.EPSLOCI / EF.LOCI before the first production attach when supported",
        "[ ] Configure the device modem for automatic LTE selection and the APN above",
        "[ ] Provision the same IMSI, K, OPc, AMF, and APN in the EPC/HSS",
        "[ ] Confirm attach evidence and run a live subscriber traffic test",
        "",
        "NOTE: PRL is a CDMA/3GPP2 file and is not used by LTE. LTE selection uses PLMN selector files.",
        "Do not issue guessed pySim write commands. File paths, encodings, and ADM access depend on the programmable USIM vendor.",
    ])
    fd, path = tempfile.mkstemp(prefix="pysim-profile-", suffix=".txt", dir=DATA_DIR)
    with os.fdopen(fd, "w") as handle: handle.write(script + "\n")
    os.chmod(path, 0o600)
    update_sim_inventory(sub, "profile_ready", iccid)
    event("sim", f"Prepared private production worksheet for UE {sub['imsi']}")
    return send_file(path, as_attachment=True, download_name=f"pysim-{sub['imsi']}.txt")


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host=os.getenv("BIND_HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8099")), debug=False)
