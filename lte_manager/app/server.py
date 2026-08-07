import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import zipfile
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


def settings():
    defaults = {
        "epc_host": "192.168.1.151", "bts_host": "192.168.1.100",
        "epc_type": "nextepc", "mongodb_uri": "mongodb://192.168.1.151:27017/nextepc",
        "apn": "internet", "mcc": "001", "mnc": "01", "tac": 1,
        "sim_programming_enabled": False,
    }
    path = Path(os.getenv("OPTIONS_PATH", "/data/options.json"))
    if path.exists():
        try:
            defaults.update(json.loads(path.read_text()))
        except (OSError, json.JSONDecodeError):
            pass
    return defaults


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
    return checks


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


def validate_subscriber(body):
    values = {k: str(body.get(k, "")).strip() for k in ("imsi", "name", "k", "opc", "amf", "apn", "msisdn")}
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
    public_config = {key: value for key, value in settings().items() if key != "mongodb_uri"}
    return render_template("index.html", config=public_config)


@app.get("/api/overview")
def overview():
    cfg = settings()
    epc_ping, bts_ping = ping_check(cfg["epc_host"]), ping_check(cfg["bts_host"])
    mme = sctp_check(cfg["epc_host"])
    mongo = tcp_check(cfg["epc_host"], 27017)
    with db() as conn:
        ue_count = conn.execute("SELECT COUNT(*) FROM subscribers").fetchone()[0]
        events = [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 8")]
    return jsonify({"epc": {"host": cfg["epc_host"], "online": epc_ping, "s1": mme, "database": mongo},
                    "bts": {"host": cfg["bts_host"], "online": bts_ping, "software": "FLF21"},
                    "subscriber_count": ue_count, "events": events, "config": {k: v for k, v in cfg.items() if k != "mongodb_uri"}})


@app.get("/api/subscribers")
def list_subscribers():
    with db() as conn:
        rows = conn.execute("SELECT imsi,name,apn,msisdn,created_at FROM subscribers ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/subscribers")
def create_subscriber():
    try:
        sub = validate_subscriber(request.get_json(silent=True) or {})
        result = provision_mongo(sub)
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO subscribers(imsi,name,k,opc,amf,apn,msisdn,created_at) VALUES(?,?,?,?,?,?,?,?)",
                         (sub["imsi"], sub["name"], sub["k"], sub["opc"], sub["amf"], sub["apn"], sub["msisdn"], int(time.time())))
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


@app.get("/api/sim/readers")
def sim_readers():
    tool = shutil.which("pySim-shell.py") or shutil.which("pySim-shell") or shutil.which("pySim-prog.py")
    detected = []
    try:
        from smartcard.System import readers
        detected = [str(reader) for reader in readers()]
    except Exception:
        # The PC/SC service may still be starting or no USB reader may be attached.
        pass
    return jsonify({"enabled": bool(settings()["sim_programming_enabled"]), "pysim": bool(tool),
                    "usb_visible": Path("/dev/bus/usb").exists(), "readers": detected,
                    "ready": bool(tool and detected and settings()["sim_programming_enabled"])})


@app.get("/api/logs")
def logs():
    limit = min(max(request.args.get("limit", 200, type=int), 10), 1000)
    with db() as conn:
        rows = conn.execute("SELECT id,kind,message,created_at FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return jsonify(list(reversed([dict(row) for row in rows])))


@app.post("/api/diagnostics/run")
def run_diagnostics():
    results = diagnostic_checks()
    failures = sum(1 for check in results if not check["ok"])
    event("diagnostic", f"Completed {len(results)} checks — {failures} need attention")
    return jsonify({"checks": results, "failures": failures, "created_at": int(time.time())})


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
    event("log", f"Analyzed {Path(upload.filename).name}: {len(findings)} issue patterns found")
    return jsonify({"findings": findings, "lines": len(text.splitlines()), "name": Path(upload.filename).name})


@app.get("/api/support-bundle")
def support_bundle():
    cfg = settings()
    safe_cfg = {key: value for key, value in cfg.items() if key != "mongodb_uri"}
    created = int(time.time())
    path = DATA_DIR / f"lte-support-{created}.zip"
    with db() as conn:
        recent = [dict(row) for row in conn.execute("SELECT kind,message,created_at FROM events ORDER BY id DESC LIMIT 250")]
    report = {"created_at": created, "configuration": safe_cfg, "diagnostics": diagnostic_checks(), "events": recent,
              "privacy": "MongoDB URI, subscriber keys, OPc values, and commissioning XML are excluded."}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.json", json.dumps(report, indent=2))
        archive.writestr("README.txt", "Redacted Baiamonte LTE support bundle. Subscriber secrets and Nokia commissioning data are not included.\n")
    os.chmod(path, 0o600)
    event("diagnostic", "Generated redacted support bundle")
    return send_file(path, as_attachment=True, download_name=path.name)


@app.post("/api/sim/script")
def sim_script():
    try:
        sub = validate_subscriber(request.get_json(silent=True) or {})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    cfg = settings()
    script = "\n".join([f"# Review before using with pySim-shell; profile for {sub['name']}",
        f"update_binary EF.IMSI --data {sub['imsi']}", f"# Authentication key K: {sub['k']}", f"# OPc: {sub['opc']}",
        f"# PLMN: {cfg['mcc']}-{cfg['mnc']}", "# Exact administrative authentication and card-specific commands depend on your programmable SIM."])
    fd, path = tempfile.mkstemp(prefix="pysim-profile-", suffix=".txt", dir=DATA_DIR)
    with os.fdopen(fd, "w") as handle: handle.write(script + "\n")
    os.chmod(path, 0o600)
    return send_file(path, as_attachment=True, download_name=f"pysim-{sub['imsi']}.txt")


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host=os.getenv("BIND_HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8099")), debug=False)
