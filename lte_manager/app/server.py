import csv
import io
import json
import ipaddress
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
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
        "ue_subnet": "45.45.0.0/16", "epc_uplink_interface": "eth0",
        "epc_routing_management_enabled": False, "epc_ssh_user": "root", "epc_ssh_port": 22,
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
    subnet = str(cfg.get("ue_subnet", "45.45.0.0/16"))
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
        event("console", f"Ran read-only EPC console tool: {action['label']}")
        return jsonify({"ok": True, "action": action_id, "label": action["label"],
                        "host": cfg["host"], "output": output, "checked_at": int(time.time())})
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
    public_config = {key: value for key, value in settings().items() if key != "mongodb_uri"}
    return render_template("index.html", config=public_config)


@app.get("/api/overview")
def overview():
    cfg = settings()
    status = sample_network()
    with db() as conn:
        ue_count = conn.execute("SELECT COUNT(*) FROM subscribers").fetchone()[0]
        events = [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 8")]
        route_row = conn.execute("SELECT value FROM app_settings WHERE key='routing_last_status'").fetchone()
        verified_row = conn.execute("SELECT value FROM app_settings WHERE key='routing_last_verified'").fetchone()
        inventory_rows = conn.execute("SELECT device_type,critical FROM subscribers").fetchall()
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
    return jsonify({"epc": status["epc"], "bts": status["bts"],
                    "routing": routing, "subscriber_count": ue_count, "events": events,
                    "inventory": inventory,
                    "config": {k: v for k, v in cfg.items() if k != "mongodb_uri"}})


@app.get("/api/subscribers")
def list_subscribers():
    with db() as conn:
        rows = conn.execute("SELECT imsi,name,zone,device_type,critical,notes,apn,msisdn,created_at FROM subscribers ORDER BY zone,name").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/subscribers")
def create_subscriber():
    try:
        sub = validate_subscriber(request.get_json(silent=True) or {})
        result = provision_mongo(sub)
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO subscribers(imsi,name,k,opc,amf,apn,msisdn,zone,device_type,critical,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                         (sub["imsi"], sub["name"], sub["k"], sub["opc"], sub["amf"], sub["apn"], sub["msisdn"],
                          sub["zone"], sub["device_type"], int(sub["critical"]), sub["notes"], int(time.time())))
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
