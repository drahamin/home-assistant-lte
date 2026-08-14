import time

from server import EPC_KNOWN_HOSTS, EPC_SSH_KEY, event, routing_check, sample_network, settings


def run():
    event("monitor", "Availability monitoring started")
    failures = 0
    last_traffic_sample = 0
    while True:
        started = time.monotonic()
        try:
            sample_network(process_alerts=True)
            if failures:
                event("monitor", "Availability monitoring recovered")
            failures = 0
        except Exception as exc:
            failures += 1
            if failures == 1 or failures % 10 == 0:
                event("monitor", f"Monitoring check failed ({failures} consecutive): {exc}")
        cfg = settings()
        now = time.time()
        traffic_interval = min(max(int(cfg.get("traffic_monitor_interval_seconds", 300)), 60), 3600)
        if (cfg.get("epc_routing_management_enabled") and EPC_SSH_KEY.exists() and EPC_KNOWN_HOSTS.exists()
                and now - last_traffic_sample >= traffic_interval):
            try:
                routing_check()
            except Exception:
                # Connectivity failures are already represented by network status; avoid log spam.
                pass
            last_traffic_sample = now
        interval = min(max(int(cfg.get("monitor_interval_seconds", 60)), 30), 900)
        time.sleep(max(1, interval - (time.monotonic() - started)))


if __name__ == "__main__":
    run()
