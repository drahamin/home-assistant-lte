import time

from server import event, sample_network, settings


def run():
    event("monitor", "Availability monitoring started")
    failures = 0
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
        interval = min(max(int(settings().get("monitor_interval_seconds", 60)), 30), 900)
        time.sleep(max(1, interval - (time.monotonic() - started)))


if __name__ == "__main__":
    run()
