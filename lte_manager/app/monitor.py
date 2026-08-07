import time

from server import event, sample_network


def run():
    event("monitor", "Availability monitoring started")
    while True:
        try:
            sample_network(process_alerts=True)
        except Exception as exc:
            event("monitor", f"Monitoring check failed: {exc}")
        time.sleep(60)


if __name__ == "__main__":
    run()
