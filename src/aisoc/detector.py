import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


LOG_FILE = Path("data/sample/auth_logs.json")
WINDOW_MINUTES = 5
FAILED_LOGIN_THRESHOLD = 5


def load_logs(path: Path = LOG_FILE) -> list[dict]:
    """Load synthetic authentication events from a JSON file."""
    with path.open("r", encoding="utf-8") as file:
        logs = json.load(file)

    if not isinstance(logs, list):
        raise ValueError("Expected a JSON list of authentication events.")

    return logs


def detect_failed_login_bursts(logs: list[dict]) -> list[dict]:
    """Flag account/IP pairs with repeated failed logins in a time window."""
    grouped = defaultdict(list)

    for event in logs:
        if event.get("event_type") != "login_failed":
            continue

        timestamp = datetime.fromisoformat(event["timestamp"])
        username = event["username"]
        source_ip = event["source_ip"]

        grouped[(username, source_ip)].append(timestamp)

    alerts = []
    window = timedelta(minutes=WINDOW_MINUTES)

    for (username, source_ip), timestamps in grouped.items():
        timestamps.sort()

        for start_index, start_time in enumerate(timestamps):
            matching = [
                timestamp
                for timestamp in timestamps[start_index:]
                if timestamp - start_time <= window
            ]

            if len(matching) >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "rule": "repeated_failed_logins",
                    "severity": "medium",
                    "username": username,
                    "source_ip": source_ip,
                    "failed_attempts": len(matching),
                    "window_minutes": WINDOW_MINUTES,
                    "first_seen": matching[0].isoformat(),
                    "last_seen": matching[-1].isoformat(),
                    "evidence": (
                        f"{len(matching)} failed login attempts for "
                        f"{username} from {source_ip} within "
                        f"{WINDOW_MINUTES} minutes."
                    ),
                    "verified_facts": [
                        "The supplied logs contain repeated failed login events."
                    ],
                    "uncertainty": [
                        "The pattern alone does not prove a brute-force attack.",
                        "The logs do not establish whether an attacker succeeded."
                    ]
                })
                break

    return alerts


def main() -> None:
    logs = load_logs()
    alerts = detect_failed_login_bursts(logs)

    print(f"Events loaded: {len(logs)}")
    print(f"Alerts detected: {len(alerts)}")
    print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    main()
