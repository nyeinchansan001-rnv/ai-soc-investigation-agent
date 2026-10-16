import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


LOG_FILE = Path("data/sample/auth_logs.json")


def load_logs(path: Path = LOG_FILE) -> list[dict]:
    with path.open("r", encoding="utf-8") as file:
        logs = json.load(file)

    if not isinstance(logs, list) or not logs:
        raise ValueError("Expected a non-empty JSON list of events.")

    return logs


def build_features(logs: list[dict]) -> pd.DataFrame:
    rows = []

    for event in logs:
        rows.append({
            "failed_login": int(event.get("event_type") == "login_failed"),
            "successful_login": int(event.get("event_type") == "login_success"),
            "is_admin": int(event.get("username") == "admin"),
            "is_known_sample_ip": int(
                event.get("source_ip") == "192.0.2.10"
            ),
        })

    return pd.DataFrame(rows)


def detect_anomalies(logs: list[dict]) -> list[dict]:
    features = build_features(logs)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.15,
        random_state=42,
    )

    predictions = model.fit_predict(features)
    scores = model.decision_function(features)

    alerts = []

    for index, prediction in enumerate(predictions):
        if prediction == -1:
            event = logs[index]

            alerts.append({
                "event_index": index,
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "event_type": event.get("event_type"),
                "anomaly_score": round(float(scores[index]), 4),
                "model": "IsolationForest",
                "note": (
                    "Unusual relative to this sample only. "
                    "Investigate with other evidence before deciding severity."
                ),
            })

    return alerts


def main() -> None:
    logs = load_logs()
    alerts = detect_anomalies(logs)

    print(f"Events loaded: {len(logs)}")
    print(f"Anomalies detected: {len(alerts)}")
    print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    main()
