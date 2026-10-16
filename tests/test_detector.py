from datetime import datetime, timedelta

from src.aisoc.detector import detect_failed_login_bursts


def test_detects_five_failed_logins():
    start = datetime.fromisoformat("2026-10-16T09:00:00")

    logs = [
        {
            "timestamp": (start + timedelta(seconds=15 * i)).isoformat(),
            "username": "admin",
            "source_ip": "203.0.113.25",
            "event_type": "login_failed",
        }
        for i in range(5)
    ]

    alerts = detect_failed_login_bursts(logs)

    assert len(alerts) == 1
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["failed_attempts"] == 5


def test_ignores_fewer_than_five_failed_logins():
    start = datetime.fromisoformat("2026-10-16T09:00:00")

    logs = [
        {
            "timestamp": (start + timedelta(seconds=15 * i)).isoformat(),
            "username": "admin",
            "source_ip": "203.0.113.25",
            "event_type": "login_failed",
        }
        for i in range(4)
    ]

    alerts = detect_failed_login_bursts(logs)

    assert alerts == []
