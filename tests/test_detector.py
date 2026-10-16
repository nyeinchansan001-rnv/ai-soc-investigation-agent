
from datetime import datetime, timedelta

from src.aisoc.detector import detect_failed_login_bursts


def make_logs(count, username="admin",
              source_ip="203.0.113.25",
              event_type="login_failed"):
    start = datetime.fromisoformat("2026-10-16T09:00:00")

    return [
        {
            "timestamp": (
                start + timedelta(seconds=15 * i)
            ).isoformat(),
            "username": username,
            "source_ip": source_ip,
            "event_type": event_type,
        }
        for i in range(count)
    ]


def test_detects_five_failed_logins():
    alerts = detect_failed_login_bursts(make_logs(5))

    assert len(alerts) == 1
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["failed_attempts"] == 5


def test_ignores_fewer_than_five_failed_logins():
    alerts = detect_failed_login_bursts(make_logs(4))

    assert alerts == []


def test_different_usernames_are_not_combined():
    logs = (
        make_logs(3, username="admin")
        + make_logs(2, username="alex")
    )

    alerts = detect_failed_login_bursts(logs)

    assert alerts == []


def test_different_source_ips_are_not_combined():
    logs = (
        make_logs(3, source_ip="203.0.113.25")
        + make_logs(2, source_ip="192.0.2.10")
    )

    alerts = detect_failed_login_bursts(logs)

    assert alerts == []


def test_successful_logins_do_not_count_as_failures():
    logs = make_logs(5, event_type="login_success")

    alerts = detect_failed_login_bursts(logs)

    assert alerts == []

def test_detects_five_failed_logins_within_five_minutes():
    start = datetime.fromisoformat("2026-10-16T09:00:00")

    logs = [
        {
            "timestamp": (
                start + timedelta(minutes=i)
            ).isoformat(),
            "username": "admin",
            "source_ip": "203.0.113.25",
            "event_type": "login_failed",
        }
        for i in range(5)
    ]

    alerts = detect_failed_login_bursts(logs)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 5


def test_does_not_detect_five_failed_logins_spread_over_six_minutes():
    start = datetime.fromisoformat("2026-10-16T09:00:00")

    logs = [
        {
            "timestamp": (
                start + timedelta(minutes=2 * i)
            ).isoformat(),
            "username": "admin",
            "source_ip": "203.0.113.25",
            "event_type": "login_failed",
        }
        for i in range(5)
    ]

    alerts = detect_failed_login_bursts(logs)

    assert alerts == []
