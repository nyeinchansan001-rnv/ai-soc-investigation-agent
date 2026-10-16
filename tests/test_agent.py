
from src.aisoc.agent import assign_investigation_priority


def test_five_failed_logins_get_medium_priority():
    alert = {
        "failed_attempts": 5,
        "successful_login_count": 0,
    }

    result = assign_investigation_priority({
        "rule_alerts": [alert]
    })

    assert result["rule_alerts"][0]["investigation_priority"] == "medium"


def test_related_successful_login_gets_high_priority():
    alert = {
        "failed_attempts": 5,
        "successful_login_count": 1,
    }

    result = assign_investigation_priority({
        "rule_alerts": [alert]
    })

    assert result["rule_alerts"][0]["investigation_priority"] == "high"


def test_fewer_failed_logins_get_low_priority():
    alert = {
        "failed_attempts": 2,
        "successful_login_count": 0,
    }

    result = assign_investigation_priority({
        "rule_alerts": [alert]
    })

    assert result["rule_alerts"][0]["investigation_priority"] == "low"
