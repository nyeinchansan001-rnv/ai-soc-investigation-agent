import httpx
from src.aisoc.agent import assign_investigation_priority, ask_local_llm


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

def test_llm_connection_error_is_handled(monkeypatch):
    from src.aisoc import agent

    def fake_post(*args, **kwargs):
        raise httpx.ConnectError("Ollama is unavailable")

    monkeypatch.setattr(agent.httpx, "post", fake_post)

    result = ask_local_llm({
        "rule_alerts": [],
        "summary": "No alerts matched the configured detection rule.",
    })

    assert "Local LLM analysis unavailable" in result["ai_analysis"]
    assert "ConnectError" in result["ai_analysis"]

def test_empty_llm_response_is_handled(monkeypatch):
    from src.aisoc import agent

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "   "}

    def fake_post(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(agent.httpx, "post", fake_post)

    result = ask_local_llm({
        "rule_alerts": [],
        "summary": "No alerts matched the configured detection rule.",
    })

    assert result["ai_analysis"] == (
        "The local model returned an empty response."
    )
    from src.aisoc import agent

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "   "}

    def fake_post(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(agent.httpx, "post", fake_post)

    result = ask_local_llm({
        "rule_alerts": [],
        "summary": "No alerts matched the configured detection rule.",
    })

    assert result["ai_analysis"] == (
        "The local model returned an empty response."
    )