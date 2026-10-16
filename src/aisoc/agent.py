import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import TypedDict


import httpx
from langgraph.graph import END, START, StateGraph

from src.aisoc.detector import detect_failed_login_bursts, load_logs


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"
REPORT_DIR = Path("reports")


class InvestigationState(TypedDict):
    logs: list[dict]
    rule_alerts: list[dict]
    summary: str
    ai_analysis: str


def detect_events(state: InvestigationState) -> dict:
    return {"rule_alerts": detect_failed_login_bursts(state["logs"])}


def summarize_findings(state: InvestigationState) -> dict:
    alerts = state["rule_alerts"]

    if not alerts:
        summary = "No alerts matched the configured detection rule."
    else:
        summary = " ".join(alert["evidence"] for alert in alerts)

    return {"summary": summary}


def enrich_alerts(state: InvestigationState) -> dict:
    """Attach related successful logins as additional evidence."""
    enriched_alerts = []

    for alert in state["rule_alerts"]:
        related_successes = []

        first_seen = datetime.fromisoformat(alert["first_seen"])
        last_seen = datetime.fromisoformat(alert["last_seen"])

        for event in state["logs"]:
            if event.get("event_type") != "login_success":
                continue

            if event.get("username") != alert["username"]:
                continue

            if event.get("source_ip") != alert["source_ip"]:
                continue

            timestamp = datetime.fromisoformat(event["timestamp"])

            if first_seen <= timestamp <= last_seen + timedelta(minutes=5):
                related_successes.append({
                    "timestamp": event["timestamp"],
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "event_type": "login_success",
                })

        enriched_alerts.append({
            **alert,
            "related_successful_logins": related_successes,
            "successful_login_count": len(related_successes),
        })

    return {"rule_alerts": enriched_alerts}


def assign_investigation_priority(state: InvestigationState) -> dict:
    """Assign a review priority using explicit alert evidence."""
    prioritized_alerts = []

    for alert in state["rule_alerts"]:
        failed_attempts = alert.get("failed_attempts", 0)
        successful_login_count = alert.get("successful_login_count", 0)

        if successful_login_count > 0:
            priority = "high"
        elif failed_attempts >= 5:
            priority = "medium"
        else:
            priority = "low"

        prioritized_alerts.append({
            **alert,
            "investigation_priority": priority,
            "priority_reason": (
                f"{failed_attempts} failed login attempts; "
                f"{successful_login_count} related successful logins."
            ),
        })

    return {"rule_alerts": prioritized_alerts}


def ask_local_llm(state: InvestigationState) -> dict:
    evidence = {
        "rule_alerts": state["rule_alerts"],
        "summary": state["summary"],
    }

    prompt = f"""
You are an assistant for a SOC Tier 1 analyst.
Analyze ONLY the supplied detector output.
Do not invent events, users, or IP reputation.
Do not claim an attack is confirmed without evidence.
Separate observed facts from possible explanations.
Mention limitations and recommend read-only investigation steps.
Never automatically block IPs or change accounts.

Detector output:
{json.dumps(evidence, indent=2)}

Write a concise report with these headings:
1. Observed evidence
2. Possible interpretation
3. Confidence and limitations
4. Recommended next steps
"""

    try:
        response = httpx.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=120.0,
        )
        response.raise_for_status()
        analysis = response.json().get("response", "").strip()
        if not analysis:
            analysis = "The local model returned an empty response."

    except (httpx.HTTPError, ValueError) as error:
        analysis = (
            "Local LLM analysis unavailable. "
            f"{type(error).__name__}: {error}"
        )

    return {"ai_analysis": analysis}



builder = StateGraph(InvestigationState)
builder.add_node("detect_events", detect_events)
builder.add_node("enrich_alerts", enrich_alerts)
builder.add_node("assign_investigation_priority", assign_investigation_priority)
builder.add_node("summarize_findings", summarize_findings)
builder.add_node("ask_local_llm", ask_local_llm)

builder.add_edge(START, "detect_events")
builder.add_edge("detect_events", "enrich_alerts")
builder.add_edge("enrich_alerts", "assign_investigation_priority")
builder.add_edge("assign_investigation_priority", "summarize_findings")
builder.add_edge("summarize_findings", "ask_local_llm")
builder.add_edge("ask_local_llm", END)

investigation_graph = builder.compile()



def main() -> None:
    logs = load_logs()

    result = investigation_graph.invoke({
        "logs": logs,
        "rule_alerts": [],
        "summary": "",
        "ai_analysis": "",
    })

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "project": "AI SOC Investigation Agent",
        "events_analyzed": len(result["logs"]),
        "alerts_found": len(result["rule_alerts"]),
        "evidence_summary": result["summary"],
        "rule_alerts": result["rule_alerts"],
        "ai_analysis": result["ai_analysis"],
        "disclaimer": (
            "Preliminary analysis only. LLM output is not verified evidence. "
            "Confirm findings using authorized logs and other evidence."
        ),
    }

    report_path = REPORT_DIR / "latest_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Investigation workflow completed.")
    print(f"Events analyzed: {report['events_analyzed']}")
    print(f"Alerts found: {report['alerts_found']}")
    print(f"JSON report saved: {report_path}")
    print(f"Summary: {report['evidence_summary']}")


if __name__ == "__main__":
    main()
