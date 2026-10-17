import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from src.aisoc.agent import investigation_graph

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_FILE = BASE_DIR / "data" / "sample" / "auth_logs.json"

st.set_page_config(
    page_title="Sentinel | AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');

:root { color-scheme: dark; }
.stApp {
    background: #080d18;
    color: #e7edf7;
    font-family: 'DM Sans', sans-serif;
}
[data-testid="stHeader"] { background: rgba(8,13,24,.92); }
[data-testid="stSidebar"] {
    background: #0d1423;
    border-right: 1px solid #202b40;
}
.block-container { padding-top: 1.8rem; max-width: 1500px; }
h1, h2, h3 { color: #edf4ff !important; letter-spacing: -.4px; }
p, label { color: #a8b6ca; }
.eyebrow {
    color: #69e3bd; font-family: 'DM Mono', monospace;
    font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
}
.hero {
    background: linear-gradient(120deg,#111e33,#101728 65%,#102b30);
    border: 1px solid #26364c; border-radius: 16px;
    padding: 26px 28px; margin: 8px 0 24px;
}
.hero p { margin-bottom: 0; color: #a9bad0; }
.kpi {
    background: #101827; border: 1px solid #263249;
    border-radius: 12px; padding: 17px 18px; min-height: 112px;
}
.kpi-label {
    font-size: 11px; color: #94a7c1; text-transform: uppercase;
    letter-spacing: 1.1px;
}
.kpi-value {
    color: #f2f6ff; font-size: 30px; font-weight: 700;
    margin-top: 8px; line-height: 1.2;
}
.kpi-note { color: #7f92ad; font-size: 12px; margin-top: 6px; }
.section-label {
    color: #69e3bd; font-family: 'DM Mono', monospace;
    font-size: 11px; letter-spacing: 1.5px; margin: 25px 0 10px;
}
.alert-card {
    background: #111b2b; border: 1px solid #2b3b53;
    border-left: 4px solid #f2b95d; border-radius: 10px;
    padding: 16px 18px; margin-bottom: 12px;
}
.priority-high { border-left-color: #ff6b79; }
.priority-medium { border-left-color: #f2b95d; }
.priority-low { border-left-color: #69e3bd; }
.small-muted { color: #91a2bb; font-size: 12px; }
div[data-testid="stMetric"] {
    background: #101827; border: 1px solid #263249;
    border-radius: 12px; padding: 12px 16px;
}
.stButton > button[kind="primary"] {
    background: #69e3bd; color: #07151a; border: 0;
    font-weight: 700; border-radius: 8px;
}
.stButton > button { border-radius: 8px; }
hr { border-color: #263249; }
</style>
""", unsafe_allow_html=True)


def load_sample():
    with SAMPLE_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_events(events):
    if not isinstance(events, list) or not events:
        raise ValueError("JSON must contain a non-empty list of event objects.")

    required = {"timestamp", "username", "source_ip", "event_type"}

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event {index + 1} must be a JSON object.")

        missing = required - event.keys()
        if missing:
            raise ValueError(
                f"Event {index + 1} is missing: {', '.join(sorted(missing))}"
            )

        if event["event_type"] not in {"login_failed", "login_success"}:
            raise ValueError(
                f"Event {index + 1} has an unsupported event_type."
            )

        try:
            datetime.fromisoformat(
                str(event["timestamp"]).replace("Z", "+00:00")
            )
        except ValueError:
            raise ValueError(f"Event {index + 1} has an invalid timestamp.")

    return events


def make_report(events, result):
    return {
        "generated_at": datetime.now().astimezone().isoformat(),
        "project": "AI SOC Investigation Agent",
        "mode": "LangGraph workflow",
        "events_analyzed": len(events),
        "failed_login_events": sum(
            e["event_type"] == "login_failed" for e in events
        ),
        "alerts_found": len(result["rule_alerts"]),
        "evidence_summary": result["summary"],
        "rule_alerts": result["rule_alerts"],
        "ai_analysis": result["ai_analysis"],
        "disclaimer": (
            "Preliminary analysis only. LLM output is not verified evidence. "
            "Confirm findings using authorized logs and other evidence. "
            "Sample documentation IPs do not represent real attackers."
        ),
    }


with st.sidebar:
    st.markdown('<div class="eyebrow">SENTINEL / SOC CONSOLE</div>',
                unsafe_allow_html=True)
    st.title("🛡️ Investigation")
    st.caption("AI-assisted authentication log triage")
    st.divider()

    st.markdown("**DATA SOURCE**")
    source_choice = st.radio(
        "Choose event source",
        ["Built-in sample", "Upload JSON"],
        label_visibility="collapsed",
    )

    uploaded_file = None
    if source_choice == "Upload JSON":
        uploaded_file = st.file_uploader(
            "Authentication events", type=["json"]
        )

    st.divider()
    st.markdown("**DETECTION RULE**")
    st.caption("5+ failed logins")
    st.caption("Within a 5-minute window")
    st.caption("Grouped by username + source IP")
    st.divider()
    st.markdown("**WORKFLOW**")
    st.caption("01 · Rule detection")
    st.caption("02 · Evidence enrichment")
    st.caption("03 · Investigation priority")
    st.caption("04 · Local LLM analysis")
    st.divider()
    st.caption("Prototype · Human review required")


st.markdown('<div class="eyebrow">SECURITY OPERATIONS / AUTHENTICATION</div>',
            unsafe_allow_html=True)
st.title("AI SOC Investigation Agent")

st.markdown("""
<div class="hero">
  <div class="eyebrow">INVESTIGATION WORKSPACE</div>
  <h2 style="margin:8px 0 8px;">Authentication Threat Triage</h2>
  <p>Review login activity, identify repeated failures, enrich evidence,
  and generate a structured investigation report.</p>
</div>
""", unsafe_allow_html=True)

events = None

try:
    if source_choice == "Built-in sample":
        events = validate_events(load_sample())
        st.caption("Using synthetic sample data from the project repository.")
    elif uploaded_file is not None:
        uploaded_data = json.load(uploaded_file)
        events = validate_events(uploaded_data)
        st.caption(f"Uploaded dataset · {len(events)} event(s)")
    else:
        st.info("Upload a JSON event list from the sidebar to begin.")
except (ValueError, OSError, json.JSONDecodeError) as exc:
    st.error(f"Could not load events: {exc}")

if events:
    event_df = pd.DataFrame(events)
    failed_count = sum(e["event_type"] == "login_failed" for e in events)
    success_count = sum(e["event_type"] == "login_success" for e in events)

    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, note in [
        (c1, "Total events", len(events), "Authentication records"),
        (c2, "Failed logins", failed_count, "Observed failure events"),
        (c3, "Successful logins", success_count, "Observed success events"),
        (c4, "Detection threshold", "5 / 5m", "Failures per user + IP"),
    ]:
        with col:
            st.markdown(
                f'<div class="kpi"><div class="kpi-label">{label}</div>'
                f'<div class="kpi-value">{value}</div>'
                f'<div class="kpi-note">{note}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown('<div class="section-label">01 / RAW AUTHENTICATION EVENTS</div>',
                unsafe_allow_html=True)
    st.dataframe(
        event_df,
        use_container_width=True,
        hide_index=True,
        height=min(300, 40 + 35 * len(event_df)),
    )

    run_analysis = st.button(
        "▶  Run investigation workflow",
        type="primary",
        use_container_width=True,
    )

    if run_analysis:
        try:
            with st.spinner(
                "Running detection, enrichment, prioritization and AI analysis..."
            ):
                result = investigation_graph.invoke({
                    "logs": events,
                    "rule_alerts": [],
                    "summary": "",
                    "ai_analysis": "",
                })
                report = make_report(events, result)

            st.session_state["soc_report"] = report
            st.session_state["soc_events"] = events
            st.success("Investigation workflow completed.")
        except Exception as exc:
            st.error(
                "The investigation workflow could not complete. "
                "Check the terminal for details."
            )
            st.exception(exc)

    report = st.session_state.get("soc_report")
    if report and st.session_state.get("soc_events") == events:
        st.markdown('<div class="section-label">02 / INVESTIGATION OVERVIEW</div>',
                    unsafe_allow_html=True)

        a1, a2, a3 = st.columns(3)
        a1.metric("Events analyzed", report["events_analyzed"])
        a2.metric("Alerts detected", report["alerts_found"])
        priorities = [
            alert.get("investigation_priority", "low").lower()
            for alert in report["rule_alerts"]
        ]
        a3.metric("High-priority alerts", priorities.count("high"))

        alerts = report["rule_alerts"]
        if alerts:
            st.markdown('<div class="section-label">03 / DETECTED ALERTS</div>',
                        unsafe_allow_html=True)

            for number, alert in enumerate(alerts, start=1):
                priority = alert.get("investigation_priority", "low").lower()
                with st.container(border=True):
                    st.markdown(
                        f'<div class="alert-card priority-{priority}">'
                        f'<div class="eyebrow">ALERT {number:02d} · '
                        f'{priority.upper()} PRIORITY</div>'
                        f'<h3 style="margin:7px 0;">Repeated Failed Logins</h3>'
                        f'<p>{alert.get("evidence", "Evidence unavailable")}</p>'
                        f'<div class="small-muted">Account: '
                        f'{alert.get("username", "Unknown")} &nbsp; · &nbsp; '
                        f'Source IP: {alert.get("source_ip", "Unknown")}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

                    detail1, detail2, detail3 = st.columns(3)
                    detail1.metric("Failed attempts", alert.get("failed_attempts", 0))
                    detail2.metric(
                        "Related successful logins",
                        alert.get("successful_login_count", 0),
                    )
                    detail3.metric(
                        "Priority",
                        priority.upper(),
                    )

                    with st.expander("Review evidence and limitations"):
                        st.write("**Observed facts**")
                        st.write(alert.get("verified_facts", []))
                        st.write("**Uncertainty**")
                        st.write(alert.get("uncertainty", []))
                        st.write("**Priority reason**")
                        st.write(alert.get("priority_reason", "Not provided"))
                        st.write("**Related successful logins**")
                        st.json(alert.get("related_successful_logins", []))
        else:
            st.success(
                "No alerts matched the configured detection rule. "
                "This does not prove the activity is safe."
            )

        st.markdown('<div class="section-label">04 / AI INVESTIGATION NOTES</div>',
                    unsafe_allow_html=True)
        analysis = report.get("ai_analysis", "")
        if "Local LLM analysis unavailable" in analysis:
            st.warning(
                "Local Ollama model is unavailable in this environment. "
                "Rule-based investigation still ran; AI analysis was not generated."
            )
            st.code(analysis)
        else:
            st.markdown(analysis)

        st.markdown('<div class="section-label">05 / EXPORT REPORT</div>',
                    unsafe_allow_html=True)
        st.download_button(
            "Download investigation report (JSON)",
            data=json.dumps(report, indent=2, ensure_ascii=False),
            file_name="soc_investigation_report.json",
            mime="application/json",
            use_container_width=True,
        )

        st.caption(
            "Priority is a triage aid, not proof of compromise. "
            "Verify findings against authorized source logs."
        )

st.divider()
st.caption(
    "AI SOC Investigation Agent · LangGraph · Rule-based detection · "
    "Optional local Ollama LLM · Defensive demonstration only"
)
