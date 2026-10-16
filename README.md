# AI SOC Investigation Agent

A local, AI-assisted Security Operations Center (SOC) investigation project built with Python, LangGraph, scikit-learn, and Ollama.

## Project Goal

Help a SOC Tier 1 analyst review authentication logs, identify suspicious patterns, and generate a preliminary investigation report.

This project is for learning and defensive security research using synthetic sample logs.

## Features

- Load authentication events from JSON.
- Detect repeated failed logins using a Python rule-based detector.
- Experiment with anomaly detection using Isolation Forest.
- Orchestrate investigation steps with LangGraph.
- Generate investigation explanations with a locally running Ollama LLM.
- Save structured investigation results as JSON.
- Test detection logic with pytest.

## Technology Stack

- Python
- LangGraph
- scikit-learn
- pandas
- Ollama (`llama3.2:3b`)
- HTTPX
- pytest

## Workflow

1. Load sample authentication logs.
2. Detect repeated failed logins.
3. Summarize evidence from the detection rule.
4. Ask the local LLM to explain the findings and suggest read-only investigation steps.
5. Save the investigation report to `reports/latest_report.json`.

## Project Structure

```text
aisoc/
├── data/
│   └── sample/
│       └── auth_logs.json
├── reports/
├── src/
│   └── aisoc/
│       ├── agent.py
│       ├── detector.py
│       └── ml_detector.py
├── tests/
│   └── test_detector.py
├── .gitignore
├── requirements.txt
└── README.md
exit
## Setup

Create and activate a Python virtual environment:

    python3.12 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    python -m pip install -r requirements.txt

Ensure Ollama is running and the model is available:

    ollama pull llama3.2:3b

## Run the Project

Rule-based detection:

    python -m src.aisoc.detector

ML anomaly detection:

    python -m src.aisoc.ml_detector

LangGraph investigation workflow with the local LLM:

    python -m src.aisoc.agent

Run automated tests:

    python -m pytest -q

The generated report is saved to `reports/latest_report.json`.

## Important Limitations

- The current dataset is small and synthetic.
- An anomaly is not proof of malicious activity.
- The LLM may produce incorrect statements. Verify findings against the original logs.
- The sample IP addresses are documentation-only IPs, not verified attacker indicators.
- The project does not automatically block IPs, disable accounts, or modify systems.
- This is a learning prototype, not a production-ready SIEM.

## Future Improvements

- Add more synthetic authentication events.
- Improve ML features and evaluate anomaly detection.
- Add stronger validation of AI-generated reports.
- Expand automated tests.
- Explore integration with a defensive log-monitoring platform.

## Disclaimer

Use only synthetic data or logs you are authorized to investigate. Findings are preliminary and require human verification.