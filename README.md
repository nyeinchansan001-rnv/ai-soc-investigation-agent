# AI SOC Investigation Agent

A local, AI-assisted Security Operations Center (SOC) investigation prototype built with Python, LangGraph, scikit-learn, and Ollama.

## Project Goal

This project demonstrates how a SOC Tier 1 analyst workflow can be supported by automated authentication-log analysis, evidence enrichment, investigation prioritization, and local LLM-generated explanations.

It is designed for cybersecurity learning and defensive research using synthetic authentication logs.

## Features

- Load authentication events from JSON.
- Detect repeated failed logins using configurable Python detection rules.
- Experiment with anomaly detection using Isolation Forest.
- Enrich alerts with related successful-login events.
- Assign heuristic investigation priorities.
- Orchestrate investigation stages using LangGraph.
- Generate preliminary explanations with a locally running Ollama LLM.
- Save structured investigation results as JSON.
- Test detection, prioritization, and LLM error handling with pytest.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and detection logic |
| LangGraph | Orchestrates the investigation workflow |
| scikit-learn | Isolation Forest anomaly-detection experiment |
| pandas | Data handling and analysis support |
| Ollama (`llama3.2:3b`) | Local LLM-generated investigation explanations |
| HTTPX | Sends requests to the Ollama API |
| pytest | Automated testing |

## Architecture and Workflow

The investigation agent follows this sequence:

1. **Load logs** — Read authentication events from the sample JSON file.
2. **Detect events** — Identify repeated failed logins using a rule-based detector.
3. **Enrich alerts** — Look for related successful logins in the configured time range.
4. **Assign priority** — Apply a heuristic to assign a low, medium, or high investigation priority.
5. **Summarize evidence** — Prepare a concise summary based on the detector output.
6. **Generate AI analysis** — Ask the local LLM to explain the supplied evidence, uncertainties, and recommended read-only investigation steps.
7. **Save the report** — Write the results to `reports/latest_report.json`.

The Isolation Forest module is a separate anomaly-detection experiment. It should not be assumed to contribute to the LangGraph investigation workflow unless explicitly integrated into that workflow.

## Detection Logic

The rule-based detector looks for repeated failed login events grouped by username and source IP within a configured time window.

The current configuration uses a threshold of five failed login attempts within five minutes.

This pattern can justify further investigation, but it does not by itself confirm a brute-force attack or account compromise.

The investigation priority is a prototype heuristic, not a standardized severity rating. A high priority indicates a need for closer review, not proof that malicious activity occurred.

## Project Structure

```text
aisoc/
├── data/
│   └── sample/
│       └── auth_logs.json
├── reports/
│   └── latest_report.json       # Generated at runtime
├── src/
│   └── aisoc/
│       ├── agent.py
│       ├── detector.py
│       └── ml_detector.py
├── tests/
│   ├── test_agent.py
│   └── test_detector.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Setup

Create and activate a Python virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Install and start Ollama if it is not already available, then download the model:

```bash
ollama pull llama3.2:3b
```

Ensure the Ollama service is running before executing the investigation workflow.

## Run the Project

Run the rule-based detector:

```bash
python -m src.aisoc.detector
```

Run the separate ML anomaly-detection experiment:

```bash
python -m src.aisoc.ml_detector
```

Run the LangGraph investigation workflow and generate a report:

```bash
python -m src.aisoc.agent
```

Run the automated tests:

```bash
python -m pytest -q
```

The current automated test suite has 13 passing tests in the latest verified run.

The investigation report is saved to:

```text
reports/latest_report.json
```

The report may be regenerated when the agent runs again.

## Testing

The automated tests cover detection thresholds, event grouping, time-window boundaries, successful-login handling, investigation-priority assignment, and LLM error or empty-response handling.

Passing tests indicate that the tested behaviors work as expected. They do not establish real-world detection accuracy or prove that the system is production-ready.

## Important Limitations

- The dataset is small and synthetic.
- Isolation Forest results from a small dataset may be unreliable.
- An anomaly is not proof of malicious activity.
- The LLM may produce incorrect or unsupported statements; verify its analysis against the original logs.
- Documentation-only sample IP addresses are not real attacker indicators.
- Investigation priorities are heuristic and require analyst judgment.
- The project does not automatically block IPs, disable accounts, or modify systems.
- This prototype is not a production-ready SIEM or autonomous incident-response platform.

## Future Improvements

- Add more diverse synthetic authentication events.
- Evaluate ML performance using a larger labeled dataset.
- Add automated checks for unsupported claims in AI-generated reports.
- Expand testing for malformed input and unexpected API responses.
- Integrate additional defensive log sources in a controlled lab.
- Improve report formatting and document investigation evidence more clearly.

## Disclaimer

Use only synthetic data or logs you are authorized to investigate. All findings are preliminary, and human verification is required before taking action.