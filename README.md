# Autonomous Threat Hunter

An autonomous SOC security agent that ingests SIEM alerts, analyzes IP reputation via a mock VirusTotal API, and enforces **human-in-the-loop** approval before taking any remediation action.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  sample_alerts   │────▶│   LogIngestor    │────▶│  Reasoning Loop  │
│    .json         │     │  (parse & validate)    │  (extract/analyze)│
└─────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                          │
                                                          ▼
                                                 ┌──────────────────┐
                                                 │  VirusTotal API  │
                                                 │  (mock tool)     │
                                                 └────────┬─────────┘
                                                          │
                                                          ▼
                                                 ┌──────────────────┐
                                                 │  Remediation     │
                                                 │  (human approval)│
                                                 └──────────────────┘
```

### Reasoning Loop

For each alert the agent follows an explicit **Extract → Decide → Analyze → Act** loop:

1. **Extract** — Pull the IP address from the alert message via regex
2. **Decide** — Route the IP to the VirusTotal reputation check tool
3. **Analyze** — Evaluate the verdict (`Malicious` / `Clean`) and confidence score
4. **Act** — If malicious, prompt the human analyst for approval before blocking

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py                     # uses sample_alerts.json
python main.py path/to/alerts.json # use a custom log file
```

### Sample Output

```
============================================================
  ALERT ALERT-004  |  CRITICAL  |  EDR
  Possible C2 beacon detected from IP 203.0.113.42 every 60s interval
------------------------------------------------------------
  [EXTRACT]  Found IP: 203.0.113.42
  [DECIDE]   Checking IP reputation via VirusTotal...
  [ANALYZE]  Verdict: Malicious (score: 91/100)
             IP 203.0.113.42 flagged by multiple threat feeds
  [ACTION]   Threat confirmed — remediation required.

  ⚠  Requesting human approval to block IP 203.0.113.42...
     This action will add 203.0.113.42 to the firewall deny list.

  >> Do you approve blocking this IP? (Y/N): Y
  [EXECUTED] IP 203.0.113.42 has been BLOCKED in the firewall.
```

## Alert Format

Alerts are JSON objects with this schema:

```json
{
  "id": "ALERT-001",
  "timestamp": "2026-02-16T08:23:11Z",
  "severity": "HIGH",
  "source": "IDS",
  "message": "Suspicious login from IP 192.168.1.50"
}
```

Severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## Key Design Decisions

- **Pydantic validation** on all data models — malformed alerts are logged and skipped, never crash the agent
- **Human-in-the-loop** — the agent **never** auto-blocks an IP; every destructive action requires explicit analyst approval (`Y`/`N`)
- **Deterministic mock scores** — IP reputation scores are hash-derived so results are reproducible across runs
- **Structured logging** — all actions are logged to `threat_hunter.log` for audit trails
