# C4 Model — Level 1: System Context Diagram

Shows how the Autonomous Threat Hunter fits into the broader SOC ecosystem.

```mermaid
C4Context
    title System Context — Autonomous Threat Hunter

    Person(analyst, "SOC Analyst", "Reviews alerts and approves remediation actions")

    System(hunter, "Autonomous Threat Hunter", "Ingests SIEM alerts, analyzes IP reputation, and recommends remediation with human approval")

    System_Ext(siem, "SIEM Platform", "Generates alert log files in JSON format")
    System_Ext(vt, "VirusTotal API", "External threat intelligence — IP reputation lookups")
    System_Ext(fw, "Firewall / WAF", "Enforces IP block rules when approved")

    Rel(siem, hunter, "Exports JSON alert logs")
    Rel(hunter, vt, "Queries IP reputation", "HTTPS / REST")
    Rel(hunter, fw, "Pushes block rules", "API / CLI")
    Rel(analyst, hunter, "Approves or denies remediation", "Terminal Y/N")
    Rel(hunter, analyst, "Presents findings and asks for approval")
```

## Data Flow Summary

| Flow | Source | Destination | Protocol | Latency Req |
|------|--------|-------------|----------|-------------|
| Alert ingestion | SIEM | Threat Hunter | File read (JSON) | Batch — seconds |
| IP reputation | Threat Hunter | VirusTotal | HTTPS REST | < 2s per query |
| Approval prompt | Threat Hunter | SOC Analyst | Terminal I/O | Human-speed |
| IP block | Threat Hunter | Firewall | API/CLI | < 1s |
