# C4 Model — Level 2: Container Diagram

Shows the internal containers (processes, modules) of the Threat Hunter system.

```mermaid
C4Container
    title Container Diagram — Autonomous Threat Hunter

    Person(analyst, "SOC Analyst")

    Container_Boundary(hunter, "Autonomous Threat Hunter") {
        Container(main, "main.py", "Python", "Entry point — configures logging, launches agent")
        Container(ingestor, "LogIngestor", "Python", "Reads and validates JSON alert files using Pydantic")
        Container(agent, "ThreatHunterAgent", "Python", "Core reasoning loop — Extract, Decide, Analyze, Act")
        Container(tools, "Tools (VirusTotal)", "Python", "Mock threat intel API — returns IP reputation scores")
        Container(remediation, "Remediation", "Python", "Human-in-the-loop approval gate + block_ip executor")
    }

    System_Ext(siem, "SIEM (JSON Logs)")
    System_Ext(fw, "Firewall")

    Rel(siem, ingestor, "Provides alert files")
    Rel(main, agent, "Starts reasoning loop")
    Rel(agent, ingestor, "Ingests alerts")
    Rel(agent, tools, "Queries IP reputation")
    Rel(agent, remediation, "Requests remediation")
    Rel(remediation, analyst, "Prompts for Y/N approval")
    Rel(remediation, fw, "Executes block_ip()")
```

## Container Responsibilities

| Container | Input | Output | Key Constraint |
|-----------|-------|--------|----------------|
| LogIngestor | JSON file path | `list[Alert]` | Skips malformed entries, never crashes |
| ThreatHunterAgent | Alert list | Summary results | Sequential per-alert reasoning |
| VirusTotal Tool | IP string | `ReputationResult` | Deterministic mock — no network I/O |
| Remediation | IP + verdict | Block/Skip action | **Must** get human approval first |
