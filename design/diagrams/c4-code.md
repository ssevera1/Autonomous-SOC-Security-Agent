# C4 Model — Level 4: Code Diagram

Class-level view of all Python modules and their relationships.

```mermaid
classDiagram
    class Severity {
        <<enumeration>>
        LOW
        MEDIUM
        HIGH
        CRITICAL
    }

    class Verdict {
        <<enumeration>>
        MALICIOUS
        CLEAN
    }

    class Alert {
        +str id
        +str timestamp
        +Severity severity
        +str source
        +str message
    }

    class ReputationResult {
        +str ip
        +int score
        +Verdict verdict
        +str details
    }

    class LogIngestor {
        -Path filepath
        +__init__(filepath: str | Path)
        +ingest() list~Alert~
    }

    class ThreatHunterAgent {
        -LogIngestor ingestor
        -list results
        +__init__(log_file: str)
        +run() list~dict~
        -_step_extract_ip(alert: Alert) str | None
        -_step_check_reputation(ip: str) dict
        -_step_remediate(ip: str, verdict: str) str
        -_print_summary() None
    }

    class tools {
        <<module>>
        +virustotal_ip_check(ip: str) ReputationResult
    }

    class remediation {
        <<module>>
        +block_ip(ip: str) None
        +request_remediation(ip: str) bool
    }

    Alert --> Severity : severity
    ReputationResult --> Verdict : verdict
    LogIngestor --> Alert : produces
    ThreatHunterAgent --> LogIngestor : uses
    ThreatHunterAgent --> tools : calls
    ThreatHunterAgent --> remediation : calls
    tools --> ReputationResult : returns
    remediation --> remediation : block_ip()
```

## Module Dependency Graph

```
main.py
  └── threat_hunter/
        ├── agent.py
        │     ├── log_ingestor.py
        │     │     └── models.py (Alert)
        │     ├── tools.py
        │     │     └── models.py (ReputationResult, Verdict)
        │     ├── remediation.py
        │     └── models.py (Alert, Verdict)
        └── models.py (shared Pydantic models)
```
