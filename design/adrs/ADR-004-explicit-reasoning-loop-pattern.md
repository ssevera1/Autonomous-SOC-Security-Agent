# ADR-004: Explicit Reasoning Loop Pattern (Extract → Decide → Analyze → Act)

**Status:** Accepted
**Date:** 2026-02-16
**Context:** The agent processes alerts and must make decisions about each one. The decision logic could be implemented as a monolithic function, a pipeline, an event-driven system, or an explicit step-by-step loop.

## Decision

Implement the agent's core logic as an explicit four-step reasoning loop with named methods:

1. `_step_extract_ip()` — Parse structured data from raw alert text
2. `_step_check_reputation()` — Route to the appropriate threat intel tool
3. `_step_remediate()` — Evaluate findings and dispatch remediation
4. `_print_summary()` — Aggregate and report results

Each step prints its reasoning to stdout with labeled prefixes (`[EXTRACT]`, `[DECIDE]`, `[ANALYZE]`, `[ACTION]`).

## Rationale

- **Auditability** — Every decision the agent makes is visible in the terminal output. A SOC analyst can trace exactly why an IP was flagged and what action was taken (or not taken).
- **Debuggability** — When something goes wrong, the labeled output immediately shows which reasoning step failed.
- **Extensibility** — New steps (e.g., GeoIP lookup, WHOIS enrichment) slot into the loop as additional `_step_*` methods without restructuring the pipeline.
- **Alignment with AI agent patterns** — The Extract-Decide-Act pattern mirrors the Observe-Orient-Decide-Act (OODA) loop used in autonomous agent frameworks (ReAct, LangChain agents).

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| Monolithic `process_alert()` | Poor separation of concerns; hard to test individual steps |
| Event-driven / pub-sub | Over-engineered for a sequential pipeline; adds async complexity |
| LangChain / CrewAI framework | Heavy dependency for a focused agent; obscures the reasoning logic we want to demonstrate |

## Trade-offs

- **Accepted:** Sequential processing — alerts are handled one at a time, not in parallel. Acceptable for a terminal-based agent where human approval is inherently sequential.
- **Accepted:** Regex-based IP extraction is simple but won't handle IPv6 or multi-IP alerts. Sufficient for the current scope.
- **Mitigated:** Each step is a separate method, so parallelization or batch processing can be added later without changing the step logic.

## Consequences

- All agent reasoning must go through named `_step_*` methods — no inline decision logic in `run()`.
- Every step must print a labeled status line for observability.
- The step interface is stable: `(Alert) → IP → ReputationResult → Action`.
