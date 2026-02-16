# ADR-001: Use Pydantic for All Data Validation

**Status:** Accepted
**Date:** 2026-02-16
**Context:** The agent ingests external data (JSON log files) and passes structured data between components. Invalid or malformed input must not crash the agent.

## Decision

Use Pydantic v2 `BaseModel` for all data structures: `Alert`, `ReputationResult`, `Severity`, and `Verdict`.

## Rationale

- **Fail-fast validation** — Pydantic raises clear errors when data doesn't match the schema, allowing us to skip bad entries gracefully instead of hitting runtime `KeyError`s deep in the pipeline.
- **Self-documenting models** — Type annotations serve as living documentation for the data contracts between LogIngestor, Agent, and Tools.
- **Serialization for free** — `model_dump()` and `model_validate()` handle JSON round-tripping without manual dict manipulation.
- **Industry standard** — Pydantic is the de-facto validation library in modern Python (FastAPI, LangChain, etc.), so the code is immediately familiar to other engineers.

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| Plain `dataclasses` | No built-in validation; would need manual type checking |
| `marshmallow` | More verbose schema definitions; less Pythonic than Pydantic v2 |
| Raw dicts | No validation, no IDE support, error-prone |

## Trade-offs

- **Accepted:** Adds `pydantic` as a dependency (but it's lightweight and widely used)
- **Accepted:** Slightly more boilerplate than raw dicts for simple cases
- **Mitigated:** Pydantic v2 is significantly faster than v1 (Rust core)

## Consequences

- All structured data entering or leaving a component boundary must use a Pydantic model.
- Malformed alert entries are caught at ingestion time, logged as warnings, and skipped.
