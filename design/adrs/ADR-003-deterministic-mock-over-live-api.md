# ADR-003: Deterministic Mock API Over Live VirusTotal Integration

**Status:** Accepted
**Date:** 2026-02-16
**Context:** The agent needs threat intelligence data to evaluate IP reputation. VirusTotal provides a real API, but integrating it introduces external dependencies, rate limits, API key management, and non-deterministic results.

## Decision

Use a deterministic mock implementation of `virustotal_ip_check()` that derives reputation scores from MD5 hashes of the IP address, with a hard-coded set of known-malicious IPs for demo scenarios.

## Rationale

- **Reproducibility** — Hash-based scoring ensures identical results across runs, environments, and demos. No flaky tests or "it worked on my machine" issues.
- **Zero infrastructure** — No API keys, no network access, no rate limit handling. The agent runs fully offline.
- **Focused testing** — Decoupling from the real API lets us test the reasoning loop, approval flow, and data pipeline in isolation without external failure modes.
- **Clear upgrade path** — The function signature `virustotal_ip_check(ip: str) -> ReputationResult` is a clean interface. Swapping in a real implementation requires changing only `tools.py` with no impact on the agent logic.

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| Live VirusTotal API | Requires API key, network access, rate limiting (4 req/min on free tier), and results vary over time |
| VCR/cassette-based recording | More realistic but brittle — recordings go stale, large fixtures to maintain |
| Random scores | Non-deterministic — makes testing and demos unpredictable |

## Trade-offs

- **Accepted:** Mock scores don't reflect real-world threat landscape — this is a demo/prototype agent.
- **Accepted:** Known-malicious IP list is static — new threats aren't captured automatically.
- **Mitigated:** The `ReputationResult` Pydantic model enforces the same contract that a real API adapter would return, so the upgrade path is clean.

## Consequences

- `tools.py` is the single file to modify when adding real API integration.
- Tests can assert on exact scores because results are deterministic.
- Demo scenarios are fully predictable and can be scripted.
