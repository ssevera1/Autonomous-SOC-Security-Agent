# ADR-002: Mandatory Human-in-the-Loop for All Destructive Actions

**Status:** Accepted
**Date:** 2026-02-16
**Context:** The agent can recommend blocking IP addresses. Automated blocking without oversight risks false positives disrupting legitimate traffic or business-critical services.

## Decision

The agent **must never** execute `block_ip()` automatically. Every destructive remediation action requires explicit human approval via an interactive terminal prompt (`Y`/`N`).

## Rationale

- **False positive risk** — Threat intelligence feeds have non-trivial false positive rates. An IP flagged as malicious may belong to a CDN, shared hosting provider, or business partner. Automated blocking could cause service outages.
- **Accountability** — SOC compliance frameworks (SOC 2, ISO 27001) require documented human authorization for actions affecting network access controls.
- **Trust calibration** — Early-stage autonomous agents should start with a "human-on-the-loop" pattern, only graduating to full autonomy after the team builds confidence in the system's accuracy.
- **Reversibility** — While IP blocks are reversible, the damage from blocking a critical service (e.g., payment gateway IP) can be immediate and costly.

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| Fully autonomous blocking | Unacceptable false-positive risk in production SOC environments |
| Confidence-threshold auto-block (e.g., score > 95) | Still no human accountability; threshold tuning is fragile |
| Async approval via Slack/email | Adds latency and infrastructure complexity; terminal prompt is sufficient for v1 |

## Trade-offs

- **Accepted:** Slower response time — analyst must be present at the terminal to approve actions.
- **Accepted:** Cannot run fully unattended (by design — this is a feature, not a limitation).
- **Mitigated:** Clean IPs are automatically cleared with no human interaction needed, so analyst time is only spent on genuine threats.

## Consequences

- `request_remediation()` is the only path to `block_ip()` — calling `block_ip()` directly is a code-review violation.
- Future versions may add tiered autonomy (auto-block for score > 99, prompt for 80-99, auto-clear for < 50) but only after sufficient operational data.
