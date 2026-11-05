# ADR-0011: Finding and alert lifecycle

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

A finding must keep its identity from one scan to the next so that changes can be detected.
Accepting a risk must remain a living decision, and alerts must stay credible: a single wave of false
alerts is enough for people to stop reading them.

## Decision

**Identity.** A finding is identified by `(target, category, service, port, protocol, title)`, never
by volatile evidence. Dynamic ports are grouped by process, because the port changes on every start.
Widening a listener changes the title, so it creates a new finding.

**Triage.** Accepting a risk or marking a false positive sets a review date, 90 days and 365 days by
default. The decision lapses on expiry **or as soon as the finding changes**: severity, version,
exposure and service form a fingerprint. The finding then goes back to `open` and says so.

**Alerts.** An alert comes from a new finding of sufficient severity that has not been dismissed.

- A target's first scan serves as the baseline and does not alert.
- A `no_response` scan does not alert and never serves as a baseline.
- Posture is compared with the last **complete** report, because a failed collection once made 78
  items look new.
- A new startup entry always alerts, whatever its severity.

**Silence.** During a session, the API reports an agent that has been quiet for 5 minutes, then its
return. Nothing is reported right after a start or after the machine wakes up.

## Options Considered

### Option A: stable identity, expiring decisions (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | Reviewing decisions periodically |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** an accepted risk is not forgotten, and changes stay visible.
**Cons:** decisions come back even if nothing changed.

### Option B: permanent decisions

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None in the short term |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** fewer prompts.
**Cons:** the acceptance survives a new vulnerable version.

### Option C: alert on every scan

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | Alert fatigue |
| Scalability | Low |
| Team familiarity | Good |

**Pros:** nothing is missed.
**Cons:** nobody reads the alerts any more.

## Trade-off Analysis

Including the title in the identity is simple, but renaming a title in the code creates false new
findings and loses the associated decisions. That is accepted at this scale.

Skipping posture alerts after a failed collection can delay the detection of a startup entry, but
never lose it: the next complete report compares against the last valid baseline.

## Consequences

- **Easier:** following what changes between two sessions.
- **Harder:** evolving finding titles without a migration.
- **To revisit:** the cause of the failed posture collection was not identified, only its consequence
  is fixed. The reason is now recorded in the report.

## Action Items

1. [x] Fingerprint and decision expiry.
2. [x] Baseline limited to complete reports.
3. [ ] Understand the collection failure if it happens again.
