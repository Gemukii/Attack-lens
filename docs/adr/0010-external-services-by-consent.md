# ADR-0010: External services by explicit consent

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

A machine's software list is sensitive: it tells a third party what to attack. Yet the dashboard
sent packages to OSV on every load, which contradicted the local-first principle of
[SECURITY.md](../../SECURITY.md).

## Decision

Nothing leaves without configuration:

| Setting | What leaves | To |
| --- | --- | --- |
| `ATTACKLENS_ENABLE_OSV=true` | Package names and versions | OSV |
| Same setting | CVE identifiers, and the catalog download | EPSS, CISA KEV |
| `ATTACKLENS_ALERT_WEBHOOK_URL` | Target name, severity and finding titles | The user's webhook |

Without a setting, the interface says so (`Package lookup is off`) rather than implying there is
nothing to report. The agent keeps the path of startup programs and drops their arguments, which may
contain secrets. An unavailable service gives `unavailable`, never an empty result.

## Options Considered

### Option A: everything off by default (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | Less information by default |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** true to the promise, no leak by default.
**Cons:** vulnerabilities only appear after a setting is changed.

### Option B: on by default

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | Inventory leak |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** immediate results.
**Cons:** sends a machine's inventory without agreement.

### Option C: local copy of the vulnerability databases

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | Storage and synchronisation |
| Scalability | Good |
| Team familiarity | Medium |

**Pros:** no leak, and works offline.
**Cons:** heavy for a personal tool.

## Trade-off Analysis

KEV alone reveals nothing, since it is a plain download, but EPSS receives the CVEs, so the same
consent covers both to keep things simple. Option C remains the right long-term answer if
confidentiality and vulnerabilities must coexist by default.

OSV requires a second request per advisory, because the batch call only returns identifiers. An
earlier version ignored this, and the test passed thanks to an unrealistic simulated response. The
tests now reproduce the real contract.

## Consequences

- **Easier:** keeping the confidentiality promise.
- **Harder:** getting vulnerabilities, which takes an action.
- **To revisit:** OSV does not index Windows software. On that system, `winget` reports available
  updates, not known vulnerabilities.

## Action Items

1. [x] Consent for OSV, EPSS and webhook.
2. [x] Validation against the real OSV, KEV and EPSS services.
3. [ ] Evaluate a local copy of OSV.
4. [ ] Test a real Discord or Slack webhook.
