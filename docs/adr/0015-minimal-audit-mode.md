# ADR-0015: Minimal audit mode

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

AttackLens could be used to assess systems that do not belong to the user. Scanning without
authorisation engages their liability. The existing allowlist compares a string and stays empty by
default, which offers no real protection. No client is targeted for now.

## Decision

Build the foundation that is useful in any case, without a multi-client product.

- An **engagement** records the name, the author of the authorisation, its reference, the scope as
  CIDR networks, and its dates.
- With `ATTACKLENS_AUDIT_MODE=true`, a scan is refused if the **resolved address** of the target is
  not in an active engagement. All resolved addresses must be in scope.
- The scope only accepts networks, never names, because a name can be repointed.
- Refusals are logged.
- The `Printable report` button produces a standalone HTML report: evidence, paths, decisions,
  limits, and a SHA-256 fingerprint. Everything coming from the network is escaped.

## Options Considered

### Option A: enforced scope and report (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | Low |
| Scalability | One audit at a time |
| Team familiarity | Good |

**Pros:** the essential safeguard, with a report that is also useful outside audits.
**Cons:** no separation between clients.

### Option B: multi-client platform

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | High |
| Scalability | Good |
| Team familiarity | Medium |

**Pros:** ready for an audit business.
**Cons:** work without a client, which would call [ADR-0004](0004-sqlite-owned-by-the-api.md) and
[ADR-0009](0009-nuxt-proxy-and-authentication.md) into question.

### Option C: no audit mode

| Dimension | Assessment |
| --- | --- |
| Complexity | None |
| Cost | None |
| Scalability | Not applicable |
| Team familiarity | Good |

**Pros:** less code.
**Cons:** no safeguard the day the tool leaves its personal setting.

## Trade-off Analysis

Checking the resolved address prevents a name from pointing outside the scope, but a resolution can
change between the check and the scan. This residual risk is accepted at this level.

A technical scope does not replace a written authorisation: it prevents mistakes, it creates no
right. The authorisation template must be validated by a lawyer before any engagement.

## Consequences

- **Easier:** staying within a scope, and handing over a report.
- **Harder:** managing several clients, who would share the same database.
- **To revisit:** the report cites the engagement with the most recent start date, without checking
  that it covers the target or that it is active. The SHA-256 fingerprint proves the content's
  integrity, not its author: it is not a signature.

## Action Items

1. [x] Engagements, scope on the resolved address, and report.
2. [ ] Tie the report to the engagement that actually covers the target.
3. [ ] Have the authorisation template validated by a lawyer.
