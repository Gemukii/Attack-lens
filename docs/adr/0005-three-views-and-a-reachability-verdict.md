# ADR-0005: Three views and a reachability verdict

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

No single point of view is enough:

- from the machine, you know what listens, but connecting to your own address does not go through
  your firewall;
- from another machine, you know what gets through, but not what listens behind it.

A score based on the local view alone would have given 0 out of 100 to a workstation with an
active firewall. Conversely, an unreachable host scored 100, since it had zero findings.

## Decision

Three views, and a per-port verdict that combines them:

| View | Command | Provides |
| --- | --- | --- |
| Agent | `attacklens agent` | Listeners, processes, firewall, posture, software |
| Network scan | `Run scan` | 36 common TCP ports, banners, active checks |
| External probe | `attacklens probe` from another machine | What crosses the firewall |

| Verdict | Meaning |
| --- | --- |
| `local` | Bound to loopback: unreachable from elsewhere |
| `shielded` | Listening, but the probe proves it is blocked |
| `exposed` | Proved reachable from outside |
| `unverified` | No probe covers this port |

A port is `open`, `closed` or `filtered`. If everything is `filtered`, the scan is `no_response` and
has **no score**. A probe stays valid for 7 days. Since the API listens locally, the result travels
as a file (`--output`, then `attacklens import`).

## Options Considered

### Option A: three correlated views (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | One manual action for the probe |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** the only option that separates "listening" from "reachable".
**Cons:** the probe needs a second machine.

### Option B: local scan only

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** fully automatic.
**Cons:** overestimates exposure, and never proves anything.

### Option C: infer reachability from firewall rules

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | None |
| Scalability | Low |
| Team familiarity | Low |

**Pros:** no second machine.
**Cons:** reimplements firewall logic, ignores the router and NAT, and produces false certainty.

## Trade-off Analysis

The tool prefers saying "not proved" to guessing. This honesty costs comfort: without a probe,
everything stays `unverified`, paths stay `potential` and the interface draws dashed lines. That is
the intended behaviour.

A port the probe does not cover stays `unverified`: absence of proof is never treated as proof of
absence.

## Consequences

- **Easier:** understanding what is known and what is not.
- **Harder:** getting a complete verdict, which requires a manual action.
- **To revisit:** no probe has run from a real second machine yet. System posture only covers
  Windows: Linux only gets listeners, packages and vulnerabilities.

## Action Items

1. [x] Port states and the `no_response` status.
2. [x] Correlation, and a probe command provided by the dashboard.
3. [ ] First real probe from another machine.
4. [ ] Linux posture.
