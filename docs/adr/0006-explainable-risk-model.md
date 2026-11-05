# ADR-0006: Explainable risk model

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

Severity came from the port number alone. A service blocked by the firewall weighed as much as a
service open to the Internet, and an actively exploited flaw as much as a theoretical one. The tool
must decide what to handle first, and be able to justify each priority.

## Decision

Two separate measures.

**A finding's risk** is `100 × impact × reachability × exploitability`:

| Factor | Values |
| --- | --- |
| Impact | critical 1 · high 0.8 · medium 0.5 · low 0.25 · info 0.05 |
| Reachability | exposed 1 · unverified 0.7 · shielded 0.3 · local 0.1 · no port 0.6 |
| Exploitability | KEV or confirmed check 1 · EPSS ≥ 0.5 its value · assumed 0.6 · mitigated 0.25 |

`now` from 60, `soon` from 21, otherwise `later`. Each finding returns its factors.

**The network score** runs from 0 to 100, higher is better. It starts at 100 and subtracts 35, 20,
10 or 4 points by severity. A `shielded` port weighs 0.25 and a `local` port 0.1. Dismissed findings
do not count.

**Host reports have no score**: a listening port is not proof of reachability, and a machine with
an active firewall would have scored 0 out of 100.

## Options Considered

### Option A: product of three factors (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** can be computed by hand, every priority can be explained.
**Cons:** the coefficients are choices, not measurements.

### Option B: CVSS alone

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** a recognised standard.
**Cons:** ignores reachability and real exploitation, and does not exist for an open port.

### Option C: score learned by a model

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | High |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** could capture subtle interactions.
**Cons:** opaque. A security tool must stay explainable, finding by finding.

## Trade-off Analysis

The coefficients are arbitrary but visible, and a badly set threshold is fixed in one line. With
`soon` at 21, a high weakness that is confirmed but blocked remains to be handled
(0.8 × 0.3 × 1 = 24), while a critical weakness that is only assumed and blocked does not come up
(1 × 0.3 × 0.6 = 18).

Keeping a network score alongside risk adds a concept. It remains useful as a simple indicator from
one session to the next.

## Consequences

- **Easier:** explaining why one finding comes before another.
- **Harder:** comparing scores across versions if the weights change.
- **To revisit:** when an advisory gives no severity, `medium` is assumed, and the finding says so.
  KEV and EPSS are inactive without consent ([ADR-0010](0010-external-services-by-consent.md)).

## Action Items

1. [x] Factors returned by the API and shown in a finding's detail.
2. [ ] Recalibrate the thresholds on several real machines.
