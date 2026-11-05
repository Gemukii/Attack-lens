# ADR-0012: Attack paths from explicit rules

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

A list of findings does not say how a machine falls, or what to fix first. Showing how weaknesses
chain together is what sets AttackLens apart from Nmap or Trivy, and what justifies its name.

## Decision

Seven explicit rules in `paths.py`: exploited flaw, Docker API, database, open firewall, remote
takeover, malicious file, device theft.

- A path only exists if **every link rests on an open finding**.
- It is `confirmed` if it rests on proof, otherwise `potential`.
- A port proved blocked or local is not an entry point.
- A dismissed finding builds no path.
- `best_cut` names the finding present in the most paths, the most cost-effective fix. It comes after
  `now` priority actions.

## Options Considered

### Option A: hand-written rules (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | One rule per scenario |
| Scalability | Limited to the catalog |
| Team familiarity | Good |

**Pros:** readable, testable, each path can be justified link by link.
**Cons:** discovers nothing outside the rules.

### Option B: generic graph and path search

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | Full modelling of relationships |
| Scalability | Good, especially with several machines |
| Team familiarity | Medium |

**Pros:** can discover unforeseen chains.
**Cons:** requires data the product does not have yet, and would produce false certainty.

### Option C: generation by a language model

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | External calls, data sent out |
| Scalability | Good |
| Team familiarity | Medium |

**Pros:** rich narratives.
**Cons:** non-deterministic, unverifiable, and contrary to
[ADR-0010](0010-external-services-by-consent.md).

## Trade-off Analysis

On a single machine, seven rules cover the essentials, and a wrong rule can be read and fixed. A
graph engine will only be worth it with several machines, when lateral movement becomes real. A tool
that invents a story loses its credibility: without proof of a link, the path does not exist.

## Consequences

- **Easier:** adding a scenario, with its rule and its test.
- **Harder:** representing a path that crosses several machines.
- **To revisit:** the rules depend on exact finding titles, a fragile coupling that a stable check
  identifier would remove.

## Action Items

1. [x] Seven rules, certainty and best fix.
2. [ ] Stable check identifiers instead of titles.
3. [ ] Reassess the graph when moving to several machines.
