# ADR-0002: Agent driven by outbound calls

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

The dashboard's scan button lives in Docker, while the scan must start from the host machine. An
order therefore has to travel from the dashboard to the agent, without giving a network service
the ability to run anything on the host.

## Decision

The agent **polls the API**: it calls `POST /api/agent/poll` every 2 seconds, which also serves as
a heartbeat, and receives the next order in the response. The API opens no connection to the host.

- Only one order type exists: a scan. The agent **runs no received command** and validates the
  target again itself.
- An agent is `online` if it called within the last 10 seconds.
- An order nobody picks up expires after 30 seconds, and an unfinished order after 180.
- Without the API, the agent does no work and retries every 30 seconds.
- Without a target, it scans the machine's network address and records the result under its host
  name, which stays stable when the address changes.

## Options Considered

### Option A: outbound polling (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | One HTTP call every 2 s |
| Scalability | Enough for a few dozen agents |
| Team familiarity | Good |

**Pros:** no open port on the host, crosses NAT, simple code, free heartbeat.
**Cons:** up to 2 s of latency when a scan starts.

### Option B: permanent WebSocket

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium: reconnections, state |
| Cost | Low |
| Scalability | Good |
| Team familiarity | Medium |

**Pros:** immediate reaction.
**Cons:** more code to save 2 seconds on a scan that lasts several.

### Option C: the API calls the agent

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | Low |
| Scalability | Medium |
| Team familiarity | Good |

**Pros:** direct response.
**Cons:** opens a listening port on the analysed machine, which is absurd for a tool that measures
exposure.

## Trade-off Analysis

Polling wastes a few calls, but it removes all inbound attack surface from the host, and missing
calls reveal a stopped agent for free (see [ADR-0011](0011-finding-lifecycle.md)).

The 2-second interval is there to keep the scan button responsive. It is not a continuous scan:
apart from the machine report sent on each connection, no work happens without an order.

## Consequences

- **Easier:** nothing to open on the host, and the agent survives API restarts.
- **Harder:** the agent must be able to reach the API.
- **To revisit:** the API listens on `127.0.0.1` over HTTP. A second machine cannot reach it today,
  and TLS would have to be added before exposing it.

## Action Items

1. [x] Order queue in the database, with expiry.
2. [x] Agent sleep without the API, verified: 0 processes started in 40 seconds.
3. [ ] TLS in front of the API before any second machine.
