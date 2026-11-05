# ADR-0004: SQLite owned by the API alone

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

Results used to be JSON files, written by the CLI and the API into a shared folder. Needs grew:
history, triage decisions, alerts, agents, scan orders, audit log. This data requires queries and
atomic writes.

The agent runs on the host and the API in Docker, so they could be tempted to share a file. But
SQLite locking is not reliable on a mount shared between a host and a container.

## Decision

- **SQLite**, in WAL mode, with one connection per operation.
- In Docker, **only the API opens the database**, placed in the `attacklens-data` named volume. The
  agent goes through HTTP (`POST /api/reports`).
- Without Docker, the CLI, the agent and the API share `results/attacklens.db`.
- A scan is stored as a JSON document, with a few indexed columns for queries.
- The schema is versioned through `PRAGMA user_version`, currently 5. Old JSON files are imported
  once, without being modified.

## Options Considered

### Option A: SQLite owned by a single process (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | A few dozen machines |
| Team familiarity | Good |

**Pros:** no service to administer, backup is one file, reliable transactions.
**Cons:** one writer at a time.

### Option B: PostgreSQL

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | One more container |
| Scalability | High |
| Team familiarity | Good |

**Pros:** concurrency, multiple users.
**Cons:** one more service to run and back up, with no real need at this scale.

### Option C: stay with JSON files

| Dimension | Assessment |
| --- | --- |
| Complexity | Low at first |
| Cost | None |
| Scalability | Low |
| Team familiarity | Good |

**Pros:** readable by eye.
**Cons:** no queries, no transactions, the whole history reread on every call.

## Trade-off Analysis

SQLite is more than enough for a workstation. Storing the whole JSON document avoids modelling each
field and keeps history intact when the format evolves, at the price of coarser queries into
findings.

Going through HTTP requires the API to be running, which is the case by construction (see
[ADR-0003](0003-on-demand-execution.md)).

## Consequences

- **Easier:** backing up, restoring and evolving the schema.
- **Harder:** querying findings across the whole history.
- **To revisit:** the database is not encrypted at rest, and it describes the machine's weaknesses.
  That is acceptable on an encrypted disk, not for client data.

## Action Items

1. [x] Migrations by schema version, tested.
2. [x] Import of old results.
3. [ ] Encryption at rest before any use with client data.
