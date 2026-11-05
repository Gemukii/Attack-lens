# ADR-0016: Off-volume backups and retention

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

The database lives in a Docker volume, which a simple `docker compose down -v` deletes. Also, scans
describe weaknesses: keeping them forever brings nothing and increases the risk.

## Decision

- The automatic backup uses SQLite's backup API, consistent even with the database open.
- It is written to `./backups`, **on the host**, outside the volume. Only the last 14 are kept.
  `POST /api/backups` creates one on demand.
- A system error during a backup is written to the audit log.
- Scans older than 365 days are deleted, always keeping **the latest of each machine**.
- Restoring is documented in the README and was carried out on a disposable stack.

## Options Considered

### Option A: folder on the host, simple rotation (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | A few MB |
| Scalability | Sufficient |
| Team familiarity | Good |

**Pros:** survives `down -v`, an ordinary file, simple restore.
**Cons:** same disk as the original.

### Option B: backup inside the volume

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | Low |
| Scalability | Sufficient |
| Team familiarity | Good |

**Pros:** no extra mount, no permission issues.
**Cons:** disappears along with what it protects.

### Option C: encrypted external storage

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | One more service |
| Scalability | Good |
| Team familiarity | Medium |

**Pros:** survives the loss of the machine.
**Cons:** sends sensitive data out, contrary to [ADR-0010](0010-external-services-by-consent.md).

## Trade-off Analysis

This data can largely be rebuilt with a new scan. What is valuable is the history and the triage
decisions. Protecting against a handling mistake is enough, and protection against disk loss does
not justify sending this data elsewhere.

Since AttackLens runs on demand, the backup starts about 30 seconds after each API start, then on
each UTC day change. Rotation counts files, not days: several sessions in one day therefore shorten
the history, which covers 14 backups, not 14 days.

## Consequences

- **Easier:** recovering from a `down -v`.
- **Harder:** on Linux, the container user must be able to write to `./backups`.
- **To revisit:** backups are not encrypted, and they hold the same sensitive data as the database.
- **Known defect:** `daily_maintenance` only catches `OSError`. An SQLite error, reproduced with a
  temporary file that cannot be opened, escapes it without an audit entry. Since the
  `_run_maintenance` loop does not catch it either, the thread stops, and the silence alert with it,
  until the next API start.

## Action Items

1. [x] Backup, rotation, retention and tested restore.
2. [ ] Catch SQLite errors and protect the maintenance loop.
3. [ ] Check the permissions of `./backups` on Linux.
4. [ ] Encrypt backups before any use with client data.
