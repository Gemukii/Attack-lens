# ADR-0008: One identity per agent, through enrollment

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

AttackLens holds the map of a machine's weaknesses. With a shared key, any client could submit an
"all clear" report in another machine's name, or order scans on its behalf. A compromised agent must
not be able to lie for the others.

## Decision

- A one-time enrollment code, valid for 15 minutes, is created by an administrator.
- `attacklens enroll` exchanges it for a **token specific to the machine**. `attacklens start` does
  this on its own, with the project key, and renews a rejected token.
- Codes and tokens are stored **hashed** with SHA-256: they are random, so high in entropy.
- **An agent's name comes from its token**, never from what it declares.
- An agent can only submit a report about itself, or about a device that is not an enrolled agent.
  It can only close its own orders.
- `DELETE /api/agents/{hostname}` revokes immediately.
- The token lives in `%LOCALAPPDATA%\AttackLens\agent.json`, readable by the user.

## Options Considered

### Option A: enrollment and per-machine token (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | None |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** revocation per machine, a compromised agent stays contained.
**Cons:** an enrollment step, automated for the local machine.

### Option B: shared API key

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | Low |
| Team familiarity | Good |

**Pros:** the simplest.
**Cons:** no distinction between machines, and one leak compromises everything.

### Option C: mutual TLS with client certificates

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | A certificate authority to manage |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** the most robust.
**Cons:** out of proportion for a local personal tool.

## Trade-off Analysis

The per-machine token offers most of the protection at a fraction of the cost of mutual TLS. It
protects **integrity between machines**, not transport confidentiality: without TLS, a token travels
in clear text, which is acceptable on `127.0.0.1` only.

## Consequences

- **Easier:** revoking a lost workstation.
- **Harder:** resetting the database invalidates tokens, which `attacklens start` handles on its
  own.
- **To revisit:** without `ATTACKLENS_API_KEY`, code creation stays open to any local process, which
  can then enroll. The key is therefore required in practice, while Compose still leaves it optional.

## Action Items

1. [x] Enrollment, revocation and isolation, with impersonation tests.
2. [ ] Refuse to start the stack without an API key, or generate one on first start.
3. [ ] Token rotation.
