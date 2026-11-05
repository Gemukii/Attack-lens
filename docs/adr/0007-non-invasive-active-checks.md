# ADR-0007: Non-invasive active checks, written in-house

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

"Redis is often deployed without authentication" is an assumption, not proof, while
[SECURITY.md](../../SECURITY.md) requires findings based on observable evidence.

## Decision

The scan only sends **harmless requests** to a few services and interprets the response. It never
tries a password, sends no payload and changes nothing.

| Port | Check |
| --- | --- |
| 445 | SMB signing, read from the negotiation that precedes authentication |
| 2375 | Docker API without authentication |
| 6379 | Redis answering `PING` without authentication |
| 9200 | Elasticsearch without authentication |
| 11211 | Memcached without authentication |
| 443, 2376, 5986, 8443 | TLS 1.0 or 1.1 accepted, certificate problems |

The result is `confirmed` or `mitigated`, and may change the severity. A check that fails proves
nothing. To identify a service, the scan deliberately accepts invalid certificates, because it has
to read self-signed ones. It then only sends an anonymous `HEAD`.

## Options Considered

### Option A: targeted in-house checks (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low: one module of a few functions |
| Cost | None |
| Scalability | Limited to the services covered |
| Team familiarity | Good |

**Pros:** no dependency, controlled behaviour, easy to read and test.
**Cons:** narrow coverage, maintained by hand.

### Option B: integrate Nmap and its NSE scripts

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium: external binary, parser |
| Cost | One more installation |
| Scalability | Very good |
| Team familiarity | Good |

**Pros:** unmatched coverage and version detection.
**Cons:** a native dependency per platform, and some scripts are intrusive.

### Option C: Nuclei or a vulnerability scanner

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | Templates to keep up to date |
| Scalability | Very good |
| Team familiarity | Medium |

**Pros:** thousands of checks.
**Cons:** a lot of noise, and traffic far more aggressive than a personal workstation calls for.

## Trade-off Analysis

This choice does not contradict the idea of not rewriting a scanner: it covers the few cases where
proof changes the decision, without a dependency. It does not claim to replace Nmap, and the limit
of 36 TCP ports is the direct consequence of this simplicity.

The checks were validated against real services: Redis with and without a password, Samba with
signing required or disabled, and a TLS server limited to obsolete versions. That last test
revealed a bug no simulation had shown.

## Consequences

- **Easier:** adding a check in one function.
- **Harder:** covering new ports or protocols.
- **To revisit:** integrating Nmap if the need goes beyond the 36 ports. The Docker API,
  Elasticsearch and Memcached checks were only tested against simulated responses.

## Action Items

1. [x] Validation against real Redis, Samba and TLS.
2. [ ] Validation against real Docker, Elasticsearch and Memcached.
3. [ ] Decide on Nmap integration.
