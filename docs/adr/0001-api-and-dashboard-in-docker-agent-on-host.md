# ADR-0001: API and dashboard in Docker, agent on the host

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

AttackLens must describe the user's machine. The first version ran everything in Docker, and the
reports actually described the container: its packages, its processes and its configuration. The
network scan, started from the container, only saw the machine from the outside, without its
processes or what listens on certain interfaces.

A container cannot see the processes, firewall or registry of its host. Allowing it would require
privileged mounts, which go against least privilege.

## Decision

- The **API** and the **dashboard** run in Docker, hardened: `cap_drop: ALL`,
  `no-new-privileges`, a read-only file system for the API, a non-root user, and ports bound to
  `127.0.0.1`.
- The **agent** runs on the host, as the current user. It is the only component outside Docker,
  and it is there out of necessity.
- `pull_policy: build` rebuilds the images on every start.

## Options Considered

### Option A: API and dashboard in Docker, agent on the host (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium: two environments |
| Cost | None |
| Scalability | Good: one agent per machine |
| Team familiarity | Good |

**Pros:** a true view of the machine, isolated network parts, an unprivileged agent.
**Cons:** Python is needed on the host in addition to Docker.

### Option B: everything in Docker

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | Low |
| Team familiarity | Good |

**Pros:** a single command, nothing to install.
**Cons:** describes the container instead of the machine. Mounting `/`, the Docker socket or using
`--privileged` would give a network service full power.

### Option C: everything native, without Docker

| Dimension | Assessment |
| --- | --- |
| Complexity | Low in use |
| Cost | None |
| Scalability | Low |
| Team familiarity | Good |

**Pros:** the simplest to start.
**Cons:** no isolation, and Python and Node are needed on every machine.

## Trade-off Analysis

Option A adds a component outside Docker, which caused real confusion in use ("I thought
everything was in Docker"). This cost is accepted, because without the agent the product does not
keep its promise. [ADR-0003](0003-on-demand-execution.md) offsets it: one command, in one visible
window.

`pull_policy: build` costs a few seconds per start, but avoids a failure already experienced: old
images started with a new configuration.

## Consequences

- **Easier:** adding a collector on the host without touching the API's isolation.
- **Harder:** installation requires Docker and a Python environment.
- **To revisit:** shipping the agent as a standalone executable if installation becomes a
  barrier.

## Action Items

1. [x] Native agent for ports, firewall, posture and software.
2. [x] Systematic image rebuilds.
3. [ ] Evaluate a standalone executable for the agent.
