# ADR-0003: On-demand execution, no background process

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

An earlier version installed the agent as a scheduled task, started at each logon for permanent
monitoring. In practice, the user lost track of what was running on their machine, and did not
need a continuous scan.

The requirement is explicit: everything runs when the project is started, and nothing else does.

## Decision

- `attacklens start` starts the containers **and** the agent, in the foreground of a single
  window. `AttackLens.cmd` does the same with a double-click.
- **Ctrl+C in that window stops everything.** Closing the window is handled the same way, and the
  container shutdown runs detached from the console, otherwise Windows would kill it along with
  the window.
- `attacklens status` shows what is running, what starts on its own and what remains on the
  machine.
- The containers have no restart policy.
- The agent sends its machine report on each connection to the API, at startup or after an
  outage. A network scan only happens when the user asks for one. `attacklens start` enables no
  periodic report: only the `--interval` option of `attacklens agent` allows it.
- `attacklens service install` remains available for server use, but is not installed by default.
  It creates a task under the user's account, not a `SYSTEM` service.

## Options Considered

### Option A: in the foreground, in a window (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | Suited to a workstation |
| Team familiarity | Good |

**Pros:** visible, one gesture stops everything, nothing to uninstall.
**Cons:** no monitoring while the tool is not started.

### Option B: scheduled task at logon

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | A permanent process |
| Scalability | Good |
| Team familiarity | Medium |

**Pros:** continuous monitoring, automatic restart.
**Cons:** rejected in use: invisible, and "what is running?" no longer has a simple answer. It also
exposed a looping collection bug.

### Option C: Windows service

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | Administrator rights |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** the standard form on Windows.
**Cons:** runs as `SYSTEM` by default, against [SECURITY.md](../../SECURITY.md).

## Trade-off Analysis

This choice gives up continuous monitoring to keep control. When AttackLens is off, nothing is
watching anything. That is deliberate: it is an on-demand tool, not a permanent monitor. The
silence alert only makes sense during a session.

## Consequences

- **Easier:** understanding the state of the machine and stopping everything.
- **Harder:** detecting a change made between two sessions, until the next session.
- **To revisit:** closing the window was verified through a signal, not a real click.

## Action Items

1. [x] `attacklens start`, `stop` and `status`, and `AttackLens.cmd`.
2. [x] Scheduled task removed from the reference machine.
3. [ ] Confirm closing with the X button in Windows Terminal.
