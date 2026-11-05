# ADR-0013: Locked supply chain

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

A security tool must be beyond reproach on its own dependencies. The audit found 23 npm alerts,
including 3 critical, 8 Python flaws in the local environment, no pinned Python versions, and images
and Actions referenced by mutable tags.

## Decision

| Element | Measure |
| --- | --- |
| Python | `requirements.lock` with hashes, installed with `--require-hashes` in the image |
| npm | `package-lock.json`, `npm ci`, and `overrides` for `glob` and `minimatch` |
| Docker images | Pinned by SHA-256 digest |
| GitHub Actions | Pinned by commit SHA |
| Monitoring | Dependabot for pip, npm, Docker and Actions |
| CI gates | `npm audit` at moderate level, `pip-audit`, tests, `ruff` |
| Proof it works | Smoke test on a real Docker stack in CI |

CI tests Python 3.12 and 3.13, on Linux and Windows.

## Options Considered

### Option A: pin everything, with Dependabot (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | Updates to validate |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** reproducible builds, an attack through a moved tag does not get through.
**Cons:** updates require an action.

### Option B: flexible version ranges

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None in the short term |
| Scalability | Low |
| Team familiarity | Good |

**Pros:** automatic fixes.
**Cons:** two builds can differ, and a malicious version gets in on its own.

### Option C: private registry and image scanning

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | Infrastructure to maintain |
| Scalability | Very good |
| Team familiarity | Low |

**Pros:** maximum control.
**Cons:** out of proportion for this project.

## Trade-off Analysis

Pinning moves the risk: a bad version no longer arrives by accident, but neither does a fix without
action. Dependabot and the blocking audit offset this.

The npm `overrides` force a major version on indirect dependencies. They were validated by a real
build, but remain a debt to re-examine on each Nuxt update. One low alert stays accepted on
`deepmerge`, which has no published fix and is absent from the image.

## Consequences

- **Easier:** reproducing a build and knowing what ships.
- **Harder:** updating, because `requirements.lock` is regenerated with `pip-compile`, on Linux and
  Python 3.12.
- **To revisit:** `pip install --no-deps .` fetches `setuptools` without locking it, and the
  Dockerfile runs `apt-get upgrade`, which is not reproducible by nature.

## Action Items

1. [x] Lockfile, digests, SHAs, Dependabot and blocking audits.
2. [x] Docker smoke test, passed on GitHub.
3. [ ] Lock the Python build backend.
4. [ ] Generate an SBOM for each release.
