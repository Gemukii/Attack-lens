# ADR-0009: Nuxt proxy, server-side API key, optional login

**Status:** Accepted
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

The browser used to call the API directly, which means either giving it the API key or leaving the
API open. A local tool is also exposed to DNS rebinding: a malicious web page can reach `localhost`
from the user's browser.

## Decision

- The browser only talks to the dashboard. A Nuxt server route relays `/api/*` to the API and **adds
  the key on the server side**, so it never reaches the browser.
- The proxy rejects any unauthorised `Host` or `Origin`, and the API rejects any unknown `Host`.
- Ports are bound to `127.0.0.1`.
- An optional password (`ATTACKLENS_DASHBOARD_PASSWORD`) enables a session through an `HttpOnly`,
  `SameSite=Strict` cookie, with constant-time comparison and a block after 5 failures per minute.
- Sensitive actions are written to the audit log with their author.

## Options Considered

### Option A: server proxy in Nuxt (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low: one route |
| Cost | None |
| Scalability | Sufficient |
| Team familiarity | Good |

**Pros:** no secret in the browser, a single origin, no CORS to manage.
**Cons:** one more network hop.

### Option B: key in the frontend

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | None |
| Scalability | Low |
| Team familiarity | Good |

**Pros:** no server code.
**Cons:** the secret can be read in the browser, so it is no longer a secret.

### Option C: full user accounts

| Dimension | Assessment |
| --- | --- |
| Complexity | High |
| Cost | User table, roles, password reset |
| Scalability | Good |
| Team familiarity | Medium |

**Pros:** traceability per person.
**Cons:** pointless for a single user.

## Trade-off Analysis

The single password is optional because the dashboard only listens locally. This is a compromise: on
this machine, any local process that reaches port 3000 acts with the dashboard's rights. The threat
model assumes the user's session is healthy, and accepts this.

## Consequences

- **Easier:** adding an API route without thinking about the browser.
- **Harder:** telling several users apart: the audit log only sees `dashboard`.
- **To revisit before opening to the network:** make the password mandatory, switch the cookie to
  `Secure` behind TLS, and keep the block somewhere other than memory. Sessions are lost on every
  dashboard restart.

## Action Items

1. [x] Proxy, `Host` and `Origin` checks, login and audit log.
2. [ ] Refuse to listen beyond localhost without a password.
3. [ ] Named accounts if several people use the tool.
