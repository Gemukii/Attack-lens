# Demo fixtures

Invented data for demo mode. Nothing here describes a real machine.

## Running it

```bash
npm run dev:demo
```

This starts `nuxt dev` with `ATTACKLENS_DEMO=1`. Every `/api` call is then answered by
`demo/handler.ts` from the files in this folder, and the real API is never contacted. A "Demo mode"
banner stays on screen on every page.

Demo mode only exists in development. The handler, the banner and these files are registered under
`$development` in `nuxt.config.ts`, which `nuxt build` drops: a production bundle contains none of
them, even if the variable is set.

## Scenarios

Pick one from the banner, or open `/?demo=<id>`.

| File | Id | Shows |
| --- | --- | --- |
| `demo-exposed.json` | `exposed` | Agent online, findings of every severity, three confirmed attack paths, a probe from outside, ten weekly readings with a score drop, a filled journal. The default |
| `demo-clear.json` | `clear` | Agent online, no way in, a probe that agrees, low and informational findings only |
| `demo-no-agent.json` | `no-agent` | Network view only: the main figure is not measured, one finding is still urgent |
| `demo-stale.json` | `stale` | The exposed scenario, 23 days older, with an agent that went quiet |
| `demo-empty.json` | `empty` | Nothing measured yet: no scan, no agent, no journal |
| `demo-api-error.json` | `api-error` | Every call answers 502 |

## Format

```json
{
  "id": "stale",
  "label": "Shown in the banner",
  "description": "Shown as a tooltip",
  "extends": "exposed",
  "shift": "-23d",
  "fail": 502,
  "responses": { "results": {}, "host": null },
  "afterScan": { "alerts": [], "findings": [] }
}
```

- `responses` is keyed by endpoint: `agents`, `results`, `host`, `scans`, `compare`, `alerts`, `audit`,
  `paths`, `exposure`, `inventory`, `vulnerabilities`, `posture`. A `null` value answers 404, as the API
  does when it has nothing.
- `extends` starts from another scenario and replaces its responses key by key.
- Dates are relative to now: `"@-2h"`, `"@-9w"`, `"@+84d"` (units `s`, `m`, `h`, `d`, `w`). `shift`
  moves all of them at once.
- `fail` makes every endpoint answer with that status.
- `afterScan` holds what a scan run from the dashboard adds: alerts on top of the journal, findings at
  the end of the network scan.

Decisions (accept, false positive, reopen) and scans are kept in memory per scenario until the dev
server restarts, or until "Reset" in the banner.

## Rules

- Addresses come from the documentation ranges only: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`. Bind addresses (`0.0.0.0`, `127.0.0.1`) are allowed.
- Host names end in `example.com`, or are the Docker name `host.docker.internal`.
- Titles, categories and risk scores follow what the backend really produces (`scanner.py`, `host.py`,
  `paths.py`, `risk.py`), so the interface is tested on realistic shapes.
- A CVE is only cited when it is real and matches the product and version shown.
