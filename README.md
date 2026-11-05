# AttackLens

AttackLens is a self-hosted security scanner for personal machines and servers. It
shows what your machines expose, tracks what changes over time, and alerts you when
something new appears.

> **Status:** Early development

## How it sees your machines

AttackLens looks at a machine from two sides, because each one misses things:

| View | Command | Sees | Cannot tell |
| --- | --- | --- | --- |
| **Network scan** | `attacklens scan --network` | Common TCP ports reachable from where the scan runs, plus service banners | Which process owns a port, or ports outside the common list |
| **Host agent** | `attacklens agent` | Every listening TCP socket, its process and bind address, the firewall state, and installed software | Whether another machine can actually reach a socket |

A socket bound to `0.0.0.0` listens on every interface, but the firewall may still
block it. This is why host reports list findings without an exposure score.

```text
 attacklens agent          attacklens scan --network      Dashboard "Run scan"
 (on the host)             (CLI)                                 │
        │                         │                              ▼
        └──────────┬──────────────┘                     Nuxt dashboard :3000
                   │                                    server-side proxy,
                   │ local SQLite, or                   adds the API key
                   │ POST /api/reports                           │
                   ▼                                             ▼
             Change detection ◄──────────────────────────── FastAPI :8000
             SQLite · alerts · triage
```

When the API runs in Docker, it owns the database and the agent must send its reports
over HTTP with `--api-url`. SQLite locking is not reliable across a bind mount shared
between a host and a container.

## Quick start with Docker

```bash
docker compose up
```

Images are rebuilt on each start, so they always match the code.

| Service   |   Port | Description        |
| --------- | -----: | ------------------ |
| Dashboard | `3000` | Nuxt web interface |
| API       | `8000` | FastAPI backend    |

Both are bound to `127.0.0.1`.

Then start the agent on the machine itself, not in a container, and leave it running:

```bash
python -m venv .venv
python -m pip install -e .
attacklens agent --watch --api-url http://127.0.0.1:8000
```

On Windows, activate the environment first with `.venv\Scripts\Activate.ps1`.

The dashboard shows when the agent is connected. `Run scan` then asks it to scan from
your machine: it probes the machine's network address, which leaves out the services
other machines cannot reach, and refreshes the host report. To scan another device
from your machine, type its address in the target field.

Without the agent, the button becomes `Scan from Docker` and scans
`host.docker.internal` from the API container, a view that misses part of the machine.

## Running without Docker

Requires Python 3.12+ and Node.js 22+.

```bash
python -m pip install -e ".[dev]"
uvicorn attacklens.web.api:app --reload
```

```bash
cd frontend
npm install
npm run dev
```

The CLI, the agent, and the API then share `results/attacklens.db`, so `--api-url` is
not needed, except for `--watch`.

## Command line

```bash
attacklens scan --network                  # scan 127.0.0.1
attacklens scan --network --host 192.168.1.10
attacklens scan --network --json           # full result document
attacklens scan --network --fail-on high   # exit 1 on a high or critical finding
attacklens agent                           # inspect this machine once
attacklens agent --watch --api-url URL     # take scan orders from the dashboard
```

| Exit code | Meaning |
| --------: | --- |
| `0` | Completed |
| `1` | A finding reached the `--fail-on` severity |
| `2` | Nothing was observed: unknown host, no port answered, or the API was unreachable |

## What a result means

Every port probe ends in one of three states:

* **open**: the port accepted the connection.
* **closed**: the host refused it, which proves the host is alive.
* **filtered**: nothing answered.

If every port is filtered, the scan status is `no_response` and the score is `null`:
the target is down or fully filtered, and nothing was observed. This is not a clean
result.

The score goes from 0 to 100, higher is better. It only reflects the network exposure
of a scan, and leaves out findings marked as accepted or false positive. The score at
scan time stays available as `raw_score`.

Probes wait 3 seconds, in parallel. Windows takes about 2 seconds to refuse a
connection, so a shorter timeout reports closed ports as filtered.

## Alerts and scheduled runs

Each new scan is compared with the last complete scan of the same target. A new
finding creates an alert in the dashboard, and is sent to a webhook if one is set.
The first scan of a target is a baseline and raises no alert. Findings you dismissed
do not alert again.

For regular reports, add `--interval 3600` to `--watch`, or schedule single runs with
the tools of your system. The API key, if any, is read from `ATTACKLENS_API_KEY`.

On Windows, from an elevated prompt or for your own user:

```powershell
schtasks /Create /SC HOURLY /TN "AttackLens agent" /TR "C:\path\to\.venv\Scripts\attacklens.exe agent --api-url http://127.0.0.1:8000"
```

On Linux, with cron:

```text
0 * * * * /path/to/.venv/bin/attacklens agent --api-url http://127.0.0.1:8000
```

## Triage

Open a finding in the dashboard to accept the risk or mark a false positive, with an
optional reason. It stays visible but stops counting in the score and in alerts. Use
`Reopen` to reverse the decision. Findings are identified per target, so a decision
on one machine does not affect another.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATTACKLENS_API_KEY` | empty | Protects the API with the `X-API-Key` header. An empty value means no key. |
| `ATTACKLENS_API_URL` | empty | Default for `--api-url`. |
| `ATTACKLENS_ALLOWED_TARGETS` | empty | Comma-separated allowlist of scan targets. |
| `ATTACKLENS_ALLOWED_HOSTS` | `localhost,127.0.0.1,api` | Host headers accepted by the API. |
| `ATTACKLENS_CORS_ORIGINS` | `http://localhost:3000` | Allowed browser origins for direct API calls. |
| `ATTACKLENS_DEFAULT_TARGET` | `127.0.0.1` | Target of a scan without an explicit one. |
| `ATTACKLENS_DB_PATH` | `results/attacklens.db` | Database location. |
| `ATTACKLENS_RESULTS_DIR` | `results` | Location of JSON results from earlier versions. |
| `ATTACKLENS_ENABLE_OSV` | `false` | Sends package names and versions to [OSV](https://osv.dev). |
| `ATTACKLENS_ALERT_WEBHOOK_URL` | empty | Discord or Slack webhook. |
| `ATTACKLENS_ALERT_MIN_SEVERITY` | `low` | Lowest severity that raises an alert. |

The dashboard reads `NUXT_API_INTERNAL_BASE`, `NUXT_API_KEY`, `NUXT_ALLOWED_HOSTS`, and
`NUXT_PUBLIC_SCAN_TARGET`. Docker Compose sets them for you.

JSON results from earlier versions are imported automatically when the database is
created. The JSON files are left untouched.

## API

```text
GET  /api/health
POST /api/scan                       run a network scan: {"target": "127.0.0.1"}
POST /api/reports                    store a scan produced by the CLI or the agent
GET  /api/results                    latest network scan
GET  /api/host                       latest host report (?target=)
GET  /api/scans                      history (?limit= &scan_type= &target=)
GET  /api/scans/compare              ?before_id= &after_id=, for the same target
PUT  /api/findings/{id}/triage       {"status": "accepted", "reason": "..."}
GET  /api/alerts
GET  /api/agents                     known host agents and whether they are online
POST /api/jobs                       ask the agent to scan: {"target": null} for itself
GET  /api/jobs/{id}                  state of a scan order
POST /api/agent/poll                 heartbeat of an agent, returns its next order
POST /api/agent/jobs/{id}/result     outcome of an order
GET  /api/inventory                  the environment running the API
GET  /api/vulnerabilities            Python packages of the API, when OSV is enabled
GET  /api/posture                    configuration of the API runtime
```

The last three describe the runtime of the API. In Docker, that is the AttackLens
container and not your machine: use the agent to inspect the host.

## Known limits

* The network scan covers 36 common TCP ports. There is no UDP.
* The agent only lists TCP listeners.
* Vulnerability lookups need Debian or Ubuntu LTS. OSV has no index of Windows
  software, so Windows programs are inventoried but not checked.
* Without elevated rights, Linux firewall rules are usually unreadable and reported
  as `unknown`.
* Inside and outside views are not correlated yet: nothing confirms automatically
  whether a listener is reachable from another machine.

## Testing

```bash
pytest
ruff check src tests
```

## Security

AttackLens is intended for systems that you own or are explicitly authorized to assess.
Do not use the scanner against systems without permission.

See [`SECURITY.md`](SECURITY.md) for the data handling policy and vulnerability
reporting.

## Roadmap

* Correlation of the inside and outside views, with a remote probe
* Nmap and Trivy integration
* TLS inspection
* Docker security checks: privileged containers, published ports
* Active checks, such as Redis without authentication
* CISA KEV and EPSS prioritization
* Audit mode: engagements, enforced scope, and reports

## License

[MIT](LICENSE)
