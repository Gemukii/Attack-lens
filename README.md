# AttackLens

AttackLens is a self-hosted security scanner for personal machines and servers. It
shows what your machines expose, explains how findings chain into a real compromise,
and alerts you when something changes.

> **Status:** Early development

## How it sees your machines

AttackLens looks at a machine from three sides, because each one misses things:

| View | Command | Sees | Cannot tell |
| --- | --- | --- | --- |
| **Host agent** | `attacklens agent` | Listening sockets and their processes, firewall, Windows posture, autostart entries, outdated software | What other machines can actually reach |
| **Network scan** | `Run scan`, or `attacklens scan --network` | Common TCP ports, banners, and active checks | Which process owns a port. On your own address, it also skips your firewall |
| **External probe** | `attacklens probe`, from another machine | What really gets through the firewall | What listens behind it |

Combining them gives a verdict for each port: `local`, `shielded` (blocked from
outside), `exposed` (proved reachable), or `unverified` (no probe covers it yet).

```text
 Agent (your machine)                 Probe (another machine)
 outbound calls only                  attacklens probe -> import
        │  token per machine                  │
        ▼                                     ▼
   FastAPI :8000  ◄───── Nuxt proxy :3000 ───── Browser
   owns SQLite          adds the API key, login
        │
        ├─ risk: impact × reachability × exploitability
        ├─ attack paths and the fix that breaks the most of them
        └─ alerts, audit log, backups, reports
```

## Quick start

Once, install the command and set `ATTACKLENS_API_KEY` in `.env` (see
[Configuration](#configuration)):

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .
```

Then, each time you want to use AttackLens, with Docker Desktop started:

```bash
.venv/Scripts/attacklens start
```

On Windows, you can also double-click `AttackLens.cmd`.

This opens the dashboard on <http://localhost:3000>. **Press Ctrl+C in that window to
stop everything.** Nothing runs in the background, and nothing starts by itself.

| Part | Where it runs | Why |
| --- | --- | --- |
| API, database | Docker | Isolated from your machine |
| Dashboard | Docker | Isolated from your machine |
| Agent | Your machine, in that window | A container cannot see your processes, firewall, or registry |

`Run scan` asks the agent to scan your machine's network address and refresh its report.
To scan another device, type its address in the target field. There is no continuous
scan: AttackLens scans when you start it and when you ask.

To see what is running and what AttackLens left on your machine at any time:

```bash
.venv/Scripts/attacklens status
```

## Proving what is reachable

Connecting to your own address does not go through your firewall, so a scan from the
machine itself reports what listens, not what is reachable. The dashboard gives the
exact command to run from another machine on the same network:

```bash
attacklens probe 192.168.1.20 --ports 135,445,902 --output probe.json
```

Copy the file back, and import it on the analyzed machine:

```bash
attacklens import probe.json
```

A probe stays valid for 7 days. Ports proved blocked weigh less in the score, and stop
counting as entry points in attack paths.

## What a result means

Every port probe ends in one of three states: **open**, **closed** (the host refused,
so it is alive), or **filtered** (nothing answered). If every port is filtered, the
status is `no_response` and the score is `null`: nothing was observed, which is not a
clean result.

The score goes from 0 to 100, higher is better. It reflects network exposure, and leaves
out dismissed findings. Host reports have no score: they list findings.

Each finding also has a **risk**, the product of three factors returned with it:

| Factor | Values |
| --- | --- |
| Impact | From the severity |
| Reachability | `exposed` > `unverified` > `shielded` > `local` |
| Exploitability | CISA KEV or proved by a check > high EPSS > assumed > proved mitigated |

Findings are sorted by risk. `now` means at least 60 out of 100.

### Active checks

Network scans send one harmless request to these services. They never try a password:

| Port | Check |
| --- | --- |
| 445 | SMB signing, read from the negotiation that precedes authentication |
| 2375 | Docker API answering without authentication |
| 6379 | Redis answering `PING` without authentication |
| 9200 | Elasticsearch answering without authentication |
| 11211 | Memcached answering without authentication |
| 443, 2376, 5986, 8443 | TLS 1.0 or 1.1 accepted, certificate problems |

### Attack paths

A path chains findings into a compromise: entry, access, privilege, impact. It only
exists when every link is backed by a finding, and is `confirmed` only with proof. The
dashboard names the single fix that breaks the most paths.

## Alerts

A new finding creates an alert in the dashboard, and goes to a webhook if one is set.
The first scan of a target is a baseline. Findings you dismissed do not alert again.
Alerts only exist while AttackLens is running.
A new autostart entry always alerts, whatever its severity.

**The API also watches the agents.** While the stack is running, an agent that stops
calling in for 5 minutes raises an alert, because a monitoring tool that goes quiet looks
exactly like a healthy machine. Nothing is raised right after the API starts or the
machine wakes up. With the stack stopped, nothing watches anything: AttackLens is an
on-demand tool, not a permanent monitor.

## Triage

Open a finding to accept the risk or mark a false positive, with a reason and a review
date. A decision stops applying when it expires, and as soon as the finding changes: a
new version or severity is not what you accepted. Findings are identified per machine.

## Security

Agents enroll with a one-time code and receive their own token, stored hashed. A token
can only report on its own machine, and revoking it takes effect immediately:

```bash
curl -X DELETE -H "X-API-Key: $ATTACKLENS_API_KEY" http://127.0.0.1:8000/api/agents/<hostname>
```

Set `ATTACKLENS_DASHBOARD_PASSWORD` to protect the dashboard, which is required before
it is reachable beyond this machine. Triage decisions, scan orders, enrollments, and
reports are written to an audit log, shown under `AttackLens runtime`.

AttackLens is intended for systems that you own or are explicitly authorized to assess.
See [`SECURITY.md`](SECURITY.md).

## Backups and retention

With Docker, the database is backed up daily to `./backups`, on the host, so backups
survive `docker compose down -v`. The last 14 are kept. Scans older than a year are
deleted, except the latest of each machine.

To restore, stop the stack and copy a backup over `attacklens.db` in the data volume:

```bash
docker compose down
docker compose run --rm -v "$PWD/backups:/restore" --entrypoint cp api /restore/attacklens-YYYYMMDD-HHMMSS.db /app/data/attacklens.db
docker compose up
```

## Audit mode

For assessments of systems that are not yours. Record the authorization and its scope,
then set `ATTACKLENS_AUDIT_MODE=true`: scans are refused unless the **resolved address**
of the target is inside an active engagement.

```bash
curl -X POST -H "X-API-Key: $ATTACKLENS_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"Acme","authorized_by":"J. Doe","reference":"CONTRACT-12","scope":["192.168.10.0/24"],"starts_at":"2026-11-01T00:00:00Z","ends_at":"2026-11-30T00:00:00Z"}' \
  http://127.0.0.1:8000/api/engagements
```

The `Report` button produces a printable report with evidence, attack paths, decisions,
limits, and a SHA-256 of its content. Scope enforcement does not replace a signed
authorization: have yours reviewed before any engagement.

## Permanent monitoring (optional)

If you do want the agent to run all the time, for example on a server:

```bash
attacklens service install
```

It then starts at each logon and restarts if it crashes, with the rights of your user
and not as `SYSTEM`. While the stack is stopped it only checks every 30 seconds whether
the API is back. `attacklens service uninstall` removes it.

## Running without Docker

Requires Python 3.12+ and Node.js 22+.

```bash
python -m pip install -e ".[dev]"
uvicorn attacklens.web.api:app --reload
```

```bash
cd frontend
npm install --legacy-peer-deps
npm run dev
```

## Command line

```bash
attacklens scan --network --host 192.168.1.10
attacklens scan --network --fail-on high   # exit 1 on a high or critical finding
attacklens start                           # everything, in this window
attacklens status                          # what runs, what starts by itself
attacklens stop                            # stop the containers
attacklens agent --json                    # inspect this machine once
attacklens probe HOST --output probe.json  # from another machine
attacklens import probe.json
attacklens enroll CODE
attacklens service install|uninstall|status
attacklens backup copy.db                  # local database
```

Exit codes: `0` completed, `1` a finding reached `--fail-on`, `2` nothing was observed.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATTACKLENS_API_KEY` | empty | Protects the API. An empty value leaves it open. |
| `ATTACKLENS_DASHBOARD_PASSWORD` | empty | Protects the dashboard. |
| `ATTACKLENS_ALLOWED_TARGETS` | empty | Comma-separated allowlist of scan targets. |
| `ATTACKLENS_ALLOWED_HOSTS` | `localhost,127.0.0.1,api` | Host headers accepted by the API. |
| `ATTACKLENS_CORS_ORIGINS` | `http://localhost:3000` | Browser origins for direct API calls. |
| `ATTACKLENS_DEFAULT_TARGET` | `127.0.0.1` | Target of a scan run from the API. |
| `ATTACKLENS_ENABLE_OSV` | `false` | Sends package names to [OSV](https://osv.dev), and CVE identifiers to [EPSS](https://www.first.org/epss/). |
| `ATTACKLENS_ALERT_WEBHOOK_URL` | empty | Discord or Slack webhook. |
| `ATTACKLENS_ALERT_MIN_SEVERITY` | `low` | Lowest severity that raises an alert. |
| `ATTACKLENS_AGENT_SILENCE_SECONDS` | `300` | Quiet time before an agent is reported. |
| `ATTACKLENS_RETENTION_DAYS` | `365` | Age of the scans to delete. |
| `ATTACKLENS_BACKUP_DIR` | empty | Enables daily backups. Set by Docker Compose. |
| `ATTACKLENS_AUDIT_MODE` | `false` | Enforces the scope of engagements. |
| `ATTACKLENS_DB_PATH` | `results/attacklens.db` | Database location. |
| `ATTACKLENS_API_URL` | empty | Default for `--api-url`. |

## Known limits

* An external probe has to be run by hand from another machine.
* The network scan covers 36 common TCP ports. There is no UDP.
* OSV has no index of Windows software, so Windows programs are compared with `winget`,
  which reports available updates and not known vulnerabilities.
* The Windows posture needs no elevation. Without it, some controls stay `unknown`.
* The posture checks are Windows only. Linux gets listeners, packages, and vulnerabilities.
* The agent runs as your user: it cannot detect an intruder who already controls that
  account, beyond the silence alert.
* The session of the dashboard is limited to a single shared password.
* The database is not encrypted at rest. Use disk encryption on the host.

## Development

```bash
pytest
ruff check src tests
cd frontend && npm test
```

Python versions are locked with hashes in `requirements.lock`, which the Docker image
installs. After changing dependencies, regenerate it on Linux with Python 3.12:

```bash
pip-compile --generate-hashes --strip-extras --no-header --no-annotate --allow-unsafe -o requirements.lock pyproject.toml
```

## License

[MIT](LICENSE)
