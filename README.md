# AttackLens

AttackLens is a self-hosted cybersecurity scanner designed to identify security issues on personal machines and servers.

The project combines a Python-based scanning engine with a web dashboard to provide a clear view of detected security findings.

> **Status:** Early development — MVP

## Overview

AttackLens is designed to progressively cover several areas of system security:

* Network exposure
* System configuration
* Docker security
* Web and TLS configuration
* Vulnerability and CVE analysis
* Security posture monitoring

The current MVP focuses on **network service discovery** and provides a web dashboard for viewing scan results.

## Architecture

```text
                         AttackLens
                              │
                 ┌────────────┴────────────┐
                 │                         │
              Scanner                  Dashboard
                 │                         │
          Python / CLI              Nuxt / Vue
                 │                         │
                 ▼                         │
        results/latest.json               │
                 │                         │
                 ▼                         │
             FastAPI API ◄────────────────┘
                 │
               :8000

Dashboard
   │
   └── :3000
```

The current data flow is:

```text
CLI
 ↓
Network Scanner
 ↓
Finding[]
 ↓
results/latest.json
 ↓
FastAPI
 ↓
Nuxt Dashboard
```

## Project Structure

```text
Attack-lens/
├── frontend/
│   ├── app/
│   │   ├── app.vue
│   │   └── pages/
│   │       └── index.vue
│   ├── public/
│   ├── Dockerfile
│   ├── nuxt.config.ts
│   ├── package.json
│   └── package-lock.json
│
├── src/
│   └── attacklens/
│       ├── web/
│       │   └── api.py
│       ├── __init__.py
│       ├── cli.py
│       ├── models.py
│       ├── results.py
│       └── scanner.py
│
├── tests/
│   ├── test_cli.py
│   ├── test_models.py
│   ├── test_results.py
│   └── test_scanner.py
│
├── results/
│   └── .gitkeep
│
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── README.md
└── SECURITY.md
```

## Current Features

### Network scanning

The current scanner checks common TCP ports on a target host and reports detected services.

Currently supported examples include:

* SSH
* FTP
* Telnet
* HTTP / HTTPS
* SMTP
* DNS
* SMB
* MySQL
* PostgreSQL
* Redis

Each detected service is represented as a security finding containing:

* Category
* Severity
* Title
* Description
* Evidence
* Remediation
* References

### Scan result persistence

Scan results are currently stored in:

```text
results/latest.json
```

This provides a simple interface between the scanner and the web dashboard while the project is still in its MVP stage.

### Web API

The FastAPI backend currently exposes:

```text
GET /api/health
POST /api/scan
GET /api/results
GET /api/scans
GET /api/scans/compare?before_id=<id>&after_id=<id>
GET /api/inventory
GET /api/vulnerabilities
GET /api/posture
```

`/api/health` provides a basic API health check.

`/api/results` returns the latest stored scan results.

`POST /api/scan` is synchronous. It expects a JSON body such as
`{"target":"127.0.0.1"}` and returns the same result document as
`GET /api/results`. A successful response includes `findings`, `score`,
`open_ports`, `services`, `completed_at`, and `duration_seconds`. It returns
`404` from `/api/results` when no scan has been stored yet.

Each completed scan is also stored in `results/history/<scan-id>.json` and is
returned by `GET /api/scans`, newest first. History entries contain the score,
findings, target, duration, detected services, and completion time.
The comparison endpoint reports new, fixed, and persistent findings, plus
score changes and ports added or removed between two scans.

`GET /api/inventory` returns safe metadata from the environment running the
API: operating system, hostname, user, CPU, memory, disks, network addresses,
and a bounded process list, plus installed Python packages and versions. In
Docker, its scope is explicitly `container`; it does not claim to be a full
inventory of the host machine or its Windows-installed software.

`GET /api/vulnerabilities` checks the visible Python packages against the OSV
public vulnerability database. It is independent from the network scan and
returns `status: unavailable` when the external advisory service cannot be
reached.

`GET /api/posture` runs non-invasive configuration checks for the API runtime,
including root privileges, Docker socket exposure, sensitive environment
variable names, and host firewall visibility.

When running with Docker, the default target is `host.docker.internal`, which
refers to the host machine from inside the API container. Override it with
`ATTACKLENS_DEFAULT_TARGET` when scanning another host.

The package inventory shown by the dashboard belongs to the API runtime. When
using Docker, rebuild the API image after changing Python packages:

```powershell
docker compose build --no-cache api
docker compose up -d api
```

The API container runs as the unprivileged `attacklens` user, and the dashboard
runs as the unprivileged Node `node` user. Both use `no-new-privileges`.
Scan results are stored in the persistent Docker volume `attacklens-results`,
which avoids host bind-mount permission issues while preserving data across
container recreation.

The Compose setup also drops all Linux capabilities, uses a read-only API
filesystem, limits CPU/memory/processes, binds local ports to `127.0.0.1`, and
waits for the API healthcheck before starting the dashboard.

### Dashboard

The Nuxt dashboard currently provides:

* Target information
* Finding count
* Severity counts
* Latest scan information
* Detected findings
* Evidence for each finding

The dashboard is intentionally kept lightweight during the MVP to make the architecture easy to evolve.

## Installation

### Requirements

* Python 3.12+
* Node.js 22+
* npm
* Git

### Clone the repository

```bash
git clone https://github.com/Gemukii/Attack-lens.git
cd Attack-lens
```

### Python environment

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install AttackLens in editable mode:

```bash
python -m pip install -e .
```

## Running a Scan

Run a network scan against localhost:

```bash
python -m attacklens.cli scan --network
```

Specify another target:

```bash
python -m attacklens.cli scan --network --host 192.168.1.10
```

Output results as JSON:

```bash
python -m attacklens.cli scan --network --json
```

The scan automatically saves its results to:

```text
results/latest.json
```

## Running the API

Start the FastAPI backend:

```bash
uvicorn attacklens.web.api:app --reload
```

The API will be available at:

```text
http://localhost:8000
```

Health check:

```text
http://localhost:8000/api/health
```

Results:

```text
http://localhost:8000/api/results
```

## Running the Dashboard

Install the frontend dependencies:

```bash
cd frontend
npm install
```

Start the Nuxt development server:

```bash
npm run dev
```

The dashboard will be available at:

```text
http://localhost:3000
```

The dashboard retrieves scan results from the FastAPI backend.

## Docker

AttackLens can also be started using Docker Compose.

From the project root:

```bash
docker compose up --build
```

This starts:

| Service   |   Port | Description        |
| --------- | -----: | ------------------ |
| Dashboard | `3000` | Nuxt web interface |
| API       | `8000` | FastAPI backend    |

The `results/` directory is shared with the API container so that scan results generated by the CLI can be displayed by the dashboard.

## Testing

Run the test suite with:

```bash
pytest
```

The tests currently cover:

* Data models
* Network scanner
* CLI argument parsing
* Result persistence

## Security

AttackLens is intended for systems that you own or are explicitly authorized to assess.

Do not use the scanner against systems without permission.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting information.

## Roadmap

### MVP

* [x] Python project structure
* [x] Finding data model
* [x] Basic network scanner
* [x] CLI
* [x] JSON result persistence
* [x] FastAPI backend
* [x] Initial Nuxt dashboard
* [ ] Docker Compose integration
* [ ] Complete dashboard/API integration

### Network security

* [ ] Local listening service discovery
* [ ] Windows network inspection
* [ ] Linux network inspection
* [ ] Service and version detection
* [ ] Network interface information
* [ ] Suspicious exposure detection
* [ ] TLS inspection

### System security

* [ ] Operating system information
* [ ] User and privilege analysis
* [ ] Firewall configuration
* [ ] Security configuration checks
* [ ] Running process analysis
* [ ] System update status

### Docker security

* [ ] Container discovery
* [ ] Image information
* [ ] Exposed container ports
* [ ] Privileged containers
* [ ] Host networking checks
* [ ] Docker socket exposure
* [ ] Container configuration analysis

### Vulnerability intelligence

* [ ] CVE enrichment
* [ ] CVSS information
* [ ] CISA KEV integration
* [ ] EPSS integration
* [ ] Software version matching

### Dashboard

* [ ] Finding details
* [ ] Finding filters
* [ ] Scan history
* [ ] Security posture overview
* [ ] Network overview
* [ ] System overview
* [ ] Docker overview
* [ ] Vulnerability overview
* [ ] Export functionality

## Development

AttackLens follows a modular architecture so that new security checks can be added without rewriting the entire application.

The long-term goal is to separate:

```text
Collectors
    ↓
Raw observations
    ↓
Security checks
    ↓
Findings
    ↓
Results
    ↓
API
    ↓
Dashboard
```

This architecture should allow AttackLens to progressively evolve from a simple local scanner into a broader self-hosted security assessment platform.

## License

See the repository for licensing information.
