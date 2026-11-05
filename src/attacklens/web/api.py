"""FastAPI backend for AttackLens."""

import hmac
import os
import re
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from threading import BoundedSemaphore
from time import perf_counter
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from attacklens.inventory import collect_inventory
from attacklens.pipeline import ingest
from attacklens.posture import collect_posture
from attacklens.results import apply_triage, compare_documents, network_document
from attacklens.scanner import TargetResolutionError, is_valid_target, scan_network
from attacklens.storage import Store, default_database_path, results_directory
from attacklens.vulnerabilities import osv_enabled, query_package_vulnerabilities


def _split_env(name: str, default: str = "") -> list[str]:
    """Read a comma-separated environment variable."""
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


app = FastAPI(
    title="AttackLens API",
    description="API for the AttackLens security scanner.",
    version="0.1.0",
)

# Rejects DNS rebinding: a web page cannot reach this API through its own hostname.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=_split_env("ATTACKLENS_ALLOWED_HOSTS", "localhost,127.0.0.1,api"),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_split_env("ATTACKLENS_CORS_ORIGINS", "http://localhost:3000"),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

DEFAULT_TARGET = os.getenv("ATTACKLENS_DEFAULT_TARGET", "127.0.0.1")
INVENTORY_SCOPE = os.getenv("ATTACKLENS_INVENTORY_SCOPE", "runtime")
API_KEY = os.getenv("ATTACKLENS_API_KEY") or None
ALLOWED_TARGETS = set(_split_env("ATTACKLENS_ALLOWED_TARGETS"))
SCAN_LIMIT = BoundedSemaphore(1)
SCAN_ID_PATTERN = r"[A-Za-z0-9_-]{1,128}"
AGENT_ONLINE_SECONDS = 10


@lru_cache(maxsize=1)
def get_store() -> Store:
    """Open the database on first use, so importing this module has no side effect."""
    return Store(default_database_path(), legacy_directory=results_directory())


StoreDependency = Annotated[Store, Depends(get_store)]


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Require a configured API key while keeping local development open by default."""
    if API_KEY is None:
        return
    if x_api_key is None or not hmac.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


def _validate_target(value: str) -> str:
    """Reject URLs and shell-like input; targets remain hostnames or IPs."""
    target = value.strip()
    if not is_valid_target(target):
        raise ValueError("target must be a hostname or IP address")
    if ALLOWED_TARGETS and target not in ALLOWED_TARGETS:
        raise ValueError("target is not allowed")
    return target


class ScanRequest(BaseModel):
    """Request body for a network scan run from the API runtime."""

    target: str = Field(
        default=DEFAULT_TARGET, min_length=1, max_length=253, validate_default=True
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        """Apply the shared target rules."""
        return _validate_target(value)


class JobRequest(BaseModel):
    """A scan order for the host agent. Without a target, it scans its own machine."""

    target: str | None = Field(default=None, max_length=253)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str | None) -> str | None:
        """Apply the shared target rules to explicit targets."""
        return _validate_target(value) if value and value.strip() else None


class AgentPoll(BaseModel):
    """An agent asking for work, which also proves it is alive."""

    hostname: str = Field(min_length=1, max_length=253)
    platform: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=32)
    address: str = Field(default="", max_length=64)


class JobResult(BaseModel):
    """The outcome of a scan order."""

    status: Literal["done", "failed"]
    error: str | None = Field(default=None, max_length=500)
    scan_id: str | None = Field(default=None, pattern=f"^{SCAN_ID_PATTERN}$")


class ReportRequest(BaseModel):
    """A finished scan sent by a CLI or by a host agent."""

    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(pattern=f"^{SCAN_ID_PATTERN}$")
    target: str = Field(min_length=1, max_length=253)
    scan_type: Literal["network", "host"]
    status: Literal["complete", "partial", "no_response"]
    completed_at: str
    score: int | None = Field(default=None, ge=0, le=100)
    findings: list[dict[str, Any]]

    @field_validator("findings")
    @classmethod
    def validate_findings(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Findings need an identity to be compared and triaged."""
        if any(not finding.get("finding_id") for finding in value):
            raise ValueError("every finding needs a finding_id")
        return value


class TriageRequest(BaseModel):
    """A decision about a finding."""

    status: Literal["open", "accepted", "false_positive"]
    reason: str | None = Field(default=None, max_length=500)


def _load_scan(store: Store, scan_id: str) -> dict[str, Any]:
    """Load one stored scan or raise a client-friendly error."""
    if not re.fullmatch(SCAN_ID_PATTERN, scan_id):
        raise HTTPException(status_code=422, detail="Invalid scan identifier.")
    document = store.get_scan(scan_id)
    if document is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return document


@app.get("/api/health")
def health() -> dict[str, str]:
    """Return the API health status."""
    return {"status": "ok"}


@app.get("/api/inventory", dependencies=[Depends(require_api_key)])
def get_inventory() -> dict[str, Any]:
    """Return safe metadata for the environment running the API."""
    return collect_inventory(INVENTORY_SCOPE)


@app.get("/api/vulnerabilities", dependencies=[Depends(require_api_key)])
def get_vulnerabilities() -> dict[str, Any]:
    """Check runtime packages against OSV when the user opted in."""
    if not osv_enabled():
        return {"status": "disabled", "packages_checked": 0, "vulnerabilities": []}
    inventory = collect_inventory(INVENTORY_SCOPE)
    return query_package_vulnerabilities(inventory["packages"])


@app.get("/api/posture", dependencies=[Depends(require_api_key)])
def get_posture() -> dict[str, Any]:
    """Return non-invasive security posture checks for the API runtime."""
    return collect_posture(INVENTORY_SCOPE)


@app.post("/api/scan", dependencies=[Depends(require_api_key)])
def run_scan(request: ScanRequest, store: StoreDependency) -> dict[str, Any]:
    """Run a synchronous network scan and return its stored result."""
    if not SCAN_LIMIT.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="A scan is already running.")
    started_at = perf_counter()
    try:
        try:
            scan = scan_network(request.target)
        except TargetResolutionError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except OSError as error:
            raise HTTPException(status_code=502, detail="Unable to scan target.") from error

        document = network_document(
            scan, request.target, perf_counter() - started_at, vantage=INVENTORY_SCOPE
        )
        ingest(store, document)
        return apply_triage(document, store.triage_statuses())
    finally:
        SCAN_LIMIT.release()


@app.post("/api/reports", status_code=201, dependencies=[Depends(require_api_key)])
def receive_report(report: ReportRequest, store: StoreDependency) -> dict[str, Any]:
    """Store a scan produced outside the API, such as a host agent report."""
    alerted = ingest(store, report.model_dump())
    return {"scan_id": report.scan_id, "alerts": len(alerted)}


def _agents_with_status(store: Store) -> list[dict[str, Any]]:
    """Return known agents, with whether each one polled recently."""
    limit = (datetime.now(UTC) - timedelta(seconds=AGENT_ONLINE_SECONDS)).isoformat()
    return [{**agent, "online": agent["last_seen"] >= limit} for agent in store.list_agents()]


@app.get("/api/agents", dependencies=[Depends(require_api_key)])
def get_agents(store: StoreDependency) -> list[dict[str, Any]]:
    """Return known host agents."""
    return _agents_with_status(store)


@app.post("/api/agent/poll", dependencies=[Depends(require_api_key)])
def agent_poll(poll: AgentPoll, store: StoreDependency) -> dict[str, Any]:
    """Record an agent heartbeat and hand it its next scan order."""
    store.touch_agent(poll.hostname, poll.platform, poll.version, poll.address)
    return {"job": store.claim_job(poll.hostname)}


@app.post("/api/agent/jobs/{job_id}/result", dependencies=[Depends(require_api_key)])
def agent_job_result(job_id: str, result: JobResult, store: StoreDependency) -> dict[str, str]:
    """Record the outcome of a scan order."""
    if not store.finish_job(job_id, result.status, result.error, result.scan_id):
        raise HTTPException(status_code=404, detail="No running scan with this identifier.")
    return {"job_id": job_id, "status": result.status}


@app.post("/api/jobs", status_code=202, dependencies=[Depends(require_api_key)])
def create_job(request: JobRequest, store: StoreDependency) -> dict[str, Any]:
    """Ask the host agent to run a scan from its machine."""
    agent = next((item for item in _agents_with_status(store) if item["online"]), None)
    if agent is None:
        raise HTTPException(status_code=409, detail="No host agent is connected.")
    job = store.create_job(agent["hostname"], request.target)
    if job is None:
        raise HTTPException(status_code=429, detail="A scan is already running.")
    return job


@app.get("/api/jobs/{job_id}", dependencies=[Depends(require_api_key)])
def get_job(job_id: str, store: StoreDependency) -> dict[str, Any]:
    """Return the state of a scan order."""
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan order.")
    return job


@app.get("/api/scans", dependencies=[Depends(require_api_key)])
def get_scan_history(
    store: StoreDependency,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    scan_type: Literal["network", "host"] | None = None,
    target: str | None = None,
) -> list[dict[str, Any]]:
    """Return stored scans, newest first."""
    statuses = store.triage_statuses()
    return [
        apply_triage(scan, statuses)
        for scan in store.list_scans(limit=limit, scan_type=scan_type, target=target)
    ]


@app.get("/api/scans/compare", dependencies=[Depends(require_api_key)])
def compare_scans(before_id: str, after_id: str, store: StoreDependency) -> dict[str, Any]:
    """Compare two scans of the same asset and classify their changes."""
    before = _load_scan(store, before_id)
    after = _load_scan(store, after_id)
    if (before["target"], before["scan_type"]) != (after["target"], after["scan_type"]):
        raise HTTPException(status_code=422, detail="Scans must cover the same asset.")
    statuses = store.triage_statuses()
    return compare_documents(apply_triage(before, statuses), apply_triage(after, statuses))


def _latest(store: Store, scan_type: str, target: str | None = None) -> dict[str, Any]:
    """Return the newest scan of a type, with triage applied."""
    document = store.latest_scan(scan_type, target)
    if document is None:
        raise HTTPException(status_code=404, detail="No scan results available.")
    return apply_triage(document, store.triage_statuses())


@app.get("/api/results", dependencies=[Depends(require_api_key)])
def get_results(store: StoreDependency) -> dict[str, Any]:
    """Return the latest network scan."""
    return _latest(store, "network")


@app.get("/api/host", dependencies=[Depends(require_api_key)])
def get_host_report(store: StoreDependency, target: str | None = None) -> dict[str, Any]:
    """Return the latest host agent report."""
    return _latest(store, "host", target)


@app.put("/api/findings/{finding_id}/triage", dependencies=[Depends(require_api_key)])
def set_finding_triage(
    finding_id: str, request: TriageRequest, store: StoreDependency
) -> dict[str, Any]:
    """Accept a risk, mark a false positive, or reopen a finding."""
    if not re.fullmatch(r"[a-f0-9]{64}", finding_id):
        raise HTTPException(status_code=422, detail="Invalid finding identifier.")
    store.set_triage(finding_id, request.status, request.reason)
    return {"finding_id": finding_id, "status": request.status, "reason": request.reason}


@app.get("/api/alerts", dependencies=[Depends(require_api_key)])
def get_alerts(
    store: StoreDependency,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
) -> list[dict[str, Any]]:
    """Return recent alerts, newest first."""
    return store.list_alerts(limit)
