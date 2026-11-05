"""FastAPI backend for AttackLens."""

import hashlib
import hmac
import os
import re
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from threading import BoundedSemaphore, Event, Thread
from time import perf_counter
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from attacklens.audit import (
    OutOfScope,
    audit_mode_enabled,
    enforce_scope,
    parse_scope,
    render_report,
)
from attacklens.exposure import annotate, exposure_report, find_probe
from attacklens.inventory import collect_inventory
from attacklens.paths import attack_paths
from attacklens.pipeline import (
    MONITOR_INTERVAL_SECONDS,
    SilenceMonitor,
    backup_directory,
    daily_maintenance,
    ingest,
    run_backup,
)
from attacklens.posture import collect_posture
from attacklens.results import (
    apply_triage,
    compare_documents,
    finding_fingerprint,
    network_document,
)
from attacklens.risk import assess_document
from attacklens.scanner import TargetResolutionError, is_valid_target, scan_network
from attacklens.storage import Store, default_database_path, results_directory
from attacklens.vulnerabilities import osv_enabled, query_package_vulnerabilities


def _split_env(name: str, default: str = "") -> list[str]:
    """Read a comma-separated environment variable."""
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _run_maintenance(stop: Event) -> None:
    """Run periodic work until the API stops."""
    store = get_store()
    monitor = SilenceMonitor(store)
    last_daily_run: date | None = None
    while not stop.wait(MONITOR_INTERVAL_SECONDS):
        monitor.tick()
        today = datetime.now(UTC).date()
        if today != last_daily_run:
            daily_maintenance(store)
            last_daily_run = today


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Start and stop the periodic work."""
    stop = Event()
    Thread(target=_run_maintenance, args=(stop,), daemon=True).start()
    yield
    stop.set()


app = FastAPI(
    title="AttackLens API",
    description="API for the AttackLens security scanner.",
    version="0.1.0",
    lifespan=lifespan,
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
ENROLLMENT_CODE_MINUTES = 15
TRIAGE_DAYS = {"accepted": 90, "false_positive": 365}


@lru_cache(maxsize=1)
def get_store() -> Store:
    """Open the database on first use, so importing this module has no side effect."""
    return Store(default_database_path(), legacy_directory=results_directory())


StoreDependency = Annotated[Store, Depends(get_store)]


def _is_valid_key(candidate: str | None) -> bool:
    """Compare an API key in constant time."""
    if API_KEY is None or candidate is None:
        return False
    return hmac.compare_digest(candidate.encode(), API_KEY.encode())


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Require a configured API key while keeping local development open by default."""
    if API_KEY is not None and not _is_valid_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


def _hash_secret(secret: str) -> str:
    """Hash a high-entropy secret, so that a stolen database does not reveal it."""
    return hashlib.sha256(secret.encode()).hexdigest()


def _bearer_agent(store: Store, authorization: str | None) -> str | None:
    """Return the machine identified by a bearer token."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return store.agent_for_token(_hash_secret(token.strip()))


def require_agent(
    store: StoreDependency, authorization: str | None = Header(default=None)
) -> str:
    """Identify the calling agent. Its name comes from its token, never from its words."""
    hostname = _bearer_agent(store, authorization)
    if hostname is None:
        raise HTTPException(status_code=401, detail="Invalid or missing agent token.")
    return hostname


def require_reporter(
    store: StoreDependency,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> str | None:
    """Accept an agent, or an administrator. Return the agent's name, if it is one."""
    hostname = _bearer_agent(store, authorization)
    if hostname is not None:
        return hostname
    if API_KEY is None or _is_valid_key(x_api_key):
        return None
    raise HTTPException(status_code=401, detail="Invalid or missing credentials.")


AgentDependency = Annotated[str, Depends(require_agent)]
ReporterDependency = Annotated[str | None, Depends(require_reporter)]


def actor_of(x_attacklens_actor: str | None = Header(default=None)) -> str:
    """Name who is acting, for the audit log."""
    return (x_attacklens_actor or "api")[:64]


ActorDependency = Annotated[str, Depends(actor_of)]


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
    scan_type: Literal["network", "host", "probe"]
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


class EnrollRequest(BaseModel):
    """An agent asking for its identity."""

    code: str = Field(min_length=8, max_length=128)
    hostname: str = Field(min_length=1, max_length=253)


class EngagementRequest(BaseModel):
    """An authorized assessment and what it covers."""

    name: str = Field(min_length=1, max_length=200)
    authorized_by: str = Field(min_length=1, max_length=200)
    reference: str = Field(min_length=1, max_length=200)
    scope: list[str] = Field(min_length=1, max_length=256)
    starts_at: datetime
    ends_at: datetime

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, value: list[str]) -> list[str]:
        """Only networks and addresses, never hostnames."""
        return parse_scope(value)


class TriageRequest(BaseModel):
    """A decision about a finding."""

    status: Literal["open", "accepted", "false_positive"]
    reason: str | None = Field(default=None, max_length=500)
    days: int | None = Field(default=None, ge=1, le=365)


def _check_scope(store: Store, target: str) -> None:
    """In audit mode, refuse any target outside an active engagement."""
    if not audit_mode_enabled():
        return
    try:
        enforce_scope(target, store.list_engagements())
    except OutOfScope as error:
        store.add_audit("api", "scan_refused", target)
        raise HTTPException(status_code=403, detail=str(error)) from error


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
    _check_scope(store, request.target)
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


@app.post("/api/reports", status_code=201)
def receive_report(
    report: ReportRequest, store: StoreDependency, reporter: ReporterDependency
) -> dict[str, Any]:
    """Store a scan produced outside the API, such as a host agent report."""
    if reporter is not None:
        # An agent speaks for itself: it cannot declare another enrolled machine clean.
        others = {agent["hostname"] for agent in store.list_agents()} - {reporter}
        if report.target in others or (report.scan_type == "host" and report.target != reporter):
            store.add_audit(reporter, "report_refused", report.target)
            raise HTTPException(status_code=403, detail="An agent can only report on itself.")
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


@app.post("/api/agents/enrollment", dependencies=[Depends(require_api_key)])
def create_enrollment_code(store: StoreDependency, actor: ActorDependency) -> dict[str, str]:
    """Create a one-time code to enroll a machine."""
    code = secrets.token_urlsafe(24)
    expires_at = (datetime.now(UTC) + timedelta(minutes=ENROLLMENT_CODE_MINUTES)).isoformat()
    store.create_enrollment_code(_hash_secret(code), expires_at)
    store.add_audit(actor, "enrollment_code_created")
    return {"code": code, "expires_at": expires_at}


@app.post("/api/agents/enroll")
def enroll_agent(request: EnrollRequest, store: StoreDependency) -> dict[str, str]:
    """Exchange a one-time code for the agent's own token."""
    if not store.consume_enrollment_code(_hash_secret(request.code)):
        store.add_audit("unknown", "enrollment_refused", request.hostname)
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment code.")
    token = secrets.token_urlsafe(32)
    store.set_agent_token(request.hostname, _hash_secret(token))
    store.add_audit(request.hostname, "agent_enrolled")
    return {"hostname": request.hostname, "token": token}


@app.delete("/api/agents/{hostname}", dependencies=[Depends(require_api_key)])
def revoke_agent(hostname: str, store: StoreDependency, actor: ActorDependency) -> dict[str, str]:
    """Remove an agent. Its token stops working immediately."""
    if not store.revoke_agent(hostname):
        raise HTTPException(status_code=404, detail="Unknown agent.")
    store.add_audit(actor, "agent_revoked", hostname)
    return {"hostname": hostname, "status": "revoked"}


@app.post("/api/agent/poll")
def agent_poll(poll: AgentPoll, store: StoreDependency, agent: AgentDependency) -> dict[str, Any]:
    """Record an agent heartbeat and hand it its next scan order."""
    store.touch_agent(agent, poll.platform, poll.version, poll.address)
    return {"job": store.claim_job(agent)}


@app.post("/api/agent/jobs/{job_id}/result")
def agent_job_result(
    job_id: str, result: JobResult, store: StoreDependency, agent: AgentDependency
) -> dict[str, str]:
    """Record the outcome of a scan order."""
    job = store.get_job(job_id)
    if job is None or job["agent"] != agent:
        raise HTTPException(status_code=404, detail="No running scan with this identifier.")
    if not store.finish_job(job_id, result.status, result.error, result.scan_id):
        raise HTTPException(status_code=404, detail="No running scan with this identifier.")
    return {"job_id": job_id, "status": result.status}


@app.post("/api/jobs", status_code=202, dependencies=[Depends(require_api_key)])
def create_job(
    request: JobRequest, store: StoreDependency, actor: ActorDependency
) -> dict[str, Any]:
    """Ask the host agent to run a scan from its machine."""
    agent = next((item for item in _agents_with_status(store) if item["online"]), None)
    if agent is None:
        raise HTTPException(status_code=409, detail="No host agent is connected.")
    _check_scope(store, request.target or agent["address"])
    job = store.create_job(agent["hostname"], request.target)
    if job is None:
        raise HTTPException(status_code=429, detail="A scan is already running.")
    store.add_audit(actor, "scan_ordered", request.target or agent["hostname"])
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
    scan_type: Literal["network", "host", "probe"] | None = None,
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


def _present(store: Store, document: dict[str, Any]) -> dict[str, Any]:
    """Add to a stored scan everything that was learned about it since."""
    host_report = store.latest_scan("host", document["target"])
    annotated = annotate(document, host_report, find_probe(store, host_report))
    return assess_document(apply_triage(annotated, store.triage_statuses()))


def _latest(store: Store, scan_type: str, target: str | None = None) -> dict[str, Any]:
    """Return the newest scan of a type, with triage applied."""
    document = store.latest_scan(scan_type, target)
    if document is None:
        raise HTTPException(status_code=404, detail="No scan results available.")
    return _present(store, document)


@app.get("/api/results", dependencies=[Depends(require_api_key)])
def get_results(store: StoreDependency) -> dict[str, Any]:
    """Return the latest network scan."""
    return _latest(store, "network")


@app.get("/api/host", dependencies=[Depends(require_api_key)])
def get_host_report(store: StoreDependency, target: str | None = None) -> dict[str, Any]:
    """Return the latest host agent report."""
    return _latest(store, "host", target)


def _asset_views(
    store: Store, target: str | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Return the latest network and host views of one machine."""
    host = store.latest_scan("host", target)
    name = target or (host["target"] if host else None)
    network = store.latest_scan("network", name) if name else None
    return (
        _present(store, network) if network else None,
        _present(store, host) if host else None,
    )


def _paths_of(network: dict[str, Any] | None, host: dict[str, Any] | None) -> dict[str, Any]:
    """Compute attack paths from both views of a machine."""
    return attack_paths([*(host or {}).get("findings", []), *(network or {}).get("findings", [])])


@app.get("/api/paths", dependencies=[Depends(require_api_key)])
def get_attack_paths(store: StoreDependency, target: str | None = None) -> dict[str, Any]:
    """Return how the findings of a machine chain into a compromise."""
    return _paths_of(*_asset_views(store, target))


@app.get("/api/report", response_class=HTMLResponse, dependencies=[Depends(require_api_key)])
def get_report(
    store: StoreDependency, actor: ActorDependency, target: str | None = None
) -> HTMLResponse:
    """Return a printable report of a machine."""
    network, host = _asset_views(store, target)
    if network is None and host is None:
        raise HTTPException(status_code=404, detail="No scan results available.")
    name = (host or network)["target"]
    engagements = store.list_engagements()
    store.add_audit(actor, "report_generated", name)
    return HTMLResponse(
        render_report(
            name, network, host, _paths_of(network, host), engagements[0] if engagements else None
        )
    )


@app.post("/api/engagements", status_code=201, dependencies=[Depends(require_api_key)])
def create_engagement(
    request: EngagementRequest, store: StoreDependency, actor: ActorDependency
) -> dict[str, Any]:
    """Record an authorized engagement. Its scope applies in audit mode."""
    if request.ends_at <= request.starts_at:
        raise HTTPException(status_code=422, detail="An engagement must end after it starts.")
    engagement = store.create_engagement(
        {
            **request.model_dump(),
            "starts_at": request.starts_at.astimezone(UTC).isoformat(),
            "ends_at": request.ends_at.astimezone(UTC).isoformat(),
        }
    )
    store.add_audit(actor, "engagement_created", request.name)
    return engagement


@app.get("/api/engagements", dependencies=[Depends(require_api_key)])
def get_engagements(store: StoreDependency) -> list[dict[str, Any]]:
    """Return the recorded engagements."""
    return store.list_engagements()


@app.get("/api/exposure", dependencies=[Depends(require_api_key)])
def get_exposure(store: StoreDependency, target: str | None = None) -> dict[str, Any]:
    """Return what is really reachable, from the agent and probe views."""
    host_report = store.latest_scan("host", target)
    return exposure_report(host_report, find_probe(store, host_report))


@app.put("/api/findings/{finding_id}/triage", dependencies=[Depends(require_api_key)])
def set_finding_triage(
    finding_id: str, request: TriageRequest, store: StoreDependency, actor: ActorDependency
) -> dict[str, Any]:
    """Accept a risk, mark a false positive, or reopen a finding."""
    if not re.fullmatch(r"[a-f0-9]{64}", finding_id):
        raise HTTPException(status_code=422, detail="Invalid finding identifier.")
    if request.status == "open":
        store.set_triage(finding_id, "open", None)
        store.add_audit(actor, "finding_reopened", finding_id[:12])
        return {"finding_id": finding_id, "status": "open", "reason": None, "expires_at": None}

    finding = store.find_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Unknown finding.")
    days = request.days or TRIAGE_DAYS[request.status]
    expires_at = (datetime.now(UTC) + timedelta(days=days)).isoformat()
    store.set_triage(
        finding_id, request.status, request.reason, expires_at, finding_fingerprint(finding)
    )
    store.add_audit(
        actor, f"finding_{request.status}", f"{finding.get('title')}: {request.reason or '-'}"
    )
    return {
        "finding_id": finding_id,
        "status": request.status,
        "reason": request.reason,
        "expires_at": expires_at,
    }


@app.get("/api/audit", dependencies=[Depends(require_api_key)])
def get_audit(
    store: StoreDependency,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> list[dict[str, Any]]:
    """Return the journal of security-relevant actions, newest first."""
    return store.list_audit(limit)


@app.post("/api/backups", status_code=201, dependencies=[Depends(require_api_key)])
def create_backup(store: StoreDependency, actor: ActorDependency) -> dict[str, str]:
    """Back the database up now."""
    directory = backup_directory()
    if directory is None:
        raise HTTPException(status_code=409, detail="ATTACKLENS_BACKUP_DIR is not configured.")
    try:
        path = run_backup(store, directory)
    except OSError as error:
        raise HTTPException(status_code=500, detail="Unable to write the backup.") from error
    store.add_audit(actor, "backup_created", path.name)
    return {"backup": path.name}


@app.get("/api/alerts", dependencies=[Depends(require_api_key)])
def get_alerts(
    store: StoreDependency,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
) -> list[dict[str, Any]]:
    """Return recent alerts, newest first."""
    return store.list_alerts(limit)
