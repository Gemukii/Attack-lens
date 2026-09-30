"""FastAPI backend for AttackLens."""

import json
import os
import re
from threading import BoundedSemaphore
from uuid import uuid4
from time import perf_counter
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
from fastapi.middleware.cors import CORSMiddleware

from attacklens.results import save_results
from attacklens.inventory import collect_inventory
from attacklens.posture import collect_posture
from attacklens.scanner import scan_network
from attacklens.vulnerabilities import query_package_vulnerabilities

app = FastAPI(
    title="AttackLens API",
    description="API for the AttackLens security scanner.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin for origin in os.getenv(
        "ATTACKLENS_CORS_ORIGINS", "http://localhost:3000"
    ).split(",") if origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

RESULTS_DIRECTORY = Path(os.getenv("ATTACKLENS_RESULTS_DIR", "results"))
RESULTS_PATH = RESULTS_DIRECTORY / "latest.json"
HISTORY_PATH = RESULTS_DIRECTORY / "history"
DEFAULT_TARGET = os.getenv("ATTACKLENS_DEFAULT_TARGET", "127.0.0.1")
INVENTORY_SCOPE = os.getenv("ATTACKLENS_INVENTORY_SCOPE", "runtime")
API_KEY = os.getenv("ATTACKLENS_API_KEY")
ALLOWED_TARGETS = {
    target.strip() for target in os.getenv("ATTACKLENS_ALLOWED_TARGETS", "").split(",")
    if target.strip()
}
SCAN_LIMIT = BoundedSemaphore(1)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Require a configured API key while keeping local development open by default."""
    if API_KEY is not None and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


class ScanRequest(BaseModel):
    """Request body for a network scan."""

    target: str = Field(default=DEFAULT_TARGET, min_length=1, max_length=253)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        """Reject URLs and shell-like input; targets remain hostnames or IPs."""
        target = value.strip()
        if not target or any(character in target for character in "/\\\x00\n\r\t"):
            raise ValueError("target must be a hostname or IP address")
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", target):
            raise ValueError("target contains unsupported characters")
        if ALLOWED_TARGETS and target not in ALLOWED_TARGETS:
            raise ValueError("target is not allowed")
        return target


def _load_scan(scan_id: str) -> dict[str, Any]:
    """Load one historical scan or raise a client-friendly 404."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", scan_id):
        raise HTTPException(status_code=422, detail="Invalid scan identifier.")
    path = HISTORY_PATH / f"{scan_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    try:
        with path.open("r", encoding="utf-8") as file:
            return _validate_scan_document(json.load(file))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="Stored scan is invalid.") from error


def _finding_key(finding: dict[str, Any]) -> str:
    """Build a stable identity for a network finding across scans."""
    return finding.get("finding_id") or "|".join(
        str(finding.get(field, ""))
        for field in ("category", "service", "port", "protocol", "title")
    )


def _validate_scan_document(document: Any) -> dict[str, Any]:
    """Validate the storage shape before exposing it through the API."""
    if not isinstance(document, dict):
        raise ValueError("scan document must be an object")
    if not isinstance(document.get("findings"), list):
        raise ValueError("findings must be a list")
    if not isinstance(document.get("score"), (int, float)):
        raise ValueError("score must be numeric")
    if not isinstance(document.get("open_ports"), list):
        raise ValueError("open_ports must be a list")
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
    """Check runtime packages against OSV without affecting network scans."""
    inventory = collect_inventory(INVENTORY_SCOPE)
    return query_package_vulnerabilities(inventory["packages"])


@app.get("/api/posture", dependencies=[Depends(require_api_key)])
def get_posture() -> dict[str, Any]:
    """Return non-invasive security posture checks for the API runtime."""
    return collect_posture(INVENTORY_SCOPE)


@app.post("/api/scan", dependencies=[Depends(require_api_key)])
def run_scan(request: ScanRequest) -> dict[str, Any]:
    """Run a synchronous network scan and return its persisted result."""
    if not SCAN_LIMIT.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="A scan is already running.")
    started_at = perf_counter()
    scan_id = str(uuid4())
    try:
        try:
            findings = scan_network(request.target)
        except (OSError, TimeoutError) as error:
            raise HTTPException(status_code=502, detail="Unable to scan target.") from error

        try:
            return save_results(
                findings=findings,
                path=RESULTS_PATH,
                target=request.target,
                scan_type="network",
                duration_seconds=perf_counter() - started_at,
                scan_id=scan_id,
                history_path=HISTORY_PATH / f"{scan_id}.json",
            )
        except OSError as error:
            raise HTTPException(status_code=500, detail="Unable to save scan results.") from error
    finally:
        SCAN_LIMIT.release()


@app.get("/api/scans", dependencies=[Depends(require_api_key)])
def get_scan_history() -> list[dict[str, Any]]:
    """Return stored scans, newest first."""
    if not HISTORY_PATH.exists():
        return []

    scans: list[dict[str, Any]] = []
    for path in HISTORY_PATH.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as file:
                scans.append(_validate_scan_document(json.load(file)))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return sorted(
        scans,
        key=lambda scan: scan.get("completed_at", ""),
        reverse=True,
    )


@app.get("/api/scans/compare", dependencies=[Depends(require_api_key)])
def compare_scans(before_id: str, after_id: str) -> dict[str, Any]:
    """Compare two historical scans and classify their changes."""
    before = _load_scan(before_id)
    after = _load_scan(after_id)
    before_findings = {_finding_key(finding): finding for finding in before["findings"]}
    after_findings = {_finding_key(finding): finding for finding in after["findings"]}
    before_keys = set(before_findings)
    after_keys = set(after_findings)

    return {
        "before_id": before_id,
        "after_id": after_id,
        "score_delta": after["score"] - before["score"],
        "finding_count_delta": len(after_findings) - len(before_findings),
        "new_findings": [after_findings[key] for key in sorted(after_keys - before_keys)],
        "fixed_findings": [before_findings[key] for key in sorted(before_keys - after_keys)],
        "persistent_findings": [after_findings[key] for key in sorted(after_keys & before_keys)],
        "ports_added": sorted(set(after.get("open_ports", [])) - set(before.get("open_ports", []))),
        "ports_removed": sorted(set(before.get("open_ports", [])) - set(after.get("open_ports", []))),
    }


@app.get("/api/results", dependencies=[Depends(require_api_key)])
def get_results() -> dict[str, Any]:
    """Return the latest scan results."""
    if not RESULTS_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="No scan results available.",
        )

    try:
        with RESULTS_PATH.open("r", encoding="utf-8") as file:
            return _validate_scan_document(json.load(file))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="Stored scan is invalid.") from error