"""FastAPI backend for AttackLens."""

import json
import os
from uuid import uuid4
from time import perf_counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from attacklens.results import save_results
from attacklens.scanner import scan_network

app = FastAPI(
    title="AttackLens API",
    description="API for the AttackLens security scanner.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RESULTS_PATH = Path("results/latest.json")
HISTORY_PATH = Path("results/history")
DEFAULT_TARGET = os.getenv("ATTACKLENS_DEFAULT_TARGET", "127.0.0.1")


class ScanRequest(BaseModel):
    """Request body for a network scan."""

    target: str = DEFAULT_TARGET


def _load_scan(scan_id: str) -> dict[str, Any]:
    """Load one historical scan or raise a client-friendly 404."""
    path = HISTORY_PATH / f"{scan_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=422, detail="Stored scan is invalid.") from error


def _finding_key(finding: dict[str, Any]) -> str:
    """Build a stable identity for a network finding across scans."""
    return "|".join(
        str(finding.get(field, ""))
        for field in ("category", "service", "port", "protocol", "title")
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    """Return the API health status."""
    return {"status": "ok"}


@app.post("/api/scan")
def run_scan(request: ScanRequest) -> dict[str, Any]:
    """Run a synchronous network scan and return its persisted result."""
    started_at = perf_counter()
    scan_id = str(uuid4())
    findings = scan_network(request.target)

    save_results(
        findings=findings,
        path=RESULTS_PATH,
        target=request.target,
        scan_type="network",
        duration_seconds=perf_counter() - started_at,
        scan_id=scan_id,
        history_path=HISTORY_PATH / f"{scan_id}.json",
    )

    return get_results()


@app.get("/api/scans")
def get_scan_history() -> list[dict[str, Any]]:
    """Return stored scans, newest first."""
    if not HISTORY_PATH.exists():
        return []

    scans: list[dict[str, Any]] = []
    for path in HISTORY_PATH.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as file:
                scans.append(json.load(file))
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(
        scans,
        key=lambda scan: scan.get("completed_at", ""),
        reverse=True,
    )


@app.get("/api/scans/compare")
def compare_scans(before_id: str, after_id: str) -> dict[str, Any]:
    """Compare two historical scans and classify their changes."""
    before = _load_scan(before_id)
    after = _load_scan(after_id)
    before_findings = {
        _finding_key(finding): finding for finding in before.get("findings", [])
    }
    after_findings = {
        _finding_key(finding): finding for finding in after.get("findings", [])
    }

    return {
        "before_id": before_id,
        "after_id": after_id,
        "score_delta": (after.get("score") or 0) - (before.get("score") or 0),
        "finding_count_delta": len(after_findings) - len(before_findings),
        "new_findings": [after_findings[key] for key in after_findings.keys() - before_findings.keys()],
        "fixed_findings": [before_findings[key] for key in before_findings.keys() - after_findings.keys()],
        "persistent_findings": [after_findings[key] for key in after_findings.keys() & before_findings.keys()],
        "ports_added": sorted(set(after.get("open_ports", [])) - set(before.get("open_ports", []))),
        "ports_removed": sorted(set(before.get("open_ports", [])) - set(after.get("open_ports", []))),
    }


@app.get("/api/results")
def get_results() -> dict[str, Any]:
    """Return the latest scan results."""
    if not RESULTS_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="No scan results available.",
        )

    with RESULTS_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)