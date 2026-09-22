"""FastAPI backend for AttackLens."""

import json
import os
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
DEFAULT_TARGET = os.getenv("ATTACKLENS_DEFAULT_TARGET", "127.0.0.1")


class ScanRequest(BaseModel):
    """Request body for a network scan."""

    target: str = DEFAULT_TARGET


@app.get("/api/health")
def health() -> dict[str, str]:
    """Return the API health status."""
    return {"status": "ok"}


@app.post("/api/scan")
def run_scan(request: ScanRequest) -> dict[str, Any]:
    """Run a synchronous network scan and return its persisted result."""
    started_at = perf_counter()
    findings = scan_network(request.target)

    save_results(
        findings=findings,
        path=RESULTS_PATH,
        target=request.target,
        scan_type="network",
        duration_seconds=perf_counter() - started_at,
    )

    return get_results()


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