"""FastAPI backend for AttackLens."""

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

app = FastAPI(
    title="AttackLens API",
    description="API for the AttackLens security scanner.",
    version="0.1.0",
)

RESULTS_PATH = Path("results/latest.json")


@app.get("/api/health")
def health() -> dict[str, str]:
    """Return the API health status."""
    return {"status": "ok"}


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