"""SQLite persistence for AttackLens.

Only one process should own the database: when the API runs in Docker, the host
agent sends its reports over HTTP, because SQLite locking is not reliable across a
bind mount shared between a host and a container.
"""

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from attacklens.models import finding_identity

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_asset ON scans (scan_type, target, completed_at);
CREATE TABLE IF NOT EXISTS finding_triage (
    finding_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    reason TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL,
    message TEXT NOT NULL,
    findings TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agents (
    hostname TEXT PRIMARY KEY,
    platform TEXT,
    version TEXT,
    address TEXT,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_jobs (
    job_id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    target TEXT,
    status TEXT NOT NULL,
    error TEXT,
    scan_id TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
"""

# An order nobody picked up, or that never reported back, must not wait forever.
JOB_QUEUE_LIMIT_SECONDS = 30
JOB_RUN_LIMIT_SECONDS = 180


def results_directory() -> Path:
    """Return the directory holding legacy JSON results."""
    return Path(os.getenv("ATTACKLENS_RESULTS_DIR", "results"))


def default_database_path() -> Path:
    """Return the configured database location."""
    configured = os.getenv("ATTACKLENS_DB_PATH")
    return Path(configured) if configured else results_directory() / "attacklens.db"


def _migrate_legacy_document(document: dict[str, Any]) -> dict[str, Any]:
    """Bring a JSON result to the current shape, with asset-scoped finding identifiers."""
    target = document.get("target") or "unknown"
    findings = [
        {
            **finding,
            "target": target,
            "finding_id": finding_identity(
                target,
                finding.get("category"),
                finding.get("service"),
                finding.get("port"),
                finding.get("protocol"),
                finding.get("title"),
            ),
        }
        for finding in document.get("findings", [])
        if isinstance(finding, dict)
    ]
    return {
        **document,
        "scan_id": document.get("scan_id") or str(uuid4()),
        "target": target,
        "scan_type": document.get("scan_type") or "network",
        "status": document.get("status") or "complete",
        "findings": findings,
        "coverage": document.get("coverage") or {},
    }


class Store:
    """Scan, triage, and alert persistence."""

    def __init__(self, path: Path, legacy_directory: Path | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.executescript(SCHEMA)
            if version == 0 and legacy_directory is not None:
                self._import_legacy(connection, legacy_directory)
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open one connection per operation, which keeps the store thread-safe."""
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _import_legacy(self, connection: sqlite3.Connection, directory: Path) -> None:
        """Import JSON results written by earlier versions, skipping invalid files."""
        paths = sorted((directory / "history").glob("*.json"))
        paths.append(directory / "latest.json")
        for path in paths:
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(document, dict) and isinstance(document.get("findings"), list):
                self._insert(connection, _migrate_legacy_document(document), ignore_existing=True)

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        document: dict[str, Any],
        ignore_existing: bool = False,
    ) -> None:
        """Insert one scan document."""
        verb = "INSERT OR IGNORE" if ignore_existing else "INSERT OR REPLACE"
        connection.execute(
            f"{verb} INTO scans (scan_id, target, scan_type, status, completed_at, document) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                document["scan_id"],
                document["target"],
                document["scan_type"],
                document["status"],
                document.get("completed_at") or datetime.now(UTC).isoformat(),
                json.dumps(document, ensure_ascii=False),
            ),
        )

    def save_scan(self, document: dict[str, Any]) -> None:
        """Persist one scan document."""
        with self._connect() as connection:
            self._insert(connection, document)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Return one scan."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row["document"]) if row else None

    def list_scans(
        self,
        limit: int = 50,
        scan_type: str | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return scans, newest first."""
        clauses: list[str] = []
        parameters: list[Any] = []
        if scan_type:
            clauses.append("scan_type = ?")
            parameters.append(scan_type)
        if target:
            clauses.append("target = ?")
            parameters.append(target)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT document FROM scans {where} ORDER BY completed_at DESC LIMIT ?",
                (*parameters, limit),
            ).fetchall()
        return [json.loads(row["document"]) for row in rows]

    def latest_scan(
        self, scan_type: str, target: str | None = None
    ) -> dict[str, Any] | None:
        """Return the newest scan of a type."""
        scans = self.list_scans(limit=1, scan_type=scan_type, target=target)
        return scans[0] if scans else None

    def previous_complete_scan(self, document: dict[str, Any]) -> dict[str, Any] | None:
        """Return the baseline of a scan: the last complete one on the same asset."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM scans WHERE scan_type = ? AND target = ? "
                "AND status = 'complete' AND scan_id != ? "
                "ORDER BY completed_at DESC LIMIT 1",
                (document["scan_type"], document["target"], document["scan_id"]),
            ).fetchone()
        return json.loads(row["document"]) if row else None

    def triage_statuses(self) -> dict[str, dict[str, Any]]:
        """Return the triage decisions, by finding identifier."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT finding_id, status, reason, updated_at FROM finding_triage"
            ).fetchall()
        return {row["finding_id"]: dict(row) for row in rows}

    def set_triage(self, finding_id: str, status: str, reason: str | None) -> None:
        """Record a triage decision. Reopening a finding removes the decision."""
        with self._connect() as connection:
            if status == "open":
                connection.execute(
                    "DELETE FROM finding_triage WHERE finding_id = ?", (finding_id,)
                )
                return
            connection.execute(
                "INSERT OR REPLACE INTO finding_triage (finding_id, status, reason, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (finding_id, status, reason, datetime.now(UTC).isoformat()),
            )

    def add_alert(
        self,
        scan_id: str,
        target: str,
        message: str,
        findings: list[dict[str, Any]],
        delivered: bool,
    ) -> None:
        """Record an alert, whether or not a webhook delivered it."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO alerts (scan_id, target, created_at, message, findings, delivered) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    target,
                    datetime.now(UTC).isoformat(),
                    message,
                    json.dumps(findings, ensure_ascii=False),
                    int(delivered),
                ),
            )

    def touch_agent(self, hostname: str, platform: str, version: str, address: str) -> None:
        """Record that an agent is alive."""
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO agents (hostname, platform, version, address, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (hostname, platform, version, address, datetime.now(UTC).isoformat()),
            )

    def list_agents(self) -> list[dict[str, Any]]:
        """Return known agents, most recently seen first."""
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        return [dict(row) for row in rows]

    def _expire_jobs(self, connection: sqlite3.Connection) -> None:
        """Fail orders that were abandoned."""
        now = datetime.now(UTC)
        connection.execute(
            "UPDATE agent_jobs SET status = 'failed', error = ?, finished_at = ? "
            "WHERE status = 'queued' AND created_at < ?",
            (
                "The agent did not pick up this scan.",
                now.isoformat(),
                (now - timedelta(seconds=JOB_QUEUE_LIMIT_SECONDS)).isoformat(),
            ),
        )
        connection.execute(
            "UPDATE agent_jobs SET status = 'failed', error = ?, finished_at = ? "
            "WHERE status = 'running' AND started_at < ?",
            (
                "The agent did not finish this scan.",
                now.isoformat(),
                (now - timedelta(seconds=JOB_RUN_LIMIT_SECONDS)).isoformat(),
            ),
        )

    def create_job(self, agent: str, target: str | None) -> dict[str, Any] | None:
        """Queue a scan order, or return None when the agent already has one."""
        with self._connect() as connection:
            self._expire_jobs(connection)
            active = connection.execute(
                "SELECT 1 FROM agent_jobs WHERE agent = ? AND status IN ('queued', 'running')",
                (agent,),
            ).fetchone()
            if active:
                return None
            job_id = str(uuid4())
            connection.execute(
                "INSERT INTO agent_jobs (job_id, agent, target, status, created_at) "
                "VALUES (?, ?, ?, 'queued', ?)",
                (job_id, agent, target, datetime.now(UTC).isoformat()),
            )
            row = connection.execute(
                "SELECT * FROM agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return dict(row)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Return one scan order."""
        with self._connect() as connection:
            self._expire_jobs(connection)
            row = connection.execute(
                "SELECT * FROM agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return dict(row) if row else None

    def claim_job(self, agent: str) -> dict[str, Any] | None:
        """Hand the oldest queued order to its agent, exactly once."""
        with self._connect() as connection:
            self._expire_jobs(connection)
            row = connection.execute(
                "SELECT * FROM agent_jobs WHERE agent = ? AND status = 'queued' "
                "ORDER BY created_at LIMIT 1",
                (agent,),
            ).fetchone()
            if row is None:
                return None
            claimed = connection.execute(
                "UPDATE agent_jobs SET status = 'running', started_at = ? "
                "WHERE job_id = ? AND status = 'queued'",
                (datetime.now(UTC).isoformat(), row["job_id"]),
            )
        return dict(row) if claimed.rowcount else None

    def finish_job(
        self, job_id: str, status: str, error: str | None, scan_id: str | None
    ) -> bool:
        """Record the outcome of a running order."""
        with self._connect() as connection:
            finished = connection.execute(
                "UPDATE agent_jobs SET status = ?, error = ?, scan_id = ?, finished_at = ? "
                "WHERE job_id = ? AND status = 'running'",
                (status, error, scan_id, datetime.now(UTC).isoformat(), job_id),
            )
        return finished.rowcount == 1

    def list_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return alerts, newest first."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY alert_id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                **dict(row),
                "findings": json.loads(row["findings"]),
                "delivered": bool(row["delivered"]),
            }
            for row in rows
        ]
