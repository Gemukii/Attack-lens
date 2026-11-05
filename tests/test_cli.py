"""Tests for the AttackLens CLI."""

import io
import json
import sys
from urllib.error import HTTPError, URLError

import pytest

from attacklens import cli, client
from attacklens.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, build_parser, exit_code, main
from attacklens.models import Finding
from attacklens.results import build_document
from attacklens.scanner import NetworkScan
from attacklens.storage import Store


@pytest.fixture
def database(tmp_path, monkeypatch):
    """Point the CLI at a temporary database, without any API."""
    path = tmp_path / "attacklens.db"
    monkeypatch.setenv("ATTACKLENS_DB_PATH", str(path))
    monkeypatch.setenv("ATTACKLENS_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.delenv("ATTACKLENS_API_URL", raising=False)
    return path


def _finding(severity: str = "high") -> Finding:
    return Finding("network", severity, "SMB", "d", target="host", port=445)


def _run(monkeypatch, *arguments: str) -> int:
    """Run the CLI and return its exit code."""
    monkeypatch.setattr(sys, "argv", ["attacklens", *arguments])
    with pytest.raises(SystemExit) as outcome:
        main()
    return outcome.value.code


def test_parser_requires_command() -> None:
    """The parser should require a command."""
    assert build_parser().parse_args(["scan", "--network"]).command == "scan"


def test_network_scan_options() -> None:
    """Scan options should be parsed."""
    args = build_parser().parse_args(
        ["scan", "--network", "--host", "127.0.0.1", "--json", "--fail-on", "high"]
    )

    assert args.network is True
    assert args.host == "127.0.0.1"
    assert args.json is True
    assert args.fail_on == "high"


def test_agent_command_accepts_scheduling_options() -> None:
    """The agent can run repeatedly and report to an API."""
    args = build_parser().parse_args(
        ["agent", "--interval", "3600", "--api-url", "http://127.0.0.1:8000"]
    )

    assert args.command == "agent"
    assert args.interval == 3600


def test_scan_requires_a_scan_type(monkeypatch) -> None:
    """Running `scan` alone is a usage error."""
    assert _run(monkeypatch, "scan") == 2


def test_cli_scan_is_stored_with_identity_and_duration(database, monkeypatch) -> None:
    """A CLI scan must appear in the same history as API scans."""
    monkeypatch.setattr(cli, "scan_network", lambda host, timeout: NetworkScan([_finding()]))

    assert _run(monkeypatch, "scan", "--network", "--host", "host") == EXIT_OK

    scans = Store(database).list_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"]
    assert scans[0]["duration_seconds"] >= 0
    assert scans[0]["open_ports"] == [445]


def test_fail_on_turns_findings_into_an_exit_code(database, monkeypatch) -> None:
    """CI pipelines rely on the exit code."""
    monkeypatch.setattr(cli, "scan_network", lambda host, timeout: NetworkScan([_finding()]))

    assert _run(monkeypatch, "scan", "--network", "--fail-on", "high") == EXIT_FINDINGS
    assert _run(monkeypatch, "scan", "--network", "--fail-on", "critical") == EXIT_OK


def test_no_response_is_an_error_and_says_so(database, monkeypatch, capsys) -> None:
    """A silent host must not exit like a clean one."""
    monkeypatch.setattr(
        cli, "scan_network", lambda host, timeout: NetworkScan(status="no_response")
    )

    assert _run(monkeypatch, "scan", "--network", "--host", "192.0.2.1") == EXIT_ERROR
    assert "Nothing was observed" in capsys.readouterr().out


def test_unresolvable_host_prints_an_error_instead_of_a_traceback(
    database, monkeypatch, capsys
) -> None:
    """DNS failures are a user-facing message."""
    code = _run(monkeypatch, "scan", "--network", "--host", "does-not-exist.invalid")

    assert code == EXIT_ERROR
    assert "Unable to resolve target" in capsys.readouterr().err


def test_json_output_is_the_full_document(database, monkeypatch, capsys) -> None:
    """Scripts receive the same document as the API."""
    monkeypatch.setattr(cli, "scan_network", lambda host, timeout: NetworkScan([_finding()]))

    _run(monkeypatch, "scan", "--network", "--json")

    document = json.loads(capsys.readouterr().out)
    assert document["findings"][0]["port"] == 445
    assert document["score"] == 80


def test_agent_stores_a_host_report(database, monkeypatch) -> None:
    """The agent writes to the local database when no API is configured."""
    monkeypatch.setattr(
        cli,
        "collect_host_report",
        lambda: build_document([_finding()], "pc", "host"),
    )

    assert _run(monkeypatch, "agent") == EXIT_OK
    assert Store(database).latest_scan("host")["target"] == "pc"


def test_api_url_sends_the_report_and_skips_the_local_database(database, monkeypatch) -> None:
    """In Docker the API owns the database: the agent must not touch a local copy."""
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["key"] = request.get_header("X-api-key")
        captured["body"] = json.loads(request.data)
        return io.BytesIO(b'{"scan_id": "x"}')

    monkeypatch.setattr(client, "urlopen", fake_urlopen)
    monkeypatch.setattr(
        cli, "collect_host_report", lambda: build_document([], "pc", "host")
    )
    monkeypatch.setenv("ATTACKLENS_API_KEY", "secret")

    code = _run(monkeypatch, "agent", "--api-url", "http://127.0.0.1:8000/")

    assert code == EXIT_OK
    assert captured["url"] == "http://127.0.0.1:8000/api/reports"
    assert captured["key"] == "secret"
    assert captured["body"]["target"] == "pc"
    assert not database.exists()


@pytest.mark.parametrize(
    "failure",
    [
        URLError("offline"),
        HTTPError("http://x", 401, "denied", {}, io.BytesIO()),
    ],
)
def test_report_delivery_failure_is_reported(database, monkeypatch, capsys, failure) -> None:
    """A lost report must be visible, in the output and in the exit code."""

    def fail(request, timeout):
        raise failure

    monkeypatch.setattr(client, "urlopen", fail)
    monkeypatch.setattr(cli, "collect_host_report", lambda: build_document([], "pc", "host"))

    assert _run(monkeypatch, "agent", "--api-url", "http://127.0.0.1:8000") == EXIT_ERROR
    assert "Error:" in capsys.readouterr().err


def test_watch_requires_an_api(database, monkeypatch) -> None:
    """Orders come from the API, so there is nothing to watch without one."""
    assert _run(monkeypatch, "agent", "--watch") == 2


def test_exit_code_ignores_lower_severities() -> None:
    """Without --fail-on, findings do not change the exit code."""
    document = build_document([_finding("critical")], "host", "network")

    assert exit_code(document, None) == EXIT_OK
    assert exit_code(document, "critical") == EXIT_FINDINGS
