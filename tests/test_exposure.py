"""Tests for the Windows posture and the inside/outside correlation."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from attacklens import cli, windows_posture
from attacklens.exposure import (
    EXPOSED,
    LOCAL,
    SHIELDED,
    UNVERIFIED,
    annotate,
    exposure_report,
    find_probe,
    port_verdict,
)
from attacklens.models import Finding
from attacklens.pipeline import ingest
from attacklens.results import build_document, probe_document
from attacklens.scanner import NetworkScan
from attacklens.windows_posture import (
    executable_of,
    is_listed_admin,
    parse_winget_upgrades,
    persistence_findings,
    posture_findings,
    software_findings,
)

NOW = datetime(2026, 11, 5, tzinfo=UTC)

HEALTHY = {
    "status": "complete",
    "last_update": "2026-11-01T06:02:04.0000000Z",
    "defender": {
        "running_mode": "Normal",
        "realtime": True,
        "signature_age_days": 0,
        "tamper_protected": True,
    },
    "bitlocker": 1,
    "uac": {"enabled": 1, "admin_prompt": 5},
    "rdp": {"enabled": False, "nla": True},
    "user_is_admin": False,
    "guest_enabled": False,
    "smb": {"smb1": False, "signing_required": True, "server_running": True},
    "autoruns": [],
}


def _titles(data: dict) -> list[str]:
    return [finding.title for finding in posture_findings("pc", data, NOW)]


def test_healthy_machine_has_no_finding() -> None:
    """A well configured machine stays quiet."""
    assert _titles(HEALTHY) == []


@pytest.mark.parametrize(
    ("change", "title", "severity"),
    [
        ({"last_update": "2026-08-01T00:00:00Z"}, "Windows updates are late", "high"),
        ({"bitlocker": 2}, "The system disk is not encrypted", "medium"),
        ({"uac": {"enabled": 0, "admin_prompt": 5}}, "User Account Control does not prompt", "high"),
        ({"uac": {"enabled": 1, "admin_prompt": 0}}, "User Account Control does not prompt", "high"),
        ({"user_is_admin": True}, "The daily account is an administrator", "low"),
        ({"guest_enabled": True}, "The Guest account is enabled", "medium"),
        ({"rdp": {"enabled": True, "nla": False}}, "Remote Desktop is enabled", "high"),
        ({"rdp": {"enabled": True, "nla": True}}, "Remote Desktop is enabled", "medium"),
        (
            {"smb": {"smb1": True, "signing_required": True, "server_running": True}},
            "SMB1 is enabled",
            "high",
        ),
        (
            {"smb": {"smb1": False, "signing_required": False, "server_running": True}},
            "SMB signing is not required",
            "low",
        ),
    ],
)
def test_weak_control_is_reported(change, title, severity) -> None:
    """Each weakness produces its finding."""
    findings = posture_findings("pc", {**HEALTHY, **change}, NOW)

    assert [(finding.title, finding.severity) for finding in findings] == [(title, severity)]


def test_defender_problems_are_reported() -> None:
    """The antivirus has several ways of being weak."""
    defender = {
        "running_mode": "Normal",
        "realtime": False,
        "signature_age_days": 30,
        "tamper_protected": False,
    }

    titles = _titles({**HEALTHY, "defender": defender})

    assert "Real-time antivirus protection is off" in titles
    assert "Antivirus signatures are old" in titles
    assert "Tamper protection is off" in titles


def test_another_antivirus_is_not_a_defender_problem() -> None:
    """Defender steps aside when another product is registered."""
    defender = {"running_mode": "Passive Mode", "realtime": False, "signature_age_days": 90}

    assert _titles({**HEALTHY, "defender": defender}) == []


def test_stopped_smb_server_needs_no_signing() -> None:
    """A service that does not run does not need hardening."""
    smb = {"smb1": False, "signing_required": False, "server_running": False}

    assert _titles({**HEALTHY, "smb": smb}) == []


@pytest.mark.parametrize(
    ("missing", "control"),
    [
        ("last_update", "Windows Update history"),
        ("defender", "Microsoft Defender"),
        ("bitlocker", "Disk encryption"),
        ("uac", "User Account Control"),
        ("user_is_admin", "Membership of the administrators group"),
    ],
)
def test_unreadable_control_is_not_a_passed_control(missing, control) -> None:
    """What could not be observed stays visible."""
    data = {key: value for key, value in HEALTHY.items() if key != missing}

    findings = posture_findings("pc", data, NOW)

    assert [finding.title for finding in findings] == [f"{control} could not be checked"]
    assert findings[0].severity == "info"


def test_failed_collection_is_reported() -> None:
    """A collector that failed must not read as a clean machine."""
    findings = posture_findings("pc", {"status": "unknown"}, NOW)

    assert findings[0].title == "Windows posture could not be checked"


def test_collector_failure_is_unknown(monkeypatch) -> None:
    """PowerShell can fail or print garbage."""

    def fail(*args, **kwargs):
        raise OSError("no powershell")

    monkeypatch.setattr(windows_posture.subprocess, "run", fail)

    assert windows_posture.collect_windows_posture()["status"] == "unknown"


@pytest.mark.parametrize(
    ("administrators", "user", "expected"),
    [
        (["PC\\Administrateur", "PC\\alrik"], "alrik", True),
        (["PC\\Administrateur", "PC\\ALRIK"], "alrik", True),
        (["PC\\Administrateur"], "alrik", False),
        ("PC\\alrik", "alrik", True),
        (None, "alrik", None),
    ],
)
def test_is_listed_admin(administrators, user, expected) -> None:
    """A single member comes back from PowerShell as a plain string."""
    assert is_listed_admin(administrators, user) is expected


@pytest.mark.parametrize(
    ("command", "program"),
    [
        ('"C:\\Program Files\\App\\app.exe" --token secret', "C:\\Program Files\\App\\app.exe"),
        ("C:\\Program Files (x86)\\App\\app.exe /background", "C:\\Program Files (x86)\\App\\app.exe"),
        ("C:\\tool\\run.cmd --password hunter2", "C:\\tool\\run.cmd"),
        ("rundll32 thing.dll,Start", "rundll32"),
    ],
)
def test_arguments_are_dropped(command, program) -> None:
    """Command lines can hold secrets, which AttackLens must not collect."""
    assert executable_of(command) == program


def test_winget_table_is_parsed_in_any_language() -> None:
    """Headers are localized, names contain spaces, and versions can be `<`."""
    output = "Nom                         ID                    Version  Disponible Source\n------------------------------------------------------------------------\nAntigravity (User)          Google.AntigravityIDE 1.16.5   2.5.5      winget\nAzul Zulu JDK 25.32 64-bit  Azul.Zulu.25.JDK      25.32.21 25.34.1    winget\nPython 3.12                 9NCVDN91XZQP          3.12.28  3.12.30    msstore\n3 mises à niveau disponibles."

    upgrades = parse_winget_upgrades(output)

    assert [item["id"] for item in upgrades] == [
        "Google.AntigravityIDE",
        "Azul.Zulu.25.JDK",
        "9NCVDN91XZQP",
    ]
    assert upgrades[1]["name"] == "Azul Zulu JDK 25.32 64-bit"
    assert upgrades[1]["available"] == "25.34.1"


def test_update_finding_survives_a_new_version() -> None:
    """The identity follows the software, so that a newer gap is the same finding."""
    first = {"name": "Git", "id": "Git.Git", "installed": "2.40", "available": "2.41"}
    second = {"name": "Git", "id": "Git.Git", "installed": "2.40", "available": "2.42"}

    one = software_findings("pc", {"items": [first]})[0]
    two = software_findings("pc", {"items": [second]})[0]

    assert one.stable_id() == two.stable_id()
    assert "winget upgrade --id Git.Git" in one.remediation


AUTORUN = {"kind": "run key", "name": "Updater", "command": "C:\\evil.exe"}
FULL = {"posture": {"status": "complete"}, "outdated_status": "complete"}
FAILED = {"posture": {"status": "unknown"}, "outdated_status": "unknown"}


def test_new_autostart_entry_always_alerts(store) -> None:
    """Persistence is the signature of a compromise, whatever its severity."""
    known = persistence_findings("pc", {"autoruns": []})
    new = persistence_findings("pc", {"autoruns": [AUTORUN]})
    ingest(store, build_document(known, "pc", "host", extra=FULL))

    alerted = ingest(store, build_document(new, "pc", "host", extra=FULL))

    assert new[0].severity == "info"
    assert [finding["title"] for finding in alerted] == [new[0].title]


def test_first_posture_report_is_a_baseline(store) -> None:
    """Existing autostart entries are not news on the first report that lists them."""
    ingest(store, build_document([], "pc", "host"))

    findings = persistence_findings("pc", {"autoruns": [AUTORUN]})
    alerted = ingest(store, build_document(findings, "pc", "host", extra=FULL))

    assert alerted == []


def test_failed_collection_does_not_flood_the_next_report(store) -> None:
    """Regression: one failed run made 78 existing findings look new."""
    findings = persistence_findings("pc", {"autoruns": [AUTORUN]})
    ingest(store, build_document(findings, "pc", "host", extra=FULL))
    ingest(store, build_document([], "pc", "host", extra=FAILED))

    alerted = ingest(store, build_document(findings, "pc", "host", extra=FULL))

    assert alerted == []


def test_real_change_is_found_across_a_failed_collection(store) -> None:
    """The comparison skips the failed report instead of giving up."""
    other = {"kind": "run key", "name": "Other", "command": "C:\\other.exe"}
    ingest(store, build_document(persistence_findings("pc", {"autoruns": [AUTORUN]}), "pc", "host", extra=FULL))
    ingest(store, build_document([], "pc", "host", extra=FAILED))

    both = persistence_findings("pc", {"autoruns": [AUTORUN, other]})
    alerted = ingest(store, build_document(both, "pc", "host", extra=FULL))

    assert [finding["title"] for finding in alerted] == [both[1].title]


def test_failed_collection_raises_no_alert_by_itself(store) -> None:
    """An unreadable posture is reported as such, not as a change."""
    ingest(store, build_document([], "pc", "host", extra=FULL))
    unknown = posture_findings("pc", {"status": "unknown"}, NOW)

    assert ingest(store, build_document(unknown, "pc", "host", extra=FAILED)) == []


def _host_report(**overrides) -> dict:
    report = build_document(
        [],
        "pc",
        "host",
        extra={
            "addresses": ["10.0.0.5"],
            "listeners": {
                "items": [
                    {"port": 445, "process": "System", "exposure": "all"},
                    {"port": 5432, "process": "postgres", "exposure": "all"},
                    {"port": 6463, "process": "Discord", "exposure": "loopback"},
                    {"port": 40000, "process": "app", "exposure": "all"},
                ]
            },
        },
    )
    return {**report, **overrides}


def _probe(states: dict[int, str], status: str = "complete", target: str = "10.0.0.5") -> dict:
    return probe_document(NetworkScan(status=status, port_states=states), target, 1.0)


@pytest.mark.parametrize(
    ("bound_to", "port", "probe", "verdict"),
    [
        ("loopback", 6463, None, LOCAL),
        ("loopback", 6463, {"port_states": {"6463": "open"}}, LOCAL),
        ("all", 445, None, UNVERIFIED),
        ("all", 445, {"port_states": {"445": "open"}}, EXPOSED),
        ("all", 445, {"port_states": {"445": "filtered"}}, SHIELDED),
        ("all", 445, {"port_states": {"445": "closed"}}, SHIELDED),
        ("all", 40000, {"port_states": {"445": "open"}}, UNVERIFIED),
        ("all", 445, {"status": "no_response", "port_states": {}}, SHIELDED),
        (None, 445, {"port_states": {"445": "open"}}, EXPOSED),
    ],
)
def test_port_verdict(bound_to, port, probe, verdict) -> None:
    """The verdict needs the inside and the outside view."""
    assert port_verdict(bound_to, port, probe) == verdict


def test_exposure_report_counts_verdicts() -> None:
    """A port the probe did not cover stays unverified, not safe."""
    report = exposure_report(_host_report(), _probe({445: "open", 5432: "filtered"}))

    assert report["status"] == "verified"
    assert report["summary"] == {EXPOSED: 1, SHIELDED: 1, UNVERIFIED: 1, LOCAL: 1}


def test_probe_command_lists_the_ports_to_test() -> None:
    """The dashboard gives the exact command to run on the other machine."""
    report = exposure_report(_host_report(), None)

    assert report["status"] == "unverified"
    assert "attacklens probe 10.0.0.5 --ports 445,5432,40000" in report["probe_command"]


def test_probe_is_matched_by_address(store) -> None:
    """A probe targets an address, the agent reports a hostname."""
    probe = _probe({445: "open"})
    store.save_scan(probe)
    store.save_scan(_probe({445: "open"}, target="10.9.9.9"))

    assert find_probe(store, _host_report())["scan_id"] == probe["scan_id"]


def test_old_probe_is_ignored(store) -> None:
    """A firewall can change: an old answer proves nothing about today."""
    probe = _probe({445: "filtered"})
    probe["completed_at"] = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    store.save_scan(probe)

    assert find_probe(store, _host_report()) is None


def test_annotate_marks_port_findings_only() -> None:
    """Findings without a port have no reachability."""
    document = build_document(
        [
            Finding("network", "high", "SMB", "d", target="pc", port=445),
            Finding("posture", "low", "UAC", "d", target="pc"),
        ],
        "pc",
        "network",
    )

    annotated = annotate(document, _host_report(), _probe({445: "filtered"}))

    assert annotated["findings"][0]["reachability"] == SHIELDED
    assert "reachability" not in annotated["findings"][1]


def test_api_serves_the_correlation(client, store) -> None:
    """The dashboard gets the verdict from the stored views."""
    store.save_scan(_host_report())
    store.save_scan(_probe({445: "open"}))
    store.save_scan(
        build_document([Finding("network", "high", "SMB", "d", target="pc", port=445)], "pc", "network")
    )

    assert client.get("/api/exposure").json()["summary"][EXPOSED] == 1
    assert client.get("/api/results").json()["findings"][0]["reachability"] == EXPOSED


def test_probe_is_kept_out_of_the_network_results(client, store) -> None:
    """A probe is another view of a machine, not its latest network scan."""
    store.save_scan(build_document([], "pc", "network"))
    store.save_scan(_probe({445: "open"}))

    assert client.get("/api/results").json()["target"] == "pc"


def test_probe_cli_writes_a_file_and_import_stores_it(tmp_path, monkeypatch, capsys) -> None:
    """The result travels from the other machine as a file."""
    path = tmp_path / "attacklens.db"
    report = tmp_path / "probe.json"
    monkeypatch.setenv("ATTACKLENS_DB_PATH", str(path))
    monkeypatch.setenv("ATTACKLENS_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.delenv("ATTACKLENS_API_URL", raising=False)
    calls = {}

    def fake_scan(host, timeout, extra_ports):
        calls.update(host=host, ports=extra_ports)
        return NetworkScan(ports_closed=1, port_states={902: "closed"})

    monkeypatch.setattr(cli, "scan_network", fake_scan)
    monkeypatch.setattr(
        "sys.argv", ["attacklens", "probe", "10.0.0.5", "--ports", "902,912", "--output", str(report)]
    )
    with pytest.raises(SystemExit):
        cli.main()

    assert calls == {"host": "10.0.0.5", "ports": [902, 912]}
    assert not path.exists()
    assert json.loads(report.read_text(encoding="utf-8"))["vantage"] == "external"

    monkeypatch.setattr("sys.argv", ["attacklens", "import", str(report)])
    with pytest.raises(SystemExit) as outcome:
        cli.main()

    assert outcome.value.code == 0
    assert "Imported the probe" in capsys.readouterr().out


def test_import_refuses_other_files(tmp_path, monkeypatch, capsys) -> None:
    """Only probe results can be imported."""
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({"scan_type": "network"}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["attacklens", "import", str(report)])

    with pytest.raises(SystemExit) as outcome:
        cli.main()

    assert outcome.value.code == 2
    assert "not a probe" in capsys.readouterr().err
