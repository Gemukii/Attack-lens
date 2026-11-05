"""Tests for the single way of running AttackLens."""

import sys
from types import SimpleNamespace

import pytest

from attacklens import cli, launcher
from attacklens.client import ApiError
from attacklens.launcher import LaunchError, read_env_file, start, status_report
from attacklens.service import load_agent_config, save_agent_config


@pytest.fixture
def project(tmp_path, monkeypatch):
    """Run inside an empty project."""
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def stack(project, monkeypatch):
    """Replace Docker and the agent, and record what happens."""
    calls = []
    monkeypatch.setattr(launcher, "docker_is_running", lambda: True)
    monkeypatch.setattr(launcher, "wait_for_api", lambda: calls.append("wait"))
    monkeypatch.setattr(launcher, "ensure_enrolled", lambda root: calls.append("enroll"))
    monkeypatch.setattr(launcher, "_compose", lambda root, *args: calls.append(args[0]))
    monkeypatch.setattr(launcher, "stop_containers", lambda root: calls.append("stop"))
    monkeypatch.setattr(launcher.signal, "signal", lambda *args: None)
    monkeypatch.setattr(launcher.webbrowser, "open", lambda url: calls.append("browser"))
    return calls


def test_project_is_found_from_a_subfolder(project, monkeypatch) -> None:
    """The command works from anywhere in the project."""
    sub = project / "src" / "deep"
    sub.mkdir(parents=True)
    monkeypatch.chdir(sub)

    assert launcher.project_root() == project


def test_env_file_is_read_without_comments(project) -> None:
    """Values can contain an equals sign."""
    (project / ".env").write_text("# comment\nA=1\nB=x=y\nEMPTY=\n", encoding="utf-8")

    assert read_env_file(project) == {"A": "1", "B": "x=y", "EMPTY": ""}


def test_stopping_the_window_stops_the_containers(stack, monkeypatch) -> None:
    """Nothing may outlive the window: that is the whole point."""

    def interrupted(*args, **kwargs):
        stack.append("watch")
        raise KeyboardInterrupt

    monkeypatch.setattr(launcher, "watch", interrupted)

    start()

    assert stack == ["up", "wait", "enroll", "browser", "watch", "stop"]


def test_failure_after_start_still_stops_the_containers(stack, monkeypatch) -> None:
    """A failed launch must not leave containers behind."""

    def fail(root):
        raise LaunchError("no identity")

    monkeypatch.setattr(launcher, "ensure_enrolled", fail)

    with pytest.raises(LaunchError):
        start()

    assert stack == ["up", "wait", "stop"]


def test_browser_is_optional(stack, monkeypatch) -> None:
    """--no-browser keeps the window only."""
    monkeypatch.setattr(launcher, "watch", lambda *args, **kwargs: None)

    start(open_browser=False)

    assert "browser" not in stack


def test_docker_must_be_running(project, monkeypatch) -> None:
    """The message says what to do, and Docker Desktop is not started behind your back."""
    monkeypatch.setattr(launcher, "docker_is_running", lambda: False)

    with pytest.raises(LaunchError, match="Start Docker Desktop"):
        start()


def test_enrollment_is_automatic_and_uses_the_project_key(project, monkeypatch) -> None:
    """One command is enough on a new installation."""
    (project / ".env").write_text("ATTACKLENS_API_KEY=project-key\n", encoding="utf-8")
    monkeypatch.delenv("ATTACKLENS_API_KEY", raising=False)
    keys = []

    def post(url, path, payload, timeout=30):
        keys.append(launcher.os.environ.get("ATTACKLENS_API_KEY"))
        return {"code": "c"} if path.endswith("enrollment") else {"token": "machine-token"}

    monkeypatch.setattr(launcher, "api_post", post)

    launcher.ensure_enrolled(project)

    assert keys == ["project-key", "project-key"]
    assert load_agent_config()["token"] == "machine-token"
    assert "ATTACKLENS_API_KEY" not in launcher.os.environ


def test_valid_identity_is_kept(project, monkeypatch) -> None:
    """No new token at each start."""
    save_agent_config("http://127.0.0.1:8000", "existing")
    paths = []
    monkeypatch.setattr(
        launcher, "api_post", lambda url, path, payload, timeout=30: paths.append(path) or {}
    )

    launcher.ensure_enrolled(project)

    assert paths == ["/api/agent/poll"]


def test_identity_lost_by_the_api_is_renewed(project, monkeypatch) -> None:
    """After a reset of the database, the old token is refused."""
    save_agent_config("http://127.0.0.1:8000", "stale")

    def post(url, path, payload, timeout=30):
        if path == "/api/agent/poll":
            raise ApiError("The API refused the request: HTTP 401.")
        return {"code": "c"} if path.endswith("enrollment") else {"token": "fresh"}

    monkeypatch.setattr(launcher, "api_post", post)

    launcher.ensure_enrolled(project)

    assert load_agent_config()["token"] == "fresh"


def test_status_shows_what_runs_and_what_starts_alone(monkeypatch) -> None:
    """The answer to `what is running on my machine?`."""
    monkeypatch.setattr(launcher, "_containers", lambda: ["attacklens-api: Up 2 minutes"])
    monkeypatch.setattr(launcher, "_agent_processes", list)
    monkeypatch.setattr(launcher, "service_status", lambda: "not installed")

    report = "\n".join(status_report())

    assert "attacklens-api: Up 2 minutes" in report
    assert "Agent: not running" in report
    assert "Background task: not installed" in report


def test_status_shows_one_agent_whatever_the_launchers(monkeypatch) -> None:
    """Windows runs an agent through several Python launchers: that is still one agent."""
    monkeypatch.setattr(launcher, "_containers", list)
    monkeypatch.setattr(launcher, "_agent_processes", lambda: ["pid 1", "pid 2", "pid 3"])
    monkeypatch.setattr(launcher, "service_status", lambda: "not installed")

    assert status_report().count("  Agent: running") == 1


def test_stop_outlives_a_closing_console(project, monkeypatch) -> None:
    """Regression: closing the window would kill a stop running in the same console."""
    calls = {}

    class Process:
        def wait(self, timeout):
            calls["timeout"] = timeout

    def popen(command, **options):
        calls.update(command=command, options=options)
        return Process()

    monkeypatch.setattr(launcher.subprocess, "Popen", popen)

    launcher.stop_containers(project)

    assert calls["command"] == ["docker", "compose", "stop"]
    if sys.platform == "win32":
        assert calls["options"]["creationflags"] == launcher.subprocess.CREATE_NO_WINDOW


def test_status_says_when_nothing_runs(monkeypatch) -> None:
    """An empty state is stated, not left to interpretation."""
    monkeypatch.setattr(launcher, "_containers", list)
    monkeypatch.setattr(launcher, "_agent_processes", list)
    monkeypatch.setattr(launcher, "service_status", lambda: "not installed")

    assert "  Containers: none" in status_report()


def test_agent_process_detection(monkeypatch) -> None:
    """Only real agents count, not an editor with the project open."""
    processes = [
        SimpleNamespace(info={"pid": 1, "name": "python.exe", "cmdline": ["python", "-m", "attacklens.cli", "agent", "--watch"]}),
        SimpleNamespace(info={"pid": 2, "name": "attacklens.exe", "cmdline": ["attacklens.exe", "start"]}),
        SimpleNamespace(info={"pid": 3, "name": "Code.exe", "cmdline": ["Code.exe", "attacklens start"]}),
        SimpleNamespace(info={"pid": 4, "name": "python.exe", "cmdline": ["python", "other.py"]}),
    ]
    monkeypatch.setattr(launcher.psutil, "process_iter", lambda fields: processes)

    assert launcher._agent_processes() == ["pid 1 python.exe", "pid 2 attacklens.exe"]


def test_cli_reports_launch_errors_cleanly(monkeypatch, capsys) -> None:
    """No traceback when Docker is off."""

    def fail(open_browser):
        raise LaunchError("Docker is not running.")

    monkeypatch.setattr(cli, "start", fail)
    monkeypatch.setattr(sys, "argv", ["attacklens", "start"])

    with pytest.raises(SystemExit) as outcome:
        cli.main()

    assert outcome.value.code == 2
    assert "Docker is not running" in capsys.readouterr().err
