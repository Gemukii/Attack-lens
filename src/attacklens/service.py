"""Keeps the agent running in the background, as the current user.

The agent deliberately does not run as a Windows service: those run as SYSTEM unless
given an account, and an agent reachable from the API needs no such rights. A scheduled
task under the user's own account restarts it on failure with least privilege.
"""

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

TASK_NAME = "AttackLens Agent"
UNIT_NAME = "attacklens-agent.service"
MAX_LOG_BYTES = 1_000_000


class ServiceError(Exception):
    """The background agent could not be managed."""


def config_directory() -> Path:
    """Return the per-user directory of the agent."""
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AttackLens"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "attacklens"


def agent_config_path() -> Path:
    """Return the file holding the identity of this agent."""
    return config_directory() / "agent.json"


def load_agent_config() -> dict[str, str]:
    """Return the identity of this agent, if it enrolled."""
    try:
        return json.loads(agent_config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_agent_config(api_url: str, token: str) -> None:
    """Store the identity of this agent, readable by the current user only."""
    path = agent_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump({"api_url": api_url, "token": token}, file)
    temporary.replace(path)


def log_path() -> Path:
    """Return the location of the background agent's log."""
    return config_directory() / "agent.log"


def file_logger(path: str | None) -> Callable[[str], None]:
    """Return a logger writing to a file, keeping the previous one when it grows."""
    if not path:
        return print
    target = Path(path)

    def log(message: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.stat().st_size > MAX_LOG_BYTES:
            target.replace(target.with_suffix(".old.log"))
        with target.open("a", encoding="utf-8") as file:
            file.write(f"{datetime.now(UTC).isoformat()} {message}\n")

    return log


def agent_arguments(api_url: str) -> list[str]:
    """Return the arguments starting the agent."""
    return [
        "-m",
        "attacklens.cli",
        "agent",
        "--watch",
        "--api-url",
        api_url,
        "--log-file",
        str(log_path()),
    ]


def windowless_python() -> str:
    """Return the interpreter that opens no console window on Windows."""
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate) if candidate.exists() else sys.executable


def _quote(value: str) -> str:
    """Quote a value for a single-quoted PowerShell string."""
    return "'" + value.replace("'", "''") + "'"


def windows_install_script(api_url: str) -> str:
    """Return the PowerShell commands registering the agent task."""
    arguments = " ".join(
        f'"{argument}"' if " " in argument else argument for argument in agent_arguments(api_url)
    )
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            # Without this, a running agent would keep its old code after a reinstall.
            f"Stop-ScheduledTask -TaskName {_quote(TASK_NAME)} -ErrorAction SilentlyContinue",
            "$user = \"$env:USERDOMAIN\\$env:USERNAME\"",
            (f"$action = New-ScheduledTaskAction -Execute {_quote(windowless_python())} "
            f"-Argument {_quote(arguments)}"),
            "$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user",
            ("$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive "
            "-RunLevel Limited"),
            ("$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries "
            "-DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew "
            "-RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) "
            "-ExecutionTimeLimit (New-TimeSpan -Seconds 0)"),
            (f"Register-ScheduledTask -TaskName {_quote(TASK_NAME)} -Action $action "
            "-Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null"),
            f"Start-ScheduledTask -TaskName {_quote(TASK_NAME)}",
        ]
    )


def systemd_unit(api_url: str) -> str:
    """Return the user unit running the agent on Linux."""
    command = " ".join([sys.executable, *agent_arguments(api_url)])
    return "\n".join(
        [
            "[Unit]",
            "Description=AttackLens agent",
            "After=network-online.target",
            "",
            "[Service]",
            f"ExecStart={command}",
            "Restart=always",
            "RestartSec=30",
            "NoNewPrivileges=true",
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ]
    )


def _run(command: list[str]) -> str:
    """Run a management command and return its output."""
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ServiceError(str(error)) from error
    if completed.returncode != 0:
        raise ServiceError((completed.stderr or completed.stdout).strip()[:400])
    return completed.stdout.strip()


def _powershell(script: str) -> str:
    """Run a PowerShell script."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    executable = Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    return _run([str(executable), "-NoProfile", "-NonInteractive", "-Command", script])


def _unit_path() -> Path:
    """Return the location of the systemd user unit."""
    return Path.home() / ".config/systemd/user" / UNIT_NAME


def install(api_url: str) -> str:
    """Start the agent now, and at each logon."""
    if sys.platform == "win32":
        _powershell(windows_install_script(api_url))
        return f"Task '{TASK_NAME}' installed and started. Log: {log_path()}"
    if shutil.which("systemctl"):
        unit = _unit_path()
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(systemd_unit(api_url), encoding="utf-8")
        _run(["systemctl", "--user", "daemon-reload"])
        _run(["systemctl", "--user", "enable", UNIT_NAME])
        _run(["systemctl", "--user", "restart", UNIT_NAME])
        return f"Unit {UNIT_NAME} installed and started. Log: {log_path()}"
    raise ServiceError("This platform has no supported service manager.")


def uninstall() -> str:
    """Stop the agent and remove it from the startup sequence."""
    if sys.platform == "win32":
        name = _quote(TASK_NAME)
        _powershell(
            f"Stop-ScheduledTask -TaskName {name} -ErrorAction SilentlyContinue; "
            f"Unregister-ScheduledTask -TaskName {name} -Confirm:$false"
        )
        return f"Task '{TASK_NAME}' removed."
    _run(["systemctl", "--user", "disable", "--now", UNIT_NAME])
    _unit_path().unlink(missing_ok=True)
    return f"Unit {UNIT_NAME} removed."


def service_status() -> str:
    """Return whether the background agent is running."""
    if sys.platform == "win32":
        state = _powershell(
            f"(Get-ScheduledTask -TaskName {_quote(TASK_NAME)} "
            "-ErrorAction SilentlyContinue).State"
        )
        return state or "not installed"
    try:
        return _run(["systemctl", "--user", "is-active", UNIT_NAME])
    except ServiceError:
        return "not running"
