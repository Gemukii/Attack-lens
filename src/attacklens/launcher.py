"""One visible way to run AttackLens.

`attacklens start` runs everything in the foreground of one window: the Docker stack,
and the agent, which has to live outside Docker because a container cannot see the
processes, firewall, or registry of its host. Stopping it stops everything. Nothing
stays behind, and nothing starts by itself.
"""

import os
import shutil
import signal
import socket
import subprocess
import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path
from time import monotonic, sleep
from urllib.error import URLError
from urllib.request import urlopen

import psutil

from attacklens.agent import identity, watch
from attacklens.client import ApiError, api_post
from attacklens.service import (
    agent_config_path,
    load_agent_config,
    save_agent_config,
    service_status,
)

API_URL = "http://127.0.0.1:8000"
DASHBOARD_URL = "http://localhost:3000"
API_START_TIMEOUT_SECONDS = 180


class LaunchError(Exception):
    """AttackLens could not be started or stopped."""


def project_root() -> Path:
    """Find the project, from the current directory or from this installation."""
    current = Path.cwd()
    for candidate in (current, *current.parents, *Path(__file__).resolve().parents):
        if (candidate / "docker-compose.yml").exists():
            return candidate
    raise LaunchError("docker-compose.yml not found. Run this from the project folder.")


def read_env_file(root: Path) -> dict[str, str]:
    """Read the settings of the project."""
    values: dict[str, str] = {}
    try:
        lines = (root / ".env").read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        key, separator, value = line.strip().partition("=")
        if separator and not key.startswith("#"):
            values[key] = value
    return values


def _compose(root: Path, *arguments: str) -> None:
    """Run Docker Compose in the project."""
    try:
        completed = subprocess.run(["docker", "compose", *arguments], cwd=root, check=False)
    except OSError as error:
        raise LaunchError("Docker is not installed.") from error
    if completed.returncode != 0:
        raise LaunchError(f"docker compose {arguments[0]} failed.")


def stop_containers(root: Path) -> None:
    """Stop the stack, even if the window of this process is closing.

    Closing a window also kills what runs in its console, and leaves about five seconds.
    The command therefore runs detached from this console, and outlives it if needed.
    """
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        process = subprocess.Popen(
            ["docker", "compose", "stop"],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        process.wait(timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        raise LaunchError("The containers could not be stopped.") from error


def docker_is_running() -> bool:
    """Return whether the Docker engine answers."""
    try:
        return (
            subprocess.run(
                ["docker", "info"], capture_output=True, timeout=30, check=False
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def api_is_up() -> bool:
    """Return whether the API answers."""
    try:
        with urlopen(f"{API_URL}/api/health", timeout=2):
            return True
    except (OSError, URLError):
        return False


def wait_for_api(wait: Callable[[float], None] = sleep) -> None:
    """Wait for the API, which takes a moment after the containers start."""
    deadline = monotonic() + API_START_TIMEOUT_SECONDS
    while monotonic() < deadline:
        if api_is_up():
            return
        wait(1)
    raise LaunchError("The API did not start in time. See: docker compose logs api")


def _enroll(api_key: str | None) -> None:
    """Give this machine an identity, using the key of the project."""
    previous = os.environ.get("ATTACKLENS_API_KEY")
    if api_key:
        os.environ["ATTACKLENS_API_KEY"] = api_key
    try:
        code = api_post(API_URL, "/api/agents/enrollment", {})["code"]
        answer = api_post(
            API_URL, "/api/agents/enroll", {"code": code, "hostname": socket.gethostname()}
        )
    finally:
        if previous is None:
            os.environ.pop("ATTACKLENS_API_KEY", None)
        else:
            os.environ["ATTACKLENS_API_KEY"] = previous
    save_agent_config(API_URL, answer["token"])


def ensure_enrolled(root: Path) -> None:
    """Enroll this machine if needed: the API may have lost its data since last time."""
    if load_agent_config().get("token"):
        try:
            api_post(API_URL, "/api/agent/poll", identity(), timeout=10)
            return
        except ApiError as error:
            if "401" not in str(error):
                raise LaunchError(str(error)) from error
    try:
        _enroll(read_env_file(root).get("ATTACKLENS_API_KEY"))
    except ApiError as error:
        raise LaunchError(f"Unable to enroll this machine: {error}") from error


def _raise_interrupt(*_: object) -> None:
    """Treat a closed window like Ctrl+C, so that the stack is stopped as well."""
    raise KeyboardInterrupt


def _short_wait(seconds: float) -> None:
    """Sleep in small steps: a closing window leaves only a few seconds to react."""
    deadline = monotonic() + seconds
    while monotonic() < deadline:
        sleep(0.2)


def start(open_browser: bool = True) -> None:
    """Start everything, and stop everything when this window stops."""
    root = project_root()
    if not docker_is_running():
        raise LaunchError("Docker is not running. Start Docker Desktop, then try again.")

    signal.signal(signal.SIGTERM, _raise_interrupt)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, _raise_interrupt)

    print("Starting Docker containers...", flush=True)
    _compose(root, "up", "-d")
    try:
        wait_for_api()
        ensure_enrolled(root)
        print(f"\nAttackLens is running: {DASHBOARD_URL}", flush=True)
        print("Press Ctrl+C here to stop everything.\n", flush=True)
        if open_browser:
            webbrowser.open(DASHBOARD_URL)
        watch(API_URL, wait=_short_wait)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping...", flush=True)
        stop_containers(root)
        print("AttackLens is stopped. Nothing keeps running.", flush=True)


def stop() -> None:
    """Stop the containers. An agent running in a window stops with its window."""
    stop_containers(project_root())


def _agent_processes() -> list[str]:
    """Return the AttackLens processes running outside Docker."""
    found = []
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        command = " ".join(process.info["cmdline"] or [])
        name = (process.info["name"] or "").lower()
        is_ours = "attacklens" in command.lower() and name.startswith(("python", "attacklens"))
        if is_ours and any(word in command for word in (" start", " agent", "--watch")):
            found.append(f"pid {process.info['pid']} {process.info['name']}")
    return found


def _containers() -> list[str]:
    """Return the AttackLens containers and their state."""
    if not shutil.which("docker") or not docker_is_running():
        return []
    completed = subprocess.run(
        ["docker", "ps", "--filter", "name=attacklens", "--format", "{{.Names}}: {{.Status}}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return completed.stdout.split("\n")[:-1]


def status_report() -> list[str]:
    """Describe everything AttackLens has running, and what it left on this machine."""
    containers = _containers()
    agents = _agent_processes()
    background = service_status()
    lines = ["Running now"]
    lines += [f"  Container  {item}" for item in containers] or ["  Containers: none"]
    lines.append("  Agent: running" if agents else "  Agent: not running")
    lines += [
        "",
        "Starts by itself",
        f"  Background task: {background}",
        "  Containers: never (restart policy: no)",
        "",
        "Files",
        f"  Agent identity: {agent_config_path()}",
        "  Database: Docker volume attack-lens_attacklens-data",
        "  Backups: backups/ in the project",
    ]
    return lines
