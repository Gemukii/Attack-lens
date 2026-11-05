"""Host agent: runs on the analyzed machine and takes orders from the dashboard.

The agent only makes outbound calls to the API, so nothing has to reach into the host.
It accepts a single kind of order, a scan, and never executes anything it receives.
"""

import platform
import socket
from collections.abc import Callable
from time import monotonic, perf_counter, sleep
from typing import Any

from attacklens import __version__
from attacklens.client import ApiError, api_post, send_report
from attacklens.host import collect_host_report
from attacklens.results import network_document
from attacklens.scanner import TargetResolutionError, is_valid_target, scan_network

POLL_SECONDS = 2.0
# Without the API there is nothing to do: the agent only checks now and then.
IDLE_SECONDS = 30.0
LOOPBACK = "127.0.0.1"


def primary_address() -> str:
    """Return the address other machines use to reach this one.

    Connecting a UDP socket only selects a route: no packet is sent.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("192.0.2.1", 9))
            return probe.getsockname()[0]
        except OSError:
            return LOOPBACK


def identity() -> dict[str, str]:
    """Describe this agent to the API."""
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "version": __version__,
        "address": primary_address(),
    }


def scan_this_machine() -> dict[str, Any]:
    """Scan the network address of this machine, recorded under its stable hostname.

    The address changes with the network, the hostname does not. Probing that address
    instead of loopback leaves out the services other machines cannot reach.
    """
    started_at = perf_counter()
    hostname = socket.gethostname()
    scan = scan_network(primary_address(), asset=hostname)
    return network_document(scan, hostname, perf_counter() - started_at)


def scan_target(target: str) -> dict[str, Any]:
    """Scan another machine from this one."""
    started_at = perf_counter()
    scan = scan_network(target)
    return network_document(scan, target, perf_counter() - started_at)


def run_job(job: dict[str, Any], api_url: str) -> None:
    """Run one scan order and report its outcome."""
    target = job.get("target")
    failure: str | None = None
    scan_id: str | None = None
    try:
        if target and not is_valid_target(target):
            raise TargetResolutionError(f"Invalid target '{target}'.")
        document = scan_target(target) if target else scan_this_machine()
        send_report(document, api_url)
        scan_id = document["scan_id"]
        if not target:
            send_report(collect_host_report(), api_url)
    except (TargetResolutionError, OSError) as error:
        failure = str(error)

    api_post(
        api_url,
        f"/api/agent/jobs/{job['job_id']}/result",
        {"status": "failed" if failure else "done", "error": failure, "scan_id": scan_id},
    )


def watch(
    api_url: str,
    report_interval: int | None = None,
    log: Callable[[str], None] = print,
    wait: Callable[[float], None] = sleep,
) -> None:
    """Wait for orders from the dashboard, and report on a schedule if asked to."""
    connected: bool | None = None
    next_report = 0.0

    while True:
        delay = POLL_SECONDS
        try:
            # The cheap call comes first: no collection happens while the API is down.
            answer = api_post(api_url, "/api/agent/poll", identity(), timeout=10)
            if not connected:
                log(f"Connected to {api_url}. Waiting for orders from the dashboard.")
                connected = True
                next_report = 0.0
            if monotonic() >= next_report:
                send_report(collect_host_report(), api_url)
                next_report = monotonic() + (report_interval or float("inf"))
            job = answer.get("job") if answer else None
            if job:
                log(f"Scanning {job.get('target') or 'this machine'}.")
                run_job(job, api_url)
        except ApiError as error:
            delay = IDLE_SECONDS
            if connected is not False:
                log(f"{error} Waiting for it to come back.")
                connected = False
        except OSError as error:
            # A long-running agent must survive a transient failure of a collector.
            log(f"Collection failed: {error}")
        wait(delay)
