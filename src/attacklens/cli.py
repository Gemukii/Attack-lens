"""Command-line interface for AttackLens."""

import argparse
import json
import os
import socket
import sys
from collections.abc import Callable
from pathlib import Path
from time import perf_counter, sleep
from typing import Any

from attacklens.agent import watch
from attacklens.client import ApiError, api_post, send_report
from attacklens.host import collect_host_report
from attacklens.launcher import LaunchError, start, status_report, stop
from attacklens.pipeline import ingest
from attacklens.results import (
    SEVERITY_ORDER,
    network_document,
    probe_document,
    severity_at_least,
)
from attacklens.scanner import DEFAULT_TIMEOUT_SECONDS, TargetResolutionError, scan_network
from attacklens.service import (
    ServiceError,
    file_logger,
    install,
    load_agent_config,
    save_agent_config,
    service_status,
    uninstall,
)
from attacklens.storage import Store, default_database_path, results_directory

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    """Build the AttackLens command-line parser."""
    parser = argparse.ArgumentParser(
        prog="attacklens",
        description="Local security scanner.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="Output the result as JSON.")
    common.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        help="Exit with code 1 when a finding reaches this severity.",
    )
    common.add_argument(
        "--interval",
        type=int,
        metavar="SECONDS",
        help="Repeat forever, waiting this long between runs.",
    )
    common.add_argument(
        "--api-url",
        default=os.getenv("ATTACKLENS_API_URL"),
        help="Send results to this API instead of the local database. Required when "
        "the API runs in Docker, since it owns the database.",
    )

    start_parser = subparsers.add_parser(
        "start", help="Start everything in this window. Ctrl+C stops everything."
    )
    start_parser.add_argument(
        "--no-browser", action="store_true", help="Do not open the dashboard."
    )
    subparsers.add_parser("stop", help="Stop the containers.")
    subparsers.add_parser("status", help="Show what is running, and what starts by itself.")

    scan_parser = subparsers.add_parser("scan", parents=[common], help="Run a security scan.")
    scan_parser.add_argument(
        "--network",
        action="store_true",
        help="Scan the network services of a target.",
    )
    scan_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host (default: 127.0.0.1).",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Seconds to wait for each port (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )

    agent_parser = subparsers.add_parser(
        "agent",
        parents=[common],
        help="Inspect this machine from the inside: listeners, firewall, and software.",
    )
    agent_parser.add_argument(
        "--watch",
        action="store_true",
        help="Stay connected to the API and run the scans requested from the dashboard. "
        "With --interval, also send a host report on that schedule.",
    )
    agent_parser.add_argument("--log-file", help="Write the agent's messages to this file.")

    probe_parser = subparsers.add_parser(
        "probe",
        parents=[common],
        help="Run from ANOTHER machine: shows what is really reachable through the firewall.",
    )
    probe_parser.add_argument("host", help="Address of the machine to test.")
    probe_parser.add_argument(
        "--ports",
        default="",
        help="Extra comma-separated ports, as listed by the dashboard.",
    )
    probe_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Seconds to wait for each port (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    probe_parser.add_argument(
        "--output",
        help="Write the result to a file, to import it on the analyzed machine.",
    )

    import_parser = subparsers.add_parser(
        "import", help="Store a probe result produced on another machine."
    )
    import_parser.add_argument("file", help="File written by `attacklens probe --output`.")
    import_parser.add_argument(
        "--api-url",
        default=os.getenv("ATTACKLENS_API_URL"),
        help="Send it to this API instead of the local database.",
    )

    enroll_parser = subparsers.add_parser(
        "enroll", help="Give this machine its own identity, with a code from the dashboard."
    )
    enroll_parser.add_argument("code", help="One-time code shown by the dashboard.")
    enroll_parser.add_argument(
        "--api-url",
        default=os.getenv("ATTACKLENS_API_URL", "http://127.0.0.1:8000"),
        help="API of the dashboard (default: http://127.0.0.1:8000).",
    )

    backup_parser = subparsers.add_parser("backup", help="Copy the local database.")
    backup_parser.add_argument("output", help="File to write.")

    service_parser = subparsers.add_parser(
        "service",
        help="Optional: run the agent permanently, at each logon. Not needed with `start`.",
    )
    service_parser.add_argument("action", choices=("install", "uninstall", "status"))
    service_parser.add_argument(
        "--api-url",
        default=os.getenv("ATTACKLENS_API_URL", "http://127.0.0.1:8000"),
        help="API the agent reports to (default: http://127.0.0.1:8000).",
    )
    return parser


def run_enroll(args: argparse.Namespace) -> int:
    """Exchange a one-time code for this machine's token."""
    try:
        answer = api_post(
            args.api_url,
            "/api/agents/enroll",
            {"code": args.code, "hostname": socket.gethostname()},
        )
    except ApiError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR
    save_agent_config(args.api_url, answer["token"])
    print(f"{answer['hostname']} is enrolled. Next: attacklens service install")
    return EXIT_OK


def run_launcher_command(args: argparse.Namespace) -> int:
    """Start, stop, or describe AttackLens."""
    try:
        if args.command == "start":
            start(open_browser=not args.no_browser)
        elif args.command == "stop":
            stop()
        else:
            print("\n".join(status_report()))
    except LaunchError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def run_service_command(args: argparse.Namespace) -> int:
    """Manage the background agent."""
    try:
        if args.action == "install":
            print(install(args.api_url))
        elif args.action == "uninstall":
            print(uninstall())
        else:
            print(service_status())
    except ServiceError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def publish(document: dict[str, Any], api_url: str | None) -> None:
    """Store a scan locally, or hand it over to the API."""
    if api_url:
        send_report(document, api_url)
    else:
        ingest(Store(default_database_path(), legacy_directory=results_directory()), document)


def run_network_scan(args: argparse.Namespace) -> dict[str, Any]:
    """Run one network scan."""
    started_at = perf_counter()
    scan = scan_network(args.host, timeout=args.timeout)
    return network_document(scan, args.host, perf_counter() - started_at)


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    """Scan a machine from the outside."""
    try:
        ports = [int(port) for port in args.ports.split(",") if port.strip()]
    except ValueError as error:
        raise TargetResolutionError("--ports must be comma-separated numbers.") from error
    started_at = perf_counter()
    scan = scan_network(args.host, timeout=args.timeout, extra_ports=ports)
    return probe_document(scan, args.host, perf_counter() - started_at)


def run_import(args: argparse.Namespace) -> int:
    """Store a probe made elsewhere."""
    try:
        document = json.loads(Path(args.file).read_text(encoding="utf-8"))
        if document.get("scan_type") != "probe":
            raise ValueError("this file is not a probe result")
        publish(document, args.api_url)
    except (OSError, ValueError, ApiError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Imported the probe of {document['target']}.")
    return EXIT_OK


def print_summary(document: dict[str, Any]) -> None:
    """Print a scan for humans."""
    print("AttackLens")
    print("==========")
    print(f"Target: {document['target']}")
    print(f"Type:   {document['scan_type']}")
    print()
    if document["status"] == "no_response":
        print("No port answered: the host is down or fully filtered. Nothing was observed.")
        return

    print(f"{len(document['findings'])} finding(s) detected")
    for finding in document["findings"]:
        print(f"[{finding['severity'].upper()}] {finding['title']}")


def exit_code(document: dict[str, Any], fail_on: str | None) -> int:
    """Return the exit code of a finished scan."""
    if document["status"] == "no_response":
        return EXIT_ERROR
    if fail_on and any(
        severity_at_least(finding["severity"], fail_on) for finding in document["findings"]
    ):
        return EXIT_FINDINGS
    return EXIT_OK


def run_once(collect: Callable[[], dict[str, Any]], args: argparse.Namespace) -> int:
    """Run one collection, publish it, and report it."""
    try:
        document = collect()
        # A probe saved to a file is imported on the analyzed machine afterwards.
        if not getattr(args, "output", None):
            publish(document, args.api_url)
    except (TargetResolutionError, ApiError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    output = getattr(args, "output", None)
    if output:
        Path(output).write_text(json.dumps(document, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(document, indent=2))
    else:
        print_summary(document)
    return exit_code(document, args.fail_on)


def main() -> None:
    """Run the AttackLens CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command in {"start", "stop", "status"}:
        sys.exit(run_launcher_command(args))
    if args.command == "service":
        sys.exit(run_service_command(args))
    if args.command == "enroll":
        sys.exit(run_enroll(args))
    if args.command == "backup":
        Store(default_database_path(), legacy_directory=results_directory()).backup(
            Path(args.output)
        )
        sys.exit(EXIT_OK)
    if not getattr(args, "api_url", None):
        args.api_url = load_agent_config().get("api_url")
    if args.command == "import":
        sys.exit(run_import(args))
    if args.command == "scan" and not args.network:
        parser.error("No scan type selected. Use --network.")
    if args.interval is not None and args.interval <= 0:
        parser.error("--interval must be positive.")

    try:
        if args.command == "agent" and args.watch:
            if not args.api_url:
                parser.error("--watch needs --api-url.")
            watch(args.api_url, args.interval, log=file_logger(args.log_file))

        collectors = {
            "agent": collect_host_report,
            "probe": lambda: run_probe(args),
            "scan": lambda: run_network_scan(args),
        }
        collect = collectors[args.command]
        if args.interval is None:
            sys.exit(run_once(collect, args))

        while True:
            run_once(collect, args)
            sleep(args.interval)
    except KeyboardInterrupt:
        sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
