"""Command-line interface for AttackLens."""

import argparse
import json
import os
import sys
from collections.abc import Callable
from time import perf_counter, sleep
from typing import Any

from attacklens.agent import watch
from attacklens.client import ApiError, send_report
from attacklens.host import collect_host_report
from attacklens.pipeline import ingest
from attacklens.results import SEVERITY_ORDER, network_document, severity_at_least
from attacklens.scanner import DEFAULT_TIMEOUT_SECONDS, TargetResolutionError, scan_network
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
    return parser


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
        publish(document, args.api_url)
    except (TargetResolutionError, ApiError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(document, indent=2))
    else:
        print_summary(document)
    return exit_code(document, args.fail_on)


def main() -> None:
    """Run the AttackLens CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan" and not args.network:
        parser.error("No scan type selected. Use --network.")
    if args.interval is not None and args.interval <= 0:
        parser.error("--interval must be positive.")

    try:
        if args.command == "agent" and args.watch:
            if not args.api_url:
                parser.error("--watch needs --api-url.")
            watch(args.api_url, args.interval)

        collect = collect_host_report if args.command == "agent" else lambda: run_network_scan(args)
        if args.interval is None:
            sys.exit(run_once(collect, args))

        while True:
            run_once(collect, args)
            sleep(args.interval)
    except KeyboardInterrupt:
        sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
