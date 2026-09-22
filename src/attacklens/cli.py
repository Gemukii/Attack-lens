"""Command-line interface for AttackLens."""
import argparse
import json
from pathlib import Path

from attacklens.results import save_results
from attacklens.scanner import scan_network


def build_parser() -> argparse.ArgumentParser:
    """Build the AttackLens command-line parser."""
    parser = argparse.ArgumentParser(
        prog="attacklens",
        description="Local security scanner.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a security scan.",
    )

    scan_parser.add_argument(
        "--network",
        action="store_true",
        help="Scan the local network services.",
    )

    scan_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host (default: 127.0.0.1).",
    )

    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON.",
    )
    return parser


def main() -> None:
    """Run the AttackLens CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.network:
        findings = scan_network(args.host)
        save_results(
            findings=findings,
            path=Path("results/latest.json"),
            target=args.host,
            scan_type="network",
        )
        if args.json:
            print(
                json.dumps(
                    [finding.to_dict() for finding in findings],
                    indent=2,
                )
            )
            return
        print("AttackLens")
        print("==========")
        print(f"Target: {args.host}")
        print()
        print(f"{len(findings)} finding(s) detected")

        for finding in findings:
            print(
                f"[{finding.severity.upper()}] "
                f"{finding.title}"
            )
    else:
        parser.error(
            "No scan type selected. Use --network."
        )


if __name__ == "__main__":
    main()