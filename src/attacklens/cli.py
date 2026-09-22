"""Command-line interface for AttackLens."""

import argparse

from attacklens import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="attacklens",
        description="Local attack surface and attack path analyzer.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def main() -> None:
    """Run the AttackLens command-line interface."""
    parser = build_parser()
    parser.parse_args()

    print(f"AttackLens {__version__}")
    print("Scanner not implemented yet.")


if __name__ == "__main__":
    main()