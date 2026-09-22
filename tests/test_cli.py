"""Tests for the AttackLens CLI."""

from attacklens.cli import build_parser


def test_parser_requires_command() -> None:
    """The parser should require a command."""
    parser = build_parser()

    assert parser.parse_args(["scan", "--network"]).command == "scan"


def test_network_scan_option() -> None:
    """The network option should be enabled."""
    parser = build_parser()

    args = parser.parse_args(
        ["scan", "--network", "--host", "127.0.0.1"]
    )

    assert args.network is True
    assert args.host == "127.0.0.1"


def test_json_option() -> None:
    """The JSON option should be enabled."""
    parser = build_parser()

    args = parser.parse_args(
        ["scan", "--network", "--json"]
    )

    assert args.json is True